#pragma warning (disable: 4005)	// warning C4005: ... macro redefinition

#include <Windows.h>
#include "..\\External\\ntdll.h"

#define int3							__debugbreak();
#define ERROR_READ_KERNEL				0xDEADBEEFDEADDEAD
#define SystemExtendedHandleInformation ((SYSTEMINFOCLASS)64)

enum
{
	WIN_7_X86 = 0,
	WIN_7_X64,
	WIN_8_X86,
	WIN_8_X64,
	WIN_81_X86,
	WIN_81_X64,
	WIN_10_1507_X86,
	WIN_10_1507_X64,
	WIN_10_1511_X86,
	WIN_10_1511_X64,
	WIN_10_1607_X86,
	WIN_10_1607_X64,
	WIN_10_1703_X86,
	WIN_10_1703_X64,
	WIN_10_1709_X86,
	WIN_10_1709_X64,
	WIN_10_1803_X86,
	WIN_10_1803_X64,
	WIN_10_1809_X86,
	WIN_10_1809_X64,
	WIN_10_1903_X86,
	WIN_10_1903_X64,
	WIN_10_1909_X86,
	WIN_10_1909_X64,
	WIN_10_2004_X86,
	WIN_10_2004_X64,
	WIN_10_20H2_X86,
	WIN_10_20H2_X64,
	WIN_10_21H1_X86,
	WIN_10_21H1_X64,
	WIN_MAX,
	WIN_UNKNOWN
};

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX 
{
	PVOID		Object;
	HANDLE		UniqueProcessId;
	HANDLE		HandleValue;
	ACCESS_MASK GrantedAccess;
	USHORT		CreatorBackTraceIndex;
	USHORT		ObjectTypeIndex;
	ULONG		HandleAttributes;
	ULONG		Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct _INTERNAL_PROCESS_OFFSETS
{
	ULONG ActiveProcessLinks;
	ULONG PreviousMode;
	ULONG Eprocess;
} INTERNAL_PROCESS_OFFSETS, *PINTERNAL_PROCESS_OFFSETS;

typedef struct _MY_KEY_VALUE_PARTIAL_INFORMATION {
  ULONG		TitleIndex;
  ULONG		Type;
  ULONG		DataLength;
  UCHAR		Data[20];
} MY_KEY_VALUE_PARTIAL_INFORMATION, *PMY_KEY_VALUE_PARTIAL_INFORMATION;

typedef NTSTATUS (NTAPI* NtQueryLicenseValueT)(
	PUNICODE_STRING ValueName,
    PULONG_PTR		Type,
    PVOID			Data,
    ULONG			DataSize,
    PULONG_PTR		ResultDataSize);

typedef NTSTATUS (NTAPI* NtSetInformationKeyT)(
    IN HANDLE			hKey,
    IN ULONG			KeyInformationClass,
    IN PVOID			KeyInformation,
    IN ULONG			KeyInformationLength
);

///////////////////////////////////////////////////////////////////////////////
// PORT ATTRIBUTE FLAGS
#define ALPC_PORTFLG_NONE 0x0
#define ALPC_PORTFLG_LPCPORT 0x1000
#define ALPC_PORTFLG_ALLOWIMPERSONATION 0x10000
#define ALPC_PORTFLG_ALLOW_LPC_REQUESTS 0x20000
#define ALPC_PORTFLG_WAITABLE_PORT 0x40000
#define ALPC_PORTFLG_SYSTEM_PROCESS 0x100000
#define ALPC_PORTFLG_ALLOW_DUP_OBJECT 0x80000
#define ALPC_PORTFLG_LRPC_WAKE_POLICY1 0x200000
#define ALPC_PORTFLG_LRPC_WAKE_POLICY2 0x400000
#define ALPC_PORTFLG_LRPC_WAKE_POLICY3 0x800000
#define ALPC_PORTFLG_DIRECT_MESSAGE 0x1000000

// ALPC Connection FLAGS
#define ALPC_SYNC_CONNECTION 0x20000
#define ALPC_USER_WAIT_MODE 0x100000
#define ALPC_WAIT_IS_ALERTABLE 0x200000

// ALPC Message Flags
#define ALPC_MSGFLG_NONE 0x0
#define ALPC_MSGFLG_REPLY_MESSAGE 0x1
#define ALPC_MSGFLG_LPC_MODE 0x2
#define ALPC_MSGFLG_RELEASE_MESSAGE 0x10000
#define ALPC_MSGFLG_SYNC_REQUEST 0x20000		// synchronous message, needs a receive buffer or else error 0xC0000705 is returned
#define ALPC_MSGFLG_WAIT_USER_MODE 0x100000
#define ALPC_MSGFLG_WAIT_ALERTABLE 0x200000
#define ALPC_MSGFLG_WOW64_CALL 0x80000000

// ALPC Message Attributes
#define ALPC_MESSAGE_SECURITY_ATTRIBUTE 0x80000000
#define ALPC_MESSAGE_VIEW_ATTRIBUTE 0x40000000
#define ALPC_MESSAGE_CONTEXT_ATTRIBUTE 0x20000000
#define ALPC_MESSAGE_HANDLE_ATTRIBUTE 0x10000000
#define ALPC_MESSAGE_TOKEN_ATTRIBUTE 0x8000000
#define ALPC_MESSAGE_DIRECT_ATTRIBUTE 0x4000000
#define ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE 0x2000000
#define ALPC_MESSAGE_ATTRIBUTE_ALL ALPC_MESSAGE_SECURITY_ATTRIBUTE | ALPC_MESSAGE_VIEW_ATTRIBUTE | ALPC_MESSAGE_CONTEXT_ATTRIBUTE | ALPC_MESSAGE_HANDLE_ATTRIBUTE | ALPC_MESSAGE_TOKEN_ATTRIBUTE | ALPC_MESSAGE_DIRECT_ATTRIBUTE | ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE

typedef struct _ALPC_PORT_MESSAGE
{
	union
	{
		struct
		{
			USHORT DataLength;
			USHORT TotalLength;
		} s1;
		ULONG Length;
	} u1;
	union
	{
		struct
		{
			USHORT Type;
			USHORT DataInfoOffset;
		} s2;
		ULONG ZeroInit;
	} u2;
	union
	{
		CLIENT_ID ClientId;
		double DoNotUseThisField;
	};
	ULONG MessageId;
	union
	{
		SIZE_T ClientViewSize;
		ULONG CallbackId;
	};
} ALPC_PORT_MESSAGE, * PALPC_PORT_MESSAGE;

typedef struct _ALPC_MESSAGE 
{
	ALPC_PORT_MESSAGE PortHeader;
	BYTE PortMessage[1000];				// Hard limit for this is 65488. An Error is thrown if AlpcMaxAllowedMessageLength() is exceeded
} ALPC_MESSAGE, * PALPC_MESSAGE;


typedef struct _CS_PORT_CONTEXT {
	ULONG PID;
	ULONG TID;
	ULONG ID;
} CS_PORT_CONTEXT, * PCS_PORT_CONTEXT;

typedef struct _PORT_VIEW 
{
	SIZE_T Length;                      // Size of this structure
	HANDLE SectionHandle;               // Handle to section object with SECTION_MAP_WRITE and SECTION_MAP_READ
	PVOID  SectionOffset;               // The offset in the section to map a view for the port data area. The offset must be aligned with the allocation granularity of the system.
	SIZE_T ViewSize;                    // The size of the view (in bytes)
	PVOID  ViewBase;                    // The base address of the view in the creator
	PVOID  ViewRemoteBase;              // The base address of the view in the process
} PORT_VIEW, *PPORT_VIEW;

typedef struct _ALPC_PORT_ATTRIBUTES
{
    ULONG Flags;
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    SIZE_T MaxMessageLength;
    SIZE_T MemoryBandwidth;
    SIZE_T MaxPoolUsage;
    SIZE_T MaxSectionSize;
    SIZE_T MaxViewSize;
    SIZE_T MaxTotalSectionSize;
    ULONG DupObjectTypes;
#ifdef _M_X64
    ULONG Reserved;
#endif
} ALPC_PORT_ATTRIBUTES, *PALPC_PORT_ATTRIBUTES;

typedef struct _LPC_SECTION_MEMORY 
{
	ULONG      Length;
	ULONG_PTR  ViewSize;
	PVOID      ViewBase;
} LPC_SECTION_MEMORY, *PLPC_SECTION_MEMORY;

typedef struct _CONNECTION_INFORMATION
{
	ULONG_PTR u1;
	ULONG_PTR u2;
	ULONG_PTR u3;
	ULONG_PTR u4;
	ULONG_PTR u5;
	ULONG_PTR u6;
} CONNECTION_INFORMATION, *PCONNECTION_INFORMATION;

typedef struct _ALPC_DATA_VIEW_ATTR {
	ULONG Flags;
	HANDLE SectionHandle;
	PVOID ViewBase;
	SIZE_T ViewSize;
} ALPC_DATA_VIEW_ATTR, * PALPC_DATA_VIEW_ATTR;

typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
    ULONG AllocatedAttributes;
    ULONG ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, *PALPC_MESSAGE_ATTRIBUTES;

typedef NTSTATUS (NTAPI* NtAlpcConnectPortT)(
	_Out_ PHANDLE PortHandle,
	_In_ PUNICODE_STRING PortName,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes,
	_In_ DWORD ConnectionFlags,
	_In_opt_ PSID RequiredServerSid,
	_In_opt_ PALPC_PORT_MESSAGE ConnectionMessage,
	_Inout_opt_ PSIZE_T ConnectMessageSize,
	_In_opt_ PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
	_In_opt_ PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
	_In_opt_ PLARGE_INTEGER Timeout
);

typedef struct _PORT_MESSAGE2
{
	union
	{
		struct
		{
			SHORT DataLength;
			SHORT TotalLength;
		} s1;
		ULONG Length;
	} u1;
	union
	{
		struct
		{
			SHORT Type;
			SHORT DataInfoOffset;
		} s2;
		ULONG ZeroInit;
	} u2;
	union
	{
		CLIENT_ID ClientId;
		double DoNotUseThisField;
	};
	ULONG MessageId;
	union
	{
		SIZE_T ClientViewSize;	// only valid for LPC_CONNECTION_REQUEST messages
		ULONG CallbackId;		// only valid for LPC_REQUEST messages
	};
} PORT_MESSAGE2, *PPORT_MESSAGE2;

typedef NTSTATUS (NTAPI* NtAlpcDisconnectPortT)(
    __in HANDLE PortHandle,
    __in ULONG Flags);

typedef NTSTATUS (NTAPI* NtAlpcSendWaitReceivePortT)(
    __in HANDLE PortHandle,
    __in ULONG Flags,
    __in_opt PPORT_MESSAGE SendMessage,
    __in_opt PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes,
    __inout_opt PPORT_MESSAGE ReceiveMessage,
    __inout_opt PULONG BufferLength,
    __inout_opt PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes,
    __in_opt PLARGE_INTEGER Timeout
    );

typedef NTSTATUS (NTAPI* NtRegisterThreadTerminatePortT)(
	HANDLE hPort);

typedef NTSTATUS(NTAPI* BaseGetNamedObjectDirectoryT)(
	HANDLE* phDir);

typedef NTSTATUS(NTAPI* NtCreateWorkerFactoryT)(
	_Out_ PHANDLE				WorkerFactoryHandleReturn,
	_In_ ACCESS_MASK			DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE					CompletionPortHandle,
	_In_ HANDLE					WorkerProcessHandle,
	_In_ PVOID					StartRoutine,
	_In_opt_ PVOID				StartParameter,
	_In_opt_ ULONG				MaxThreadCount,
	_In_opt_ SIZE_T				StackReserve,
	_In_opt_ SIZE_T				StackCommit);

typedef NTSTATUS(NTAPI* NtSetInformationWorkerFactoryT)(
	_In_ HANDLE WorkerFactoryHandle,
	_In_ ULONG WorkerFactoryInformationClass,
	_In_reads_bytes_(WorkerFactoryInformationLength) PVOID WorkerFactoryInformation,
	_In_ ULONG WorkerFactoryInformationLength);

typedef NTSTATUS(NTAPI* NtShutdownWorkerFactoryT)(
	HANDLE hFactory,
	PVOID  pBuf);


typedef struct _PDC_STRUCT
{
	PVOID p1;
	PVOID p2;
	PVOID p3;
	PVOID p4;
	PVOID p5;
	PVOID p6;
	PVOID p7;
	WORD  wIndex;
	WORD  wNull;
} PDC_STRUCT, * PPDC_STRUCT;

typedef struct _PDC_STRUCT2
{
	ULONG_PTR u1;
	ULONG_PTR u2;
	ULONG_PTR uPdcIndex;
	PVOID p1;
	PVOID p2;
	ULONG_PTR u3;
	ULONG_PTR uu[0x200];
} PDC_STRUCT2, * PPDC_STRUCT2;

///////////////////////////////////////////////////////////////////////////////

ULONG_PTR MyRand();

__declspec(noinline) BOOL		InitInternal();
__declspec(noinline) BOOL		InitInternal2();
__declspec(noinline) PVOID		FindObjectByHandle(ULONG uProcessId, HANDLE Handle, BOOL bObjectTypeIndex);

__declspec(noinline) ULONG_PTR	GetKernelValue(ULONG_PTR pAddr);
__declspec(noinline) VOID		SetKernelValue(ULONG_PTR pAddr, ULONG_PTR pVal);
__declspec(noinline) BOOL		ChangeToken(DWORD dPid, ULONG_PTR pThread);