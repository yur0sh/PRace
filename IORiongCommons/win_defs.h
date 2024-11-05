#ifndef _WIN_DEFS_H_
#define _WIN_DEFS_H_

#define EPROC_TOKEN_OFFSET 0x4b8

#define SystemHandleInformation (SYSTEM_INFORMATION_CLASS)16

#define int3 __debugbreak();

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING  TypeName;
    ULONG           TotalNumberOfObjects;
    ULONG           TotalNumberOfHandles;
    ULONG           TotalPagedPoolUsage;
    ULONG           TotalNonPagedPoolUsage;
    ULONG           TotalNamePoolUsage;
    ULONG           TotalHandleTableUsage;
    ULONG           HighWaterNumberOfObjects;
    ULONG           HighWaterNumberOfHandles;
    ULONG           HighWaterPagedPoolUsage;
    ULONG           HighWaterNonPagedPoolUsage;
    ULONG           HighWaterNamePoolUsage;
    ULONG           HighWaterHandleTableUsage;
    ULONG           InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG           ValidAccessMask;
    BOOLEAN         SecurityRequired;
    BOOLEAN         MaintainHandleCount;
    BOOLEAN         TypeIndex;
    CHAR            ReservedByte;
    ULONG           PoolType;
    ULONG           DefaultPagedPoolCharge;
    ULONG           DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT  UniqueProcessId;
    USHORT  CreatorBackTraceIndex;
    UCHAR   ObjectTypeIndex;
    UCHAR   HandleAttributes;
    USHORT  HandleValue;
    PVOID   Object;
    ULONG   GrantedAccess;
    LONG    __PADDING__[1];
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _DISPATCHER_HEADER
{
    union
    {
        volatile long Lock;
        long LockNV;
        struct
        {
            unsigned char Type;
            unsigned char Signalling;
            unsigned char Size;
            unsigned char Reserved1;
        };
        struct
        {
            unsigned char TimerType;
            union
            {
                unsigned char TimerControlFlags;
                struct
                {
                    struct
                    {
                        unsigned char Absolute : 1;
                        unsigned char Wake : 1;
                        unsigned char EncodedTolerableDelay : 6;
                    };
                    unsigned char Hand;
                    union
                    {
                        unsigned char TimerMiscFlags;
                        struct
                        {
                            unsigned char Index : 6;
                            unsigned char Inserted : 1;
                            volatile unsigned char Expired : 1;
                        };
                    };
                };
            };
        };
        struct
        {
            unsigned char Timer2Type;
            union
            {
                unsigned char Timer2Flags;
                struct
                {
                    struct
                    {
                        unsigned char Timer2Inserted : 1;
                        unsigned char Timer2Expiring : 1;
                        unsigned char Timer2CancelPending : 1;
                        unsigned char Timer2SetPending : 1;
                        unsigned char Timer2Running : 1;
                        unsigned char Timer2Disabled : 1;
                        unsigned char Timer2ReservedFlags : 2;
                    };
                    unsigned char Timer2ComponentId;
                    unsigned char Timer2RelativeId;
                };
            };
        };
        struct
        {
            unsigned char QueueType;
            union
            {
                unsigned char QueueControlFlags;
                struct
                {
                    struct
                    {
                        unsigned char Abandoned : 1;
                        unsigned char DisableIncrement : 1;
                        unsigned char QueueReservedControlFlags : 6;
                    };
                    unsigned char QueueSize;
                    unsigned char QueueReserved;
                };
            };
        };
        struct
        {
            unsigned char ThreadType;
            unsigned char ThreadReserved;
            union
            {
                unsigned char ThreadControlFlags;
                struct
                {
                    struct
                    {
                        unsigned char CycleProfiling : 1;
                        unsigned char CounterProfiling : 1;
                        unsigned char GroupScheduling : 1;
                        unsigned char AffinitySet : 1;
                        unsigned char Tagged : 1;
                        unsigned char EnergyProfiling : 1;
                        unsigned char SchedulerAssist : 1;
                        unsigned char ThreadReservedControlFlags : 1;
                    };
                    union
                    {
                        unsigned char DebugActive;
                        struct
                        {
                            unsigned char ActiveDR7 : 1;
                            unsigned char Instrumented : 1;
                            unsigned char Minimal : 1;
                            unsigned char Reserved4 : 2;
                            unsigned char AltSyscall : 1;
                            unsigned char Emulation : 1;
                            unsigned char Reserved5 : 1;
                        };
                    };
                };
            };
        };
        struct
        {
            unsigned char MutantType;
            unsigned char MutantSize;
            unsigned char DpcActive;
            unsigned char MutantReserved;
        };
    };
    long SignalState;
    LIST_ENTRY WaitListHead;
} DISPATCHER_HEADER, * PDISPATCHER_HEADER;

typedef struct _KEVENT
{
    struct _DISPATCHER_HEADER Header;
} KEVENT, * PKEVENT;

DWORD(WINAPI* _NtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass, 
    PVOID SystemInformation, 
    ULONG SystemInformationLength, 
    PULONG ReturnLength);

typedef HRESULT(NTAPI* CreateIoRingT)(
    IORING_VERSION ioringVersion, 
    IORING_CREATE_FLAGS flags, 
    UINT32 submissionQueueSize, 
    UINT32 completionQueueSize, 
    _Out_ HIORING* h);

CreateIoRingT _CreateIoRing;

typedef HRESULT(NTAPI* BuildIoRingWriteFileT)(
    _In_ HIORING ioRing,
    IORING_HANDLE_REF fileRef,
    IORING_BUFFER_REF bufferRef,
    UINT32 numberOfBytesToWrite,
    UINT64 fileOffset,
    FILE_WRITE_FLAGS writeFlags,
    UINT_PTR userData,
    IORING_SQE_FLAGS sqeFlags);

BuildIoRingWriteFileT _BuildIoRingWriteFile;

typedef HRESULT(NTAPI* BuildIoRingReadFileT)(
    _In_ HIORING ioRing,
    IORING_HANDLE_REF fileRef,
    IORING_BUFFER_REF dataRef,
    UINT32 numberOfBytesToRead,
    UINT64 fileOffset,
    UINT_PTR userData,
    IORING_SQE_FLAGS sqeFlags);

BuildIoRingReadFileT _BuildIoRingReadFile;

typedef HRESULT(NTAPI* PopIoRingCompletionT)(
    _In_ HIORING ioRing, 
    _Out_ IORING_CQE* cqe);

PopIoRingCompletionT _PopIoRingCompletion;

typedef HRESULT(NTAPI* SubmitIoRingT)(
    _In_ HIORING ioRing, 
    UINT32 waitOperations, 
    UINT32 milliseconds, 
    _Out_opt_ UINT32* submittedEntries);

SubmitIoRingT _SubmitIoRing;

#endif
