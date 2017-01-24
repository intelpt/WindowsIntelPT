/**********************************************************************
 *  Windows Intel Processor Trace (PT) Driver
 *  Filename: UndocNt.h
 *  Defines the undocumented Windows Nt data structures
 *  Last revision: 01/06/2016
 *
 *  Copyright© 2016 Andrea Allievi, Richard Johnson
 *  Microsoft Ltd & TALOS Research and Intelligence Group
 *  All right reserved
 **********************************************************************/
#pragma once
#define ANYSIZE_ARRAY 1

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation, // 0 Y N
	SystemProcessorInformation, // 1 Y N
	SystemPerformanceInformation, // 2 Y N
	SystemTimeOfDayInformation, // 3 Y N
	SystemNotImplemented1, // 4 Y N
	SystemProcessesAndThreadsInformation, // 5 Y N
	SystemCallCounts, // 6 Y N
	SystemConfigurationInformation, // 7 Y N
	SystemProcessorTimes, // 8 Y N
	SystemGlobalFlag, // 9 Y Y
	SystemNotImplemented2, // 10 Y N
	SystemModuleInformation // 11 Y N
} SYSTEM_INFORMATION_CLASS;

// Undocumented NT functions
NTKERNELAPI BOOLEAN PsIsThreadTerminating(PETHREAD Thread);
NTKERNELAPI NTSTATUS PsLookupThreadByThreadId(HANDLE ThreadId, PETHREAD *Thread);
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS *Process);
NTKERNELAPI NTSTATUS PsSuspendProcess(PEPROCESS Process);
NTKERNELAPI NTSTATUS ZwCreateEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType, BOOLEAN InitialState);
NTKERNELAPI BOOLEAN HalEnableInterrupt(PKINTERRUPT pkInterrupt);
NTKERNELAPI BOOLEAN PsGetProcessExitProcessCalled(PEPROCESS Process);
NTKERNELAPI NTSTATUS ZwSetSystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength);
NTKERNELAPI NTSTATUS ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);


// APC Routines and data structures
typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;

typedef struct _KAPC_STATE {
	LIST_ENTRY ApcListHead[MaximumMode];
	struct _KPROCESS *Process;
	union {
		UCHAR InProgressFlags;
		struct {
			BOOLEAN KernelApcInProgress : 1;
			BOOLEAN SpecialApcInProgress : 1;
		}u;
	};

	BOOLEAN KernelApcPending;
	BOOLEAN UserApcPending;
} KAPC_STATE, *PKAPC_STATE, *PRKAPC_STATE;

typedef VOID(*PKNORMAL_ROUTINE) (IN PVOID NormalContext, IN PVOID SystemArgument1, IN PVOID SystemArgument2);

typedef VOID(*PKKERNEL_ROUTINE) (IN struct _KAPC *Apc, IN OUT PKNORMAL_ROUTINE *NormalRoutine,
	IN OUT PVOID *NormalContext, IN OUT PVOID *SystemArgument1, IN OUT PVOID *SystemArgument2);

typedef VOID(*PKRUNDOWN_ROUTINE) (IN struct _KAPC *Apc);

NTKERNELAPI VOID KeInitializeApc(PRKAPC Apc, PRKTHREAD Thread, KAPC_ENVIRONMENT Environment, PKKERNEL_ROUTINE KernelRoutine, PKRUNDOWN_ROUTINE RundownRoutine,
	PKNORMAL_ROUTINE NormalRoutine, KPROCESSOR_MODE ApcMode, PVOID NormalContext);
NTKERNELAPI BOOLEAN KeInsertQueueApc(PRKAPC Apc, PVOID SystemArgument1, PVOID SystemArgument2, KPRIORITY Increment);



typedef struct _SYSTEM_MODULE_INFORMATION { // Information Class 11
	PVOID Reserved[2];						// + 0x00
	PVOID Base;								// + 0x10
	ULONG Size;								// + 0x18
	ULONG Flags;							// + 0x1C
	USHORT Index;							// + 0x20
	USHORT Unknown;							// + 0x22
	USHORT LoadCount;						// + 0x24
	USHORT ModuleNameOffset;				// + 0x26
	CHAR ImageName[256];					// + 0x28
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

struct SYSTEM_ALL_MODULES {
	DWORD dwNumOfModules;
	SYSTEM_MODULE_INFORMATION modules[ANYSIZE_ARRAY];
};