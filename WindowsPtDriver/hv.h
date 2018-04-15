/**********************************************************************
*  Windows Intel Processor Trace (PT) Driver
*  Filename: hv.h
*  Defines all the HyperV data structures and functions for Intercepts
*  https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/reference/tlfs
*  Last revision: xx/xx/2017
*
*  Copyright© 2017 Andrea Allievi, Richard Johnson
*  Microsoft Ltd and TALOS Research and Intelligence Group
*  All right reserved
**********************************************************************/

#pragma once

// Memory Types

typedef UINT64 HV_SPA, *PHV_SPA;
typedef UINT64 HV_GVA, *PHV_GVA;

#ifndef X64_PAGE_SIZE
#define X64_PAGE_SIZE 0x1000
#endif

typedef UINT64 HV_GPA_PAGE_NUMBER, *PHV_GPA_PAGE_NUMBER;
typedef UINT64 HV_GVA_PAGE_NUMBER, *PHV_GVA_PAGE_NUMBER;

typedef const HV_GPA_PAGE_NUMBER *PCHV_GPA_PAGE_NUMBER;
typedef const HV_GVA_PAGE_NUMBER *PCHV_GVA_PAGE_NUMBER;

// Some HyperV return codes
// https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/reference/tlfs
// Appendix B - Page 202
typedef unsigned short HV_STATUS;
#define HV_STATUS_SUCCESS                ((HV_STATUS)0x0000)
// The hypervisor does not support the operation because the specified hypercall code is not supported.
#define HV_STATUS_INVALID_HYPERCALL_CODE ((HV_STATUS)0x0002)
// The hypervisor does not support the operation because the encoding for the hypercall input register is not supported.
#define HV_STATUS_INVALID_HYPERCALL_INPUT ((HV_STATUS)0x0003)
// The hypervisor could not perform the operation because a parameter has an invalid alignment.
#define HV_STATUS_INVALID_ALIGNMENT      ((HV_STATUS)0x0004)
// The hypervisor could not perform the operation because an invalid parameter was specified.
#define HV_STATUS_INVALID_PARAMETER      ((HV_STATUS)0x0005)
// Access to the specified object was denied.
#define HV_STATUS_ACCESS_DENIED          ((HV_STATUS)0x0006)
// The hypervisor could not perform the operation because the partition is entering or in an invalid state.
#define HV_STATUS_INVALID_PARTITION_STATE ((HV_STATUS)0x0007)
// The operation is not allowed in the current state.
#define HV_STATUS_OPERATION_DENIED       ((HV_STATUS)0x0008)
// The requested operation was unsuccessful.
#define HV_STATUS_UNSUCCESSFUL           ((HV_STATUS)0x1001)


#pragma pack(push)
#pragma pack(1)

#define HV_X64_MSR_HYPERCALL 0x40000001
#define HvCallGetLogicalProcessorRegisters		0x0088

typedef enum _HV_LOGICAL_PROC_REGISTER_TYPE
{
	HvX64LpRegisterTypeCpuid = 0x00010000,
	HvX64LpRegisterTypeMsr = 0x00010001
} HV_LOGICAL_PROC_REGISTER_TYPE, *PHV_LOGICAL_PROC_REGISTER_TYPE;

typedef union _HV_LOGICAL_PROC_REGISTER_ADDRESS
{
	struct
	{
		UINT32 Eax;
		UINT32 Ecx;
	} CpuId;
	UINT32 MsrIndex;
} HV_LOGICAL_PROC_REGISTER_ADDRESS, *PHV_LOGICAL_PROC_REGISTER_ADDRESS;

// HvCallGetLogicalProcessorRegisters input - passed in RDX
typedef struct _HV_LOGICAL_PROC_REGISTERS_INPUT
{
	UINT32									VCpuIndex;
	HV_LOGICAL_PROC_REGISTER_TYPE			Type;
	HV_LOGICAL_PROC_REGISTER_ADDRESS		Address;
} HV_LOGICAL_PROC_REGISTERS_INPUT, *PHV_LOGICAL_PROC_REGISTERS_INPUT;

typedef struct _HYPERV_LIMITS {
	DWORD	MaxVpSupported;
	DWORD	MaxRealCpuSupported;
	DWORD	MAxInterruptsAvail;
} HYPERV_LIMITS, *PHYPERV_LIMITS;

// HyperV Partition privilege mask 
typedef struct _HV_PARTITION_PRIVILEGE_MASK {
	// Access to virtual MSRs 
	UINT64 AccessVpRunTimeReg : 1;
	UINT64 AccessPartitionReferenceCounter : 1;
	UINT64 AccessSynicRegs : 1;
	UINT64 AccessSyntheticTimerRegs : 1;
	UINT64 AccessIntrCtrlRegs : 1;
	UINT64 AccessHypercallMsrs : 1;
	UINT64 AccessVpIndex : 1;
	UINT64 AccessResetReg : 1;
	UINT64 AccessStatsReg : 1;
	UINT64 AccessPartitionReferenceTsc : 1;
	UINT64 AccessGuestIdleReg : 1;
	UINT64 AccessFrequencyRegs : 1;
	UINT64 AccessDebugRegs : 1;
	UINT64 Reserved1 : 19;
	
	// Access to hypercalls 
	UINT64 CreatePartitions : 1;
	UINT64 AccessPartitionId : 1;
	UINT64 AccessMemoryPool : 1;
	UINT64 AdjustMessageBuffers : 1;
	UINT64 PostMessages : 1;
	UINT64 SignalEvents : 1;
	UINT64 CreatePort : 1;
	UINT64 ConnectPort : 1;
	UINT64 AccessStats : 1;
	UINT64 Reserved2 : 2;
	UINT64 Debugging : 1;
	UINT64 CpuManagement : 1;
	UINT64 Reserved3 : 3;
	UINT64 AccessVSM : 1;
	UINT64 AccessVpRegisters : 1;
	UINT64 Reserved4 : 2;
	UINT64 EnableExtendedHypercalls : 1;
	UINT64 StartVirtualProcessor : 1;
	UINT64 Reserved5 : 10;
} HV_PARTITION_PRIVILEGE_MASK, *PHV_PARTITION_PRIVILEGE_MASK;

// HyperV Partition features (Chapter 2.4.4 of the TLFS)
typedef struct _HYPERV_FEATURES {
	HV_PARTITION_PRIVILEGE_MASK	 PartitionPrivilegeMask;
	UINT32 Reserved;
	union {
		struct {
			UINT32 MWaitSupport : 1; 					// [0] - Deprecated (previously indicated availability of the MWAIT command).
			UINT32 GuestDebugging : 1; 					// [1] - Guest debugging support is available
			UINT32 PmuSupport : 1; 						// [2] - Performance Monitor support is available
			UINT32 CpuDynamicPartitions : 1; 			// [3] - Support for physical CPU dynamic partitioning events is available
			UINT32 HypercallsViaXmm : 1; 				// [4] - Support for passing hypercall input parameter block via XMM registers is available
			UINT32 VirtualIdleState : 1; 				// [5] - Support for a virtual guest idle state is available
			UINT32 HvSleepState : 1; 					// [6] - Support for hypervisor sleep state is available.
			UINT32 QueryNumaDistance : 1; 				// [7] - Support for querying NUMA distances is available.
			UINT32 TimerFrequencies : 1; 				// [8] - Support for determining timer frequencies is available.
			UINT32 InjectSyntMachineChecks : 1; 		// [9] - Support for injecting synthetic machine checks is available.
			UINT32 GuestCrashMSRs : 1; 					// [10] - Support for guest crash MSRs is available.
			UINT32 DebugMSRs : 1; 						// [11] - Support for debug MSRs is available.
			UINT32 NpiepSupport : 1; 					// [12] - Support for NPIEP is available.
			UINT32 DisableHypervisor : 1; 				// [13] - DisableHypervisorAvailable
			UINT32 ExtendedGvaRangesForFlushVirtualAddressList : 1; 		// [14] - ExtendedGvaRangesForFlushVirtualAddressListAvailable
			UINT32 HypercallsOutputViaXmm : 1; 			// [15] - Support for returning hypercall output via XMM registers is available.
			UINT32 Reserved1 : 1; 						// [16] - Reserved
			UINT32 SintPollingMode : 1; 				// [17] - SintPollingModeAvailable
			UINT32 HypercallMsrLock : 1; 				// [18] - HypercallMsrLockAvailable
			UINT32 UseDirectSyntTimers : 1; 			// [19] - Use direct synthetic timers
			UINT32 Reserved2 : 12; 						// [31:20] - Reserved
		} Fields;
		UINT32 AsUInt32;
	} HvFeatures;
} HYPERV_FEATURES, *PHYPERV_FEATURES;

typedef struct _HYPERV_INFO {
	DWORD				Build;
	WORD				MajorVersion;
	WORD				MinorVersion;
	DWORD				ServicePack;
	UCHAR				ServiceBranch;
	DWORD				ServiceNumber;
	HYPERV_FEATURES		Features;
	//HYPERV_IMPLEMENTATION			Implementations;
	//HYPERV_LIMITS					Limits;
	//HYPERV_HARDWARE_FEATURES		HardwareFeatures;
	//HYPERV_CPU_MANAGEMENT			CpuManagementFeatures;
	//HYPERV_NESTED_HV_FEATURES		NestedHvFeatures;
	//HYPERV_NESTED_VIRT_FEATURES	NestedVirtFeatures;
} HYPERV_INFO, *PHYPERV_INFO;

// The Hypercall Input Value (RCX, first param, see page 21 of the TLFS) 
typedef union _HV_HYPERCALL_INFO
{
	// See the Specs: https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/reference/tlfs (page 29)
	struct
	{
		UINT32 CallCode : 16;				// [15:0] HyperCall code
		UINT32 IsFast : 1;					// [16]  Set to 1 if the hypercall uses the register-based calling convention
		UINT32 VarHdr : 9;					// [25:17]  Variable header size
		UINT32 Reserved1 : 5;				// [30:26]	Reserved
		UINT32 IsNested : 1;				// [31]	 This hypercall is nested, comes from the L0 Hypervisor
		UINT32 CountOfElements : 12;		// [43:31]  REP Counter
		UINT32 Reserved2 : 4;				// [47:44]
		UINT32 RepStartIndex : 12;			// [59:48]  Indicates the particular repetition relative to the start of the list
		UINT32 Reserved3 : 4;				// [63:60]
	} Fields;
	UINT64 AsUINT64;
} HV_HYPERCALL_INFO, *PHV_HYPERCALL_INFO;

// The Hypercall Result Value (RAX, page 32)
typedef union _HV_HYPERCALL_OUTPUT
{
	struct
	{
		UINT16 Result;					// [15:0]  The Hypercall results
		UINT16 Reserved1;				// [31:15]
		UINT32 RepsCompleted : 12;		// [43:32]  Number of reps successfully completed
		UINT32 Reserved2 : 20;			// [63:44]
	} Fields;
	UINT64 AsUINT64;
} HV_HYPERCALL_OUTPUT, *PHV_HYPERCALL_OUTPUT;

union HV_X64_MSR_HYPERCALL_DESC {
	struct {
		UINT64		EnableHypercallPage : 1;	// [0] - Enables the hypercall page
		UINT64		Locked : 1;					// [1] - Indicates if this MSR is immutable
		UINT64		Reserved : 10;				// [11:2]
		UINT64		HypercallGPA : 52;			// [63:12] - ndicates the Guest Physical Page Number of the hypercall page
	} Fields;
	UINT64 AsUINT64;
};
#pragma pack(pop)

// The Hypervisor Memory descriptor
typedef struct _HV_MEMDESC {
	LPVOID VirtualAddr;
	PHYSICAL_ADDRESS PhysicalAddr;
	DWORD Size;
} HV_MEMDESC, *PHV_MEMDESC;

typedef HV_HYPERCALL_OUTPUT(*PHV_PERFORM_HYPERCALL)(HV_HYPERCALL_INFO HvCallInfo, PHYSICAL_ADDRESS Argument1_Phys, PHYSICAL_ADDRESS Argument2_Phys);

typedef struct _HYPERV_DATA {
	BOOLEAN IsValid;
	HYPERV_INFO Info;
	// TODO: Move the following 3 buffer descriptor to a Per CPU data structure
	HV_MEMDESC InputPage;
	HV_MEMDESC OutputPage;
	HV_MEMDESC HypercallPage;
	PHV_PERFORM_HYPERCALL CallHv;
} HYPERV_DATA, *PHYPERV_DATA;


// Detect the Hypervisor
NTSTATUS DetectMicrosoftHyperV(HYPERV_INFO * HyperVInfo);

// Emit an HyperV real CPUINFO
NTSTATUS HvCpuId(int CpuInfo[4], int Function, int SubLeaf);

// Initialize HyperV data structures and memory
NTSTATUS InitGlobalHv();

// Destroy the HyperV data structures and memory
VOID DestroyGlobalHv();

// Convert a HV_STATUS value to the corresponding NTSTATUS
NTSTATUS HvStatusToNtStatus(HV_STATUS HvStatus);