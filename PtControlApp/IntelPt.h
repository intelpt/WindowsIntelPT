/**********************************************************************
 *  Windows Intel Processor Trace (PT) Driver
 *  Filename: IntelPt.h
 *	Defines the Intel Processor Trace driver function prototypes 
 *  for the User-mode control application 
 *  Last revision: 12/01/2016
 *
 *  Copyright© 2016 Andrea Allievi, Richard Johnson
 *  Microsoft Ltd & TALOS Research and Intelligence Group
 *  All right reserved
 **********************************************************************/
#pragma once

typedef long NTSTATUS;

#pragma pack(1)
struct INTEL_PT_CAPABILITIES {
	UINT16 bCr3Filtering : 1;						// [0] - CR3 Filtering Support (Indicates that IA32_RTIT_CTL.CR3Filter can be set to 1)
	UINT16 bConfPsbAndCycSupported : 1;				// [1] - Configurable PSB and Cycle-Accurate Mode Supported (IA32_RTIT_CTL.PSBFreq can be set to a non-zero value, IA32_RTIT_STATUS.PacketByteCnt can be set to a non-zero value)
	UINT16 bIpFiltering : 1;						// [2] - IP Filtering and TraceStop	supported, and Preserve Intel PT MSRs across warm reset
	UINT16 bMtcSupport : 1;							// [3] - IA32_RTIT_CTL.MTCEn can be set to 1, and MTC packets will be generated (section 36.2.5)
	UINT16 bPtWriteSupport : 1;						// [4] - indicates support of PTWRITE
	UINT16 bPETSupport : 1;							// [5] - indicates support of Power Event Trace
	UINT16 bVmxSupport : 1;							// [6] - Indicates whether Intel PT can be used in VMX operations
	UINT16 bTopaOutput : 1;							// [7] - Tracing can be enabled with IA32_RTIT_CTL.ToPA = 1, hence utilizing the ToPA output scheme (section 36.2.4.2)
	UINT16 bTopaMultipleEntries : 1;				// [8] - ToPA tables can hold any number of output entries, up to the maximum allowed by the MaskOrTableOffset field of IA32_RTIT_OUTPUT_MASK_PTRS
	UINT16 bSingleRangeSupport : 1;					// [9] - Single-Range Output Supported
	UINT16 bTransportOutputSupport : 1;				// [10] - Output to Trace Transport Subsystem Supported (Setting IA32_RTIT_CTL.FabricEn to 1 is supported)
	UINT16 bIpPcksAreLip : 1;						// [11] - IP Payloads are LIP (Specifies if the generated packets that contain IP payloads have LIP values or RIP values)	<-- Very important
	SHORT numOfAddrRanges;							// + 0x02 - Number of Address Ranges - specifies the number ADDRn_CFG field supported in IA32_RTIT_CTL for IP filtering	and IP TraceStop
	SHORT mtcPeriodBmp;								// + 0x04 - Bitmap of supported MTC Period Encodings
	SHORT cycThresholdBmp;							// + 0x06 - Bitmap of supported Cycle Threshold values
	SHORT psbFreqBmp;								// + 0x08 - Bitmap of supported	Configurable PSB Frequency encoding
};

// The IA32_PERF_GLOBAL_STATUS descriptor of Intel Broadwell microarchitecture 
union MSR_IA32_PERF_GLOBAL_STATUS_DESC {
	struct {
		DWORD PMC0_OVF : 1;						// [0] - Read only
		DWORD PMC1_OVF : 1;						// [1] - Read only 
		DWORD PMC2_OVF : 1;						// [2] - Read only
		DWORD PMC3_OVF : 1;						// [3] - Read only
		DWORD PMC4_OVF : 1;						// [4] - Read only (if PMC4 present)
		DWORD PMC5_OVF : 1;						// [5] - Read only (if PMC5 present) 
		DWORD PMC6_OVF : 1;						// [6] - Read only (if PMC6 present)
		DWORD PMC7_OVF : 1;						// [7] - Read only (if PMC7 present)
		DWORD Reserved : 24;					// [8:31] - Reserved
		DWORD FIXED_CTR0 : 1;					// [32] - FIXED_CTR0 Overflow (RO)
		DWORD FIXED_CTR1 : 1;					// [33] - FIXED_CTR1 Overflow (RO)
		DWORD FIXED_CTR2 : 1;					// [34] - FIXED_CTR2 Overflow (RO)
		DWORD Reserved2 : 20;					// [35:54] - Reserved
		DWORD TraceToPAPMI : 1;				// [55] - The ToPA PMI Interrupt status
		DWORD Reserved3 : 5;					// [56:60] - Reserved
		DWORD Ovf_UncorePMU : 1;				// [61]
		DWORD Ovf_Buffer : 1;					// [62]
		DWORD CondChgd : 1;						// [63]
	} Fields;
	ULONGLONG All;
};


// The Table of Physical Address Entry format (Section 36.2.4.2)
union TOPA_TABLE_ENTRY {
	struct {
		QWORD End : 1;						// [0] - If set, indicates that this is an END entry, and thus the address field points to a table base rather than an output region base.
		QWORD Reserved1 : 1;				// [1] - Must be 0
		QWORD Int : 1;						// [2] - When the output region indicated by this entry is filled, signal Perfmon LVT interrupt.
		QWORD Reserved2 : 1;				// [3] - Must be 0
		QWORD Stop : 1;						// [4] - When the output region indicated by this entry is filled, software should disable packet generation
		QWORD Reserved3 : 1;				// [5] - Must be 0
		QWORD Size : 4;						// [6:9] - Indicates the size of the associated output region. Encodings are: 0: 4K, 1 : 8K, 2 : 16K, 3 : 32K, 4 : 64K, 5 : 128K, 6 : 256K, 7 : 512K, 8 : 1M, 9 : 2M, 10 : 4M, 11 : 8M, 12 : 16M, 13 : 32M, 14 : 64M, 15 : 128M
		QWORD Reserved4 : 2;				// [10] - Must be 0
		QWORD BaseAddr : 48;				// [12:MAXPHYADDR-1] - If END=0, this is the base physical address of the output region specified by this entry; If END=1, this is the 4K-aligned base physical address of the next ToPA table
	} Fields;
	ULONGLONG All;
};
#pragma pack()

// Undocumented Win32 APIs
extern "C" NTSTATUS ZwResumeProcess(HANDLE hProcess);

