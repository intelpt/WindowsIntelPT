/**********************************************************************
 *  Windows Intel Processor Trace (PT) Driver
 *  Filename: Intel_Defs.h
 *  Intel Processor Trace definitions and data structures
 *  Last revision: 01/24/2017
 *
 *  Copyright© 2017 Andrea Allievi, Richard Johnson
 *  TALOS Research and Intelligence Group and Microsoft Ltd
 *  All right reserved
 **********************************************************************/
#pragma once

#define MSR_IA32_PERF_GLOBAL_STATUS		0x0000038E
#define MSR_IA32_APIC_BASE				0x0000001B			// The APIC base address register
#define MSR_IA32_PERF_GLOBAL_OVF_CTRL	0x00000390			// Aka IA32_GLOBAL_STATUS_RESET
#define MSR_IA32_RTIT_OUTPUT_BASE		0x00000560
#define MSR_IA32_RTIT_OUTPUT_MASK_PTRS	0x00000561
#define MSR_IA32_RTIT_CTL				0x00000570
#define MSR_IA32_RTIT_STATUS			0x00000571
#define MSR_IA32_X2APIC_LVT_PMI			0x00000834

// Filtering by CR3:
#define MSR_IA32_RTIT_CR3_MATCH			0x00000572

// Filtering by IP:
#define MSR_IA32_RTIT_ADDR0_START		0x00000580
#define MSR_IA32_RTIT_ADDR0_END			0x00000581
#define MSR_IA32_RTIT_ADDR1_START		0x00000582
#define MSR_IA32_RTIT_ADDR1_END			0x00000583
#define MSR_IA32_RTIT_ADDR2_START		0x00000584
#define MSR_IA32_RTIT_ADDR2_END			0x00000585
#define MSR_IA32_RTIT_ADDR3_START		0x00000586
#define MSR_IA32_RTIT_ADDR3_END			0x00000587


// The maximum physical address (set to 48 bit)
#define MAXPHYADDR 48

#pragma pack(push)
#pragma pack(1)
// IA32_RTIT_CTL MSR descriptor (paragraph 36.2.5.2)
union MSR_RTIT_CTL_DESC {
	struct {
		QWORD TraceEn : 1;					// [0] - If 1, enables tracing; else tracing is disabled if 0.
		QWORD CycEn : 1;					// [1] - Enables or disables CYC Packet (see Section 36.4.2.14).
		QWORD Os : 1;						// [2] - Packet generation is enabled/disabled when CPL = 0.
		QWORD User : 1;						// [3] - Packet generation is enabled/disabled when CPL > 0.
		QWORD Reserved : 2;					// [4:5] - MUST BE 0
		QWORD FabricEn : 1;					// [6] - 0: Trace output is directed to the memory subsystem, mechanism depends on IA32_RTIT_CTL.ToPA. / 1: Trace output is directed to the trace transport subsystem, IA32_RTIT_CTL.ToPA is ignored.
		QWORD CR3Filter : 1;				// [7] - Enables/disables CR3 filtering
		QWORD ToPA : 1;						// [8] - Single-range output scheme / ToPA output scheme
		QWORD MTCEn : 1;					// [9] - Enables/disables MTC Packet
		QWORD TSCEn : 1;					// [10] - Enables/disables TSC packets
		QWORD DisRETC : 1;					// [11] - Enables/disables RET compression
		QWORD Reserved2 : 1;				// [12] - MUST BE 0
		QWORD BranchEn : 1;					// [13] - Enables/disables COFI-based packets: FUP, TIP, TIP.PGE, TIP.PGD, TNT, MODE.Exec, MODE.TSX
		QWORD MTCFreq : 4;					// [14:17] - Defines MTC packet Frequency, which is based on the core crystal clock, or Always Running Timer(ART)
		QWORD Reserved3 : 1;				// [18] - Must be 0
		QWORD CycThresh : 4;				// [19:22] - CYC packet threshold (Section 36.3.6)
		QWORD Reserved4 : 1;				// [23] - Must be 0
		QWORD PSBFreq : 4;					// [24:27] - Indicates the frequency of PSB packets
		QWORD Reserved5 : 4;				// [28:31] - Must be 0
		QWORD Addr0Cfg : 4;					// [32:35] - Configures the base/limit register pair IA32_RTIT_ADDR0_A/B. This field is reserved if CPUID.(EAX=14H, ECX=1):EBX.RANGECNT[2:0] >= 0.
		QWORD Addr1Cfg : 4;					// [36:39] - Configures the base/limit register pair IA32_RTIT_ADDR1_A/B. This field is reserved if CPUID.(EAX=14H, ECX=1):EBX.RANGECNT[2:0] < 2.
		QWORD Addr2Cfg : 4;					// [40:43] - Configures the base/limit register pair IA32_RTIT_ADDR2_A/B. This field is reserved if CPUID.(EAX=14H, ECX=1):EBX.RANGECNT[2:0] < 3.
		QWORD Addr3Cfg : 4;					// [44:47] - Configures the base/limit register pair IA32_RTIT_ADDR3_A/B. This field is reserved if CPUID.(EAX=14H, ECX=1):EBX.RANGECNT[2:0] < 4.
		QWORD Reserved6 : 16;				// [48:63] - Must be 0
	} Fields;
	ULONGLONG All;
};

// IA32_RTIT_STATUS MSR descriptor (paragraph 36.2.5.4)
union MSR_RTIT_STATUS_DESC {
	struct {
		ULONG FilterEn : 1;					// [0] - This bit is written by the processor, and indicates that tracing is allowed for the current IP
		ULONG ContextEn : 1;				// [1] - The processor sets this bit to indicate that tracing is allowed for the current context
		ULONG TriggerEn : 1;				// [2] - The processor sets this bit to indicate that tracing is enabled
		ULONG Reserved1 : 1;				// [3] - Must be 0
		ULONG Error : 1;					// [4] - The processor sets this bit to indicate that an operational error has been encountered
		ULONG Stopped : 1;					// [5] - The processor sets this bit to indicate that a ToPA Stop condition has been encountered
		ULONG Reserved2 : 26;				// [6:31] - Must be 0
		ULONG PacketByteCnt : 17;			// [32:48] - This field is written by the processor, and holds a count of packet bytes that have been sent out
		ULONG Reserved3 : 15;				// [49:63] - Must be 0
	} Fields;
	ULONGLONG All;
};

// The Table of Physical Address Entry format (Section 36.2.4.2)
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

// IA32_RTIT_OUTPUTBASE MSR descriptor (paragraph 36.2.5.7)
union MSR_RTIT_OUTPUTBASE_DESC {
	struct {
		QWORD Reserved : 7;					// [0:6] - Must be 0 
		QWORD BasePhysAddr : MAXPHYADDR;	// [7:MAXPHYADDR-1] - The base physical address
		QWORD Reserved2 : 57 - MAXPHYADDR;	// [MAXPHYADDR:63] - Must be 0
	} Fields;
	ULONGLONG All;
};

// IA32_RTIT_OUTPUTMASK_PTRS MSR descriptor (paragraph 36.2.5.8)
union MSR_RTIT_OUTPUT_MASK_PTRS_DESC {
	struct {
		ULONG LowerMask : 7;				// [0:6] - Forced to 1
		ULONG MaskOrTableOffset : 25;		// [7:31] - The use of this field depends on the value of IA32_RTIT_CTL.ToPA:
											//			0: This field holds bits 31:7 of the mask value for the single, contiguous physical output region
											//			1: This field holds bits 27:3 of the offset pointer into the current ToPA table
		ULONG OutputOffset;					// [32:63] - The use of this field depends on the value of IA32_RTIT_CTL.ToPA
											//			0: This is bits 31:0 of the offset pointer into the single, contiguous physical output region
											//			1: This field holds bits 31:0 of the offset pointer into the current ToPA output region
	} Fields;
	ULONGLONG All;
};

// The APIC Base physical address MSR in xAPIC Mode
union MSR_IA32_APIC_BASE_DESC {
	struct {
		ULONGLONG Reserved1 : 8;			// [0:7] - Reserved
		ULONGLONG Bsp : 1;					// [8] - Indicates if the processor is the bootstrap processor (BSP)
		ULONGLONG Reserved2 : 1;			// [9] - Reserved
		ULONGLONG EXTD : 1;					// [10] - Enable x2APIC mode
		ULONGLONG EN : 1;					// [11] - APIC global enable/disable
		ULONGLONG ApicBase : 24;			// [12:35] - Base Physical Address
	} Fields;
	ULONGLONG All;
};

// A local vector table (LVT) entry
union LVT_Entry {
	struct {
		USHORT Vector : 8;					// [0:7] - The Vector number
		USHORT Reserved1 : 4;				// [8:11] - Reserved
		USHORT DeliveryStatus : 1;			// [12] - Delivery status: 0 - Idle; 1 - Send Pending;
		USHORT Reserved2 : 3;				// [13:15] - Reserved
		USHORT Masked : 1;					// [16] - Masked: 0 - Not Masked; 1 - Masked
		USHORT TimerMode : 2;				// [17:18] - Timer mode: 00 - One-shot; 01 - Periodic; 10 - TSC-Deadline;
		USHORT Reserved3 : 13;				// [19:31] - Reserved
	} Fields;
	DWORD All;
};

// The IA32_PERF_GLOBAL_STATUS descriptor of Intel Broadwell microarchitecture 
union MSR_IA32_PERF_GLOBAL_STATUS_DESC {
	struct {
		DWORD PMC0_OVF: 1;					// [0] - Read only
		DWORD PMC1_OVF : 1;					// [1] - Read only 
		DWORD PMC2_OVF : 1;					// [2] - Read only
		DWORD PMC3_OVF : 1;					// [3] - Read only
		DWORD PMC4_OVF : 1;					// [4] - Read only (if PMC4 present)
		DWORD PMC5_OVF : 1;					// [5] - Read only (if PMC5 present) 
		DWORD PMC6_OVF : 1;					// [6] - Read only (if PMC6 present)
		DWORD PMC7_OVF : 1;					// [7] - Read only (if PMC7 present)
		DWORD Reserved : 24;				// [8:31] - Reserved
		DWORD FIXED_CTR0 : 1;				// [32] - FIXED_CTR0 Overflow (RO)
		DWORD FIXED_CTR1 : 1;				// [33] - FIXED_CTR1 Overflow (RO)
		DWORD FIXED_CTR2 : 1;				// [34] - FIXED_CTR2 Overflow (RO)
		DWORD Reserved2 : 20;				// [35:54] - Reserved
		DWORD TraceToPAPMI : 1;				// [55] - The ToPA PMI Interrupt status
		DWORD Reserved3 : 5;				// [56:60] - Reserved
		DWORD Ovf_UncorePMU : 1;			// [61]
		DWORD Ovf_Buffer : 1;				// [62]
		DWORD CondChgd : 1;					// [63]
	} Fields;
	ULONGLONG All;
};

// The IA32_PERF_GLOBAL_OVF_CTRL descriptor of Intel Broadwell microarchitecture 
// Global Performance Counter Overflow Control (Section 18-73 of System Programming Guide Volume 3B)
union MSR_IA32_PERF_GLOBAL_OVF_CTRL_DESC {
	struct {
		DWORD PMC0_ClrOVF : 1;				// [0]
		DWORD PMC1_ClrOVF : 1;				// [1]
		DWORD PMC2_ClrOVF : 1;				// [2]
		DWORD PMC3_ClrOVF : 1;				// [3]
		DWORD PMC4_ClrOVF : 1;				// [4] - (if PMC4 present)
		DWORD PMC5_ClrOVF : 1;				// [5] - (if PMC5 present) 
		DWORD PMC6_ClrOVF : 1;				// [6] - (if PMC6 present)
		DWORD PMC7_ClrOVF : 1;				// [7] - (if PMC7 present)
		DWORD Reserved : 24;				// [8:31] - Reserved
		DWORD FIXED_CTR0 : 1;				// [32] - FIXED_CTR0 ClrOverflow
		DWORD FIXED_CTR1 : 1;				// [33] - FIXED_CTR1 ClrOverflow
		DWORD FIXED_CTR2 : 1;				// [34] - FIXED_CTR2 ClrOverflow
		DWORD Reserved2 : 20;				// [35:54] - Reserved
		DWORD ClrTraceToPA_PMI : 1;			// [55] - The ToPA PMI Interrupt status
		DWORD Reserved3 : 5;				// [56:60] - Reserved
		DWORD ClrOvfUncore : 1;				// [61]
		DWORD ClrOvfDsBuffer : 1;			// [62]
		DWORD ClrCondChgd : 1;				// [63]
	} Fields;
	ULONGLONG All;
};

#pragma pack(pop)

#define MTC_MASK	(0xf << 14)
#define CYC_MASK	(0xf << 19)
#define PSB_MASK	(0xf << 24)

#define ADDR0_SHIFT	32
#define ADDR1_SHIFT	32
#define ADDR0_MASK	(0xfULL << ADDR0_SHIFT)
#define ADDR1_MASK	(0xfULL << ADDR1_SHIFT)
#define TOPA_SIZE_SHIFT 6
