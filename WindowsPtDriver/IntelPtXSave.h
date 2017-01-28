/**********************************************************************
*  Windows Intel Processor Trace (PT) Driver 0.5
*  Filename: IntelPtXSave.h
*  Defines the Intel Processor Trace support data structures for XSAVE feature
*  Last revision: 01/25/2017
*
*  Copyright© 2017 Andrea Allievi, Richard Johnson
*  TALOS Research and Intelligence Group and Microsoft Ltd
*  All right reserved
**********************************************************************/
#pragma once
#include "Intel_Defs.h"

// The XSAVES function used in AMD64/X86 CPUs (defined in Amd64XSAve.asm)
extern "C" void _xsaves(void *mem, unsigned __int64 save_mask);

#define CPUID_XSAVE_MASK			(1 << 26)			// The XSAVE support in CPUID leaf 1
#define PT_XSAVE_MASK				(1 << 8)			// The PT support in XSAVE 
#define IA32_XSS_XSAVE_MASK			(1 << 8)			// The XSS MSR support in XSAVE 
#define MSR_IA32_XSS				(0x00000DA0)		// IA32_XSS Model specific register ID
#define OSXSAVE_CR4_MASK			(1i64 << 18)		// The XSAVE on/off bitmask in CR4 register

typedef struct _GLOBAL_DATA {
	DWORD dwXSaveSAreaSize;					// Supervisor XSAVE Area maximum size
	DWORD dwXSaveUAreaSize;					// User-mode XSAVE Area maximum size
} GLOBAL_DATA;

// Intel PT XSAVE Area
typedef struct DECLSPEC_ALIGN(16) _XSAVE_PT_EXTENDED_AREA {
	MSR_RTIT_CTL_DESC rtit_ctl;								// + 0x00 - IA32_RTIT_CTL MSR
	MSR_RTIT_OUTPUTBASE_DESC rtit_outputbase;				// + 0x08 - IA32_RTIT_OUTPUTBASE MSR
	MSR_RTIT_OUTPUT_MASK_PTRS_DESC rtit_output_mask_ptrs;	// + 0x10 - IA32_RTIT_OUTPUTMASK_PTRS MSR
	MSR_RTIT_STATUS_DESC rtit_status;						// + 0x18 - IA32_RTIT_STATUS MSR
	ULONGLONG rtit_cr3_match;								// + 0x20 - IA32_RTIT_CR3_MATCH
	ULONGLONG rtit_addr0_a;									// + 0x28 - MSR_IA32_RTIT_ADDR0_A (start) MSR 
	ULONGLONG rtit_addr0_b;									// + 0x30 - MSR_IA32_RTIT_ADDR0_B (end) MSR 
	ULONGLONG rtit_addr1_a;									// + 0x38 - MSR_IA32_RTIT_ADDR0_A (start) MSR 
	ULONGLONG rtit_addr1_b;									// + 0x40 - MSR_IA32_RTIT_ADDR0_B (end) MSR 
} XSAVE_PT_EXTENDED_AREA;

typedef struct DECLSPEC_ALIGN(16) _XSAVE_AREA_EX {
	XSAVE_FORMAT LegacyState;					// + 0x00
	XSAVE_AREA_HEADER Header;					// + 0x200
	XSAVE_PT_EXTENDED_AREA ExtendedArea;		// + 0x240
} XSAVE_AREA_EX, *PXSAVE_AREA_EX;

#pragma pack(push)
#pragma pack(1)
typedef union _MSR_IA32_XSS_DESC {
	struct {
		DWORD Reserved : 8;					// [7:0] Reserved
		DWORD IntelPt : 1;					// [8] Trace Packet Configuration State (R/W)
		DWORD Reserved2 : 23;
	} Bits;
	ULONG64 value;
} MSR_IA32_XSS_DESC;

typedef union _XCR0_DESC {
	struct {
		DWORD FpuMmx : 1;					// [0] x87 FPU/MMX state (must be 1)
		DWORD Sse : 1;						// [1] SSE state
		DWORD Avx : 1;						// [2] AVX state	
		DWORD BNDREG : 1;					// [3] BNDREG state
		DWORD BNDCSR : 1;					// [4] BNDCSR state
		DWORD OpMask : 1;					// [5] Opmask state	
		DWORD ZMM_Hi256 : 1;				// [6] ZMM_Hi256 state	
		DWORD Hi16_ZMM : 1;					// [7] Hi16_ZMM state
		DWORD Reserved : 1;					// [8] Reserved - Used for Intel PT in IA32_XSS MSR
		DWORD PKRU : 1;						// [9] PKRU state
		DWORD Reserved2 : 22;				// [10:32] Reserved for future expansion
	} Bits;
	ULONG64 value;
} XCR0_DESC;
#pragma pack(pop)

// Check if the current processor support the XSAVE feature for Intel PT
NTSTATUS CheckPtXSaveSupport(DWORD * pdwSAreaSize, DWORD * pdwUAreaSize, DWORD * pdwPtSize);
// Get the current XSAVE Area size for the enabled features in XCR0 and IA32_XSS MSR of current CPU
DWORD GetCurXSaveAreaSize();
// Save all the PT data to an XSAVE area
NTSTATUS SavePtData(PXSAVE_AREA_EX lpXSaveArea, DWORD dwSize);
