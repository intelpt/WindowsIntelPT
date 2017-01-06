/**********************************************************************
 *  Windows Intel Processor Trace (PT) Driver 0.4
 *  Filename: KernelTracing.h
 *  Defines data structures needed for Kernel Tracing
 *  Last revision: 01/06/2016
 *
 *  Copyright© 2016 Andrea Allievi, Richard Johnson
 *  TALOS Research and Intelligence Group and Microsoft Ltd
 *  All right reserved
 **********************************************************************/
#pragma once

#ifndef INTEL_PT_HDRS
// Data structure that describe the trace type request
struct PT_TRACE_DESC {
	PEPROCESS peProc;						// Trace by CR3: The Process address space to trace (if any)
	BOOL bTraceKernel;						// Trace by CPL: TRUE if tracing Kernel mode components
	DWORD dwNumOfRanges;					// Trace by IP: Number of range to trace
	struct PT_TRACE_RANGE Ranges[4];		// Trace by IP: the VA ranges to trace
};

// The trace options Bitmask
union TRACE_OPTIONS {
	struct {
		BOOLEAN bTraceCycPcks : 1;					// [0] - Enables/disables CYC Packet (Cycle Count Packet - default is 0)
		BOOLEAN bTraceMtcPcks : 1;					// [1] - Enables/disables MTC Packet (Wall-clock time packets - default is 0)
		BOOLEAN bTraceTscPcks : 1;					// [2] - Enables/disables TSC Packet (Time Stamp packets - default is 0)
		BOOLEAN bTraceBranchPcks : 1;				// [3] - Enables/disables COFI-based packets: FUP, TIP, TIP.PGE, TIP.PGD, TNT, MODE.Exec, MODE.TSX.		(default is 1)
		BOOLEAN bUseTopa : 1;						// [4] - Enable/disable the usage of Table of Physical Address (if available, default is 1)
		BOOLEAN bEnableRetCompression : 1;			// [5] - Enables/disables RET compression (default is 1)
		BOOLEAN Reserved : 2;						// [6-7] - Reserved
		BYTE MTCFreq : 4;							// [8:11] - MTC packet Frequency, which is based on the core crystal clock, or Always Running Timer (ART)
		BYTE CycThresh : 4;							// [12:15] - CYC packet threshold. CYC packets will be sent with the first eligible packet after N cycles have passed since the last CYC packet
		BYTE PSBFreq : 4;							// [16:19] - The frequency of PSB packets. PSB packet frequency is based on the number of Intel PT packet bytes output
	} Fields;
	DWORD All;
};

// The descriptor of the Tracing buffer
typedef struct _PT_BUFFER_DESCRIPTOR {
	union {
		struct {
			LPVOID lpTraceBuffVa;					// + 0x00 - Kernel VA Pointer to a contiguous memory buffer
			ULONG_PTR lpTraceBuffPhysAddr;			// + 0x08 - The physical address of the contiguous memory buffer
		} Simple;
		struct {
			LPVOID lpTopaVa;						// + 0x00 - Kernel VA pointer to the ToPA
			ULONG_PTR lpTopaPhysAddr;				// + 0x08 - The Physical adress of the ToPA
		} ToPA;
	} u;
	BOOLEAN bUseTopa;								// + 0x10 - TRUE if this processor uses ToPa
	BOOLEAN bDefaultPmiSet;							// + 0x11 - TRUE if the default PMI is on
	BOOLEAN bBuffIsFull;							// + 0x12 - TRUE if the ToPa or Simple buffer is full
	QWORD qwBuffSize;								// + 0x18 - The physical buffer size
	PMDL pTraceMdl;									// + 0x20 - The MDL used for mapping pages
	LPVOID lpKernelVa;								// + 0x28 - The kernel-mode virtual address 
}PT_BUFFER_DESCRIPTOR, *PPT_BUFFER_DESCRIPTOR;

// The custom PMI ISR routines
typedef VOID(*INTELPT_PMI_HANDLER)(DWORD dwProcId, PT_BUFFER_DESCRIPTOR * ptBuffDesc);

// Check the Intel Processor Trace support on this processor
NTSTATUS IntelPtCheckCpuSupport(INTEL_PT_CAPABILITIES * lpPtCap);

// Pause/Resume the Trace
NTSTATUS IntelPtPauseResumeTrace(BOOLEAN bPause);

// Free and destroy a Trace buffer
NTSTATUS IntelPtFreeBuffer(PT_BUFFER_DESCRIPTOR * ptBuffDesc);
#endif // !INTEL_PT_HDRS

// Allocate the buffer needed for kernel tracing
NTSTATUS IntelPtAllocBuffer(PPT_BUFFER_DESCRIPTOR * pBuffDesc, QWORD qwSize, BOOLEAN bUseTopa, BOOLEAN bSetStdPmi = TRUE);

// Add a PMI interrupt for a page in the ToPA
NTSTATUS IntelPtAddBufferPmi(PT_BUFFER_DESCRIPTOR * pBuffDesc, QWORD qwOffset);

// Remove a PMI interrupt from a page in the ToPA
NTSTATUS IntelPtRemoveBufferPmi(PT_BUFFER_DESCRIPTOR * pBuffDesc, QWORD qwOffset);

// Start the Kernel tracing for current processor
NTSTATUS IntelPtStartTracing(PT_TRACE_DESC traceDesc, PT_BUFFER_DESCRIPTOR * pBuffDesc);

// Register a PMI handler for ALL processor
NTSTATUS IntelPtRegisterPmiHandler(INTELPT_PMI_HANDLER pCustomPmiHandler);

// Delete the previous registered Intel PT PMI handler routine
NTSTATUS IntelPtRemovePmiHandler(INTELPT_PMI_HANDLER pCustomPmiHandler);

// Set/Get the Trace options for current CPU
NTSTATUS IntelPtSetOptions(TRACE_OPTIONS opts);
TRACE_OPTIONS IntelPtGetOptions();

// Stop the Tracing 
VOID IntelPtStopTrace();
