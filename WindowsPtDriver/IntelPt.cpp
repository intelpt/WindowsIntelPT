/**********************************************************************
 *  Windows Intel Processor Trace (PT) Driver
 * 	Filename: IntelPt.cpp
 *	Implement the Intel Processor Trace driver
 *	Last revision: 01/06/2016
 *
 *  Copyright© 2016 Andrea Allievi, Richard Johnson 
 * 	Microsoft Ltd & TALOS Research and Intelligence Group
 *	All right reserved
 **********************************************************************/
#include "stdafx.h"
#include "DriverEntry.h"
#include "IntelPt.h"
#include "Debug.h"
#include "UndocNt.h"
#include "IntelPtXSave.h"
#include <intrin.h>

#define DirectoryTableBaseOffset 0x28

#pragma region Intel PT management functions
#pragma code_seg(".nonpaged")
NTSTATUS CheckIntelPtSupport(INTEL_PT_CAPABILITIES * lpPtCap)
{
	INTEL_PT_CAPABILITIES ptCap = { 0 };		// The processor PT capabilities
	int cpuid_ctx[4] = { 0 };					// EAX, EBX, ECX, EDX

	// Processor support for Intel Processor Trace is indicated by CPUID.(EAX=07H,ECX=0H):EBX[bit 25] = 1.
	__cpuidex(cpuid_ctx, 0x07, 0);
	if ((cpuid_ctx[1] & (1 << 25)) == 0) 
		return STATUS_NOT_SUPPORTED;

	// We can return now if capability struct was not requested
	if (!lpPtCap)
		return STATUS_SUCCESS;

	// Enumerate the Intel Processor Trace capabilities
	RtlZeroMemory(cpuid_ctx, sizeof(cpuid_ctx));
	__cpuidex(cpuid_ctx, 0x14, 0);
	ptCap.bCr3Filtering = (cpuid_ctx[1] & (1 << 0)) != 0;					// EBX
	ptCap.bConfPsbAndCycSupported = (cpuid_ctx[1] & (1 << 1)) != 0;
	ptCap.bIpFiltering = (cpuid_ctx[1] & (1 << 2)) != 0;
	ptCap.bMtcSupport = (cpuid_ctx[1] & (1 << 3)) != 0;
	ptCap.bTopaOutput = (cpuid_ctx[2] & (1 << 0)) != 0;						// ECX
	ptCap.bTopaMultipleEntries = (cpuid_ctx[2] & (1 << 1)) != 0;
	ptCap.bSingleRangeSupport = (cpuid_ctx[2] & (1 << 2)) != 0;
	ptCap.bTransportOutputSupport = (cpuid_ctx[2] & (1 << 3)) != 0;
	ptCap.bIpPcksAreLip = (cpuid_ctx[2] & (1 << 31)) != 0;

	// Enumerate secondary capabilities (sub-leaf 1)
	if (cpuid_ctx[0] != 0)
	{
		RtlZeroMemory(cpuid_ctx, sizeof(cpuid_ctx));
		__cpuidex(cpuid_ctx, 0x14, 1);
		ptCap.numOfAddrRanges = (BYTE)(cpuid_ctx[0] & 0x7);
		ptCap.mtcPeriodBmp = (SHORT)((cpuid_ctx[0] >> 16) & 0xFFFF);
		ptCap.cycThresholdBmp = (SHORT)(cpuid_ctx[1] & 0xFFFF);
		ptCap.psbFreqBmp = (SHORT)((cpuid_ctx[1] >> 16) & 0xFFFF);
	}
 
	*lpPtCap = ptCap;
	return STATUS_SUCCESS;
}

// Enable the Intel PT trace for current processor 
NTSTATUS StartCpuTrace(PT_TRACE_DESC desc, PT_BUFFER_DESCRIPTOR * pPtBuffDesc) {
	NTSTATUS ntStatus = STATUS_NOT_SUPPORTED;				// Returned NTSTATUS value
	INTEL_PT_CAPABILITIES ptCap = { 0 };					// The per-processor PT capabilities
	PER_PROCESSOR_PT_DATA * lpProcPtData = NULL;			// The per processor data structure
	ULONG_PTR targetCr3 = 0;								// The target CR3 value
	KIRQL kOldIrql = KeGetCurrentIrql();					// The current IRQL
	ULONG curProcId = KeGetCurrentProcessorNumber();		// Current processor number
	if (!pPtBuffDesc) return STATUS_INVALID_PARAMETER;
	if (!g_pDrvData) return STATUS_INTERNAL_ERROR;
	
	// PT data structures
	MSR_RTIT_CTL_DESC rtitCtlDesc = { 0 };
	MSR_RTIT_STATUS_DESC rtitStatusDesc = { 0 };
	MSR_RTIT_OUTPUTBASE_DESC rtitOutBaseDesc = { 0 };
	MSR_RTIT_OUTPUT_MASK_PTRS_DESC rtitOutMasksDesc = { 0 };
	if (!pPtBuffDesc || !pPtBuffDesc->qwBuffSize) return STATUS_INVALID_PARAMETER_2;

	ntStatus = CheckIntelPtSupport(&ptCap);
	if (!NT_SUCCESS(ntStatus)) return ntStatus;

	// Check here the support based on the Trace structure
	if (desc.peProc != NULL)
		// Check the support for CR3 filtering
		if (!ptCap.bCr3Filtering) return STATUS_NOT_SUPPORTED;
	if (desc.dwNumOfRanges > 0) {
		if (!ptCap.bIpFiltering) return STATUS_NOT_SUPPORTED;
		if (desc.dwNumOfRanges > 4) return STATUS_INVALID_PARAMETER_1;
		if (ptCap.numOfAddrRanges < desc.dwNumOfRanges) return STATUS_NOT_SUPPORTED;
	}
	// Now check the output mode
	if (!ptCap.bSingleRangeSupport && !ptCap.bTopaOutput) return STATUS_NOT_SUPPORTED;

	// To proper read the value of the CR3 register of a target process, the KiSwapProcess routines does this:
	// From KTHREAD go to ETHREAD, then use the ApcState field to return back to a EPROCESS
	// Finally grab it from peProc->DirectoryTableBase (offset + 0x28) 
	if (desc.peProc) {
		targetCr3 = ((ULONG_PTR *)desc.peProc)[5];
		// Check the found target CR3 (it should have the last 12 bits set to 0, due to the PFN standard)
		if ((targetCr3 & 0xFFF) != 0) return STATUS_INVALID_ADDRESS;
		DrvDbgPrint("[" DRV_NAME "] Starting Intel Processor Trace for processor %i. Target CR3: 0x%llX\r\n", curProcId, targetCr3);
	}
	else if (desc.bTraceKernel)
		DrvDbgPrint("[" DRV_NAME "] Starting Intel Processor Trace for processor %i. Tracing Kernel address space...\r\n", curProcId);
	else 
		DrvDbgPrint("[" DRV_NAME "] Starting Intel Processor Trace for processor %i. Tracing all user mode processes.\r\n", curProcId);

	if (desc.dwNumOfRanges > 0)
		DrvDbgPrint("[" DRV_NAME "] Enabled %i filtering windows. IP range 1. Start VA: 0x%llX, Size 0x%08X\r\n ",
			desc.dwNumOfRanges, (LPVOID)desc.Ranges[0].lpStartVa, (LPVOID)((DWORD)((QWORD)desc.Ranges[0].lpEndVa - (QWORD)desc.Ranges[0].lpStartVa)));

	// Check if the passed data structure that describe the buffer is valid
	if ((pPtBuffDesc->bUseTopa && !ptCap.bTopaOutput) ||
		pPtBuffDesc->qwBuffSize < PAGE_SIZE ||
		(!pPtBuffDesc->bUseTopa && !ptCap.bSingleRangeSupport) ||
		!pPtBuffDesc->u.Simple.lpTraceBuffPhysAddr)
		return STATUS_INVALID_PARAMETER_2;

	// Initially set up all the descriptor data in the Per-processor control structure
	lpProcPtData = &g_pDrvData->procData[curProcId];
	lpProcPtData->lpTargetProcCr3 = targetCr3;
	lpProcPtData->lpTargetProc = desc.peProc;
	if (desc.dwNumOfRanges) {
		RtlZeroMemory(lpProcPtData->IpRanges, sizeof(lpProcPtData->IpRanges));
		RtlCopyMemory(lpProcPtData->IpRanges, desc.Ranges, desc.dwNumOfRanges * sizeof(PT_TRACE_RANGE));
		lpProcPtData->dwNumOfActiveRanges = desc.dwNumOfRanges;
	}

	// Check if the options have been initialized
	if (!lpProcPtData->TraceOptions.Fields.bInitialized)
		SetDefaultTraceOptions(curProcId);

	// Raise the IRQL (we don't want to be swapped out)
	if (kOldIrql < DISPATCH_LEVEL)
		KeRaiseIrql(DISPATCH_LEVEL, &kOldIrql);

	// Step 1. Disable all the previous PT flags
	rtitCtlDesc.All = __readmsr(MSR_IA32_RTIT_CTL);
	rtitCtlDesc.Fields.TraceEn = 0;
	__writemsr(MSR_IA32_RTIT_CTL, rtitCtlDesc.All);

	// Clear IA32_RTIT_STATUS MSR
	rtitStatusDesc.All = __readmsr(MSR_IA32_RTIT_STATUS);
	rtitStatusDesc.Fields.Error = 0;						// See Intel's manuals, section 36.3.2.1
	rtitStatusDesc.Fields.Stopped = 0;
	rtitStatusDesc.Fields.ContextEn = 0;
	rtitStatusDesc.Fields.PacketByteCnt = 0;				// Restore the Byte counter to 0
	lpProcPtData->PacketByteCount = 0;						// In both values
	__writemsr(MSR_IA32_RTIT_STATUS, rtitStatusDesc.All);

	// Set the IA32_RTIT_OUTPUT and IA32_RTIT_OUTPUT_MASK_PTRS MSRs
	if (pPtBuffDesc->bUseTopa)
	{
		// Use Table of Physical Addresses 
		rtitCtlDesc.Fields.ToPA = 1;

		// Set the proc_trace_table_base
		rtitOutBaseDesc.All = (ULONGLONG)pPtBuffDesc->u.ToPA.lpTopaPhysAddr;
		__writemsr(MSR_IA32_RTIT_OUTPUT_BASE, rtitOutBaseDesc.All);

		// Set the proc_trace_table_offset: indicates the entry of the current table that is currently in use
		rtitOutMasksDesc.Fields.LowerMask = 0x7F;
		rtitOutMasksDesc.Fields.MaskOrTableOffset = 0;		// Start from the first entry in the table
		rtitOutMasksDesc.Fields.OutputOffset = 0;			// Start at offset 0
		__writemsr(MSR_IA32_RTIT_OUTPUT_MASK_PTRS, rtitOutMasksDesc.All);
	}
	else
	{
		// Use the single range output implementation
		rtitCtlDesc.Fields.ToPA = 0;						// We use the single-range output scheme
		rtitOutBaseDesc.All = (ULONGLONG)pPtBuffDesc->u.Simple.lpTraceBuffPhysAddr;
		__writemsr(MSR_IA32_RTIT_OUTPUT_BASE, rtitOutBaseDesc.All);

		rtitOutMasksDesc.All = (1 << PAGE_SHIFT) - 1;		// The physical page always has low 12 bits NULL
		__writemsr(MSR_IA32_RTIT_OUTPUT_MASK_PTRS, rtitOutMasksDesc.All);
	}

	// Set the TRACE options:
	TRACE_OPTIONS & options = lpProcPtData->TraceOptions;
	rtitCtlDesc.Fields.FabricEn = 0;
	rtitCtlDesc.Fields.Os = (desc.bTraceKernel ? 1 : 0);	// Trace Kernel address space	
	rtitCtlDesc.Fields.User = (desc.bTraceUser ? 1 : 0);	// Trace the user mode process
	rtitCtlDesc.Fields.BranchEn = options.Fields.bTraceBranchPcks;

	if (lpProcPtData->lpTargetProcCr3) {
		// Set the page table filter for the target process 
		__writemsr(MSR_IA32_RTIT_CR3_MATCH, (ULONGLONG)targetCr3);
		rtitCtlDesc.Fields.CR3Filter = 1;
	}
	else {
		// Set the register to 0
		__writemsr(MSR_IA32_RTIT_CR3_MATCH, 0);
		rtitCtlDesc.Fields.CR3Filter = 0;
	}

	// Set the IP range flags and registers to 0 
	rtitCtlDesc.Fields.Addr0Cfg = 0;
	rtitCtlDesc.Fields.Addr1Cfg = 0;
	rtitCtlDesc.Fields.Addr2Cfg = 0;
	rtitCtlDesc.Fields.Addr3Cfg = 0;

	// Now set them to the proper values (see Intel Manuals, chapter 36.2.5.2 - IA32_RTIT_CTL MSR)
	if (lpProcPtData->dwNumOfActiveRanges > 0) {
		if (lpProcPtData->IpRanges[0].bStopTrace) rtitCtlDesc.Fields.Addr0Cfg = 2;
		else rtitCtlDesc.Fields.Addr0Cfg = 1;
		__writemsr(MSR_IA32_RTIT_ADDR0_START, (QWORD)lpProcPtData->IpRanges[0].lpStartVa);
		__writemsr(MSR_IA32_RTIT_ADDR0_END, (QWORD)lpProcPtData->IpRanges[0].lpEndVa);
	}
	if (lpProcPtData->dwNumOfActiveRanges > 1) {
		if (lpProcPtData->IpRanges[1].bStopTrace) rtitCtlDesc.Fields.Addr1Cfg = 2;
		else rtitCtlDesc.Fields.Addr1Cfg = 1;
		__writemsr(MSR_IA32_RTIT_ADDR1_START, (QWORD)lpProcPtData->IpRanges[1].lpStartVa);
		__writemsr(MSR_IA32_RTIT_ADDR1_END, (QWORD)lpProcPtData->IpRanges[1].lpEndVa);
	}
	if (lpProcPtData->dwNumOfActiveRanges > 2) {
		if (lpProcPtData->IpRanges[2].bStopTrace) rtitCtlDesc.Fields.Addr2Cfg = 2;
		else rtitCtlDesc.Fields.Addr2Cfg = 1;
		__writemsr(MSR_IA32_RTIT_ADDR2_START, (QWORD)lpProcPtData->IpRanges[2].lpStartVa);
		__writemsr(MSR_IA32_RTIT_ADDR2_END, (QWORD)lpProcPtData->IpRanges[2].lpEndVa);
	}
	if (lpProcPtData->dwNumOfActiveRanges > 3) {
		if (lpProcPtData->IpRanges[3].bStopTrace) rtitCtlDesc.Fields.Addr3Cfg = 2;
		else rtitCtlDesc.Fields.Addr3Cfg = 1;
		__writemsr(MSR_IA32_RTIT_ADDR3_START, (QWORD)lpProcPtData->IpRanges[3].lpStartVa);
		__writemsr(MSR_IA32_RTIT_ADDR3_END, (QWORD)lpProcPtData->IpRanges[3].lpEndVa);
	}

	if (ptCap.bMtcSupport)
	{
		rtitCtlDesc.Fields.MTCEn = options.Fields.bTraceMtcPcks;
		if ((1 << options.Fields.MTCFreq) & ptCap.mtcPeriodBmp)
			rtitCtlDesc.Fields.MTCFreq = options.Fields.MTCFreq;
	}
	if (ptCap.bConfPsbAndCycSupported)
	{
		rtitCtlDesc.Fields.CycEn = options.Fields.bTraceCycPcks;
		if ((1 << options.Fields.CycThresh) & ptCap.cycThresholdBmp)
			rtitCtlDesc.Fields.CycThresh = options.Fields.CycThresh;
		if ((1 << options.Fields.PSBFreq) & ptCap.psbFreqBmp)
			rtitCtlDesc.Fields.PSBFreq = options.Fields.PSBFreq;
	}
	rtitCtlDesc.Fields.DisRETC = (options.Fields.bEnableRetCompression == 0);
	rtitCtlDesc.Fields.TSCEn = options.Fields.bTraceTscPcks;

	// Switch the tracing to ON dude :-)
	rtitCtlDesc.Fields.TraceEn = 1;
	__writemsr(MSR_IA32_RTIT_CTL, rtitCtlDesc.All);

	// Read the status register
	rtitStatusDesc.All = __readmsr(MSR_IA32_RTIT_STATUS);

	// Finally lower the IRQL
	if (kOldIrql < DISPATCH_LEVEL)
		KeLowerIrql(kOldIrql);

	if (rtitStatusDesc.Fields.TriggerEn) {
		DbgPrint("[" DRV_NAME "] Successfully enabled Intel PT tracing for processor %i. Log Virtual Address: 0x%llX. :-)\r\n",
			curProcId, pPtBuffDesc->bUseTopa ? pPtBuffDesc->u.ToPA.lpTopaVa : pPtBuffDesc->u.Simple.lpTraceBuffVa);
		lpProcPtData->curState = PT_PROCESSOR_STATE_TRACING;
		// Set the PT buffer as current
		lpProcPtData->pPtBuffDesc = pPtBuffDesc;
		return STATUS_SUCCESS;
	}
	else
	{
		DbgPrint("[" DRV_NAME "] Error: unable to successfully enable Intel PT tracing for processor %i.", curProcId);
		//__writemsr(MSR_IA32_RTIT_STATUS, 0);
		lpProcPtData->curState = PT_PROCESSOR_STATE_ERROR;
		lpProcPtData->lpTargetProc = NULL;
		lpProcPtData->lpTargetProcCr3 = NULL;
		lpProcPtData->dwNumOfActiveRanges = 0;
		RtlZeroMemory(lpProcPtData->IpRanges, sizeof(lpProcPtData->IpRanges));
		return STATUS_UNSUCCESSFUL;
	}
}

// Enable the Intel PT trace for current processor (allocate the needed buffer)
NTSTATUS StartCpuTrace(PT_TRACE_DESC desc, QWORD qwBuffSize)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	BOOLEAN bBuffAllocated = FALSE;				// TRUE if buffer for current CPU has been allocated
	DWORD dwCurCpu = KeGetCurrentProcessorNumber();
	if (!g_pDrvData) return STATUS_INTERNAL_ERROR;
	ntStatus = CheckIntelPtSupport(NULL);
	if (!NT_SUCCESS(ntStatus)) return ntStatus;

	// Grab the memory descriptor
	PER_PROCESSOR_PT_DATA & cpuPtData = g_pDrvData->procData[dwCurCpu];

	// Check if the options have been initialized
	if (!cpuPtData.TraceOptions.Fields.bInitialized)
		SetDefaultTraceOptions(dwCurCpu);

	// Allocate the physical memory
	if (!cpuPtData.pPtBuffDesc || !cpuPtData.pPtBuffDesc->qwBuffSize || cpuPtData.pPtBuffDesc->qwBuffSize != qwBuffSize)
	{
		BOOLEAN bUseTopa = (cpuPtData.TraceOptions.Fields.bUseTopa == 1);
		ntStatus = AllocCpuPtBuffer(dwCurCpu, qwBuffSize, bUseTopa);
		if (!NT_SUCCESS(ntStatus)) {
			DbgPrint("[" DRV_NAME "] Error: unable to allocate the trace buffer.\r\n");
			cpuPtData.lpTargetProcCr3 = NULL;
			cpuPtData.lpTargetProc = NULL;
			return STATUS_INVALID_PARAMETER_2;
		}
		bBuffAllocated = TRUE;
	}

	ntStatus = StartCpuTrace(desc, cpuPtData.pPtBuffDesc);

	if (!NT_SUCCESS(ntStatus) && bBuffAllocated)
		FreeCpuResources(dwCurCpu);
	return ntStatus;
}

// Start the Tracing of a particular usermode process 
NTSTATUS StartProcessTrace(DWORD dwProcId, QWORD qwBuffSize) 
{
	NTSTATUS ntStatus = 0;
	PEPROCESS peProc = NULL;
	PT_TRACE_DESC ptDesc = { 0 };			// The kernel tracing data structure
	if (!g_pDrvData) return STATUS_INTERNAL_ERROR;

	// PsLookupProcessByProcessId should be executed at IRQL < DISPATCH_LEVEL
	ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);				
	ntStatus = PsLookupProcessByProcessId((HANDLE)dwProcId, &peProc);

	if (!NT_SUCCESS(ntStatus)) 
		return ntStatus;
	else {
		// Compose the right data structure and pass the control to the main function
		ptDesc.bTraceKernel = FALSE;
		ptDesc.bTraceUser = TRUE;
		ptDesc.dwNumOfRanges = 0;
		ptDesc.peProc = peProc;
		return StartCpuTrace(ptDesc, qwBuffSize);
	}
}

// Put the tracing in PAUSE mode
NTSTATUS PauseResumeTrace(BOOLEAN bPause) 
{
	MSR_RTIT_CTL_DESC rtitCtlDesc = { 0 };					// The RTIT MSR descriptor
	MSR_RTIT_STATUS_DESC rtitStatusDesc = { 0 };			// The Status MSR descriptor
	MSR_RTIT_OUTPUTBASE_DESC rtitOutBaseDesc = { 0 };		// IA32_RTIT_OUTPUT_BASE Model specific Register
	MSR_RTIT_OUTPUT_MASK_PTRS_DESC rtitOutMasksDesc = { 0 };// IA32_RTIT_OUTPUT_MASK_PTRS Model specific Register
	DWORD dwCurCpu = 0;										// Current running CPU
	NTSTATUS ntStatus = STATUS_NOT_SUPPORTED;			 	// Returned NTSTATUS value
	if (!g_pDrvData) return STATUS_INTERNAL_ERROR;

	ntStatus = CheckIntelPtSupport(NULL);
	if (!NT_SUCCESS(ntStatus)) return ntStatus;

	dwCurCpu = KeGetCurrentProcessorNumber();
	PER_PROCESSOR_PT_DATA & curCpuData = g_pDrvData->procData[dwCurCpu];
	if (curCpuData.curState != PT_PROCESSOR_STATE_TRACING && bPause) return STATUS_SUCCESS;
	if (curCpuData.curState != PT_PROCESSOR_STATE_PAUSED && bPause == FALSE) return STATUS_INVALID_DEVICE_REQUEST;

	// Read the current state
	rtitCtlDesc.All = __readmsr(MSR_IA32_RTIT_CTL);
	rtitStatusDesc.All = __readmsr(MSR_IA32_RTIT_STATUS);

	// XXX: This seems unnecessary 
	// Update the STATUS register 
	if (rtitCtlDesc.Fields.TraceEn == 0) {
		rtitStatusDesc.Fields.Stopped = 0;
		rtitStatusDesc.Fields.Error = 0;
		__writemsr(MSR_IA32_RTIT_STATUS, rtitStatusDesc.All);
	}

	if (bPause)	{
		// Pause Intel PT tracing 
		rtitCtlDesc.Fields.TraceEn = 0;
	}
	else 
	{
		PT_BUFFER_DESCRIPTOR * ptBuffDesc =	curCpuData.pPtBuffDesc;
		// If we paused to dump buffer lets reset it 
		if (ptBuffDesc && ptBuffDesc->bUseTopa && ptBuffDesc->bBuffIsFull) {
			// Restore the Topa Buffer, Set the proc_trace_table_base
			rtitOutBaseDesc.All = (ULONGLONG)ptBuffDesc->u.ToPA.lpTopaPhysAddr;
			__writemsr(MSR_IA32_RTIT_OUTPUT_BASE, rtitOutBaseDesc.All);

			// Set the proc_trace_table_offset: indicates the entry of the table that is currently in use
			rtitOutMasksDesc.Fields.LowerMask = 0x7F;
			rtitOutMasksDesc.Fields.MaskOrTableOffset = 0;	// Start from the first entry in the table
			rtitOutMasksDesc.Fields.OutputOffset = 0;		// Start at offset 0
			__writemsr(MSR_IA32_RTIT_OUTPUT_MASK_PTRS, rtitOutMasksDesc.All);
			ptBuffDesc->bBuffIsFull = FALSE;
		}

		// Resume Intel PT tracing
		rtitCtlDesc.Fields.TraceEn = 1;
	}

	// Update the Control register
	__writemsr(MSR_IA32_RTIT_CTL, rtitCtlDesc.All);

	/* XXX: should not be needed 
	if (kIrql <= DISPATCH_LEVEL) {
		// STALL the execution for a little time
		KeStallExecutionProcessor(42);
	} // else ... Interrupt routine should be VERY FAST
	*/

	// Read the final status
	rtitStatusDesc.All = __readmsr(MSR_IA32_RTIT_STATUS);
	
	if (rtitStatusDesc.Fields.Error) {
		curCpuData.curState = PT_PROCESSOR_STATE_ERROR;
		return STATUS_UNSUCCESSFUL;
	}

	if (bPause) {
		// Copy and reset the current number of packets
		curCpuData.PacketByteCount += (QWORD)rtitStatusDesc.Fields.PacketByteCnt;
		rtitStatusDesc.Fields.PacketByteCnt = 0;
		__writemsr(MSR_IA32_RTIT_STATUS, rtitStatusDesc.All);
		curCpuData.curState = PT_PROCESSOR_STATE_PAUSED;
	}
	else
		curCpuData.curState = PT_PROCESSOR_STATE_TRACING;

	return STATUS_SUCCESS;
}

// Disable Intel PT for the current processor
NTSTATUS StopAndDisablePt() 
{
	NTSTATUS ntStatus = STATUS_NOT_SUPPORTED;				// Returned NTSTATUS value
	INTEL_PT_CAPABILITIES ptCap = { 0 };					// Intel Processor Tracing capabilities
	PER_PROCESSOR_PT_DATA * lpProcPtData = NULL;			// The per processor data structure
	MSR_RTIT_CTL_DESC rtitCtlDesc = { 0 };
	MSR_RTIT_STATUS_DESC rtitStatusDesc = { 0 };			// The Status MSR descriptor
	ULONG dwCurProc = 0;
	if (!g_pDrvData) return STATUS_INTERNAL_ERROR;

	ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);

	dwCurProc = KeGetCurrentProcessorNumber();
	lpProcPtData = &g_pDrvData->procData[dwCurProc];

	ntStatus = CheckIntelPtSupport(&ptCap);
	if (!NT_SUCCESS(ntStatus)) return ntStatus;

	#ifdef ENABLE_EXPERIMENTAL_XSAVE
	ntStatus = SavePtData((PXSAVE_AREA_EX)lpProcPtData->lpXSaveArea, lpProcPtData->dwXSaveAreaSize);
	#endif

	// Stop and disable the Intel PT
	rtitCtlDesc.All = __readmsr(MSR_IA32_RTIT_CTL);
	rtitCtlDesc.Fields.TraceEn = 0;
	__writemsr(MSR_IA32_RTIT_CTL, rtitCtlDesc.All);

	// Copy the final number of Acquired packets
	rtitStatusDesc.All = __readmsr(MSR_IA32_RTIT_STATUS);
	lpProcPtData->PacketByteCount += (QWORD)rtitStatusDesc.Fields.PacketByteCnt;

	// Reset all the configuration registers
	__writemsr(MSR_IA32_RTIT_OUTPUT_BASE, 0);
	__writemsr(MSR_IA32_RTIT_OUTPUT_MASK_PTRS, 0);
	if (ptCap.numOfAddrRanges > 0) {
		__writemsr(MSR_IA32_RTIT_ADDR0_START, 0);
		__writemsr(MSR_IA32_RTIT_ADDR0_END, 0);
	}
	if (ptCap.numOfAddrRanges > 1) {
		__writemsr(MSR_IA32_RTIT_ADDR1_START, 0);
		__writemsr(MSR_IA32_RTIT_ADDR1_END, 0);
	}
	if (ptCap.numOfAddrRanges > 2) {
		__writemsr(MSR_IA32_RTIT_ADDR2_START, 0);
		__writemsr(MSR_IA32_RTIT_ADDR2_END, 0);
	}
	if (ptCap.numOfAddrRanges > 3) {
		__writemsr(MSR_IA32_RTIT_ADDR3_START, 0);
		__writemsr(MSR_IA32_RTIT_ADDR3_END, 0);
	}
	if (ptCap.bCr3Filtering)
		__writemsr(MSR_IA32_RTIT_CR3_MATCH, 0);

	// Set the new processor State
	lpProcPtData->curState = PT_PROCESSOR_STATE_STOPPED;

	lpProcPtData->lpTargetProcCr3 = NULL;
	lpProcPtData->lpTargetProc = NULL;
	lpProcPtData->dwNumOfActiveRanges = 0;
	RtlZeroMemory(lpProcPtData->IpRanges, sizeof(lpProcPtData->IpRanges));

	return STATUS_SUCCESS;
}

// Get the active Trace options for a particular CPU
NTSTATUS GetTraceOptions(DWORD dwCpuId, TRACE_OPTIONS * pOptions) 
{
	DWORD dwNumCpus = KeQueryActiveProcessorCount(NULL);
	if (!g_pDrvData) return STATUS_INTERNAL_ERROR;
	if (dwCpuId >= dwNumCpus) 
		return STATUS_INVALID_PARAMETER;

	// Initialize the default trace options if not any is set
	if (g_pDrvData->procData[dwCpuId].TraceOptions.Fields.bInitialized == FALSE)
		SetDefaultTraceOptions(dwCpuId);

	if (pOptions)
		*pOptions = g_pDrvData->procData[dwCpuId].TraceOptions;

	return STATUS_SUCCESS;
}

// Set the trace options for a particular CPU
NTSTATUS SetTraceOptions(DWORD dwCpuId, TRACE_OPTIONS opts) 
{
	KAFFINITY curCpuAffinity = 0;
	DWORD dwNumCpus = 0;
	INTEL_PT_CAPABILITIES ptCap = { 0 };
	NTSTATUS ntStatus = 0;

	dwNumCpus = KeQueryActiveProcessorCount(&curCpuAffinity);
	if (!g_pDrvData) return STATUS_INTERNAL_ERROR;
	if (dwCpuId >= dwNumCpus) return STATUS_INVALID_PARAMETER;
	PER_PROCESSOR_PT_DATA & cpuData = g_pDrvData->procData[dwCpuId];
	ntStatus = CheckIntelPtSupport(&ptCap);
	if (!NT_SUCCESS(ntStatus)) return ntStatus;

	// Check the options now
	if (opts.Fields.bTraceMtcPcks && (ptCap.bMtcSupport == 0)) return STATUS_NOT_SUPPORTED;
	if (opts.Fields.bTraceCycPcks && (ptCap.bConfPsbAndCycSupported == 0)) return STATUS_NOT_SUPPORTED;
	if (opts.Fields.bUseTopa && !(ptCap.bTopaOutput && ptCap.bTopaMultipleEntries)) return STATUS_NOT_SUPPORTED;

	// Check now the frequency bitmaps:
	if (opts.Fields.MTCFreq && ((1 << opts.Fields.MTCFreq) & (ptCap.mtcPeriodBmp == 0))) return STATUS_NOT_SUPPORTED;
	if (opts.Fields.PSBFreq && (ptCap.bConfPsbAndCycSupported == 0)) return STATUS_NOT_SUPPORTED;
	if (opts.Fields.PSBFreq && ((1 << opts.Fields.PSBFreq) & (ptCap.psbFreqBmp == 0))) return STATUS_NOT_SUPPORTED;
	if (opts.Fields.CycThresh && (ptCap.bConfPsbAndCycSupported == 0)) return STATUS_NOT_SUPPORTED;
	if (opts.Fields.CycThresh && ((1 << opts.Fields.CycThresh) & (ptCap.cycThresholdBmp == 0))) return STATUS_NOT_SUPPORTED;

	// Copy the options
	opts.Fields.bInitialized = 1;
	cpuData.TraceOptions = opts;
	return STATUS_SUCCESS;
}

// Set the default trace options for a particular CPU
NTSTATUS SetDefaultTraceOptions(DWORD dwCpuId) {
	KAFFINITY curCpuAffinity = 0;
	DWORD dwNumCpus = 0;
	INTEL_PT_CAPABILITIES ptCap = { 0 };
	NTSTATUS ntStatus = 0;

	dwNumCpus = KeQueryActiveProcessorCount(&curCpuAffinity);
	if (!g_pDrvData) return STATUS_INTERNAL_ERROR;
	if (dwCpuId >= dwNumCpus) return STATUS_INVALID_PARAMETER;
	PER_PROCESSOR_PT_DATA * lpProcPtData = &g_pDrvData->procData[dwCpuId];

	ntStatus = CheckIntelPtSupport(&ptCap);
	if (!NT_SUCCESS(ntStatus)) return ntStatus;

	// Set the default trace options if needed
	if (lpProcPtData->TraceOptions.All == 0) {
		lpProcPtData->TraceOptions.Fields.bTraceBranchPcks = TRUE;
		if (ptCap.bTopaOutput)
			lpProcPtData->TraceOptions.Fields.bUseTopa = TRUE;
		lpProcPtData->TraceOptions.Fields.bEnableRetCompression = TRUE;
	}
	lpProcPtData->TraceOptions.Fields.bInitialized = 1;
	return STATUS_SUCCESS;
}
#pragma endregion

#pragma region Trace Buffer memory management Code
/* BRIEF EXPLANATION HERE
 * What is the difference between AllocCpuPtBuffer/FreeCpuResources and AllocPtBuffer/FreePtBuffer???
 * The 2 functions perform more or less the same work BUT in different ways:
 * AllocCpuPtBuffer/FreeCpuResources verify if the ONLY buffer associated with the CPU is legal and mapped 
 * to some User-mode address space. THERE IS ONLY ONE BUFFER PER CPU for the driver
 *
 * AllocPtBuffer/FreePtBuffer doesn't suffer for this limitations and are used even from external kernel modules.
 * It's duty of the External module to decide what to do with the buffer descriptor.
 */

// Allocate a Trace buffer for a specific CPU
NTSTATUS AllocCpuPtBuffer(DWORD dwCpuId, QWORD qwSize, BOOLEAN bUseToPA)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;						// Returned NTSTATUS value
	INTEL_PT_CAPABILITIES ptCap = { 0 };					// Current processor capabilities
	PT_BUFFER_DESCRIPTOR * pPtNewBuffDesc = NULL;			// The NEW Buffer descriptor
	if (dwCpuId > KeQueryActiveProcessorCount(NULL)) return STATUS_INVALID_PARAMETER_3;

	PER_PROCESSOR_PT_DATA & perCpuData = g_pDrvData->procData[dwCpuId];
	ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);

	// Get this processor capabilities
	ntStatus = CheckIntelPtSupport(&ptCap);
	if (!NT_SUCCESS(ntStatus)) return ntStatus;

	if (bUseToPA && !(ptCap.bTopaOutput && ptCap.bTopaMultipleEntries))
		return STATUS_NOT_SUPPORTED;
	if (!bUseToPA && !ptCap.bSingleRangeSupport)
		return STATUS_NOT_SUPPORTED;
	if (perCpuData.curState >= PT_PROCESSOR_STATE_TRACING) return STATUS_INVALID_DEVICE_REQUEST;

	if (bUseToPA) {
		if (perCpuData.pPtBuffDesc && perCpuData.pPtBuffDesc->u.ToPA.lpTopaPhysAddr)
			ntStatus = FreeCpuResources(dwCpuId);
		if (!NT_SUCCESS(ntStatus)) return ntStatus;
		// Table of Physical Address usage
		ntStatus = AllocAndSetTopa(&pPtNewBuffDesc, qwSize);
		if (NT_SUCCESS(ntStatus))
			// Enable the default PMI handler
			pPtNewBuffDesc->bDefaultPmiSet = TRUE;
	} else 	{
		if (perCpuData.pPtBuffDesc && perCpuData.pPtBuffDesc->u.Simple.lpTraceBuffVa)
			ntStatus = FreeCpuResources(dwCpuId);
		if (!NT_SUCCESS(ntStatus)) return ntStatus;
		ntStatus = AllocPtBuffer(&pPtNewBuffDesc, qwSize, FALSE);
	}

	if (NT_SUCCESS(ntStatus))
		// Set the current descriptor as default one for current CPU
		perCpuData.pPtBuffDesc = pPtNewBuffDesc;
	else
		ExFreePool(pPtNewBuffDesc);

	return ntStatus;
}

// Free the resources used by a CPU
NTSTATUS FreeCpuResources(DWORD dwCpuId) {
	NTSTATUS ntStatus = STATUS_SUCCESS;
	DWORD dwCurProcId = 0, dwTargetPid = 0;					// Current and target Process ID
	BOOLEAN bExited = FALSE;								// True if the target process has already exited
	KIRQL kIrql = KeGetCurrentIrql();
	KAFFINITY curCpuAffinity = 0;
	DWORD dwNumCpus = 0;

	dwNumCpus = KeQueryActiveProcessorCount(&curCpuAffinity);
	if (dwCpuId >= dwNumCpus) return STATUS_INVALID_PARAMETER;
	PER_PROCESSOR_PT_DATA & perCpuData = g_pDrvData->procData[dwCpuId];
	if (perCpuData.curState >= PT_PROCESSOR_STATE_TRACING) return STATUS_INVALID_DEVICE_REQUEST;

	// Very important: Check the user-mode process here:
	if (perCpuData.lpUserVa) {
		dwCurProcId = (DWORD)PsGetCurrentProcessId();
		if (perCpuData.lpMappedProc)
			dwTargetPid = (DWORD)PsGetProcessId(perCpuData.lpMappedProc);

		bExited = PsGetProcessExitProcessCalled(perCpuData.lpMappedProc);

		if ((!dwTargetPid || (dwTargetPid == dwCurProcId) || bExited)  && kIrql <= APC_LEVEL) {
			// We can safely unmap the PT buffer here
			ntStatus = UnmapTraceBuffToUserVa(dwCpuId);
			if (!NT_SUCCESS(ntStatus)) {
				DbgPrint("[" DRV_NAME "] Error: Unable to unmap the trace buffer for process %i.\r\n", dwTargetPid);
				return ntStatus;
			}
		}
		else {
			DbgPrint("[" DRV_NAME "] Warning: Unable to free the the allocated physical memory for processor %i. The process with PID %i has still not unmapped the buffer. "
				"Base VA: 0x%llX, physical address: 0x%llX.\r\n", dwCpuId, dwTargetPid, perCpuData.lpUserVa, perCpuData.pPtBuffDesc ? perCpuData.pPtBuffDesc->u.Simple.lpTraceBuffPhysAddr : 0);
			return STATUS_CONTEXT_MISMATCH;
		}
		if (bExited) g_pDrvData->bManualAllocBuff = FALSE;
	}

	// Now finally release the buffer
	PT_BUFFER_DESCRIPTOR * ptBuffDesc = perCpuData.pPtBuffDesc;
	if (ptBuffDesc) {
		perCpuData.pPtBuffDesc = NULL;
		ntStatus = FreePtBuffer(ptBuffDesc);
	}
	return ntStatus;
}

// Allocate and set a buffer for Intel Processor Trace
NTSTATUS AllocPtBuffer(PT_BUFFER_DESCRIPTOR ** lppBuffDesc, QWORD qwSize, BOOLEAN bUseTopa) {
	PHYSICAL_ADDRESS MaxAddr; MaxAddr.QuadPart = -1ll;		// Maximum physical address
	PT_BUFFER_DESCRIPTOR * pBuffDesc = NULL;

	if (bUseTopa)
		return AllocAndSetTopa(lppBuffDesc, qwSize, TRUE);

	// Simple output range implementation
	LPVOID lpBuffVa = MmAllocateContiguousMemory(qwSize, MaxAddr);
	if (!lpBuffVa) return STATUS_INSUFFICIENT_RESOURCES;
	RtlZeroMemory(lpBuffVa, qwSize);

	// Grab the physical address:
	PHYSICAL_ADDRESS physAddr = MmGetPhysicalAddress(lpBuffVa);

	// Allocate the relative MDL
	PMDL pPtMdl = IoAllocateMdl(lpBuffVa, (ULONG)qwSize, FALSE, FALSE, NULL);
	if (pPtMdl && lppBuffDesc) {
		pBuffDesc = (PT_BUFFER_DESCRIPTOR*)ExAllocatePoolWithTag(NonPagedPool, sizeof(PT_BUFFER_DESCRIPTOR), MEMTAG);
		RtlZeroMemory(pBuffDesc, sizeof(PT_BUFFER_DESCRIPTOR));
		pBuffDesc->pTraceMdl = pPtMdl;
		pBuffDesc->u.Simple.lpTraceBuffVa = lpBuffVa;
		pBuffDesc->qwBuffSize = qwSize;
		pBuffDesc->u.Simple.lpTraceBuffPhysAddr = (ULONG_PTR)physAddr.QuadPart;
		*lppBuffDesc = pBuffDesc;
	}
	return STATUS_SUCCESS;
}

// Free a PT trace buffer (use with caution, avoid BSOD please)
NTSTATUS FreePtBuffer(PT_BUFFER_DESCRIPTOR * ptBuffDesc) {
	//ULONG dwCurCpu = 0;										// Current CPU number
#ifdef _DEBUG
	KIRQL kIrql = KeGetCurrentIrql();
	ASSERT(kIrql <= DISPATCH_LEVEL);
#endif
	if (!ptBuffDesc) return STATUS_INVALID_PARAMETER;
	if (ptBuffDesc->qwBuffSize < PAGE_SIZE) return STATUS_INVALID_BUFFER_SIZE;

	if (ptBuffDesc->bUseTopa) {
		// Free the ToPA table
		if (ptBuffDesc->u.ToPA.lpTopaVa) {
			MmFreeContiguousMemory(ptBuffDesc->u.ToPA.lpTopaVa);
			ptBuffDesc->u.ToPA.lpTopaVa = NULL;
			ptBuffDesc->u.ToPA.lpTopaPhysAddr = NULL;
		}

		// Free the actual physical memory
		if (ptBuffDesc->pTraceMdl) {
			// Free the used pages 
			MmFreePagesFromMdl(ptBuffDesc->pTraceMdl);
			ExFreePool(ptBuffDesc->pTraceMdl);
			ptBuffDesc->pTraceMdl = NULL;
		}
	}
	else {
		// Free the simple output region
		if (ptBuffDesc->u.Simple.lpTraceBuffVa)
			MmFreeContiguousMemory(ptBuffDesc->u.Simple.lpTraceBuffVa);

		if (ptBuffDesc->pTraceMdl) {
			IoFreeMdl(ptBuffDesc->pTraceMdl);
			ptBuffDesc->pTraceMdl = NULL;
		}

		ptBuffDesc->u.Simple.lpTraceBuffVa = NULL;
		ptBuffDesc->u.Simple.lpTraceBuffPhysAddr = NULL;
	}

	// Free the data structure itself
	ExFreePool(ptBuffDesc);
	return STATUS_SUCCESS;
}

// Allocate and set a ToPA (with the Windows API)
NTSTATUS AllocAndSetTopa(PT_BUFFER_DESCRIPTOR ** lppBuffDesc, QWORD qwReqBuffSize, BOOLEAN bSetPmiAndStop)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;						// Returned NTSTATUS
	DWORD dwNumEntriesInMdl = 0;							// Number of entries in the MDL
	DWORD dwTopaSize = 0;									// Size of the ToPa
	TOPA_TABLE_ENTRY * pTopa = NULL;						// Pointer to the ToPa
	PHYSICAL_ADDRESS highPhysAddr = { (ULONG)-1, -1 };		// Highest physical memory address
	PHYSICAL_ADDRESS lowPhysAddr = { 0i64 };				// Lowest physical memory address
	PHYSICAL_ADDRESS topaPhysAddr = { 0i64 };				// The ToPA physical address
	PMDL pTraceBuffMdl = NULL;
	PT_BUFFER_DESCRIPTOR * pBuffDesc = NULL;

	ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);

	if (qwReqBuffSize % PAGE_SIZE) return STATUS_INVALID_PARAMETER_2;

	// Allocate the needed physical memory
	pTraceBuffMdl = MmAllocatePagesForMdlEx(lowPhysAddr, highPhysAddr, lowPhysAddr, (SIZE_T)qwReqBuffSize + PAGE_SIZE, MmCached, MM_ALLOCATE_FULLY_REQUIRED);
	if (!pTraceBuffMdl) return STATUS_INSUFFICIENT_RESOURCES;

	// Get the PFN array
	dwNumEntriesInMdl = ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(pTraceBuffMdl), MmGetMdlByteCount(pTraceBuffMdl));
	PPFN_NUMBER pfnArray = MmGetMdlPfnArray(pTraceBuffMdl);

	// Allocate the ToPA
	dwTopaSize = (dwNumEntriesInMdl + 1) * 8;
	dwTopaSize = ROUND_TO_PAGES(dwTopaSize);
	pTopa = (TOPA_TABLE_ENTRY *)MmAllocateContiguousMemory(dwTopaSize, highPhysAddr);
	topaPhysAddr = MmGetPhysicalAddress(pTopa);
	if (!pTopa) {
		MmFreePagesFromMdl(pTraceBuffMdl);
		ExFreePool(pTraceBuffMdl);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory(pTopa, dwTopaSize);

	// Create the ToPA 
	for (DWORD i = 0; i < dwNumEntriesInMdl; i++)  {
		pTopa[i].Fields.BaseAddr = pfnArray[i];				// Pfn array contains the PFN offset, not the actual Physical address
		pTopa[i].Fields.Size = 0;		// Encoding: 0 - 4K pages
	} 

	// LVT interrupt entry (if any)
	if (bSetPmiAndStop) {
		pTopa[dwNumEntriesInMdl - 1].Fields.Int = 1;
		pTopa[dwNumEntriesInMdl - 1].Fields.Stop = 1;
	}

	// END entries 
	RtlZeroMemory(&pTopa[dwNumEntriesInMdl], sizeof(TOPA_TABLE_ENTRY));
	pTopa[dwNumEntriesInMdl].Fields.BaseAddr = (ULONG_PTR)(topaPhysAddr.QuadPart >> 0xC);
	pTopa[dwNumEntriesInMdl].Fields.End = 1;

	// Now create the descriptor and set the ToPA data
	if (lppBuffDesc) {
		pBuffDesc = (PT_BUFFER_DESCRIPTOR*)ExAllocatePoolWithTag(NonPagedPool, sizeof(PT_BUFFER_DESCRIPTOR), MEMTAG);
		RtlZeroMemory(pBuffDesc, sizeof(PT_BUFFER_DESCRIPTOR));
		pBuffDesc->bUseTopa = TRUE;
		pBuffDesc->u.ToPA.lpTopaPhysAddr = (ULONG_PTR)topaPhysAddr.QuadPart;
		pBuffDesc->u.ToPA.lpTopaVa = pTopa;
		pBuffDesc->qwBuffSize = qwReqBuffSize;
		pBuffDesc->pTraceMdl = pTraceBuffMdl;
		pBuffDesc->bDefaultPmiSet = bSetPmiAndStop;
		*lppBuffDesc = pBuffDesc;
	}
	return ntStatus;
}

// Get if the PT buffer is allocated and valid for a particular processor
QWORD IsPtBufferAllocatedAndValid(DWORD dwCpuId, BOOLEAN bTestUserVa) {
	PER_PROCESSOR_PT_DATA * pPerCpuData = NULL;
	if (dwCpuId > KeQueryActiveProcessorCount(NULL)) return FALSE;
	
	pPerCpuData = &g_pDrvData->procData[dwCpuId];
	if (bTestUserVa)
		if (!pPerCpuData->lpUserVa) return 0;

	if (!(pPerCpuData->pPtBuffDesc && pPerCpuData->pPtBuffDesc->u.Simple.lpTraceBuffPhysAddr))
		return 0;

	// Return the size of the buffer
	return pPerCpuData->pPtBuffDesc->qwBuffSize;
}

// Clear the PT buffer
NTSTATUS ClearCpuPtBuffer(DWORD dwCpuId) {
	PER_PROCESSOR_PT_DATA * pPerCpuData = NULL;
	LPVOID lpKernelVa = NULL;							// The kernel VA
	if (dwCpuId > KeQueryActiveProcessorCount(NULL)) return FALSE;
	pPerCpuData = &g_pDrvData->procData[dwCpuId];

	//DbgBreak();
	if (!pPerCpuData->pPtBuffDesc || !pPerCpuData->pPtBuffDesc->u.Simple.lpTraceBuffPhysAddr)
		return STATUS_NOT_FOUND;

	if (!pPerCpuData->pPtBuffDesc->pTraceMdl)
		return STATUS_INTERNAL_ERROR;

	if (!pPerCpuData->pPtBuffDesc->lpKernelVa) {
		// We do not want to map the MDL in Kernel Address space, try to use the User-mode VA
		if (pPerCpuData->lpUserVa && PsGetCurrentProcess() == pPerCpuData->lpMappedProc) {
			RtlZeroMemory(pPerCpuData->lpUserVa, (DWORD)pPerCpuData->pPtBuffDesc->qwBuffSize);
			return STATUS_SUCCESS;
		} else {
			DrvDbgPrint("[" DRV_NAME "] Warning, the ClearCpuPtBuffer routine is re-mapping the PT buffer (size 0x%08X) for CPU %i in Kernel mode. "
				"This could be very time consuming. Are you sure that is needed?\r\n", (DWORD)pPerCpuData->pPtBuffDesc->qwBuffSize, dwCpuId);
			lpKernelVa = MmGetSystemAddressForMdlSafe(pPerCpuData->pPtBuffDesc->pTraceMdl, NormalPagePriority);
			if (!lpKernelVa) return STATUS_INTERNAL_ERROR;
			RtlZeroMemory(lpKernelVa, (DWORD)pPerCpuData->pPtBuffDesc->qwBuffSize);
			MmUnmapLockedPages(lpKernelVa, pPerCpuData->pPtBuffDesc->pTraceMdl);
		}
	}
	return STATUS_SUCCESS;

}

#pragma code_seg()

// Map a physical page buffer to a User-mode process
// Only one PT buffer per CPU supported in Usermode
NTSTATUS MapTracePhysBuffToUserVa(DWORD dwCpuId) 
{
	PMDL pMdl = NULL;									// The new MDL describing the physical memory
	LPVOID lpUserBuff = NULL;							// The user-mode accessible buffer
	PEPROCESS pCurProc = NULL;							// The current EPROCESS target
	if (!g_pDrvData->procData[dwCpuId].pPtBuffDesc) return STATUS_NO_MEMORY;
	PT_BUFFER_DESCRIPTOR * pPtBuffDesc = g_pDrvData->procData[dwCpuId].pPtBuffDesc;

	// This should be executed at IRQL level <= APC for MmMapLockedPagesSpecifyCache
	ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

	if (!pPtBuffDesc->u.Simple.lpTraceBuffVa || !pPtBuffDesc->qwBuffSize)
		return STATUS_INVALID_PARAMETER;

	if (pPtBuffDesc->bUseTopa)
	{
		// Table of Physical Address Implementation
		pMdl = pPtBuffDesc->pTraceMdl;
		if (!pMdl) return STATUS_INTERNAL_ERROR;
	}
	else 
	{
		// Simple-output scheme implementation
		if (!pPtBuffDesc->u.Simple.lpTraceBuffPhysAddr)
		{
			PHYSICAL_ADDRESS physAddr = MmGetPhysicalAddress(pPtBuffDesc->u.Simple.lpTraceBuffVa);
			pPtBuffDesc->u.Simple.lpTraceBuffPhysAddr = (ULONG_PTR)physAddr.QuadPart;
		}

		if (pPtBuffDesc->pTraceMdl)
			pMdl = pPtBuffDesc->pTraceMdl;
		else
			pMdl = IoAllocateMdl(pPtBuffDesc->u.Simple.lpTraceBuffVa, (ULONG)pPtBuffDesc->qwBuffSize, FALSE, FALSE, NULL);

		// Update this MDL to describe the underlying already-locked physical pages
		MmBuildMdlForNonPagedPool(pMdl);	// do this only here and nowhere else

		pPtBuffDesc->pTraceMdl = pMdl;
		if (!pMdl) return STATUS_INSUFFICIENT_RESOURCES;
	}

	pCurProc = PsGetCurrentProcess();

	// Now map the MDL to the current user-mode process 
	// If AccessMode is Usermode, the caller must be running at IRQL <= APC_LEVEL
	lpUserBuff = MmMapLockedPagesSpecifyCache(pMdl, UserMode, MmCached, NULL, FALSE, NormalPagePriority);				

	if (lpUserBuff) 
	{
		g_pDrvData->procData[dwCpuId].lpUserVa = lpUserBuff;
		g_pDrvData->procData[dwCpuId].lpMappedProc = pCurProc;
		ObReferenceObject(pCurProc);			// prevent process termination without freeing the resource
		return STATUS_SUCCESS;
	}
	else
		return STATUS_UNSUCCESSFUL;
}

// Unmap the memory-mapped physical memory from usermode
// Only one PT buffer per CPU supported in USER-mode
NTSTATUS UnmapTraceBuffToUserVa(DWORD dwCpuId) 
{
	PEPROCESS pCurProc = NULL;						// The current EPROCESS target
	PER_PROCESSOR_PT_DATA * pPerCpuData = &g_pDrvData->procData[dwCpuId];
	pCurProc = PsGetCurrentProcess();

	if (pPerCpuData->lpUserVa) 
	{
		BOOLEAN bExited = FALSE;
		PEPROCESS pMappedProc = pPerCpuData->lpMappedProc;

		if (!pPerCpuData->pPtBuffDesc || !pPerCpuData->pPtBuffDesc->pTraceMdl)
			return STATUS_INTERNAL_ERROR;	// THIS SHOULD NEVER HAPPEN

		// Get if the mapped process is already terminated
		if (pMappedProc) 
			bExited = PsGetProcessExitProcessCalled(pMappedProc);

		if (pMappedProc && (bExited == FALSE) && (pCurProc != pMappedProc))
			return STATUS_CONTEXT_MISMATCH;

		if (!bExited)
			MmUnmapLockedPages(pPerCpuData->lpUserVa, pPerCpuData->pPtBuffDesc->pTraceMdl);
			
		pPerCpuData->lpUserVa = NULL;
		pPerCpuData->lpMappedProc = NULL;
		ObDereferenceObject(pMappedProc);
	}
	return STATUS_SUCCESS;
}
#pragma endregion

#pragma region PMI Interrupt management code
#pragma code_seg(".nonpaged")
// Register the LVT (Local Vector Table) PMI interrupt
NTSTATUS RegisterPmiInterrupt() 
{
	NTSTATUS ntStatus = STATUS_SUCCESS;						// Returned NTSTATUS
	PMIHANDLER pNewPmiHandler = NULL;
	//PMIHANDLER pOldPmiHandler = NULL; 					// The old PMI handler (currently not implemented)

	BYTE lpBuff[0x20] = { 0 };
	//XXX ULONG dwBytesIo = 0;								// Number of I/O bytes

	// First of all we need to search for HalpLocalApic symbol
	MSR_IA32_APIC_BASE_DESC ApicBase = { 0 };				// In Multi-processors systems this address could change
	ApicBase.All = __readmsr(MSR_IA32_APIC_BASE);			// In Windows systems all the processors LVT are mapped at the same physical address

	if (!ApicBase.Fields.EXTD) 	{
		LPDWORD lpdwApicBase = NULL;
		PHYSICAL_ADDRESS apicPhys = { 0 };

		apicPhys.QuadPart = ApicBase.All & (~0xFFFi64);
		lpdwApicBase = (LPDWORD)MmMapIoSpace(apicPhys, 0x1000, MmNonCached);

		if (lpdwApicBase) 
		{ 
			DrvDbgPrint("[" DRV_NAME "] Successfully mapped the local APIC to 0x%llX.\r\n", lpdwApicBase);
			g_pDrvData->lpApicBase = lpdwApicBase;
		} else
			return STATUS_NOT_SUPPORTED;

		// Now read the entry 0x340 (not really needed)
		g_pDrvData->pmiVectDesc.All = lpdwApicBase[0x340 / 4];
	}
	else {
		// Current system uses x2APIC mode, no need to map anything
		g_pDrvData->bCpuX2ApicMode = TRUE;
	}

	// The following functions must be stored in HalDispatchTable 
	// TODO: Find a way to proper get the old PMI interrupt handler routine. Search inside the HAL code?
	// ntStatus = HalQuerySystemInformation(HalProfileSourceInformation, COUNTOF(lpBuff), (LPVOID)lpBuff, &dwBytesIo);		

	// Now set the new PMI handler, WARNING: we do not save and restore old handler
	pNewPmiHandler = IntelPtPmiHandler;
	ntStatus = HalSetSystemInformation(HalProfileSourceInterruptHandler, sizeof(PMIHANDLER), (LPVOID)&pNewPmiHandler);
	if (NT_SUCCESS(ntStatus))  {
		DrvDbgPrint("[" DRV_NAME "] Successfully registered system PMI handler to function 0x%llX.\r\n", (LPVOID)pNewPmiHandler);
		g_pDrvData->bPmiInstalled = TRUE;
	}

	return ntStatus;
}

// Unregister and remove the LVT PMI interrupt 
NTSTATUS UnregisterPmiInterrupt()
{
	NTSTATUS ntStatus = STATUS_SUCCESS;						// Returned NTSTATUS
	PMIHANDLER pOldPmiHandler = g_pDrvData->pOldPmiHandler;	// The old PMI handler
		
	// This is currently not restoring old PMI handler since we don't know how to retrieve it, just nulling it out
	ntStatus = HalSetSystemInformation(HalProfileSourceInterruptHandler, sizeof(PMIHANDLER), (LPVOID)&pOldPmiHandler);

	if (NT_SUCCESS(ntStatus)) 
	{
		g_pDrvData->bPmiInstalled = FALSE;
		if (g_pDrvData->lpApicBase)
			MmUnmapIoSpace(g_pDrvData->lpApicBase, 0x1000);
	}

	return ntStatus;
}

// The PMI LVT handler routine (Warning! This should run at very high IRQL)
VOID IntelPtPmiHandler(PKTRAP_FRAME pTrapFrame) 
{
	PKDPC pProcDpc = NULL;									// This processor DPC
	MSR_IA32_PERF_GLOBAL_STATUS_DESC pmiDesc = { 0 };		// The PMI Interrupt descriptor
	LVT_Entry perfMonDesc = { 0 };							// The LVT Performance Monitoring register
	LPDWORD lpdwApicBase = g_pDrvData->lpApicBase;			// The LVT Apic I/O space base address (if not in x2Apic mode)
	DWORD dwCurCpu = 0;
	PER_PROCESSOR_PT_DATA * pCurCpuData = NULL;				// The Per-Processor data structure
	PT_BUFFER_DESCRIPTOR * ptBuffDesc = NULL;				// The PT Buffer descriptor
	UNREFERENCED_PARAMETER(pTrapFrame);

	ASSERT(KeGetCurrentIrql() > DISPATCH_LEVEL);

	dwCurCpu = KeGetCurrentProcessorNumber();
	pCurCpuData = &g_pDrvData->procData[dwCurCpu];
	ptBuffDesc = g_pDrvData->procData[dwCurCpu].pPtBuffDesc;

	// Check if the interrupt is mine
	pmiDesc.All = __readmsr(MSR_IA32_PERF_GLOBAL_STATUS);
	if (pmiDesc.Fields.TraceToPAPMI == 0)
		return;

	// Pause the Tracing. From Intel's Manual: "Software can minimize the likelihood of the second case by clearing
	//	TraceEn at the beginning of the PMI handler"
	PauseResumeTrace(TRUE);

	// Check the Intel PT status
	MSR_RTIT_STATUS_DESC traceStatusDesc = { 0 };
	traceStatusDesc.All = __readmsr(MSR_IA32_RTIT_STATUS);
	if (traceStatusDesc.Fields.Error)
		DrvDbgPrint("[" DRV_NAME "] Warning: Intel PT Pmi has raised, but the PT Status register indicates an error!\r\n");

	if (ptBuffDesc && ptBuffDesc->bDefaultPmiSet) {
		// Queue a DPC only if the Default PMI handler is set
		ptBuffDesc->bBuffIsFull = TRUE;

		// The IRQL is too high so we use DPC 
		pProcDpc = (PKDPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KDPC), MEMTAG);
		KeInitializeDpc(pProcDpc, IntelPmiDpc, NULL);
		KeSetTargetProcessorDpc(pProcDpc, (CCHAR)dwCurCpu);
		KeInsertQueueDpc(pProcDpc, (LPVOID)dwCurCpu, NULL);
	}

	MSR_IA32_PERF_GLOBAL_OVF_CTRL_DESC globalResetMsrDesc = { 0 };
	// Set the PMI Reset: Once the ToPA PMI handler has serviced the relevant buffer, writing 1 to bit 55 of the MSR at 390H
	// (IA32_GLOBAL_STATUS_RESET)clears IA32_PERF_GLOBAL_STATUS.TraceToPAPMI.
	globalResetMsrDesc.Fields.ClrTraceToPA_PMI = 1;
	__writemsr(MSR_IA32_PERF_GLOBAL_OVF_CTRL, globalResetMsrDesc.All);

	// Call the External PMI handler (if any)
	if (g_pDrvData->pCustomPmiIsr) {
		g_pDrvData->pCustomPmiIsr(dwCurCpu, ptBuffDesc);
	}

	// Re-enable the PMI
	if (g_pDrvData->bCpuX2ApicMode) 
	{
		// Check Intel Manuals, Vol. 3A section 10-37
		ULONGLONG perfMonEntry = __readmsr(MSR_IA32_X2APIC_LVT_PMI);
		perfMonDesc.All = (ULONG)perfMonEntry;
		perfMonDesc.Fields.Masked = 0;
		perfMonEntry = (ULONGLONG)perfMonDesc.All;
		__writemsr(MSR_IA32_X2APIC_LVT_PMI, perfMonEntry);
	} else {
		if (!lpdwApicBase)
			// XXX: Not sure how to continue, No MmMapIoSpace at this IRQL (should not happen)
			KeBugCheckEx(INTERRUPT_EXCEPTION_NOT_HANDLED, NULL, NULL, NULL, NULL);
		perfMonDesc.All = lpdwApicBase[0x340 / 4];
		perfMonDesc.Fields.Masked = 0;
		lpdwApicBase[0x340 / 4] = perfMonDesc.All;
	}
};

// The Kernel mode PMI callback APC
VOID ApcKernelRoutine(PKAPC pApc, PKNORMAL_ROUTINE *NormalRoutine, PVOID *NormalContext, PVOID *SystemArgument1, PVOID *SystemArgument2) {
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
	// ??? What to do here?? 
	// Simple only free the APC structure
	if (pApc) ExFreePool(pApc);
}

// Check and clean the dead PMI callbacks
NTSTATUS CheckUserPmiCallbackList() {
	KIRQL kOldIrql = KeGetCurrentIrql();
	PLIST_ENTRY pNextEntry = NULL, pCurEntry = NULL;
	if (IsListEmpty(&g_pDrvData->userCallbackList)) return STATUS_NOT_FOUND;

	KeAcquireSpinLock(&g_pDrvData->userCallbackListLock, &kOldIrql);
	pNextEntry = g_pDrvData->userCallbackList.Flink;
	while (pNextEntry != &g_pDrvData->userCallbackList) {
		PPMI_USER_CALLBACK_DESC pCurPmiDesc = NULL;
		pCurEntry = pNextEntry;
		pCurPmiDesc = CONTAINING_RECORD(pCurEntry, PMI_USER_CALLBACK_DESC, entry);
		if (PsIsThreadTerminating(pCurPmiDesc->pTargetThread)) {
			// Auto delete this damn entry
			pNextEntry = pCurEntry->Flink;
			RemoveEntryList(pCurEntry);
			DrvDbgPrint("[" DRV_NAME "] Successfully removed dead user-mode PMI Callback (Thread ID: %i, Address: 0x%llX).\r\n",
				PsGetThreadId(pCurPmiDesc->pTargetThread), pCurPmiDesc->lpUserAddress);
			ObDereferenceObject(pCurPmiDesc->pTargetThread);
			ExFreePool(pCurPmiDesc);
			continue;
		}
		pNextEntry = pCurEntry->Flink;
	}
	KeReleaseSpinLock(&g_pDrvData->userCallbackListLock, kOldIrql);
	return STATUS_SUCCESS;
}

// Clear the user PMI Callback list and free the memory
NTSTATUS ClearAndFreePmiCallbackList() {
	KIRQL kOldIrql = KeGetCurrentIrql();
	PLIST_ENTRY pCurEntry = NULL;
	PPMI_USER_CALLBACK_DESC pCurCallback = NULL;
	if (IsListEmpty(&g_pDrvData->userCallbackList)) return  STATUS_NOT_FOUND;

	KeAcquireSpinLock(&g_pDrvData->userCallbackListLock, &kOldIrql);
	while (TRUE) {
		pCurEntry = RemoveHeadList(&g_pDrvData->userCallbackList);
		if (pCurEntry == &g_pDrvData->userCallbackList) break;
		pCurCallback = CONTAINING_RECORD(pCurEntry, PMI_USER_CALLBACK_DESC, entry);
		ObDereferenceObject(pCurCallback->pTargetThread);
		ExFreePool(pCurCallback);
	}
	KeReleaseSpinLock(&g_pDrvData->userCallbackListLock, kOldIrql);
	return STATUS_SUCCESS;
}

// The PMI DPC routine
VOID IntelPmiDpc(struct _KDPC *pDpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2) 
{
	UNREFERENCED_PARAMETER(DeferredContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
	DWORD dwCpuNum = KeGetCurrentProcessorNumber();			// This CPU number
	ULONGLONG targetCr3 = 0ui64;							// The target CR3 register value
	KIRQL kOldIrql = KeGetCurrentIrql();
	
	// A quick integrity check
	ASSERT(dwCpuNum == (DWORD)SystemArgument1);

	PER_PROCESSOR_PT_DATA & curCpuData = g_pDrvData->procData[dwCpuNum];	// This processor DPC data
		
	if (curCpuData.lpTargetProc) 
	{
		// Verify that the Target CR3 still matches
		targetCr3 = ((ULONGLONG*)curCpuData.lpTargetProc)[5];
		ASSERT(targetCr3 == curCpuData.lpTargetProcCr3);

		// queue work item to suspend the target process 
		PWORK_QUEUE_ITEM pWorkItem = (PWORK_QUEUE_ITEM)ExAllocatePoolWithTag(NonPagedPool, sizeof(WORK_QUEUE_ITEM) + sizeof(LPVOID), MEMTAG);
		if (pWorkItem) 
		{
			ExInitializeWorkItem(pWorkItem, IntelPmiWorkItem, (PVOID)pWorkItem);
			*((LPVOID*)(LPBYTE(pWorkItem) + sizeof(WORK_QUEUE_ITEM))) = (LPVOID)curCpuData.lpTargetProc;
			ExQueueWorkItem(pWorkItem, CriticalWorkQueue);
		}
	}

	// Set the Buffer full Event (if any)
	if (g_pDrvData->pPmiEvent)
		KeSetEvent(g_pDrvData->pPmiEvent, IO_NO_INCREMENT, FALSE);

	// Queue the User-mode APC and call the User-mode Callbacks
	if (!IsListEmpty(&g_pDrvData->userCallbackList)) {
		PLIST_ENTRY pNextEntry = NULL,				// Next entry
			pCurEntry = NULL;						// Current entry
		PRKAPC pkApc = NULL;
		
		KeAcquireSpinLock(&g_pDrvData->userCallbackListLock, &kOldIrql);
		pNextEntry = g_pDrvData->userCallbackList.Flink;
		while (pNextEntry != &g_pDrvData->userCallbackList) {
			PPMI_USER_CALLBACK_DESC pCurPmiDesc = NULL;
			pCurEntry = pNextEntry;
			pCurPmiDesc = CONTAINING_RECORD(pCurEntry, PMI_USER_CALLBACK_DESC, entry);
			if ((1i64 << dwCpuNum) & pCurPmiDesc->kAffinity) {
				// Found a valid User-mode callback, verify it and call it
				if (PsIsThreadTerminating(pCurPmiDesc->pTargetThread)) {
					// Auto delete this damn entry
					pNextEntry = pCurEntry->Flink;
					RemoveEntryList(pCurEntry);
					ObDereferenceObject(pCurPmiDesc->pTargetThread);
					ExFreePool(pCurPmiDesc);
					continue;
				}
				pkApc = (PRKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), MEMTAG);
				KeInitializeApc(pkApc, (PRKTHREAD)pCurPmiDesc->pTargetThread, CurrentApcEnvironment, &ApcKernelRoutine, NULL,
					(PKNORMAL_ROUTINE)pCurPmiDesc->lpUserAddress, UserMode, (PVOID)dwCpuNum);
				KeInsertQueueApc(pkApc, (LPVOID)curCpuData.lpUserVa, (LPVOID)curCpuData.pPtBuffDesc->qwBuffSize, IO_NO_INCREMENT);
			}
			pNextEntry = pCurEntry->Flink;
		}
		KeReleaseSpinLock(&g_pDrvData->userCallbackListLock, kOldIrql);
	}

	ExFreePool(pDpc);
}

// The PMI Work Item
VOID IntelPmiWorkItem(PVOID Parameter) 
{
	PWORK_QUEUE_ITEM pWorkItem = NULL;					// This work item 
	PEPROCESS pTargetProc = NULL;						// The Target Process
	NTSTATUS ntStatus = STATUS_ABANDONED;				// The returned NTSTATUS 
	DWORD dwProcId = 0;									// The target process ID

	if (!Parameter) return;
	pWorkItem = (PWORK_QUEUE_ITEM)Parameter;
	pTargetProc = *(PEPROCESS*)((LPBYTE)Parameter + sizeof(WORK_QUEUE_ITEM));
	dwProcId = (DWORD)PsGetProcessId(pTargetProc);

	ntStatus = PsSuspendProcess(pTargetProc);
	if (NT_SUCCESS(ntStatus))
		DrvDbgPrint("[" DRV_NAME "] Successfully suspended process ID: %i.\r\n", dwProcId);

	ExFreePool(pWorkItem);
}
#pragma code_seg()
#pragma endregion