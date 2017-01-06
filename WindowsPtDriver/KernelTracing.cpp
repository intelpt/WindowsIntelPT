/**********************************************************************
 *  Windows Intel Processor Trace (PT) Driver
 * 	Filename: KernelTracing.cpp
 *	Implement the exported functions needed for Kernel Tracing
 *	Last revision: 01/06/2016
 *
 *  Copyright© 2016 Andrea Allievi, Richard Johnson 
 * 	Microsoft Ltd & TALOS Research and Intelligence Group
 *	All right reserved
 **********************************************************************/
#include "stdafx.h"
#include "IntelPt.h"
#include "DriverEntry.h"
#include "KernelTracing.h"


// Allocate the buffer needed for kernel tracing
NTSTATUS IntelPtAllocBuffer(PPT_BUFFER_DESCRIPTOR * ppBuffDesc, QWORD qwSize, BOOLEAN bUseTopa, BOOLEAN bSetStdPmi) {
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PPT_BUFFER_DESCRIPTOR ptBuffDesc = { 0 };

	if (bUseTopa)
		ntStatus = AllocAndSetTopa(&ptBuffDesc, qwSize, bSetStdPmi);
	else
		ntStatus = AllocPtBuffer(&ptBuffDesc, qwSize, FALSE);

	if (NT_SUCCESS(ntStatus)) 
		if (ppBuffDesc) *ppBuffDesc = ptBuffDesc;
	
	return ntStatus;
}

// Add a PMI interrupt for a page in the ToPA
NTSTATUS IntelPtAddBufferPmi(PT_BUFFER_DESCRIPTOR * pBuffDesc, QWORD qwOffset) {
	QWORD qwEntryOffset = (qwOffset / PAGE_SIZE);
	TOPA_TABLE_ENTRY * pCurTopaEntry = NULL;
	if (!pBuffDesc) return STATUS_INVALID_PARAMETER;
	if (!pBuffDesc->bUseTopa || !pBuffDesc->u.ToPA.lpTopaVa) return STATUS_INVALID_PARAMETER_1;

	// Calculate and get the current ToPA entry:
	pCurTopaEntry = (TOPA_TABLE_ENTRY*)((LPBYTE)pBuffDesc->u.ToPA.lpTopaVa + (qwEntryOffset * sizeof(TOPA_TABLE_ENTRY)));
	pCurTopaEntry->Fields.Int = 1;
	return STATUS_SUCCESS;
}

// Remove a PMI interrupt from a page in the ToPA
NTSTATUS IntelPtRemoveBufferPmi(PT_BUFFER_DESCRIPTOR * pBuffDesc, QWORD qwOffset) {
	QWORD qwEntryOffset = (qwOffset / PAGE_SIZE);
	TOPA_TABLE_ENTRY * pCurTopaEntry = NULL;
	if (!pBuffDesc) return STATUS_INVALID_PARAMETER;
	if (!pBuffDesc->bUseTopa || !pBuffDesc->u.ToPA.lpTopaVa) return STATUS_INVALID_PARAMETER_1;
	// Calculate and get the current ToPA entry:
	pCurTopaEntry = (TOPA_TABLE_ENTRY*)((LPBYTE)pBuffDesc->u.ToPA.lpTopaVa + (qwEntryOffset * sizeof(TOPA_TABLE_ENTRY)));
	pCurTopaEntry->Fields.Int = 0;
	return STATUS_SUCCESS;
}

// Delete the previous registered Intel PT PMI handler routine
NTSTATUS IntelPtRemovePmiHandler(INTELPT_PMI_HANDLER pCustomPmiHandler) {
	if (g_pDrvData->pCustomPmiIsr != pCustomPmiHandler) return STATUS_NOT_FOUND;
	else g_pDrvData->pCustomPmiIsr = NULL;
	return STATUS_SUCCESS;
}

// Register a PMI handler for ALL processor
NTSTATUS IntelPtRegisterPmiHandler(INTELPT_PMI_HANDLER pCustomPmiHandler) {
	if (g_pDrvData->pCustomPmiIsr) return STATUS_ALREADY_REGISTERED;
	g_pDrvData->pCustomPmiIsr = pCustomPmiHandler;
	return STATUS_SUCCESS;
}

// Start the Kernel tracing for current processor
NTSTATUS IntelPtStartTracing(PT_TRACE_DESC traceDesc, PT_BUFFER_DESCRIPTOR * pBuffDesc) {
	return StartCpuTrace(traceDesc, pBuffDesc);
}

// Stop the Tracing 
VOID IntelPtStopTrace() {
	DWORD dwCurCpuId = KeGetCurrentProcessorNumber();
	StopAndDisablePt();
	// Do not forget to do the following:
	// We are using external buffer here, it is not our duty to clean-up
	if (g_pDrvData) g_pDrvData->procData[dwCurCpuId].pPtBuffDesc = NULL;		
}

// Set/Get the Trace options for current CPU
NTSTATUS IntelPtSetOptions(TRACE_OPTIONS opts) {
	DWORD dwCurCpuId = KeGetCurrentProcessorNumber();
	NTSTATUS retStatus = SetTraceOptions(dwCurCpuId, opts);
	return retStatus;
}

TRACE_OPTIONS IntelPtGetOptions() {
	NTSTATUS ntStatus = STATUS_SUCCESS;
	TRACE_OPTIONS opts = { 0 };
	DWORD dwCurCpuId = KeGetCurrentProcessorNumber();
	ntStatus = GetTraceOptions(dwCurCpuId, &opts);
	return opts;
}
