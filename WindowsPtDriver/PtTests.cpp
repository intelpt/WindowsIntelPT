/**********************************************************************
 *  Windows Intel Processor Trace (PT) Driver
 * 	Filename: PtTests.cpp
 *	Implements some tests and use cases, especially for kernel tracing
 *	Last revision: 01/06/2016
 *
 *  Copyright© 2016 Andrea Allievi, Richard Johnson 
 * 	Microsoft Ltd & TALOS Research and Intelligence Group
 *	All right reserved
 **********************************************************************/
#include "stdafx.h"
#include "IntelPt.h"
#include "UndocNt.h"
#include "KernelTracing.h"
#include "Ntstrsafe.h"

#ifdef _DEBUG
// Find a Kernel module in memory using documented method
NTSTATUS GetKernelModule(LPTSTR lpName, SYSTEM_MODULE_INFORMATION * pSysModuleDesc);

struct {
	PPT_BUFFER_DESCRIPTOR pBuffDesc;
	KEVENT workItemEvt;
	NTSTATUS workItmStatus;
	BOOLEAN bKernelExcRaised;
} g_testData = { 0 };

int DriverExcFilter(DWORD excCode, struct _EXCEPTION_POINTERS *ep, LPTSTR lpDrvFileName) {
	// Process here the exception and continue the execution if possible
	NTSTATUS ntStatus = 0;
	PT_TRACE_DESC ptDesc = { 0 };
	SYSTEM_MODULE_INFORMATION sysModInfo = { 0 };
	UNREFERENCED_PARAMETER(excCode);
	
	// Search the actual loaded module
	ntStatus = GetKernelModule(lpDrvFileName, &sysModInfo);
	if (!NT_SUCCESS(ntStatus))
		return EXCEPTION_EXECUTE_HANDLER;

	// Modify the guilty opcode in a NOP
	ULONG_PTR lpAddr = (ULONG_PTR)ep->ContextRecord->Rip;
	DWORD dwOffset = (DWORD)(lpAddr % PAGE_SIZE);
	PMDL pNewMdl = IoAllocateMdl((LPVOID)(lpAddr - dwOffset), PAGE_SIZE, NULL, FALSE, NULL);
	MmProbeAndLockPages(pNewMdl, KernelMode, IoWriteAccess);
	LPBYTE lpNewAddr = (LPBYTE)MmMapLockedPagesSpecifyCache(pNewMdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	
	if (lpNewAddr[dwOffset+1] == 0x89)
		lpNewAddr[dwOffset] = 0x48;				// Put a MOV QWORD PTR opcode
	else
		lpNewAddr[dwOffset] = 0x90;				// Put a NOP opcode
	MmUnmapLockedPages(lpNewAddr, pNewMdl);
	IoFreeMdl(pNewMdl);

	// Enable here processor trace
	ptDesc.bTraceKernel = TRUE;
	ptDesc.dwNumOfRanges = 1;
	ptDesc.Ranges[0].lpStartVa = sysModInfo.Base;
	ptDesc.Ranges[0].lpEndVa = (LPVOID)((QWORD)sysModInfo.Base + sysModInfo.Size);
	ntStatus = IntelPtStartTracing(ptDesc, g_testData.pBuffDesc);
	g_testData.bKernelExcRaised = TRUE;

	return EXCEPTION_CONTINUE_EXECUTION;
}

// The Driver Trace Test work item (runs in System process context)
VOID KernelTraceWorkItem(PVOID Parameter) {
	// Get the parameters
	LPTSTR lpDrvFileName = *((LPTSTR*)Parameter);
	LPTSTR lpDumpFile = *((LPTSTR*)Parameter + 1);
	DWORD dwBuffSize = *((DWORD*)Parameter + 2);
	KIRQL kIrql = KeGetCurrentIrql();
	PEPROCESS pCurProc = IoGetCurrentProcess();
	NTSTATUS ntStatus = STATUS_SUCCESS;
	ASSERT(kIrql < DISPATCH_LEVEL && pCurProc == PsInitialSystemProcess);

	DWORD dwCurCpuId = KeGetCurrentProcessorNumber();
	KAFFINITY kAffinity = (KAFFINITY)(1i64 << dwCurCpuId);
	KeSetSystemAffinityThread(kAffinity);
	ntStatus = DoDriverTraceTest(lpDrvFileName, lpDumpFile, dwBuffSize);
	g_testData.workItmStatus = ntStatus;
	KeSetEvent(&g_testData.workItemEvt, IO_NO_INCREMENT, FALSE);
}


NTSTATUS DoDriverTraceTest(LPTSTR lpDrvFileName, LPTSTR lpDumpFile, DWORD dwBuffSize) {
	NTSTATUS ntStatus = 0;					// Returned NTSTATUS
	KIRQL kIrql = KeGetCurrentIrql();		// Current IRQL
	TCHAR lpDrvRegPath[0x200] = { 0 };		// The complete driver's service registry path
	LPTSTR lpDotPtr = NULL;
	DWORD dwStrLen = 0;						// String size in characters
	UNICODE_STRING drvRegString = { 0 };
	ASSERT(kIrql == PASSIVE_LEVEL);

	if (PsGetCurrentProcess() != PsInitialSystemProcess) {
		WORK_QUEUE_ITEM workItem = { 0 };
		KeInitializeEvent(&g_testData.workItemEvt, NotificationEvent, FALSE);
		ExInitializeWorkItem(&workItem, KernelTraceWorkItem, (LPVOID)&lpDrvFileName);
		ExQueueWorkItem(&workItem, DelayedWorkQueue);
		KeWaitForSingleObject((LPVOID)&g_testData.workItemEvt, Executive, KernelMode, FALSE, NULL);
		return g_testData.workItmStatus;

	}

	// Check the parameters:
	if (!dwBuffSize) dwBuffSize = 512 * 1024;
	if (!lpDumpFile || lpDumpFile[0] == 0) lpDumpFile = L"\\??\\c:\\pt_dump.bin";

	// Compose the full registry path
	RtlStringCchCopyW(lpDrvRegPath, COUNTOF(lpDrvRegPath), L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
	lpDotPtr = wcsrchr(lpDrvFileName, L'.');
	if (lpDotPtr) dwStrLen = (DWORD)(lpDotPtr - lpDrvFileName);
	else dwStrLen = (DWORD)wcslen(lpDrvFileName);
	RtlStringCchCatNW(lpDrvRegPath, COUNTOF(lpDrvRegPath), lpDrvFileName, dwStrLen);
	RtlInitUnicodeString(&drvRegString, lpDrvRegPath);

	// Allocate a buffer big enough for processor trace
	ntStatus = IntelPtAllocBuffer(&g_testData.pBuffDesc, dwBuffSize, TRUE, TRUE);
	if (!NT_SUCCESS(ntStatus)) return ntStatus;

	__try {
		ntStatus = ZwLoadDriver(&drvRegString);
	}
	__except (DriverExcFilter(GetExceptionCode(), GetExceptionInformation(), lpDrvFileName)) {
		// PASS
		ntStatus = STATUS_UNHANDLED_EXCEPTION;
	}

	// Check the exception:
	if (!g_testData.bKernelExcRaised) {
		// The exception handler has not run exception :-)
		ZwUnloadDriver(&drvRegString);
		ntStatus = STATUS_INVALID_EXCEPTION_HANDLER;
	}

	if (!NT_SUCCESS(ntStatus)) {
		FreePtBuffer(g_testData.pBuffDesc);
		g_testData.pBuffDesc = NULL;
		return ntStatus;
	}
	ntStatus = ZwUnloadDriver(&drvRegString);

	// Stop the PT Trace
	IntelPtStopTrace();
	// Dump the buffer
	g_testData.pBuffDesc->lpKernelVa = MmGetSystemAddressForMdlSafe(g_testData.pBuffDesc->pTraceMdl, NormalPagePriority);

	// Create a target file
	HANDLE hOutFile = NULL;
	OBJECT_ATTRIBUTES outFileOa = { 0 };
	UNICODE_STRING outFileName = { 0 };
	IO_STATUS_BLOCK ioSb = { 0 };
	LARGE_INTEGER fileOffset = { 0 };

	RtlInitUnicodeString(&outFileName, lpDumpFile);
	InitializeObjectAttributes(&outFileOa, &outFileName, OBJ_KERNEL_HANDLE, NULL, NULL);
	ntStatus = ZwCreateFile(&hOutFile, FILE_ALL_ACCESS, &outFileOa, &ioSb, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_SUPERSEDE, FILE_NON_DIRECTORY_FILE, NULL, 0);
	if (NT_SUCCESS(ntStatus)) {
		ntStatus = ZwWriteFile(hOutFile, NULL, NULL, NULL, &ioSb, g_testData.pBuffDesc->lpKernelVa, (DWORD)g_testData.pBuffDesc->qwBuffSize, &fileOffset, NULL);
		ZwClose(hOutFile);
	}

	FreePtBuffer(g_testData.pBuffDesc);
	g_testData.pBuffDesc = NULL;

	return STATUS_SUCCESS;
}
#endif

// Find a Kernel module in memory using documented method
NTSTATUS GetKernelModule(LPTSTR lpName, SYSTEM_MODULE_INFORMATION * pSysModuleDesc) {
	NTSTATUS ntStatus = 0;
	SYSTEM_ALL_MODULES * pAllModules = NULL;
	ULONG dwBuffSize = 0,
		dwRetLength = 0;
#if _DEBUG
	KIRQL kIrql = KeGetCurrentIrql();	// Current IRQL
	ASSERT(kIrql == PASSIVE_LEVEL);
#endif 
	ntStatus = ZwQuerySystemInformation(SystemModuleInformation, (PVOID)pAllModules, NULL, &dwBuffSize);
	if (ntStatus != STATUS_INFO_LENGTH_MISMATCH) return ntStatus;

	pAllModules = (SYSTEM_ALL_MODULES*)ExAllocatePoolWithTag(PagedPool, dwBuffSize, MEMTAG);
	RtlZeroMemory(pAllModules, dwBuffSize);
	ntStatus = ZwQuerySystemInformation(SystemModuleInformation, (PVOID)pAllModules, dwBuffSize, &dwRetLength);

	if (!NT_SUCCESS(ntStatus)) {
		ExFreePool(pAllModules);
		return ntStatus;
	}

	ntStatus = STATUS_NOT_FOUND;
	for (unsigned i = 0; i < pAllModules->dwNumOfModules; i++) {
		TCHAR lpCurModName[0x100] = { 0 };
		SYSTEM_MODULE_INFORMATION * pCurModule = &pAllModules->modules[i];

		RtlStringCchPrintfW(lpCurModName, COUNTOF(lpCurModName), L"%S", pCurModule->ImageName + pCurModule->ModuleNameOffset);
		if (_wcsicmp(lpCurModName, lpName) == 0) {
			// Found
			if (pSysModuleDesc != NULL)
				(*pSysModuleDesc) = (*pCurModule);
			ntStatus = STATUS_SUCCESS;
			break;
		}
	}

	ExFreePool(pAllModules);
	return ntStatus;
}
