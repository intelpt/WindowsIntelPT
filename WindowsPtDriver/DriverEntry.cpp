/**********************************************************************
 *  Windows Intel Processor Trace (PT) Driver
 *  Filename: DriverEntry.cpp
 *	Implement Driver Entry point and startup functions
 *  Last revision: 01/06/2016
 *
 *  Copyright© 2016 Andrea Allievi, Richard Johnson
 *  TALOS Research and Intelligence Group and Microsoft Ltd
 *  All right reserved
 **********************************************************************/
#include "stdafx.h"
#include "DriverEntry.h"
#include "DriverIo.h"
#include "Debug.h"
#include "UndocNt.h"

const LPTSTR g_lpDevName = L"\\Device\\WindowsIntelPtDev";
const LPTSTR g_lpDosDevName = L"\\DosDevices\\WindowsIntelPtDev";

// The global driver data
DRIVER_GLOBAL_DATA * g_pDrvData = NULL;

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath) 
{
	UNREFERENCED_PARAMETER(pRegPath);
	NTSTATUS ntStatus = STATUS_SUCCESS;
	KAFFINITY activeProcessorsMask = 0;					// The active processors mask
	DWORD dwNumOfProcs = 0;								// Number of system processors
	DWORD dwBuffSize = 0;								// The global driver data size in bytes
	UNICODE_STRING devNameString = { 0 };				// The I/O device name
	UNICODE_STRING dosDevNameString = { 0 };			// The DOS device name (Usermode access)
	PDEVICE_OBJECT pDevObj = NULL;						// The device object
	INTEL_PT_CAPABILITIES ptCap = { 0 };				// The Intel PT Capabilities for this processor

	// Debug helper
	if ((*KdDebuggerNotPresent) == FALSE)
		DbgBreak();
	EnableDebugOutput();

	// Get the total number of system processors
	dwNumOfProcs = KeQueryActiveProcessorCount(&activeProcessorsMask);

	// Allocate memory for my own global data
	dwBuffSize = sizeof(DRIVER_GLOBAL_DATA) + (dwNumOfProcs * sizeof(PER_PROCESSOR_PT_DATA));
	g_pDrvData = (PDRIVER_GLOBAL_DATA)ExAllocatePoolWithTag(NonPagedPool, dwBuffSize, MEMTAG);
	if (!g_pDrvData) return STATUS_INSUFFICIENT_RESOURCES;
	RtlZeroMemory(g_pDrvData, dwBuffSize);
	g_pDrvData->dwNumProcs = dwNumOfProcs;

	// Check PT support
	ntStatus = CheckIntelPtSupport(&ptCap);
	if (!NT_SUCCESS(ntStatus)) 
	{
		DbgPrint("[" DRV_NAME "] Intel Processor Trace is not supported on this system. Exiting...\r\n");
		RevertToDefaultDbgSettings();
		ExFreePool(g_pDrvData);
		return ntStatus;
	}
	if (ptCap.numOfAddrRanges < 4) {
		DbgPrint("[" DRV_NAME "] Info: The processor %i supports maximum of %i IP ranges.\r\n", KeGetCurrentProcessorNumber(), ptCap.numOfAddrRanges);
	}

	// Create a Pmi Event name and register the PMI interrupt
	CreateSharedPmiEvent(INTEL_PT_PMI_EVENT_NAME);
	RegisterPmiInterrupt();
	// Initialize the user-mode callbacks list 
	InitializeListHead(&g_pDrvData->userCallbackList);
	KeInitializeSpinLock(&g_pDrvData->userCallbackListLock);

	// Build the controller device
	RtlInitUnicodeString(&devNameString, g_lpDevName);
	RtlInitUnicodeString(&dosDevNameString, g_lpDosDevName);

	// XXX: require admin to prevent side channel attacks on 3rd party programs (IoCreateDeviceSecure)
	ntStatus = IoCreateDevice(pDriverObject, 0, &devNameString, FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN, FALSE, &pDevObj);
	
	if (NT_SUCCESS(ntStatus)) {
		ntStatus = IoCreateSymbolicLink(&dosDevNameString, &devNameString);
		g_pDrvData->pMainDev = pDevObj;
	}

	if (!NT_SUCCESS(ntStatus)) {
		if (g_pDrvData->pMainDev) IoDeleteDevice(g_pDrvData->pMainDev);
		ExFreePool(g_pDrvData);
		return ntStatus;
	}

	// Put the needed routines in the NonPaged pool
	MmLockPagableCodeSection(CheckIntelPtSupport);

	// Initialize Driver dispatch routine
	for (DWORD i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
		pDriverObject->MajorFunction[i] = DeviceUnsupported;

	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoControl;
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = DevicePassThrough;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DevicePassThrough;
	pDriverObject->MajorFunction[IRP_MJ_CLEANUP] = DevicePassThrough;
	pDriverObject->MajorFunction[IRP_MJ_READ] = DeviceUnsupported;		
	pDriverObject->MajorFunction[IRP_MJ_WRITE] = DeviceUnsupported;	
	
	pDriverObject->DriverUnload = DriverUnload;

	return STATUS_SUCCESS;
}

// Create the shared PMI event
NTSTATUS CreateSharedPmiEvent(LPTSTR lpEvtName) 
{
	NTSTATUS ntStatus = STATUS_SUCCESS;					// Returned NT_STATUS value
	DWORD dwNameLen = 0;								// Size in CHARs
	HANDLE hEvent = NULL;								// Handle to the named event
	PKEVENT pEvent = NULL;								// The EVENT object body
	OBJECT_ATTRIBUTES oa = { 0 };						// The EVENT object attributes
	UNICODE_STRING eventNameString = { 0 };				// The EVENT name string
	TCHAR newName[COUNTOF(g_pDrvData->pmiEventName)] = { 0 };

	dwNameLen = (DWORD)wcslen(lpEvtName);
	if (!lpEvtName || dwNameLen < 2)
		return STATUS_INVALID_PARAMETER;

	// Preliminary buffer checks
	if (lpEvtName[0] != L'\\') 	{
		// Add the trailing "\BasedNamedObject\" (18 chars)
		if ((dwNameLen + 1 + 18) > COUNTOF(g_pDrvData->pmiEventName))
			return STATUS_INVALID_BUFFER_SIZE;

		wcscpy_s(newName, COUNTOF(newName), L"\\BaseNamedObjects\\");
		wcscat_s(newName, COUNTOF(newName), lpEvtName);

	} else {
		if ((dwNameLen + 1) > COUNTOF(g_pDrvData->pmiEventName))
			return STATUS_INVALID_BUFFER_SIZE;

		wcscpy_s(newName, COUNTOF(newName), lpEvtName);
	}

	if (g_pDrvData->pPmiEvent) {
		KeResetEvent(g_pDrvData->pPmiEvent);
		// Delete the object (DO NOT use ExFreePool, the Object Manager has allocated this)
		ObDereferenceObject(g_pDrvData->pPmiEvent);
		if (g_pDrvData->hPmiEvent) ZwClose(g_pDrvData->hPmiEvent);
		g_pDrvData->pPmiEvent = NULL;
		RtlZeroMemory(g_pDrvData->pmiEventName, COUNTOF(g_pDrvData->pmiEventName));
	}

	RtlInitUnicodeString(&eventNameString, newName);
	InitializeObjectAttributes(&oa, &eventNameString, OBJ_KERNEL_HANDLE, NULL, NULL);

	// Create the named event
	ntStatus = ZwCreateEvent(&hEvent, EVENT_ALL_ACCESS, &oa, SynchronizationEvent, FALSE);

	if (NT_SUCCESS(ntStatus)) {
		ntStatus = ObReferenceObjectByHandle(hEvent, EVENT_ALL_ACCESS, *ExEventObjectType, KernelMode, (PVOID*)&pEvent, NULL);
		if (NT_SUCCESS(ntStatus)) {
			RtlCopyMemory(g_pDrvData->pmiEventName, newName, COUNTOF(g_pDrvData->pmiEventName));
			g_pDrvData->pPmiEvent = pEvent;
			g_pDrvData->hPmiEvent = hEvent;
		}
		else
			ZwClose(hEvent);
	}
	
	return ntStatus;
}

VOID UnloadPtDpc(struct _KDPC *Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2) 
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
	
	NTSTATUS ntStatus = STATUS_SUCCESS;
	ULONG dwCurProc = 0;

	dwCurProc = KeGetCurrentProcessorNumber();

	DbgPrint("[" DRV_NAME "] Stopping and unloading the Trace for CPU #%i...\r\n", dwCurProc);
	ntStatus = StopAndDisablePt();
	ntStatus = FreeCpuResources(dwCurProc);

	if (DeferredContext) 
	{
		// This is a pointer to the KEVENT, signal it without wait anything (It could be done at DISPATCH IRQL)
		KeSetEvent((PRKEVENT)DeferredContext, IO_NO_INCREMENT, FALSE);
	}
	// END
}

// XXX: This will currently bugcheck if the IOCTL is called from within the traced process
VOID DriverUnload(PDRIVER_OBJECT pDrvObj) 
{
	UNREFERENCED_PARAMETER(pDrvObj);
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	UNICODE_STRING dosDevNameString = { 0 };
	ULONG dwCurProc = 0;
	KDPC unloadDpc = { 0 };
	KIRQL kIrql = KeGetCurrentIrql();

	dwCurProc = KeGetCurrentProcessorNumber();
	for (DWORD i = 0; i < g_pDrvData->dwNumProcs; i++) 
	{
		KEVENT kUnloadEvent = { 0 };
		PER_PROCESSOR_PT_DATA * procData = &g_pDrvData->procData[i];;
		KeInitializeEvent(&kUnloadEvent, NotificationEvent, FALSE);

		// This will fail if called from within the traced process
		ntStatus = UnmapTraceBuffToUserVa(i);
		if (!NT_SUCCESS(ntStatus)) 
		{
			// Memory mappings are inconsistent so we bugcheck
			KeBugCheckEx(PROCESS_HAS_LOCKED_PAGES, 0x00, (ULONG_PTR)procData->lpMappedProc, procData->pPtBuffDesc->qwBuffSize / PAGE_SIZE, 0);
		}

		// Queue the unload DPC
		KeInitializeDpc(&unloadDpc, UnloadPtDpc, (LPVOID)&kUnloadEvent);
		KeSetTargetProcessorDpc(&unloadDpc, (CCHAR)i);
		KeInsertQueueDpc(&unloadDpc, NULL, NULL);

		KeWaitForSingleObject(&kUnloadEvent, Executive, KernelMode, FALSE, NULL);
	}

	// Unload each registered User-mode PMI Callback
	ClearAndFreePmiCallbackList();

	// Unload the device object and the Symbolic Link
	if (g_pDrvData->pMainDev) 
	{
		// Delete the symbolic Link
		RtlInitUnicodeString(&dosDevNameString, g_lpDosDevName);
		IoDeleteSymbolicLink(&dosDevNameString);
		IoDeleteDevice(g_pDrvData->pMainDev);
	}

	// uninstall PMI
	if (g_pDrvData->bPmiInstalled)
		UnregisterPmiInterrupt();
	
	// delete the PMI event
	if (g_pDrvData->hPmiEvent)
		ZwClose(g_pDrvData->hPmiEvent);
	g_pDrvData->hPmiEvent = NULL;

	if (g_pDrvData->pPmiEvent)
		ObDereferenceObject(g_pDrvData->pPmiEvent);
	g_pDrvData->pPmiEvent = NULL;

	if (g_pDrvData) 
		ExFreePool(g_pDrvData);

	DbgPrint("[" DRV_NAME "] driver successfully unloaded.");
	RevertToDefaultDbgSettings();
}