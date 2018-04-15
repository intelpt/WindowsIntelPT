/**********************************************************************
*  Windows Intel Processor Trace (PT) Driver
*  Filename: HyperV.cpp
*  Implements the HyperV support for IntelPt
*  Last revision: xx/xx/2017
*
*  Copyright© 2017 Andrea Allievi, Richard Johnson
*  Microsoft Ltd and TALOS Research and Intelligence Group
*  All right reserved
**********************************************************************/
#include "stdafx.h"
#include "DriverEntry.h"
#include <hv.h>
#include "Debug.h"
#include <intrin.h>

// This routine detects if the system is under a not-obfuscated hypervisor, and,
// if so, it detect if the Hypervisor is Microsoft HyperV
NTSTATUS DetectMicrosoftHyperV(HYPERV_INFO * HyperVInfo) {
	int CpuInfo[4] = { 0 };
	HYPERV_INFO HvInfo = { 0 };
	BOOLEAN IsMicrosoftHv = FALSE;

	// Follow the SPECS
	__cpuidex(CpuInfo, 0x40000000, 0);
	IsMicrosoftHv = memcmp(&CpuInfo[1], "Microsoft Hv", sizeof(DWORD) * 3) == 0;
	if (!IsMicrosoftHv ||
		CpuInfo[0] < 0x40000005)
		return STATUS_NOT_FOUND;

	__cpuidex(CpuInfo, 0x40000001, 0);
	if (CpuInfo[0] != (DWORD)'1#vH')
		return STATUS_NOT_FOUND;

	if (!HyperVInfo)
		return STATUS_SUCCESS;

	// ... Grab the HyperV Information
	__cpuidex(CpuInfo, 0x40000002, 0);
	HvInfo.Build = (DWORD)CpuInfo[0];
	HvInfo.MajorVersion = (WORD)(CpuInfo[1] >> 16);
	HvInfo.MinorVersion = (WORD)CpuInfo[1];
	HvInfo.ServicePack = (DWORD)CpuInfo[2];
	HvInfo.ServiceBranch = (UCHAR)(CpuInfo[3] >> 24) & 0xFF;
	HvInfo.ServiceNumber = (DWORD)(CpuInfo[3] & 0xFFFFFF);

	// Grab the HyperV partition features 
	__cpuidex(CpuInfo, 0x40000003, 0);
	RtlCopyMemory(&HvInfo.Features, CpuInfo, sizeof(HYPERV_FEATURES));

	*HyperVInfo = HvInfo;
	return STATUS_SUCCESS;
}

// Emit an HyperV real CPUINFO
NTSTATUS HvCpuId(int CpuInfo[4], int Function, int SubLeaf) {
	HV_HYPERCALL_INFO HvCallInfo = { 0 };				// Hypercall Input structure
	HV_HYPERCALL_OUTPUT HvOutput = { 0 };				// Hypercall output
	PHV_LOGICAL_PROC_REGISTERS_INPUT HvInput = NULL;	// HvCallGetLogicalProcessorRegisters input buffer
	DWORD * CpuIdDataPtr = NULL;						// HvCallGetLogicalProcessorRegisters output buffer
	ULONG CpuNumber = 0;								// The current CPU Number
	KIRQL OldIrql = 0;									// Previous processor IRQL
	HV_STATUS HvStatus = 0;								// Returned status from the Hypervisor
	PHYPERV_DATA pHvData = NULL;
	
	// Grab the global data
	if (!g_pDrvData) return STATUS_INVALID_DEVICE_STATE;
	pHvData = (PHYPERV_DATA)&g_pDrvData->HyperV_Data;

	// HvCallGetLogicalProcessorRegisters is a REP hypercall.
	HvCallInfo.AsUINT64 = HvCallGetLogicalProcessorRegisters;
	HvCallInfo.Fields.CountOfElements = 1;

	if (!pHvData->IsValid)
		return STATUS_UNSUCCESSFUL;

	// Protect this code from pre-emption
	KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);
	CpuNumber = KeGetCurrentProcessorNumber();

	// From the TLFS: Callers must specify the 64-bit guest physical address (GPA) of the input and/or output parameters. GPA pointers must by 8-byte aligned (page 17)
	HvInput = (PHV_LOGICAL_PROC_REGISTERS_INPUT)pHvData->InputPage.VirtualAddr;
	CpuIdDataPtr = (DWORD*)pHvData->OutputPage.VirtualAddr;

	HvInput->VCpuIndex = CpuNumber;
	HvInput->Type = HvX64LpRegisterTypeCpuid;
	HvInput->Address.CpuId.Eax = (DWORD)Function;
	HvInput->Address.CpuId.Ecx = (DWORD)SubLeaf;

	// Perform the actual Hypercall
	HvOutput = pHvData->CallHv(HvCallInfo, pHvData->InputPage.PhysicalAddr, pHvData->OutputPage.PhysicalAddr);
	KeLowerIrql(OldIrql);

	HvStatus = HvOutput.Fields.Result;
	if (HvStatus == HV_STATUS_SUCCESS)
	{
		RtlCopyMemory(CpuInfo, pHvData->OutputPage.VirtualAddr, sizeof(int) * 4);
	}
	// ALWAYS zero out the used buffers
	RtlZeroMemory(pHvData->OutputPage.VirtualAddr, PAGE_SIZE);
	RtlZeroMemory(pHvData->InputPage.VirtualAddr, PAGE_SIZE);

	return (HvStatusToNtStatus(HvStatus));
}

// Initialize HyperV data structures and memory
NTSTATUS InitGlobalHv() {
	NTSTATUS NtStatus = STATUS_SUCCESS;
	HYPERV_INFO HvInfo = { 0 };
	HV_MEMDESC MemDesc = { 0 };									// Current Memory Descriptor
	PHYSICAL_ADDRESS physMaxAddr = { 0 };						// The maximum acceptable physical address
	HV_X64_MSR_HYPERCALL_DESC HypercallMsr = { 0 };				// The Hypercall MSR
	PHYPERV_DATA pHvData = NULL;

	// Grab the global data
	if (!g_pDrvData) return STATUS_INVALID_DEVICE_STATE;
	pHvData = (PHYPERV_DATA)&g_pDrvData->HyperV_Data;

	NtStatus = DetectMicrosoftHyperV(&HvInfo);
	if (!NT_SUCCESS(NtStatus))
	{
		DrvDbgPrint("InitGlobalHv - No Hypervisor detected, or Hypervisor is not HyperV\r\n");
		return STATUS_NOT_FOUND;
	}
	pHvData->Info = HvInfo;

	// Allocate memory for the Hypercalls
	physMaxAddr.QuadPart = (LONGLONG)-1;
	MemDesc.Size = PAGE_SIZE;
	MemDesc.VirtualAddr = MmAllocateContiguousMemory(PAGE_SIZE, physMaxAddr);
	if (MemDesc.VirtualAddr) {
		MemDesc.PhysicalAddr = MmGetPhysicalAddress(MemDesc.VirtualAddr);
		RtlZeroMemory(MemDesc.VirtualAddr, PAGE_SIZE);
	}
	pHvData->InputPage = MemDesc;

	// Output page
	RtlZeroMemory(&MemDesc, sizeof(HV_MEMDESC));
	MemDesc.VirtualAddr = MmAllocateContiguousMemory(PAGE_SIZE, physMaxAddr);
	MemDesc.Size = PAGE_SIZE;
	if (MemDesc.VirtualAddr) {
		MemDesc.PhysicalAddr = MmGetPhysicalAddress(MemDesc.VirtualAddr);
		RtlZeroMemory(MemDesc.VirtualAddr, PAGE_SIZE);
	}
	pHvData->OutputPage = MemDesc;

	if (!pHvData->InputPage.VirtualAddr ||
		!pHvData->OutputPage.VirtualAddr)
	{
		if (pHvData->InputPage.VirtualAddr)
			MmFreeContiguousMemory(pHvData->InputPage.VirtualAddr);
		if (pHvData->OutputPage.VirtualAddr)
			MmFreeContiguousMemory(pHvData->OutputPage.VirtualAddr);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Discover the Hypercall page (page 26 of the TLFS Specs)
	HypercallMsr.AsUINT64 = __readmsr(HV_X64_MSR_HYPERCALL);
	if (!HypercallMsr.Fields.EnableHypercallPage || !HypercallMsr.Fields.HypercallGPA)
	{
		// Internal error, this should be not the case
		MmFreeContiguousMemory(pHvData->InputPage.VirtualAddr);
		MmFreeContiguousMemory(pHvData->OutputPage.VirtualAddr);
		return STATUS_INTERNAL_ERROR;
	}

	// Map this Physical page
	RtlZeroMemory(&MemDesc, sizeof(HV_MEMDESC));
	MemDesc.PhysicalAddr.QuadPart = ((UINT64)HypercallMsr.Fields.HypercallGPA << 12);
	MemDesc.VirtualAddr = MmMapIoSpace(MemDesc.PhysicalAddr, PAGE_SIZE, MmNonCached);
	MemDesc.Size = PAGE_SIZE;
	pHvData->HypercallPage = MemDesc;
	pHvData->CallHv = (PHV_PERFORM_HYPERCALL)MemDesc.VirtualAddr;

	// Finalize the configuration
	pHvData->IsValid = TRUE;
	return STATUS_SUCCESS;
}

// Destroy the HyperV data structures and memory
VOID DestroyGlobalHv() {
	PHYPERV_DATA pHvData = NULL;

	// Grab the global data
	if (!g_pDrvData) return;
	pHvData = (PHYPERV_DATA)&g_pDrvData->HyperV_Data;

	if (pHvData->InputPage.VirtualAddr)
		MmFreeContiguousMemory(pHvData->InputPage.VirtualAddr);
	if (pHvData->OutputPage.VirtualAddr)
		MmFreeContiguousMemory(pHvData->OutputPage.VirtualAddr);
	if (pHvData->HypercallPage.VirtualAddr)
		MmUnmapIoSpace(pHvData->HypercallPage.VirtualAddr, PAGE_SIZE);
}

// Utility function that converts a HV_STATUS value in its correspondent NTSTATUS (if any)
NTSTATUS HvStatusToNtStatus(HV_STATUS HvStatus) {
	NTSTATUS ntStatus = (NTSTATUS)0;

	if (HvStatus == HV_STATUS_SUCCESS)
		ntStatus = STATUS_SUCCESS;
	else if (HvStatus == HV_STATUS_UNSUCCESSFUL)
		ntStatus = STATUS_UNSUCCESSFUL;
	else if (HvStatus >= 0x1000)
		// No corrispondent NTSTATUS value here
		ntStatus = STATUS_INVALID_PARAMETER;
	else
		// For all others, return the equivalent STATUS_HV* codes.
		ntStatus = (NTSTATUS)(0xC0350000 | HvStatus);

	return ntStatus;
}