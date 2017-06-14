/**********************************************************************
*  Windows Intel Processor Trace (PT) Driver 0.5
*  Filename: IntelPtXSave.cpp
*  Implements the support routines for the PT XSAVE feature
*  Last revision: 01/25/2017
*
*  Copyright© 2017 Andrea Allievi, Richard Johnson
*  TALOS Research and Intelligence Group and Microsoft Ltd
*  All right reserved
**********************************************************************/

#include "stdafx.h"
#include "IntelPtXSave.h"
#include "DriverEntry.h"
#include <intrin.h>

// Check if the current processor support the XSAVE feature for Intel PT
NTSTATUS CheckPtXSaveSupport(DWORD * pdwSAreaSize, DWORD * pdwUAreaSize, DWORD * pdwPtSize) {
	int cpuInfo[4] = { 0 };
	// Check the presence of XSAVE Feature (chapter 13.2 of Intel Basic Architecure manual)
	__cpuidex(cpuInfo, 1, 0);
	if ((cpuInfo[2] & CPUID_XSAVE_MASK) != CPUID_XSAVE_MASK) return STATUS_NOT_SUPPORTED;
	// Now use the Processor Extended State Enumeration Main Leaf
	__cpuidex(cpuInfo, 0xD, 0);
	// Check the x87 and SSE state
	if ((cpuInfo[0] & (1 << 0)) == 0) return STATUS_NOT_SUPPORTED;
	if ((cpuInfo[0] & (1 << 1)) == 0) return STATUS_NOT_SUPPORTED;
	if (pdwUAreaSize) (*pdwUAreaSize) = cpuInfo[2];
	// Now check the support of XSAVES/XRSTORS and IA32_XSS MSR
	__cpuidex(cpuInfo, 0xD, 1);
	if ((cpuInfo[0] & (1 << 3)) == 0) return STATUS_NOT_SUPPORTED;
	// Check the opfficial PT support
	if ((cpuInfo[2] & PT_XSAVE_MASK) == 0) return STATUS_NOT_SUPPORTED;
	if (pdwSAreaSize) (*pdwSAreaSize) = cpuInfo[1];

	// Try to get the size and position of the PT data in the EXTENDED REGION of the XSAVE area 
	__cpuidex(cpuInfo, 0xD, 8);
	if (pdwPtSize) (*pdwPtSize) = cpuInfo[0];
	ASSERT((cpuInfo[2] & (1 << 0)) == 1);				// ECX Bit 00 is set if the bit n(corresponding to the sub - leaf index) is supported in the IA32_XSS MSR; it is clear if bit n is instead supported in XCR0.

	// ps. Take a look at KeSaveExtendedProcessorState - RtlXSave and RtlGetEnabledExtendedFeatures
	return STATUS_SUCCESS;
}

// Get the current XSAVE Area size for the enabled features in XCR0 and IA32_XSS MSR of current CPU
DWORD GetCurXSaveAreaSize() {
	int cpuInfo[4] = { 0 };
	// Processor Extended State Enumeration Sub - leaf(EAX = 0DH, ECX = 1)
	__cpuidex(cpuInfo, 0xD, 1);
	// EBX Bits 31 - 00: The size in bytes of the XSAVE area containing all states enabled by XCRO | IA32_XSS.
	return (DWORD)cpuInfo[1];
}

// Save all the PT data to an XSAVE area
NTSTATUS SavePtData(PXSAVE_AREA_EX lpXSaveArea, DWORD dwSize) {
	MSR_IA32_XSS_DESC xssDesc = { 0 };					// The IA32_XSS MSR descriptor
	XCR0_DESC xcr0Desc = { 0 };							// The XCR0 extended register descriptor
	XCR0_DESC xcr0OrgDesc = { 0 };						// The XCR0 original extended register descriptor
	NTSTATUS ntStatus = STATUS_SUCCESS;					// Returned NTSTATUS
	ULONG_PTR cr4 = { 0 };								// Value of CR4 register (we must enable the XSAVE feature)
	DWORD dwPtAreaSize = 0;								// XSAVE area with Intel PT enable
	if (!lpXSaveArea || !dwSize) return STATUS_INVALID_PARAMETER;

	ntStatus = CheckPtXSaveSupport(NULL, NULL, &dwPtAreaSize);
	if (!NT_SUCCESS(ntStatus)) return ntStatus;

	// Step 1. Enable XSAVE in CR4 register
	cr4 = __readcr4();
	cr4 = (cr4 | OSXSAVE_CR4_MASK);
	__writecr4(cr4);

	// Check the XSAVE area (must be 64-BYTE aligned)
	if (((ULONG_PTR)lpXSaveArea & 0x0FF) != 0)
		return STATUS_INVALID_ADDRESS;

	RtlZeroMemory(lpXSaveArea, dwSize);

	// Set the proper bit in the MSR_IA32_XSS and in XCR0
	xcr0OrgDesc.value = _xgetbv(0);					// Read the original XCR0 descriptor, because otherwise we could have problem with the Windows Context Dispatcher
	xcr0Desc.Bits.FpuMmx = 1;
	xssDesc.Bits.IntelPt = 1;
	__writemsr(MSR_IA32_XSS, xssDesc.value);
	_xsetbv(0, xcr0Desc.value);

	// Check the size of the XSAVE area
	dwPtAreaSize = GetCurXSaveAreaSize();
	if (dwSize < dwPtAreaSize) return STATUS_INVALID_BUFFER_SIZE;

	// Now perform the XSAVES
	//DbgBreak();
	_xsaves((LPVOID)lpXSaveArea, xssDesc.value);

	// Restore old XCR0 register
	_xsetbv(0, xcr0OrgDesc.value);

	return STATUS_SUCCESS;
}