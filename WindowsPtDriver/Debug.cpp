/**********************************************************************
 *  Windows Intel Processor Trace (PT) Driver
 *  Filename: Debug.cpp
 *	Implement Driver Debug functions
 *  Last revision: 01/06/2017
 *
 *  Copyright© 2016 Andrea Allievi, Richard Johnson
 *  TALOS Research and Intelligence Group and Microsoft Ltd
 *  All right reserved
 **********************************************************************/
#include "stdafx.h"
#include "Debug.h"
#include <stdarg.h>

#pragma region Debug Functions
BOOLEAN g_bOldDbgState = FALSE;
/*  When DbgPrintEx is called in kernel-mode code, Windows compares the message importance bitfield that is 
 *  specified by Level with the filter mask of the component that is specified by ComponentId.
 *
 *  Note 
 *  Recall that when the Level parameter is between 0 and 31, the importance bitfield is equal to 1 << Level. 
 *  But when the Level parameter is 32 or higher, the importance bitfield is simply equal to Level.
 *  Windows performs an AND operation on the importance bitfield and the component filter mask. 
 *  If the result is nonzero, the message is sent to the debugger.
 *
*/
//DPFLTR_SYSTEM_ID = 0x0 - DPFLTR_DEFAULT_ID = 0x65h	
//DPFLTR_IHVDRIVER_ID = 77
NTSTATUS EnableDebugOutput() 
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	ntStatus = DbgQueryDebugFilterState(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL);
	if (ntStatus == FACILITY_DEBUGGER) 
		g_bOldDbgState = TRUE;
	else 
		g_bOldDbgState = FALSE;
	// Now set new Mask
	ntStatus = DbgSetDebugFilterState(DPFLTR_IHVDRIVER_ID, DPFLTR_MASK | 0x0E, TRUE);
	return ntStatus;
}

VOID RevertToDefaultDbgSettings() 
{
	DbgSetDebugFilterState(DPFLTR_IHVDRIVER_ID, DPFLTR_MASK | 0x0E, g_bOldDbgState);
}

ULONG DrvDbgPrint(PCHAR Format, ...) 
{
	va_list arglist;
	va_start(arglist, Format);
	return vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, Format, arglist);
}

PVOID DbgAllocateMemory(IN POOL_TYPE  PoolType, IN SIZE_T  NumberOfBytes, IN ULONG  Tag) 
{
	PVOID retBuff = ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);
	DbgPrint("[" DRV_NAME "] Allocated 0x%08X bytes at base address 0x%08X, Tag '%.04s', %s.\r\n", 
		NumberOfBytes, (LPBYTE)retBuff, (LPSTR)&Tag, (PoolType == NonPagedPool ? "NonPaged Pool" : "Paged Pool"));
	return retBuff;
}

VOID DbgFreeMemory(PVOID pMem) 
{
	ExFreePool(pMem);
	DbgPrint("[" DRV_NAME "] Deallocated memory at base address 0x%08X\r\n", (LPBYTE)pMem);
}
#pragma endregion