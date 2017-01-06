/**********************************************************************
 *  Windows Intel Processor Trace (PT) Driver
 *	Filename: Debug.h
 *	Implement Driver Debug function prototypes
 *	Last revision: 01/06/2016
 *
 *  Copyright© 2016 Andrea Allievi, Richard Johnson
 *  TALOS Research and Intelligence Group and Microsoft Ltd
 *	All right reserved
 **********************************************************************/

#pragma once

// Macro to substitute the old original DbgPrint routine with the new one
#define DbgPrint DrvDbgPrint		

// Enable debug output for DPFLTR_DEFAULT_ID  component filter mask 
NTSTATUS EnableDebugOutput();

// Revert to default Debug Settings
VOID RevertToDefaultDbgSettings();

// Allocate Debug Memory  with auditing
PVOID DbgAllocateMemory(IN POOL_TYPE  PoolType, IN SIZE_T  NumberOfBytes, IN ULONG  Tag);

// Free Allocated Debug Memory
VOID DbgFreeMemory(PVOID pMem);

// Write a driver message to the Kernel Debugger
ULONG DrvDbgPrint(PCHAR Format, ...); 
