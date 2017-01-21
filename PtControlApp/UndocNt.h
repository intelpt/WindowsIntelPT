/**********************************************************************
 *  Windows Intel Processor Trace (PT) Driver
 *  Filename: UndocNt.h
 *  Defines the undocumented Windows Nt data structures
 *  Last revision: 12/01/2016
 *
 *  Copyright© 2016 Andrea Allievi, Richard Johnson
 *  Microsoft Ltd & TALOS Research and Intelligence Group
 *  All right reserved
 **********************************************************************/
#pragma once
#define ANYSIZE_ARRAY 1
// The specified information record length does not match the length required for the specified information class.
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)

//typedef int NTSTATUS;

extern "C" NTSTATUS ZwQuerySystemInformation(DWORD SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

typedef struct _SYSTEM_MODULE_INFORMATION { // Information Class 11
	PVOID Reserved[2];						// + 0x00
	PVOID Base;								// + 0x10
	ULONG Size;								// + 0x18
	ULONG Flags;							// + 0x1C
	USHORT Index;							// + 0x20
	USHORT Unknown;							// + 0x22
	USHORT LoadCount;						// + 0x24
	USHORT ModuleNameOffset;				// + 0x26
	CHAR ImageName[256];					// + 0x28
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

struct SYSTEM_ALL_MODULES {
	DWORD dwNumOfModules;
	SYSTEM_MODULE_INFORMATION modules[ANYSIZE_ARRAY];
};