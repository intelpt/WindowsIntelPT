/**********************************************************************
 *  Windows Intel Processor Trace (PT) Driver 0.4
 *  Filename: stdafx.h
 *	Implement Driver Standard definitions
 *  Last revision: 01/06/2016
 *
 *  Copyright© 2016 Andrea Allievi, Richard Johnson
 *  TALOS Research and Intelligence Group and Microsoft Ltd
 *  All right reserved
 **********************************************************************/
#pragma once
#include <ntddk.h>
#include <wdmsec.h>

// Common data types
typedef unsigned char BYTE, *LPBYTE, *PBYTE;
typedef unsigned long DWORD, UINT, *LPDWORD, *PDWORD;
typedef unsigned __int64 QWORD, *LPQWORD, *PQWORD;
typedef unsigned short WORD, *LPWORD, *PWORD;
typedef int BOOL, *PBOOL;
typedef unsigned char BOOLEAN, *PBOOLEAN, *LPBOOLEAN;
typedef void * LPVOID;

// Default Memory Tag
#define MEMTAG (ULONG)'rDtP'

// Definizione per far sentire il compilatore contento
#pragma warning(disable: 4005)
#define DECLSPEC_IMPORT extern "C" __declspec(dllimport)
#define DDKBUILD extern "C"
#define EXTERN_C extern "C"
#pragma warning(default: 4005)

#pragma warning (disable : 4302)			// HANDLE to DWORD truncation
#pragma warning (disable : 4311)			// HANDLE to DWORD truncation


#ifdef _DEBUG
#define DbgBreak() __debugbreak()
#else
#define DbgBreak() __noop()
#endif

#define COUNTOF(x) sizeof(x) / sizeof(x[0])