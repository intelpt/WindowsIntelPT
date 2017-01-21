/**********************************************************************
 *  Windows Intel Processor Trace (PT) Driver
 *  Filename: IntelPtControlApp.h
 *	A simple Intel PT driver control application header file
 *  Last revision: 12/01/2016
 *
 *  Copyright© 2016 Andrea Allievi, Richard Johnson
 *  Microsoft Ltd & TALOS Research and Intelligence Group
 *  All right reserved
 **********************************************************************/
#pragma once
#include "IntelPt.h"
#include "..\WindowsPtDriver\DriverIo.h"

#define DEFAULT_TRACE_BUFF_SIZE 64 * 1024			// Default TRACE buffer size
#define ROUND_TO_PAGES(Size)  (((ULONG_PTR)(Size) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))
#define PAGE_SIZE 0x1000

// The Application global data
struct GLOBAL_DATA {
	DWORD dwTraceBuffSize;						// The size of the trace buffer
	BOOLEAN bTraceByIp;							// TRUE if I have to trace by IP
	HANDLE hTraceFile;							// The trace file handle
	HANDLE hTraceTextFile;						// The text trace file handle
	HANDLE hPtDev;								// The handle to the Intel PT device
	HANDLE hTargetProc;							// The traced process handle
	LPBYTE lpPtBuff;							// The Trace buffer
	DWORD dwTraceSize;							// The trace size in BYTES
	HANDLE hExitEvt;							// The handle to the exit event
	HANDLE hPmiThread;							// The handle of the current PMI thread
	DWORD dwMainThrId;							// The main application thread ID
	PT_USER_REQ currentTrace;

	GLOBAL_DATA() { dwTraceBuffSize = DEFAULT_TRACE_BUFF_SIZE; bTraceByIp = TRUE; }
};
// The only unique GLOBAL_DATA structure
extern GLOBAL_DATA g_appData;		// (defined in EntryPoint.cpp)

// Application Entry Point
int wmain(int argc, LPTSTR argv[]);

// Entry point without command line arguments
int NoCmdlineStartup();

// Show command line usage
void ShowCommandLineUsage();

// Parse command line
bool ParseCommandLine(int argc, LPTSTR argv[]);

// Check the support of Intel Processor Tarce on this CPU
BOOL CheckIntelPtSupport(INTEL_PT_CAPABILITIES * lpPtCap);

// The PMI interrupt Thread 
DWORD WINAPI PmiThreadProc(LPVOID lpParameter);

// Spawn a suspended process and oblige the loader to load the remote image in memory
BOOL SpawnSuspendedProcess(LPTSTR lpAppName, LPTSTR lpCmdLine, PROCESS_INFORMATION * outProcInfo);

// Parse the command line arguments
bool ParseCommandLine();

// Try some Kernel tracing activity :-)
bool DoKernelTrace(HANDLE hPtDev, PT_USER_REQ ptUserReq, LPTSTR lpDrvName);


// AaLl86 Test driver stuff
typedef struct _KERNEL_MODULE {
	LPVOID lpStartAddr;
	DWORD dwSize;
	TCHAR modName[100];
}KERNEL_MODULE, *PKERNEL_MODULE;

// Search a particular kernel module in memory and return the associated structure
#define IOCTL_PTBUG_SEARCHKERNELMODULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0xB01, METHOD_BUFFERED, FILE_READ_DATA)
// Kernel Tracing Test IOCTL
#define IOCTL_PTDR_DO_KERNELDRV_TEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA0C, METHOD_BUFFERED, FILE_EXECUTE)
