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

// The PT buffer data structure
struct PT_CPU_BUFFER_DESC {
	HANDLE hBinFile;						// The binary file handle
	HANDLE hTextFile;						// The human readable file handle
	LPBYTE lpPtBuff;						// The PT buffer pointer
	DWORD dwBuffSize;						// The PT buffer size in BYTEs
	QWORD qwDelta;							// The delta value used in translating each packet
	HANDLE hPmiThread;						// The handle of the current PMI thread
	DWORD dwPmiThrId;						// The PMI Thread ID
};

// The Application global data
struct GLOBAL_DATA {
	DWORD dwTraceBuffSize;						// The size of the trace buffer
	BOOLEAN bTraceByIp;							// TRUE if I have to trace by IP
	BOOLEAN bTraceOnlyKernel;					// TRUE if I would like to trace only kernel
	HANDLE hPtDev;								// The handle to the Intel PT device
	HANDLE hTargetProc;							// The traced process handle
	HANDLE hExitEvt;							// The handle to the exit event
	DWORD dwMainThrId;							// The main application thread ID
	HANDLE hMainThr;							// The handle of the main application thread
	PT_USER_REQ currentTrace;
	PT_CPU_BUFFER_DESC * pCpuDescArray;			// The PT CPU buffer descriptor array ptr
	DWORD dwNumOfActiveCpus;					// The number of active CPUs
	KAFFINITY kActiveCpuAffinity;				// The current active CPUs affinity mask

	// Struct constructor
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
// The PMI callback
VOID PmiCallback(DWORD dwCpuId, PVOID lpBuffer, QWORD qwBufferSize);

// Spawn a suspended process and oblige the loader to load the remote image in memory
BOOL SpawnSuspendedProcess(LPTSTR lpAppName, LPTSTR lpCmdLine, PROCESS_INFORMATION * outProcInfo);

// Parse the command line arguments
bool ParseCommandLine();

// Try some Kernel tracing activity :-)
bool DoKernelTrace(HANDLE hPtDev, PT_USER_REQ ptUserReq, LPTSTR lpDrvName);

// Initialize and open the per-CPU files and data structures
bool InitPerCpuData(ULONG_PTR kCpuAffinity, LPTSTR lpBasePath);

// Close and flush the per-CPU files and data structures
bool FreePerCpuData(BOOL bDeleteFiles = FALSE);

// Write the human readable dump file header
bool WriteCpuTextDumpsHeader(LPTSTR lpImgName, ULONG_PTR qwBase, DWORD dwSize, BOOLEAN bKernelTrace = FALSE);



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
