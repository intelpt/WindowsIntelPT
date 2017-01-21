/**********************************************************************
 *  Windows Intel Processor Trace (PT) Driver
 *  Filename: IntelPtControlApp.cpp
 *	Implement the entire PT driver's Control Application 
 *  Last revision: 12/01/2016
 *
 *  Copyright© 2016 Andrea Allievi, Richard Johnson
 *  Microsoft Ltd & TALOS Research and Intelligence Group
 *  All right reserved
 **********************************************************************/
#include "stdafx.h"
#include "IntelPtControlApp.h"
#include "Psapi.h"
#include <crtdbg.h>
#include "pt_dump.h"
#include "UndocNt.h"
const LPTSTR g_ptDevName = L"\\\\.\\WindowsIntelPtDev";
#pragma comment (lib, "ntdll.lib")

// Entry point without command line arguments
int NoCmdlineStartup()
{
	BOOL bRetVal = FALSE;
	INTEL_PT_CAPABILITIES ptCap = { 0 };
	HANDLE hPtDev = NULL,							// Handle to the PT device
		hPmiThread = NULL;							// Handle to the PMI thread
	TCHAR procPath[MAX_PATH] = { 0 };				// The target process full path
	PT_USER_REQ ptStartStruct = { 0 };				// The Intel PT starting structure
	LPBYTE lpPtBuff = NULL;							// The Trace buffer
	DWORD dwBytesIo = 0;							// Number of I/O bytes
	DWORD dwTargetCpu = 0;							// The target CPU
	DWORD dwPmiThrId = 0;							// The PMI Thread ID
	DWORD dwLastErr = 0;							// Last Win32 Error
	DWORD_PTR cpuAffinity = 0;						// The processor Affinity mask
	BOOLEAN bDoKernelTrace = FALSE;					// TRUE if I would like to do kernel tracing
	PROCESS_INFORMATION pi = { 0 };

	// Output files:
	LPTSTR lpOutBinFile = NULL;						// The binary dump file
	LPTSTR lpOutTxtFile = NULL;						// The text dump file

	// Allocate memory for the file names
	lpOutBinFile = new TCHAR[MAX_PATH]; RtlZeroMemory(lpOutBinFile, MAX_PATH * sizeof(TCHAR));
	lpOutTxtFile = new TCHAR[MAX_PATH]; RtlZeroMemory(lpOutTxtFile, MAX_PATH * sizeof(TCHAR));

	bRetVal = CheckIntelPtSupport(&ptCap);
	wprintf(L"Intel Processor Tracing support for this CPU: ");
	if (bRetVal) cl_wprintf(GREEN, L"YES\r\n"); else cl_wprintf(RED, L"NO\r\n");
	hPtDev = CreateFile(g_ptDevName, FILE_ALL_ACCESS, 0, NULL, OPEN_EXISTING, 0, NULL);
	dwLastErr = GetLastError();

	if (hPtDev == INVALID_HANDLE_VALUE) {
		wprintf(L"Unable to open the Intel PT device object!\r\n");
		return 0;
	}
	else
		g_appData.hPtDev = hPtDev;

	// Create the Exit Event
	g_appData.hExitEvt = CreateEvent(NULL, FALSE, FALSE, NULL);

	#pragma region Generate Output file names
	GetModuleFileName(GetModuleHandle(NULL), lpOutBinFile, MAX_PATH);
	GetModuleFileName(GetModuleHandle(NULL), lpOutTxtFile, MAX_PATH);
	LPTSTR slashPtr = wcsrchr(lpOutBinFile, L'\\');
	if (slashPtr) {
		slashPtr[1] = 0; lpOutTxtFile[slashPtr - lpOutBinFile + 1] = 0;
	}
	wcscat_s(lpOutBinFile, MAX_PATH, L"pt_dump.bin");
	wcscat_s(lpOutTxtFile, MAX_PATH, L"pt_dump.txt");
	#pragma endregion

	TCHAR answer[10] = { 0 };
	wprintf(L"Would you like to do the Kernel Tests? [Y/N] ");
	wscanf_s(L"%2s", answer, 10);
	if ((answer[0] | 0x20) == L'y') {
		g_appData.dwMainThrId = GetCurrentThreadId();
		bDoKernelTrace = TRUE;
	}

	wprintf(L"Insert here the target %s to trace: ", (bDoKernelTrace ? L"kernel driver" : L"process"));
	wscanf_s(L"%s", procPath, MAX_PATH);

	#pragma region Create the Trace Files
	wprintf(L"Creating trace files (binary and readable)... ");
	HANDLE hBinDump = CreateFile(lpOutBinFile, FILE_GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
	HANDLE hTxtDump = CreateFile(lpOutTxtFile, FILE_GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
	if (hBinDump == INVALID_HANDLE_VALUE || hTxtDump == INVALID_HANDLE_VALUE) {
		cl_wprintf(RED, L"Error!\r\n");
		CloseHandle(hPtDev);
		return -1;
	}
	cl_wprintf(GREEN, L"OK\r\n");
	g_appData.hTraceFile = hBinDump;
	if (hTxtDump != INVALID_HANDLE_VALUE)
		g_appData.hTraceTextFile = hTxtDump;
	#pragma endregion

	#pragma region Spawn of the new process and PMI thread code
	if (!bDoKernelTrace) {
		wprintf(L"Creating target process... ");
		bRetVal = SpawnSuspendedProcess(procPath, NULL, &pi);
		if (bRetVal) cl_wprintf(GREEN, L"OK\r\n");
		else {
			wprintf(L"Error!\r\n");
			CloseHandle(hPtDev);
			wprintf(L"Press any key to exit...");
			getwchar();
			return -1;
		}
		g_appData.hTargetProc = pi.hProcess;
	} else {
		// Set this process as the remote one
		pi.hProcess = GetCurrentProcess();
		pi.hThread = GetCurrentThread();
		pi.dwProcessId = GetCurrentProcessId();
	}

	// The following 3 lines are really important:
	cpuAffinity = (1i64 << dwTargetCpu);			// Only CPU 0 for now
	if (!bDoKernelTrace) bRetVal = SetProcessAffinityMask(pi.hProcess, cpuAffinity);
	else bRetVal = (BOOL)SetThreadAffinityMask(pi.hThread, cpuAffinity);
	_ASSERT(bRetVal);
	if (!bRetVal) {
		cl_wprintf(YELLOW, L"Warning!\r\n");
		wprintf(L"   Unable Set the processor affinity for the spawned process.\r\n");
	}

	// Create the PMI thread
	hPmiThread = CreateThread(NULL, 0, PmiThreadProc, NULL, 0, &dwPmiThrId);
	g_appData.hPmiThread = hPmiThread;
	#pragma endregion

	#pragma region Set IP filtering
	if (g_appData.bTraceByIp) {
		// Now grab the remote image base address and size
		HMODULE hRemoteMod = NULL;						// The remote module base address
		MODULEINFO remoteModInfo = { 0 };				// The remote module information
		if (!bDoKernelTrace) {
			bRetVal = EnumProcessModules(pi.hProcess, &hRemoteMod, sizeof(HMODULE), &dwBytesIo);
			bRetVal = GetModuleInformation(pi.hProcess, hRemoteMod, &remoteModInfo, sizeof(MODULEINFO));
			dwLastErr = GetLastError();
		}
		else {
			// Grab the target module base address
			SYSTEM_ALL_MODULES * pSysAllModules = NULL;
			NTSTATUS ntStatus = 0;
			CHAR modNameAnsi[0x80] = { 0 };
			sprintf_s(modNameAnsi, COUNTOF(modNameAnsi), "%S", procPath);
			ntStatus = ZwQuerySystemInformation(11, pSysAllModules, 0, &dwBytesIo);
			if (ntStatus == STATUS_INFO_LENGTH_MISMATCH) {
				pSysAllModules = (SYSTEM_ALL_MODULES*)VirtualAlloc(NULL, dwBytesIo + 64, MEM_COMMIT, PAGE_READWRITE);
				RtlZeroMemory(pSysAllModules, dwBytesIo);

				ntStatus = ZwQuerySystemInformation(11, pSysAllModules, dwBytesIo, &dwBytesIo);
				if (ntStatus == 0) {
					// Search for SimplePt
					for (unsigned i = 0; i < pSysAllModules->dwNumOfModules; i++) {
						SYSTEM_MODULE_INFORMATION curMod = pSysAllModules->modules[i];
						LPSTR lpTargetModName = curMod.ImageName + curMod.ModuleNameOffset;
						if (_stricmp(modNameAnsi, lpTargetModName) == 0) {
							// Target module found
							wprintf(L"Found \"%S\" kernel driver in memory.\r\n", lpTargetModName);
							remoteModInfo.lpBaseOfDll = curMod.Base;
							remoteModInfo.SizeOfImage = curMod.Size;
							break;
						}
					}
				}
			}
			if (pSysAllModules) VirtualFree((LPVOID)pSysAllModules, 0, MEM_RELEASE);
			ptStartStruct.bTraceKernel = TRUE;
			ptStartStruct.bTraceUser = FALSE;
		}

		#ifdef _DEBUG
		if (!remoteModInfo.lpBaseOfDll && _wcsicmp(procPath, L"AaLl86TestDriver.sys") == 0) {
			wprintf(L"Would you like to perform the Tracing test from Kernel-mode? [Y/N] ");
			wscanf_s(L"%2s", answer, 10);
			// Do the special Kernel-mode test of AaLl86
			if ((answer[0] | 0x20) == L'y') {
				if (hBinDump != INVALID_HANDLE_VALUE) CloseHandle(hBinDump);
				if (hTxtDump != INVALID_HANDLE_VALUE) CloseHandle(hTxtDump);
				DoKernelTrace(hPtDev, PT_USER_REQ(), procPath);
				CloseHandle(hPtDev);
				return 0;
			}
		}
		#endif

		if (!remoteModInfo.lpBaseOfDll) {
			cl_wprintf(RED, L"Error! ");
			wprintf(L"I was not able to find the target %s base address and size.\r\n", (bDoKernelTrace ? L"kernel module" : L"process' main module"));
			if (hBinDump != INVALID_HANDLE_VALUE) CloseHandle(hBinDump);
			if (hTxtDump != INVALID_HANDLE_VALUE) CloseHandle(hTxtDump);
			CloseHandle(hPtDev);
			return -1;
		}

		cl_wprintf(PINK, L"\r\n       Using IP filtering mode!\r\n");
		wprintf(L"%s base address: 0x%llX, size 0x%08X.\r\n\r\n", (bDoKernelTrace ? L"Target kernel driver" : L"New Process main module"),
			(QWORD)remoteModInfo.lpBaseOfDll, remoteModInfo.SizeOfImage);

		// Set the PT_USER_REQUEST structure
		ptStartStruct.IpFiltering.dwNumOfRanges = 1;
		ptStartStruct.IpFiltering.Ranges[0].lpStartVa = (LPVOID)((ULONG_PTR)remoteModInfo.lpBaseOfDll);
		ptStartStruct.IpFiltering.Ranges[0].lpEndVa = (LPVOID)((ULONG_PTR)remoteModInfo.lpBaseOfDll + remoteModInfo.SizeOfImage);
		ptStartStruct.IpFiltering.Ranges[0].bStopTrace = FALSE;

		// Write some information in the output text file:
		if (hTxtDump != INVALID_HANDLE_VALUE) {
			CHAR fullLine[0x200] = { 0 };
			sprintf_s(fullLine, COUNTOF(fullLine), "Intel PT Trace file. Version 0.4\r\n");
			WriteFile(hTxtDump, fullLine, (DWORD)strlen(fullLine), &dwBytesIo, NULL);
			if (!bDoKernelTrace)
				sprintf_s(fullLine, COUNTOF(fullLine), "Executable name: %S\r\n", wcsrchr(procPath, L'\\') + 1);
			else
				sprintf_s(fullLine, COUNTOF(fullLine), "Kernel driver name: %S\r\n", procPath);
			WriteFile(hTxtDump, fullLine, (DWORD)strlen(fullLine), &dwBytesIo, NULL);
			sprintf_s(fullLine, COUNTOF(fullLine), "Base address: 0x%016llX - Size 0x%08X\r\n", (QWORD)remoteModInfo.lpBaseOfDll, remoteModInfo.SizeOfImage);
			WriteFile(hTxtDump, fullLine, (DWORD)strlen(fullLine), &dwBytesIo, NULL);
			sprintf_s(fullLine, COUNTOF(fullLine), "\r\n");
			WriteFile(hTxtDump, fullLine, (DWORD)strlen(fullLine), &dwBytesIo, NULL);
		}
	}		// END Tracing by IP block
	#pragma endregion

	if (hTxtDump != INVALID_HANDLE_VALUE)
		WriteFile(hTxtDump, "Begin Trace Dump:\r\n", (DWORD)strlen("Begin Trace Dump:\r\n"), &dwBytesIo, NULL);
	// For now do not set the frequencies....
	//ptStartStruct.dwOptsMask = PT_TRACE_TSC_PCKS_MASK | PT_TRACE_BRANCH_PCKS_MASK | PT_ENABLE_RET_COMPRESSION_MASK;
	ptStartStruct.dwTraceSize = g_appData.dwTraceBuffSize;
	ptStartStruct.dwCpuId = dwTargetCpu;

	#pragma region Kernel Mode Tracing (experimental)
	if (bDoKernelTrace) {
		DoKernelTrace(hPtDev, ptStartStruct, procPath);
		if (hBinDump != INVALID_HANDLE_VALUE) CloseHandle(hBinDump);
		if (hTxtDump != INVALID_HANDLE_VALUE) CloseHandle(hTxtDump);
		CloseHandle(hPtDev);
		return 0;
	}
	#pragma endregion

	// Start the device Tracing
	wprintf(L"Starting the Tracing and resuming the process... ");
	ptStartStruct.dwProcessId = pi.dwProcessId;
	bRetVal = DeviceIoControl(hPtDev, IOCTL_PTDRV_START_TRACE, (LPVOID)&ptStartStruct, sizeof(PT_USER_REQ), &lpPtBuff, sizeof(LPVOID), &dwBytesIo, NULL);

	if (bRetVal) {
		cl_wprintf(GREEN, L"OK\r\n");
		g_appData.lpPtBuff = lpPtBuff;
		g_appData.dwTraceSize = g_appData.dwTraceBuffSize;
		g_appData.currentTrace = ptStartStruct;

		// Resume the target process
		wprintf(L"\r\n");
		Sleep(100);
		ResumeThread(pi.hThread);
		wprintf(L"Waiting for the traced process to exit...\r\n");
		WaitForSingleObject(pi.hProcess, INFINITE);
		wprintf(L"\r\n");
	}
	else  {
		TerminateProcess(pi.hProcess, -1);
		cl_wprintf(RED, L"Error!\r\n");
	}

	SetEvent(g_appData.hExitEvt);
	WaitForSingleObject(hPmiThread, INFINITE);

	// Get the number of written packets
	PT_TRACE_DETAILS ptDetails = { 0 };
	bRetVal = DeviceIoControl(hPtDev, IOCTL_PTDR_GET_TRACE_DETAILS, (LPVOID)&dwTargetCpu, 4, (LPVOID)&ptDetails, sizeof(ptDetails), &dwBytesIo, NULL);
	wprintf(L"Total number of Trace packets stored in the Dump: %I64i\r\n", ptDetails.qwTotalNumberOfPackets);

	// Free the resources
	CloseHandle(hPmiThread);
	CloseHandle(pi.hProcess); 
	CloseHandle(pi.hThread);
	if (hBinDump != INVALID_HANDLE_VALUE) CloseHandle(hBinDump);
	if (hTxtDump != INVALID_HANDLE_VALUE) CloseHandle(hTxtDump);

	// Don't forget to clear the trace buffer otherwise we will bugcheck
	bRetVal = DeviceIoControl(hPtDev, IOCTL_PTDRV_CLEAR_TRACE, (LPVOID)&dwTargetCpu, sizeof(DWORD), NULL, 0, &dwBytesIo, NULL);
	CloseHandle(hPtDev);
    return 0;
}

// Check if the current CPU has support for Intel PT
BOOL CheckIntelPtSupport(INTEL_PT_CAPABILITIES * lpPtCap)
{
	INTEL_PT_CAPABILITIES ptCap = { 0 };
	int cpuid_ctx[4] = { 0 };			// EAX, EBX, ECX, EDX

	// Processor support for Intel Processor Trace is indicated by CPUID.(EAX=07H,ECX=0H):EBX[bit 25] = 1.
	__cpuidex(cpuid_ctx, 0x07, 0);
	if (!(cpuid_ctx[1] & (1 << 25))) return FALSE;

	// Now enumerate the Intel Processor Trace capabilities
	RtlZeroMemory(cpuid_ctx, sizeof(cpuid_ctx));
	__cpuidex(cpuid_ctx, 0x14, 0);
	// If the maximum valid sub-leaf index is 0 exit immediately
	if (cpuid_ctx[0] == 0) return FALSE;

	ptCap.bCr3Filtering = (cpuid_ctx[1] & (1 << 0)) != 0;					// EBX
	ptCap.bConfPsbAndCycSupported = (cpuid_ctx[1] & (1 << 1)) != 0;
	ptCap.bIpFiltering = (cpuid_ctx[1] & (1 << 2)) != 0;
	ptCap.bMtcSupport = (cpuid_ctx[1] & (1 << 3)) != 0;
	ptCap.bTopaOutput = (cpuid_ctx[2] & (1 << 0)) != 0;						// ECX
	ptCap.bTopaMultipleEntries = (cpuid_ctx[2] & (1 << 1)) != 0;
	ptCap.bSingleRangeSupport = (cpuid_ctx[2] & (1 << 2)) != 0;
	ptCap.bTransportOutputSupport = (cpuid_ctx[2] & (1 << 3)) != 0;
	ptCap.bIpPcksAreLip = (cpuid_ctx[2] & (1 << 31)) != 0;

	// Enmeration part 2:
	RtlZeroMemory(cpuid_ctx, sizeof(cpuid_ctx));
	__cpuidex(cpuid_ctx, 0x14, 1);
	ptCap.numOfAddrRanges = (BYTE)(cpuid_ctx[0] & 0x7);
	ptCap.mtcPeriodBmp = (SHORT)((cpuid_ctx[0] >> 16) & 0xFFFF);
	ptCap.cycThresholdBmp = (SHORT)(cpuid_ctx[1] & 0xFFFF);
	ptCap.psbFreqBmp = (SHORT)((cpuid_ctx[1] >> 16) & 0xFFFF);

	if (lpPtCap) *lpPtCap = ptCap;
	return TRUE;
}
// Spawn a suspended process and oblige the loader to load the remote image in memory
BOOL SpawnSuspendedProcess(LPTSTR lpAppName, LPTSTR lpCmdLine, PROCESS_INFORMATION * pOutProcInfo) {
	BYTE remote_opcodes[] = { 0x90, 0x90, 0xc3, 0x90, 0x90 };			// NOP - RET opcodes
	PROCESS_INFORMATION pi = { 0 };					// Process information
	STARTUPINFO si = { 0 };							// The process Startup options
	ULONG_PTR ulBytesIo = 0;						// Number of I/O bytes
	LPVOID lpRemBuff = NULL;						// Remote memory buffer
	HANDLE hRemoteThr = NULL;						// The remote thread stub 
	BOOL bRetVal = FALSE;							// Win32 return value
	DWORD dwThrId = 0;								// Remote thread ID

	si.cb = sizeof(STARTUPINFO);
	bRetVal = CreateProcess(lpAppName, lpCmdLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

	// To get the remote image base address I need to instruct the Windows loader to load the 
	// Target image file in memory, and to compile the PEB
	lpRemBuff = VirtualAllocEx(pi.hProcess, NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (lpRemBuff) 
		bRetVal = WriteProcessMemory(pi.hProcess, lpRemBuff, (LPCVOID)remote_opcodes, sizeof(remote_opcodes), (SIZE_T*)&ulBytesIo);
	else
		bRetVal = FALSE;

	if (bRetVal) 
		hRemoteThr = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpRemBuff, NULL, 0, &dwThrId);

	if (hRemoteThr) {
		WaitForSingleObject(hRemoteThr, INFINITE);
		if (lpRemBuff) VirtualFreeEx(pi.hProcess, lpRemBuff, 0, MEM_RELEASE);

		// Get rid of it:
		CloseHandle(hRemoteThr);
		if (pOutProcInfo) *pOutProcInfo = pi;
		return TRUE;
	} else {
		TerminateProcess(pi.hProcess, -1);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return FALSE;
	}
}

// The PMI interrupt Thread 
DWORD WINAPI PmiThreadProc(LPVOID lpParameter) {
	LPTSTR lpEventName = L"Global\\" INTEL_PT_PMI_EVENT_NAME;
	HANDLE hKernelEvt = NULL;
	BOOL bRetVal = FALSE;										// Returned Win32 value
	DWORD dwBytesIo = 0,										// Number of I/O bytes
		dwEvtNum = 0,											// The event number that has satisfied the wait
		dwLastErr = 0;											// Last Win32 error
	HANDLE hWaitEvts[2] = { 0 };
	HANDLE hMainThread = NULL;									// An handle of the main program thread (if any, used for Kernel tracing)

	hKernelEvt = OpenEvent(SYNCHRONIZE, FALSE, lpEventName);
	dwLastErr = GetLastError();

	if (!hKernelEvt) return -1;
	hWaitEvts[0] = hKernelEvt;
	hWaitEvts[1] = g_appData.hExitEvt;

	// Check if there is the main thread, open if so
	if (g_appData.dwMainThrId) 
		hMainThread = OpenThread(SYNCHRONIZE | THREAD_SUSPEND_RESUME, FALSE, g_appData.dwMainThrId);

	while (TRUE) {
		LPBYTE lpTraceBuff = NULL;						// The PT tracing buffer
		DWORD dwTraceBuffSize = 0;						// The trace buffer size
		HANDLE hTraceBinFile = NULL;					// The trace BINARY file
		HANDLE hTraceTextFile = NULL;					// The trace Text file
		QWORD qwDelta = 0;								// Offset DELTA value
		dwEvtNum = WaitForMultipleObjects(2, hWaitEvts, FALSE, INFINITE);

		// Grab the parameters
		lpTraceBuff = g_appData.lpPtBuff;
		dwTraceBuffSize = g_appData.dwTraceSize;
		hTraceBinFile = g_appData.hTraceFile;
		hTraceTextFile = g_appData.hTraceTextFile;
		
		if (dwEvtNum - WAIT_OBJECT_0 == 1) {
			// We are exiting, pause the Tracing
			bRetVal = DeviceIoControl(g_appData.hPtDev, IOCTL_PTDRV_PAUSE_TRACE, (LPVOID)&g_appData.currentTrace.dwCpuId, sizeof(DWORD), NULL, 0, &dwBytesIo, NULL);
		}
		if (!lpTraceBuff)
			// Continue and do not bother about anything here
			continue;

		// Suspend the main thread if any
		if (hMainThread) SuspendThread(hMainThread);

		if (hTraceBinFile) {
			bRetVal = WriteFile(hTraceBinFile, lpTraceBuff, dwTraceBuffSize, &dwBytesIo, NULL);
			if (!bRetVal) {
				cl_wprintf(RED, L"Warning! ");
				wprintf(L"Unable to write in the log file. Results could be erroneous.\r\n");
			}
		}
		if (hTraceTextFile) {
			// Dump the text trace file immediately
			bRetVal = pt_dumpW(lpTraceBuff, dwTraceBuffSize, hTraceTextFile, qwDelta);
			qwDelta += (QWORD)dwTraceBuffSize;
		}
		RtlZeroMemory(lpTraceBuff, dwTraceBuffSize);

		// If I am here the PMI interrupt has been fired
		if (dwEvtNum - WAIT_OBJECT_0 == 0) {
			// Resume the tracing and the execution of the target process
			bRetVal = DeviceIoControl(g_appData.hPtDev, IOCTL_PTDRV_RESUME_TRACE, (LPVOID)&g_appData.currentTrace.dwCpuId, sizeof(DWORD), NULL, 0, &dwBytesIo, NULL);
			if (!g_appData.currentTrace.bTraceKernel)
				ZwResumeProcess(g_appData.hTargetProc);
			if (hMainThread) ResumeThread(hMainThread);
		} else
			// Exit from this thread
			break;
	}

	if (hMainThread) ResumeThread(hMainThread);
	CloseHandle(hMainThread);
	return 0;
}

// Try some Kernel tracing activity :-)
bool DoKernelTrace(HANDLE hPtDev, PT_USER_REQ ptUserReq, LPTSTR lpDrvName) {
	BOOL bRetVal = FALSE;
	HANDLE hTestDev = NULL;
	DWORD dwLastErr = 0, dwBytesIo = 0;
	KERNEL_MODULE kernelMod = { 0 };
	LPVOID lpPtBuff = NULL;
	TCHAR answer[0x20] = { 0 };

#ifdef _DEBUG
	// Specific Test Driver data:
	const LPTSTR DosDevName = L"\\\\.\\IntelPtTest";
	LPTSTR lpKernelModName = L"acpi.sys";

	bool bAaLl86Test = (_wcsicmp(lpDrvName, L"AaLl86TestDriver.sys") == 0);
	
	if (bAaLl86Test && ptUserReq.dwTraceSize == 0) {
		// Here theoretically I have to open the target driver module and insert the special BAD_OPCODE 
		// BUT I am too lazy.
		wprintf(L"Testing Kernel-mode Tracing from a Kernel module... ");
		// Send the special IOCTLs
		dwBytesIo = (wcslen(lpDrvName) + 1) * sizeof(WCHAR);
		bRetVal = DeviceIoControl(hPtDev, IOCTL_PTDR_DO_KERNELDRV_TEST, (LPVOID)lpDrvName, dwBytesIo, NULL, 0, &dwBytesIo, NULL);
		if (bRetVal) {
			cl_wprintf(GREEN, L"OK\r\n");
			wprintf(L"The dump file has been saved in the \"C:\" volume.\r\n");
			return true;
		}
		else {
			cl_wprintf(RED, L"Error!\r\n");
			return false;
		}
	}


	if (bAaLl86Test) {
		// Open the target kernel device object
		wprintf(L"Simple Kernel Driver Test - Opening the device... ");
		hTestDev = CreateFile(DosDevName, FILE_ALL_ACCESS, 0, NULL, OPEN_EXISTING, 0, NULL);
		dwLastErr = GetLastError();
		if (hTestDev != INVALID_HANDLE_VALUE)
			cl_wprintf(GREEN, L"OK\r\n");
		else {
			cl_wprintf(RED, L"Error!\r\n");
			return false;
		}
	}
	#endif

	// Start the device Tracing
	wprintf(L"Starting the Kernel-mode Tracing... ");
	bRetVal = DeviceIoControl(hPtDev, IOCTL_PTDRV_START_TRACE, (LPVOID)&ptUserReq, sizeof(PT_USER_REQ), &lpPtBuff, sizeof(LPVOID), &dwBytesIo, NULL);

	if (bRetVal) {
		cl_wprintf(GREEN, L"OK\r\n");
		g_appData.lpPtBuff = (LPBYTE)lpPtBuff;
		g_appData.dwTraceSize = g_appData.dwTraceBuffSize;
		g_appData.currentTrace = ptUserReq;
	}
	else {
		cl_wprintf(RED, L"Error!\r\n");
		return false;
	}
	Sleep(100);

	#ifdef _DEBUG
	if (bAaLl86Test) {
		wprintf(L"Doing some test malicious activity (this could crash your system)... ");
		// Test the Search Module IOCTL
		bRetVal = DeviceIoControl(hTestDev, IOCTL_PTBUG_SEARCHKERNELMODULE, (LPVOID)lpKernelModName, (DWORD)(wcslen(lpKernelModName) + 1) * sizeof(WCHAR), 
			(LPVOID)&kernelMod,	sizeof(KERNEL_MODULE), &dwBytesIo, NULL);
		dwLastErr = GetLastError();

		if (bRetVal) {
			LPBYTE lpBuff = new BYTE[0x1000];
			bRetVal = ReadFile(hTestDev, (LPVOID)lpBuff, 0x1000, &dwBytesIo, NULL);

			if (bRetVal && lpBuff[0] == 'M' && lpBuff[1] == 'Z') {
				LPSTR lpValue = "test test test!";
				DWORD dwOffset = 0xF0;

				bRetVal = SetFilePointer(hTestDev, dwOffset, NULL, FILE_BEGIN);
				bRetVal = WriteFile(hTestDev, (LPCVOID)lpValue, (DWORD)strlen(lpValue), &dwBytesIo, NULL);
			}
		}
		if (bRetVal)
			cl_wprintf(GREEN, L"OK\r\n");
		else
			cl_wprintf(RED, L"Error!\r\n");
	}
	else 
	#endif //_DEBUG
	{
		wprintf(L"\r\n\r\nPress any key when you would like to stop the tracing...\r\n");
		rewind(stdin);
		getwchar();
	}

	// END the tracing
	SetEvent(g_appData.hExitEvt);
	WaitForSingleObject(g_appData.hPmiThread, INFINITE);
	CloseHandle(g_appData.hPmiThread);

	// Get the number of written packets
	PT_TRACE_DETAILS ptDetails = { 0 };
	bRetVal = DeviceIoControl(hPtDev, IOCTL_PTDR_GET_TRACE_DETAILS, (LPVOID)&ptUserReq.dwCpuId, 4, (LPVOID)&ptDetails, sizeof(ptDetails), &dwBytesIo, NULL);
	wprintf(L"Total number of Trace packets stored in the Dump: %I64i\r\n", ptDetails.qwTotalNumberOfPackets);

	// Don't forget to clear the trace buffer otherwise we will bugcheck
	DeviceIoControl(hPtDev, IOCTL_PTDRV_CLEAR_TRACE, (LPVOID)&ptUserReq.dwCpuId, sizeof(DWORD), NULL, 0, &dwBytesIo, NULL);
	CloseHandle(hTestDev);	
	return (bRetVal != FALSE);
}
