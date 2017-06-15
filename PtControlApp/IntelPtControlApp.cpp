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
	HANDLE hPtDev = NULL;							// Handle to the PT device
	TCHAR procPath[MAX_PATH] = { 0 };				// The target process full path
	PT_USER_REQ ptStartStruct = { 0 };				// The Intel PT starting structure
	DWORD dwBytesIo = 0;							// Number of I/O bytes
	DWORD dwCpusCount = 1;							// Number of CPUs in which to run the code
	DWORD dwLastErr = 0;							// Last Win32 Error
	KAFFINITY cpuAffinity = 0;						// The processor Affinity mask
	BOOLEAN bDoKernelTrace = FALSE;					// TRUE if I would like to do kernel tracing
	PT_CPU_BUFFER_DESC * pCpuDescArray;				// The CPU PT buffer descriptor array
	LPTSTR lpOutBasePath = NULL;					// The dump files base directory
	BOOLEAN bManuallyAllocBuff = FALSE;				// TRUE if I would like to manually allocate the buffer (used for test purposes)
	BOOLEAN bDeleteFiles = FALSE;					// TRUE if some errors that require the file deletion
	PROCESS_INFORMATION pi = { 0 };
	SYSTEM_INFO sysInfo = { 0 };

	// Allocate memory for the file names
	lpOutBasePath = new TCHAR[MAX_PATH]; 
	RtlZeroMemory(lpOutBasePath, MAX_PATH * sizeof(TCHAR));

	GetNativeSystemInfo(&sysInfo);
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
	g_appData.hExitEvt = CreateEvent(NULL, TRUE, FALSE, NULL);

	#pragma region 1. Generate Output dunp files base path string 
	SYSTEMTIME curTime = { 0 };
	GetModuleFileName(GetModuleHandle(NULL), lpOutBasePath, MAX_PATH);
	GetLocalTime(&curTime);
	LPTSTR slashPtr = wcsrchr(lpOutBasePath, L'\\');
	if (slashPtr) slashPtr[1] = 0; 
	swprintf_s(lpOutBasePath, MAX_PATH, L"%s%.2i%.2i-%.2i%.2i%.4i_Dumps",
		lpOutBasePath, curTime.wHour, curTime.wMinute, curTime.wMonth, curTime.wDay, curTime.wYear);
	CreateDirectory(lpOutBasePath, NULL);
	#pragma endregion

	#pragma region 2. Ask the user and check the CPU affinity
	TCHAR answer[10] = { 0 };
	wprintf(L"Would you like to do the Kernel Tests? [Y/N] ");
	wscanf_s(L"%2s", answer, 10);
	if ((answer[0] | 0x20) == L'y') {
		g_appData.dwMainThrId = GetCurrentThreadId();
		bDoKernelTrace = TRUE;
	}

	wprintf(L"Insert here the target %s to trace: ", (bDoKernelTrace ? L"kernel driver" : L"process"));
	wscanf_s(L"%s", procPath, MAX_PATH);
	if (sysInfo.dwNumberOfProcessors > 1) {
		// Ask how many processor to use
		wprintf(L"On how many processors would you like to run the process? [1/%i] ", sysInfo.dwNumberOfProcessors);
		wscanf_s(L"%i", &dwCpusCount);

		if (dwCpusCount > sysInfo.dwNumberOfProcessors) {
			wprintf(L"Invalid value, assuming all the processors as valid.\r\n");
			cpuAffinity = sysInfo.dwActiveProcessorMask;
		} else
			cpuAffinity = ((DWORD_PTR)(-1i64) >> ((sizeof(DWORD_PTR) * 8) - dwCpusCount));
		if (FALSE) 
			// If you would like to test the different affinities:
			cpuAffinity = 0xd;
		_ASSERT((sysInfo.dwActiveProcessorMask | cpuAffinity) == sysInfo.dwActiveProcessorMask);
	}
	else
	{
		cpuAffinity = sysInfo.dwActiveProcessorMask;
	}
#pragma endregion
	
	#pragma region 3. Create the CPU buffer data structures and trace files
	wprintf(L"Creating trace files (binary and readable)... ");
	bRetVal = (BOOL)InitPerCpuData(cpuAffinity, lpOutBasePath);
	if (bRetVal) 
		cl_wprintf(GREEN, L"Success!\r\n");
	else {
		RemoveDirectory(lpOutBasePath);
		// We are great, we would like to try to write to the TEMP directory
		dwBytesIo = GetTempPath(MAX_PATH, lpOutBasePath);
		LPTSTR slashPtr = wcsrchr(lpOutBasePath, L'\\');
		if (lpOutBasePath[dwBytesIo - 1] == '\\')  lpOutBasePath[--dwBytesIo] = 0;
		swprintf_s(lpOutBasePath, MAX_PATH, L"%s\\IntelPt_Dumps_%.2i%.2i-%.2i%.2i%.4i",
			lpOutBasePath, curTime.wHour, curTime.wMinute, curTime.wMonth, curTime.wDay, curTime.wYear);
		CreateDirectory(lpOutBasePath, NULL);
		bRetVal = (BOOL)InitPerCpuData(cpuAffinity, lpOutBasePath);
		if (bRetVal) {
			cl_wprintf(GREEN, L"Success! ");
			wprintf(L"(in TEMP directory)\r\n");
		}
	}
	if (!bRetVal) {
		RemoveDirectory(lpOutBasePath);
		cl_wprintf(RED, L"Error!\r\n");
		wprintf(L"Unable to create the output dump file.\r\n");
		CloseHandle(hPtDev);
		return -1;
	}
	pCpuDescArray = g_appData.pCpuDescArray;
	#pragma endregion

	#pragma region 4. Spawn of the new process and PMI threads
	if (!bDoKernelTrace) {
		wprintf(L"Creating target process... ");
		bRetVal = SpawnSuspendedProcess(procPath, NULL, &pi);
		if (bRetVal) cl_wprintf(GREEN, L"OK\r\n");
		else {
			wprintf(L"Error!\r\n");
			FreePerCpuData(TRUE);
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

	if (!bDoKernelTrace) bRetVal = SetProcessAffinityMask(pi.hProcess, cpuAffinity);
	else bRetVal = (BOOL)SetThreadAffinityMask(pi.hThread, cpuAffinity);
	_ASSERT(bRetVal);
	if (!bRetVal) {
		cl_wprintf(YELLOW, L"Warning!\r\n");
		wprintf(L"   Unable Set the processor affinity for the spawned process.\r\n");
	}

	// Create the PMI threads (1 per target CPU)
	for (int i = 0; i < (int)dwCpusCount; i++) {
		PT_PMI_USER_CALLBACK pmiDesc = { 0 };
		HANDLE hNewThr = NULL;
		DWORD newThrId = 0;

		hNewThr = CreateThread(NULL, 0, PmiThreadProc, (LPVOID)(QWORD)i, CREATE_SUSPENDED, &newThrId);
		// Register this thread and its callback
		pmiDesc.dwThrId = newThrId;
		pmiDesc.kCpuAffinity = (1i64 << i);
		pmiDesc.lpAddress = PmiCallback;
		bRetVal = DeviceIoControl(hPtDev, IOCTL_PTDRV_REGISTER_PMI_ROUTINE, (LPVOID)&pmiDesc, sizeof(PT_PMI_USER_CALLBACK), NULL, 0, &dwBytesIo, NULL);
		if (bRetVal) {
			pCpuDescArray[i].dwPmiThrId = newThrId;
			pCpuDescArray[i].hPmiThread = hNewThr;
			ResumeThread(hNewThr);
		}
	}
	#pragma endregion

	#pragma region 5. Set IP filtering (if any) and TRACE options
	HMODULE hRemoteMod = NULL;						// The remote module base address
	MODULEINFO remoteModInfo = { 0 };				// The remote module information
	if (g_appData.bTraceByIp) {
		// Now grab the remote image base address and size
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
					// Search for the SimplePt
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
		g_appData.bTraceOnlyKernel = bDoKernelTrace;

		#ifdef _DEBUG
		if (!remoteModInfo.lpBaseOfDll && _wcsicmp(procPath, L"AaLl86TestDriver.sys") == 0) {
			wprintf(L"Would you like to perform the Tracing test from Kernel-mode? [Y/N] ");
			wscanf_s(L"%2s", answer, 10);
			// Do the special Kernel-mode test of AaLl86
			if ((answer[0] | 0x20) == L'y') {
				DoKernelTrace(hPtDev, PT_USER_REQ(), procPath);
				goto CloseTrace;
			}
		}
		#endif

		if (!remoteModInfo.lpBaseOfDll) {
			cl_wprintf(RED, L"Error! ");
			wprintf(L"I was not able to find the target %s base address and size.\r\n", (bDoKernelTrace ? L"kernel module" : L"process' main module"));
			FreePerCpuData();
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
	}		// END Tracing by IP block

	// Write some information in the output text file:
	WriteCpuTextDumpsHeader(procPath, (ULONG_PTR)remoteModInfo.lpBaseOfDll, remoteModInfo.SizeOfImage, bDoKernelTrace);
	ptStartStruct.bTraceUser = !bDoKernelTrace;
	ptStartStruct.bTraceKernel = bDoKernelTrace;
	// For now do not set the frequencies....
	ptStartStruct.dwOptsMask = PT_TRACE_BRANCH_PCKS_MASK | PT_ENABLE_RET_COMPRESSION_MASK | PT_ENABLE_TOPA_MASK;
	ptStartStruct.kCpuAffinity = cpuAffinity;
	ptStartStruct.dwTraceSize = g_appData.dwTraceBuffSize;
	#pragma endregion

	#pragma region 6. Optional - Allocate each PT CPU buffer (we can even skip this process, the START_TRACE IOCTL can do it for us) 
	LPVOID * lpBuffArray = new LPVOID[dwCpusCount];
	RtlZeroMemory(lpBuffArray, sizeof(LPVOID)* dwCpusCount);
	if (bManuallyAllocBuff) {
		// 2 Things to keep in mind here:
		//    1. The IOCTL_PTDRV_ALLOC_BUFFERS checks PT_ENABLE_TOPA bit for the buffer allocations
		//    2. We do not need to send the entire PT_USER_REQ structure but only CPU mask, Size and a BOOL value (that contains the bit for the TOPA)
		DeviceIoControl(hPtDev, IOCTL_PTDRV_FREE_BUFFERS, (LPVOID)&ptStartStruct, FIELD_OFFSET(PT_USER_REQ, dwProcessId), NULL, 0, &dwBytesIo, NULL);
		bRetVal = DeviceIoControl(hPtDev, IOCTL_PTDRV_ALLOC_BUFFERS, (LPVOID)&ptStartStruct, FIELD_OFFSET(PT_USER_REQ, dwProcessId), lpBuffArray, sizeof(LPVOID) * dwCpusCount, &dwBytesIo, NULL);
		dwLastErr = GetLastError();
		if (bRetVal) {
			// Save our buffers
			for (int i = 0; i < (int)dwCpusCount; i++)
				g_appData.pCpuDescArray[i].lpPtBuff = (LPBYTE)lpBuffArray[i];
		}
		else {
			cl_wprintf(RED, L"Error! ");
			wprintf(L"Unable to allocate the PT buffers!\r\n");
			FreePerCpuData();
			CloseHandle(hPtDev);
			return 0;
		}
	}
	#pragma endregion

	#pragma region 8. Start the tracing and wait the process to exit
	// Start the device Tracing
	if (!bDoKernelTrace) {
		wprintf(L"Starting the Tracing and resuming the process... ");
		ptStartStruct.dwProcessId = pi.dwProcessId;
		ptStartStruct.kCpuAffinity = cpuAffinity;
		bRetVal = DeviceIoControl(hPtDev, IOCTL_PTDRV_START_TRACE, (LPVOID)&ptStartStruct, sizeof(PT_USER_REQ), lpBuffArray, sizeof(LPVOID) * dwCpusCount, &dwBytesIo, NULL);
		dwLastErr = GetLastError();

		if (bRetVal) {
			cl_wprintf(GREEN, L"OK\r\n");
			g_appData.currentTrace = ptStartStruct;

			// Copy the returned Buffer array
			for (int i = 0; i < (int)g_appData.dwNumOfActiveCpus; i++) {
				g_appData.pCpuDescArray[i].lpPtBuff = (LPBYTE)lpBuffArray[i];
				g_appData.pCpuDescArray[i].dwBuffSize = ptStartStruct.dwTraceSize;
			}

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
			bDeleteFiles = TRUE;
		}
	}
	else {
		DoKernelTrace(hPtDev, ptStartStruct, procPath);
	}

	// Set the event and wait for all PMI thread to exit
#ifdef _DEBUG
CloseTrace:
#endif
	SetEvent(g_appData.hExitEvt);
	for (int i = 0; i < (int)dwCpusCount; i++) {
		WaitForSingleObject(pCpuDescArray[i].hPmiThread, INFINITE);
		CloseHandle(pCpuDescArray[i].hPmiThread);
		pCpuDescArray[i].hPmiThread = NULL;
		pCpuDescArray[i].dwPmiThrId = 0;
	}
	#pragma endregion

	#pragma region 9. Optional - Get the results of our tracing (like the number of written packets)
	PT_TRACE_DETAILS ptDetails = { 0 };
	QWORD qwTotalNumOfPtPcks = 0;					// The TOTAL number of acquired packets
	wprintf(L"\r\n\r\n");
	cl_wprintf(DARKYELLOW, L"*** PT Trace results ***\r\n");
	wprintf(L"Number of traced CPUs: %i   -   Affinity mask: 0x%08X.\r\n", dwCpusCount, (DWORD)cpuAffinity);
	for (int i = 0; i < sizeof(cpuAffinity) * 8; i++) {
		if (!(cpuAffinity & (1i64 << i))) continue;

		wprintf(L"CPU %i\r\n", i);
		RtlZeroMemory(&ptDetails, sizeof(ptDetails));
		bRetVal = DeviceIoControl(hPtDev, IOCTL_PTDR_GET_TRACE_DETAILS, (LPVOID)&i, sizeof(int), (LPVOID)&ptDetails, sizeof(ptDetails), &dwBytesIo, NULL);
		if (bRetVal) {
			wprintf(L"   Number of traced IP ranges: %i\r\n", ptDetails.IpFiltering.dwNumOfRanges);
			wprintf(L"   Number of acquired packets: %I64i\r\n", ptDetails.qwTotalNumberOfPackets);
			qwTotalNumOfPtPcks += ptDetails.qwTotalNumberOfPackets;
		} else
			cl_wprintf(RED, L"   Error!\r\n");
	}
	wprintf(L"\r\nGlobal number of PT packets acquired: %I64i.\r\n", qwTotalNumOfPtPcks);
	wprintf(L"All the dumps have been saved in \"%s\".\r\n", lpOutBasePath);
	#pragma endregion

	#pragma region 10. Free the resources and close each files
	// Stop the Tracing (and clear the buffer if not manually allocated)
	bRetVal = DeviceIoControl(hPtDev, IOCTL_PTDRV_CLEAR_TRACE, (LPVOID)&cpuAffinity, sizeof(cpuAffinity), NULL, 0, &dwBytesIo, NULL);

	CloseHandle(pi.hProcess); 
	CloseHandle(pi.hThread);
	FreePerCpuData(bDeleteFiles);
	if (bManuallyAllocBuff)
		bRetVal = DeviceIoControl(g_appData.hPtDev, IOCTL_PTDRV_FREE_BUFFERS, (LPVOID)&cpuAffinity,
			sizeof(cpuAffinity), NULL, 0, &dwBytesIo, NULL);


	CloseHandle(hPtDev);
	#pragma endregion
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

// Close and flush the per-CPU files and data structures
bool FreePerCpuData(BOOL bDeleteFiles) {
	PT_CPU_BUFFER_DESC * pCpuDesc = NULL;				// Current CPU Descriptor
	BOOLEAN bBuffValid = FALSE;
	DWORD dwBytesIo = 0;
	if (g_appData.pCpuDescArray == NULL) return false;

	for (int i = 0; i < (int)g_appData.dwNumOfActiveCpus; i++) {
		pCpuDesc = &g_appData.pCpuDescArray[i];
		if (pCpuDesc->hBinFile) { 
			if (bDeleteFiles)
				SetFileInformationByHandle(pCpuDesc->hBinFile, FileDispositionInfo, (LPVOID)&bDeleteFiles, sizeof(BOOL));
			CloseHandle(pCpuDesc->hBinFile); pCpuDesc->hBinFile = NULL; 
		}
		if (pCpuDesc->hTextFile) { 
			if (bDeleteFiles)
				SetFileInformationByHandle(pCpuDesc->hTextFile, FileDispositionInfo, (LPVOID)&bDeleteFiles, sizeof(BOOL));
			CloseHandle(pCpuDesc->hTextFile); pCpuDesc->hTextFile = NULL;
		}
		if (pCpuDesc->lpPtBuff) bBuffValid = TRUE;
	}

	// The actual PT buffer deallocation is done in the main routine (by the PT driver)
	delete[] g_appData.pCpuDescArray;
	g_appData.pCpuDescArray = NULL;
	g_appData.dwNumOfActiveCpus = 0;
	g_appData.kActiveCpuAffinity = 0;
	return true;
}

// Initialize and open the per-CPU files and data structures
bool InitPerCpuData(ULONG_PTR kCpuAffinity, LPTSTR lpBasePath) {
	PT_CPU_BUFFER_DESC * pCpuArray = NULL;				// The new PER-CPU array
	HANDLE hNewFile = NULL;								// The handle of the new file
	TCHAR newFileName[MAX_PATH] = { 0 };
	DWORD dwPathLen = 0;
	DWORD dwNumOfCpus = 0,								// Total number of CPUs
		dwCurCpuCount = 0;								// Current CPU counter (different from ID)

	FreePerCpuData();
	for (int i = 0; i < sizeof(kCpuAffinity) * 8; i++)
		if (kCpuAffinity & (1i64 << i)) dwNumOfCpus++;

	pCpuArray = new PT_CPU_BUFFER_DESC[dwNumOfCpus];
	RtlZeroMemory(pCpuArray, sizeof(PT_CPU_BUFFER_DESC) * dwNumOfCpus);
	g_appData.dwNumOfActiveCpus = dwNumOfCpus;
	g_appData.kActiveCpuAffinity = kCpuAffinity;
	g_appData.pCpuDescArray = pCpuArray;

	dwPathLen = (DWORD)wcslen(lpBasePath);

	for (int i = 0; sizeof(kCpuAffinity) * 8; i++) {
		PT_CPU_BUFFER_DESC * pCurCpuDesc = &pCpuArray[dwCurCpuCount];
		if (!(kCpuAffinity & (1i64 << i))) continue;
		if (dwCurCpuCount >= dwNumOfCpus) break;

		newFileName[0] = 0;
		swprintf_s(newFileName, MAX_PATH, L"%s\\cpu%.2i_bin.bin", lpBasePath, i);
		// Create the binary file 
		hNewFile = CreateFile(newFileName, FILE_GENERIC_WRITE | DELETE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);

		// Create the text file 
		if (hNewFile != INVALID_HANDLE_VALUE) {
			pCurCpuDesc->hBinFile = hNewFile;
			newFileName[0] = 0;
			swprintf_s(newFileName, MAX_PATH, L"%s\\cpu%.2i_text.log", lpBasePath, i);
			hNewFile = CreateFile(newFileName, FILE_GENERIC_WRITE | DELETE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
		}
		if (hNewFile != INVALID_HANDLE_VALUE)
			pCurCpuDesc->hTextFile = hNewFile;
		else {
			FreePerCpuData(TRUE);
			return false;
		}
		dwCurCpuCount++;
	}
	return true;
}

// Write the human readable dump file header
bool WriteCpuTextDumpsHeader(LPTSTR lpImgName, ULONG_PTR qwBase, DWORD dwSize, BOOLEAN bKernelTrace) {
	DWORD dwCurCpuCount = 0;			// Current CPU counter (different from ID)
	DWORD dwNumOfCpus = 0;				// Total number of CPUs
	KAFFINITY kCpuAffinity = 0;			// Current CPU affinity mask
	CHAR fullLine[0x200] = { 0 };		// A full line of log dump
	DWORD dwBytesIo = 0;
	if (!g_appData.pCpuDescArray) return false;

	// Grab some basic data
	dwNumOfCpus = g_appData.dwNumOfActiveCpus;
	kCpuAffinity = g_appData.kActiveCpuAffinity;

	if (lpImgName && wcsrchr(lpImgName, L'\\'))
		lpImgName = wcsrchr(lpImgName, L'\\') + 1;

	for (int i = 0; i < sizeof(g_appData.kActiveCpuAffinity) * 8; i++) {
		PT_CPU_BUFFER_DESC * pCurCpuBuff = &g_appData.pCpuDescArray[dwCurCpuCount];
		HANDLE hTextFile = NULL;
		if (!(kCpuAffinity & (1i64 << i))) continue;
		if (dwCurCpuCount > dwNumOfCpus) break;
		hTextFile = pCurCpuBuff->hTextFile;
		if (!hTextFile) { dwCurCpuCount++; continue; }

		sprintf_s(fullLine, COUNTOF(fullLine), "Intel PT Trace file. Version 0.5.\r\nCPU ID : %i\r\n", i);
		WriteFile(hTextFile, fullLine, (DWORD)strlen(fullLine), &dwBytesIo, NULL);
		if (qwBase && dwSize) {
			if (!bKernelTrace)
				sprintf_s(fullLine, COUNTOF(fullLine), "Executable name: %S\r\n", lpImgName);
			else
				sprintf_s(fullLine, COUNTOF(fullLine), "Kernel driver name: %S\r\n", lpImgName);
			WriteFile(hTextFile, fullLine, (DWORD)strlen(fullLine), &dwBytesIo, NULL);
			sprintf_s(fullLine, COUNTOF(fullLine), "Base address: 0x%016llX - Size 0x%08X\r\n", (QWORD)qwBase, dwSize);
			WriteFile(hTextFile, fullLine, (DWORD)strlen(fullLine), &dwBytesIo, NULL);
		}
		sprintf_s(fullLine, COUNTOF(fullLine), "\r\n");
		WriteFile(hTextFile, fullLine, (DWORD)strlen(fullLine), &dwBytesIo, NULL);
		WriteFile(hTextFile, "Begin Trace Dump:\r\n", (DWORD)strlen("Begin Trace Dump:\r\n"), &dwBytesIo, NULL);

		dwCurCpuCount++;
	}
	return true;
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
	DWORD dwLastErr = 0;										// Last Win32 error
	DWORD dwBytesIo = 0,										// Number of I/O bytes
		dwEvtNum = 0;											// The event number that has satisfied the wait
	BOOLEAN bRetVal = FALSE;
	DWORD dwCpuNumber = (DWORD)(QWORD)lpParameter;
	HANDLE hWaitEvts[2] = { 0 };
	PT_PMI_USER_CALLBACK pmiDesc = { 0 };
	PT_CPU_BUFFER_DESC * pCurCpuBuff = &g_appData.pCpuDescArray[dwCpuNumber];

	hKernelEvt = OpenEvent(SYNCHRONIZE, FALSE, lpEventName);
	dwLastErr = GetLastError();

	if (!hKernelEvt) return -1;
	hWaitEvts[0] = hKernelEvt;
	hWaitEvts[1] = g_appData.hExitEvt;

	while (TRUE) {
		// Perform an ALERTABLE wait
		dwEvtNum = WaitForMultipleObjectsEx(2, hWaitEvts, FALSE, INFINITE, TRUE);

		// WAIT_IO_COMPLETION means APC has been queued
		if (dwEvtNum - WAIT_OBJECT_0 == 1) {
			// We are exiting, pause the Tracing
			DeviceIoControl(g_appData.hPtDev, IOCTL_PTDRV_PAUSE_TRACE, (LPVOID)&g_appData.kActiveCpuAffinity, sizeof(KAFFINITY), NULL, 0, &dwBytesIo, NULL);
			break;
		}
		// Continue to wait on the PMI Event, and raise the appropriate Callbacks
	}
	// Deregister my callback
	pmiDesc.dwThrId = GetCurrentThreadId();
	pmiDesc.lpAddress = PmiCallback;
	DeviceIoControl(g_appData.hPtDev, IOCTL_PTDRV_FREE_PMI_ROUTINE, (LPVOID)&pmiDesc, sizeof(PT_PMI_USER_CALLBACK), NULL, 0, &dwBytesIo, NULL);

	// Sleep a bit
	Sleep(500);

	// and write the rest of the log
	if (pCurCpuBuff->lpPtBuff && pCurCpuBuff->hBinFile) {
		BYTE zeroArray[16] = { 0 };
		DWORD dwEndOffset = 0;

		for (DWORD i = 0; i < pCurCpuBuff->dwBuffSize - sizeof(zeroArray); i += sizeof(zeroArray)) 
			if (RtlCompareMemory(pCurCpuBuff->lpPtBuff + i, zeroArray, sizeof(zeroArray)) == sizeof(zeroArray)) {
				dwEndOffset = i; break;
			}
		
		if (!dwEndOffset) dwEndOffset = g_appData.pCpuDescArray[dwCpuNumber].dwBuffSize;
		bRetVal = WriteFile(pCurCpuBuff->hBinFile, pCurCpuBuff->lpPtBuff, dwEndOffset, &dwBytesIo, NULL);
		if (pCurCpuBuff->hTextFile) {
			// Dump the text trace file immediately
			bRetVal = pt_dumpW((LPBYTE)pCurCpuBuff->lpPtBuff, (DWORD)dwEndOffset, pCurCpuBuff->hTextFile, pCurCpuBuff->qwDelta, g_appData.bTraceOnlyKernel);
			pCurCpuBuff->qwDelta += (QWORD)dwEndOffset;
		}
	}

	return 0;
}

// The PMI callback
VOID PmiCallback(DWORD dwCpuId, PVOID lpBuffer, QWORD qwBufferSize) {
	HANDLE hTraceBinFile = NULL;					// The trace BINARY file
	HANDLE hTraceTextFile = NULL;					// The trace Text file
	DWORD dwDescNum = 0;							// The descriptor number
	DWORD dwBytesIo = 0;							// Number of I/O bytes
	BOOL bRetVal = FALSE;							// Returned Win32 value
	DWORD dwLastErr = 0;							// Last Win32 error
	KAFFINITY thisCpuAffinity = (1i64 << dwCpuId);

	// Check if there is the main thread, open if so
	if (g_appData.dwMainThrId && !g_appData.hMainThr)
		g_appData.hMainThr = OpenThread(SYNCHRONIZE | THREAD_SUSPEND_RESUME, FALSE, g_appData.dwMainThrId);

	// Convert the CPU ID in descriptor number
	for (int i = 0; i < sizeof(KAFFINITY) * 8; i++) {
		if ((1i64 << i) & g_appData.kActiveCpuAffinity) {
			if (i == dwCpuId) break;
			dwDescNum++;
		}
	}
	// Grab the parameters
	hTraceBinFile = g_appData.pCpuDescArray[dwDescNum].hBinFile;
	hTraceTextFile = g_appData.pCpuDescArray[dwDescNum].hTextFile;
	QWORD & qwDelta = g_appData.pCpuDescArray[dwDescNum].qwDelta;

	// Suspend the main thread if any
	if (g_appData.hMainThr) SuspendThread(g_appData.hMainThr);

	if (hTraceBinFile) {
		bRetVal = WriteFile(hTraceBinFile, lpBuffer, (DWORD)qwBufferSize, &dwBytesIo, NULL);
		
		if (!bRetVal) {
			cl_wprintf(RED, L"Warning! ");
			wprintf(L"Unable to write in the log file. Results could be erroneous.\r\n");
		}
	}

	if (hTraceTextFile) {
		// Dump the text trace file immediately
		bRetVal = pt_dumpW((LPBYTE)lpBuffer, (DWORD)qwBufferSize, hTraceTextFile, qwDelta, g_appData.bTraceOnlyKernel);
		qwDelta += (QWORD)qwBufferSize;
	}
	RtlZeroMemory((LPBYTE)lpBuffer, (DWORD)qwBufferSize);

	// Resume the tracing and the execution of the target process
	bRetVal = DeviceIoControl(g_appData.hPtDev, IOCTL_PTDRV_RESUME_TRACE, (LPVOID)&thisCpuAffinity, sizeof(KAFFINITY), NULL, 0, &dwBytesIo, NULL);
	
	if (!g_appData.currentTrace.bTraceKernel)
		ZwResumeProcess(g_appData.hTargetProc);
	if (g_appData.hMainThr) ResumeThread(g_appData.hMainThr);
}

// Try some Kernel tracing activity :-)
bool DoKernelTrace(HANDLE hPtDev, PT_USER_REQ ptUserReq, LPTSTR lpDrvName) {
	BOOL bRetVal = FALSE;
	HANDLE hTestDev = NULL;
	DWORD dwLastErr = 0, dwBytesIo = 0;
	KERNEL_MODULE kernelMod = { 0 };
	LPVOID lpPtBuff = NULL;
	TCHAR answer[0x20] = { 0 };
	LPVOID * lpBuffArray = NULL;
	DWORD dwNumOfCpus = g_appData.dwNumOfActiveCpus;
	
	// Specific AaLl86 Driver data:
	const LPTSTR DosDevName = L"\\\\.\\IntelPtTest";
	LPTSTR lpKernelModName = L"ci.dll";
	bool bAaLl86Test = (_wcsicmp(lpDrvName, L"AaLl86TestDriver.sys") == 0);

	#ifdef _DEBUG
	if (bAaLl86Test && ptUserReq.dwTraceSize == 0) {
		// Here theoretically I have to open the target driver module and insert the special BAD_OPCODE 
		// BUT I am too lazy.
		wprintf(L"Testing Kernel-mode Tracing from a Kernel module... ");
		// Send the special IOCTLs
		dwBytesIo = (DWORD)((wcslen(lpDrvName) + 1) * sizeof(WCHAR));
		bRetVal = DeviceIoControl(hPtDev, IOCTL_PTDR_DO_KERNELDRV_TEST, (LPVOID)lpDrvName, dwBytesIo, NULL, 0, &dwBytesIo, NULL);
		dwLastErr = GetLastError();
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
	#endif

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

	// Allocate the buffer array
	lpBuffArray = new LPVOID[dwNumOfCpus];
	RtlZeroMemory(lpBuffArray, dwNumOfCpus * sizeof(LPVOID));

	// Start the device Tracing
	wprintf(L"Starting the Kernel-mode Tracing... ");
	bRetVal = DeviceIoControl(hPtDev, IOCTL_PTDRV_START_TRACE, (LPVOID)&ptUserReq, sizeof(PT_USER_REQ), 
		lpBuffArray, sizeof(LPVOID) * dwNumOfCpus, &dwBytesIo, NULL);
	dwLastErr = GetLastError();

	if (bRetVal) {
		cl_wprintf(GREEN, L"OK\r\n");
		g_appData.currentTrace = ptUserReq;

		// Copy the returned Buffer array
		for (int i = 0; i < (int)dwNumOfCpus; i++) {
			g_appData.pCpuDescArray[i].lpPtBuff = (LPBYTE)lpBuffArray[i];
			g_appData.pCpuDescArray[i].dwBuffSize = ptUserReq.dwTraceSize;
		}
	}
	else {
		cl_wprintf(RED, L"Error!\r\n");
		return false;
	}
	Sleep(100);

	if (bAaLl86Test) {
		wprintf(L"Doing some test malicious activity (this could crash your system)... ");
		// Test the Search Module IOCTL
		bRetVal = DeviceIoControl(hTestDev, IOCTL_PTBUG_SEARCHKERNELMODULE, (LPVOID)lpKernelModName, (DWORD)(wcslen(lpKernelModName) + 1) * sizeof(WCHAR), 
			(LPVOID)&kernelMod,	sizeof(KERNEL_MODULE), &dwBytesIo, NULL);
		dwLastErr = GetLastError();

		if (bRetVal) {
			// READ some memory from the CI.DLL module
			LPBYTE lpBuff = new BYTE[0x1000];
			bRetVal = ReadFile(hTestDev, (LPVOID)lpBuff, 0x1000, &dwBytesIo, NULL);

			if (bRetVal && lpBuff[0] == 'M' && lpBuff[1] == 'Z') {
				DWORD dwValue = 0x4000C;
				DWORD dwOffset = 0x00194b4;				// CI!g_CiDeveloperMode symbol

				bRetVal = SetFilePointer(hTestDev, dwOffset, NULL, FILE_BEGIN);
				bRetVal = WriteFile(hTestDev, (LPCVOID)&dwValue, sizeof(DWORD), &dwBytesIo, NULL);
			}
		}
		if (bRetVal)
			cl_wprintf(GREEN, L"OK\r\n");
		else
			cl_wprintf(RED, L"Error!\r\n");
	}
	else {
		wprintf(L"\r\n\r\nPress any key when you would like to stop the tracing...\r\n");
		rewind(stdin);
		getwchar();
	}

	CloseHandle(hTestDev);	
	return (bRetVal != FALSE);
}
