/**********************************************************************
 *  Windows Intel Processor Trace (PT) Driver
 *  Filename: EntryPoint.h
 *  The Control application entry point and startup functions
 *  Last revision: 12/01/2016
 *
 *  Copyright© 2016 Andrea Allievi, Richard Johnson
 *  Microsoft Ltd & TALOS Research and Intelligence Group
 *  All right reserved
 **********************************************************************/
#include "stdafx.h"
#include "IntelPtControlApp.h"
#include "pt_dump.h"

// Global app data
GLOBAL_DATA g_appData;

int wmain(int argc, LPTSTR argv[])
{
	int iRetVal = 0;
	wprintf(L"Talos Intel PT Test Application\r\n");
	wprintf(L"Version 0.4\r\n\r\n");

	if (!ParseCommandLine(argc, argv)) {
		iRetVal = NoCmdlineStartup();
	}

	rewind(stdin);
	wprintf(L"Press any key to exit...");
	getwchar();
	return iRetVal;
}

// Parse command line
bool ParseCommandLine(int argc, LPTSTR argv[]) {
	BOOL bRetVal = FALSE;				// Win32 Returned value
	bool bError = false;				// TRUE if I found some parsing errors
	LPTSTR lpPtBinFile = NULL,			// Input binary file
		lpOutFile = NULL,				// Output file
		lpFileOnlyName = NULL;			// A file name without the path
	QWORD qwBaseAddr = 0;				// The dump base address
	DWORD dwSize = 0;					// Maximum size to read from the dump
	LPTSTR endPtr = NULL;				// END string pointer


	for (int i = 1; i < argc; i++) {
		LPTSTR arg = argv[i];
		LPTSTR param = NULL;

		param = wcschr(arg, L':');
		if (param) { param[0] = 0; param++; }

		// Check the arg starting chr
		if (arg[0] == L'/' || arg[0] == L'-')
			arg++;
		else {
			bError = true;
			break;
		}

		if (_wcsicmp(arg, L"help") == 0) {
			ShowCommandLineUsage();
			return true;
		}

		// Live PT trace switches
		else if (_wcsicmp(arg, L"buffsize") == 0) {
			DWORD dwBuffSize = 0;
			if (param[0] == L'0' && (param[1] | 0x20) == 'x')
				dwBuffSize = wcstoul(param + 2, &endPtr, 16);
			else
				// Consider this as an integer value
				dwBuffSize = wcstoul(param, &endPtr, 10);
			if (dwBuffSize == 0) bError = true;
			if (dwBuffSize % PAGE_SIZE) dwBuffSize += (PAGE_SIZE - (dwBuffSize % PAGE_SIZE));
			g_appData.dwTraceBuffSize = dwBuffSize;
		}

		// Binary Files switches
		else if (_wcsicmp(arg, L"decode") == 0)
			lpPtBinFile = param;
		else if (_wcsicmp(arg, L"out") == 0)
			lpOutFile = param;
		else if (_wcsicmp(arg, L"base") == 0) {
			if (param == NULL || wcslen(param) < 2) {
				bError = true;
				break;
			}
			if (param[0] == L'0' && (param[1] | 0x20) == 'x')
				qwBaseAddr = wcstoull(param + 2, &endPtr, 16);
			else
				qwBaseAddr = wcstoull(param, &endPtr, 16);
		}
		else if (_wcsicmp(arg, L"filesize") == 0) {
			if (param == NULL || wcslen(param) < 2) {
				bError = true;
				break;
			}
			if (param[0] == L'0' && (param[1] | 0x20) == 'x')
				dwSize = wcstoul(param + 2, &endPtr, 16);
			else
				// Consider this as an integer value
				dwSize = wcstoul(param, &endPtr, 10);
			if (dwSize == 0) bError = true;
			if (dwSize % 4096) dwSize += (4096 - (dwSize % 4096));
		}
		else
			bError = true;
		if (bError) break;
	}

	if (lpPtBinFile) {
		bool bNoOutFile = false;
		if (!FileExists(lpPtBinFile)) {
			wprintf(L"Error! The specified file name doesn't exists!\r\n");
			return true;
		}

		// Do the decoding here and exit
		lpFileOnlyName = wcsrchr(lpPtBinFile, L'\\');
		if (lpFileOnlyName) lpFileOnlyName++; else lpFileOnlyName = lpPtBinFile;
		wprintf(L"Decoding \"%s\" file... ", lpFileOnlyName);

		if (!lpOutFile) {
			lpOutFile = new TCHAR[MAX_PATH];
			LPTSTR lpSlashPtr = NULL;
			GetModuleFileName(GetModuleHandle(NULL), lpOutFile, MAX_PATH);
			lpSlashPtr = wcsrchr(lpOutFile, L'\\');
			if (lpSlashPtr) lpSlashPtr[1] = 0;
			wcscat_s(lpOutFile, MAX_PATH, L"pt_dump.txt");
			bNoOutFile = true;
		}
		HANDLE hTxtDump = CreateFile(lpOutFile, FILE_WRITE_ACCESS, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hTxtDump == INVALID_HANDLE_VALUE) {
			if (bNoOutFile) { delete[] lpOutFile; lpOutFile = NULL; }
			cl_wprintf(RED, L"Error %i!\r\n", (LPVOID)GetLastError());
			return true;
		}
		CHAR fullLine[0x200] = { 0 }; DWORD dwBytesIo = 0;
		sprintf_s(fullLine, COUNTOF(fullLine), "AaLl86 Intel PT Trace file. Version 0.4\r\n");
		WriteFile(hTxtDump, fullLine, (DWORD)strlen(fullLine), &dwBytesIo, NULL);
		sprintf_s(fullLine, COUNTOF(fullLine), "Binary dump file name: %S\r\n", wcsrchr(lpPtBinFile, L'\\') + 1);
		WriteFile(hTxtDump, fullLine, (DWORD)strlen(fullLine), &dwBytesIo, NULL);
		sprintf_s(fullLine, COUNTOF(fullLine), "Base address: 0x%016llX\r\n", qwBaseAddr);
		WriteFile(hTxtDump, fullLine, (DWORD)strlen(fullLine), &dwBytesIo, NULL);
		sprintf_s(fullLine, COUNTOF(fullLine), "\r\n");
		WriteFile(hTxtDump, fullLine, (DWORD)strlen(fullLine), &dwBytesIo, NULL);
		WriteFile(hTxtDump, "Begin Trace Dump:\r\n", (DWORD)strlen("Begin Trace Dump:\r\n"), &dwBytesIo, NULL);
		CloseHandle(hTxtDump);

		bRetVal = pt_dump_file(lpPtBinFile, lpOutFile, dwSize);
		if (bNoOutFile) { delete[] lpOutFile; lpOutFile = NULL; }
		if (bRetVal)
			cl_wprintf(GREEN, L"OK\r\n");
		else {
			cl_wprintf(RED, L"Some Errors!\r\n");
			DeleteFile(lpOutFile);
		}
		return true;
	}
	return false;
}

// Show command line usage
void ShowCommandLineUsage() {
	wprintf(L"Command line usage.\r\n");
	wprintf(L"\r\nSwitches used for the live-tracing:\r\n"
		L"  /buffSize:<size> - Specify a PT trace buffer size (the default is 64 KBytes).\r\n"
		L"\r\n"
		L"Switches used for the decoding of a binary file:\r\n"
		L"  /decode:<dumpFile> - Decode a binary PT Dump file\r\n"
		L"  /fileSize:<sizeToRead> - Specify the maximum amount of data to read from the PT dump file\r\n"
		L"  /base:<baseAddressInHex> - Specify the base address for the PT dump (in HEX digits).\r\n"
		L"  /out:<outFile> - Output human-readable file path\r\n"
		L"  /help - Show this help.\r\n");
	wprintf(L"\r\n");
}



