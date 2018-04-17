/********************************************************************
*
* [Microsoft Internal]
* _____________________
*
*  (c) 2017 Microsoft Threat Intelligence Center (MSTIC)
*  All Rights Reserved.
*
*  Author            : Andrea Allievi (andreaa)
*  Date              : 06/23/2017
*  Filename			 : Log.cpp
*  Description       : My generic Log class used to write data into a .LOG
*					   file very easily from C++
*					   The LOGTITLE symbol is defined in "stdafx.h" precompiled header
*********************************************************************/
#include "stdafx.h"
#include "log.h"
//#include <crtdbg.h>
#pragma comment (lib, "version.lib")
CLog staticLog;

// Static function to write data to an uninitialized log
// Default behaviour: if Application Communication instance is not NULL, use that, else use Dbg Output
void WriteToLog(LPTSTR dbgStr, LPVOID arg1, LPVOID arg2, LPVOID arg3, LPVOID arg4) {
	//CLog log;
	staticLog.WriteLine(dbgStr, arg1, arg2, arg3, arg4);
}

// Default Class Constructor
CLog::CLog():
	g_hLogFile(NULL),
	g_strLogTitle(NULL),
	g_bIsAutoDeleteLog(true),
	g_bAtLeastOneWrite(false),
	g_bImCopy(false),
	g_strLogFile(NULL)
{
	g_strLogFile = new TCHAR[MAX_PATH];
	RtlZeroMemory(g_strLogFile, MAX_PATH * sizeof(TCHAR));
}

// Specialized Class Constructor
CLog::CLog(LPTSTR logFile, LPTSTR logTitle) {
	g_bIsAutoDeleteLog = true;
	g_bAtLeastOneWrite = false;
	g_bImCopy = false;
	g_hLogFile = NULL;
	g_strLogFile = new TCHAR[MAX_PATH];
	g_strLogTitle = NULL;
	RtlZeroMemory(g_strLogFile, MAX_PATH * sizeof(TCHAR));
	if (logTitle) this->SetLogTitle(logTitle);
	if (!this->Open(logFile))
		DbgBreak();
}

// Copy constructor
CLog::CLog(CLog &log) {
	g_bAtLeastOneWrite = log.g_bAtLeastOneWrite;
	g_bIsAutoDeleteLog = log.g_bIsAutoDeleteLog;
	g_hLogFile = log.g_hLogFile;
	if (log.g_hLogFile) {
		HANDLE hProc = GetCurrentProcess();
		DuplicateHandle(hProc, log.g_hLogFile, hProc, &g_hLogFile, 0, FALSE, DUPLICATE_SAME_ACCESS);
	}
	if (log.g_strLogFile) {
		g_strLogFile = new TCHAR[MAX_PATH];
		RtlCopyMemory(g_strLogFile, log.g_strLogFile, MAX_PATH * sizeof(TCHAR));
	}
	if (log.g_strLogTitle) {
		int titleLen = (int)wcslen(log.g_strLogTitle);
		g_strLogTitle = new TCHAR[titleLen+1];
		RtlZeroMemory(g_strLogTitle, (titleLen+1) * sizeof(TCHAR));
		RtlCopyMemory(g_strLogTitle, log.g_strLogTitle, (titleLen+1) * sizeof(TCHAR));
	}
	g_bImCopy = true;
	log.g_bAtLeastOneWrite = true;
}

// Destructor
CLog::~CLog() {
	this->Close();
	if (g_strLogTitle) delete[] g_strLogTitle;
	if (g_strLogFile) delete[] g_strLogFile;
}

// Set log Title
void CLog::SetLogTitle(LPTSTR strTitle) {
	if (!strTitle) return;
	int titleLen = (int)wcslen(strTitle);

	if (this->g_strLogTitle) {
		delete g_strLogTitle;
		g_strLogTitle = NULL;
	}
	g_strLogTitle = new TCHAR[titleLen+1];
	wcscpy_s(g_strLogTitle, titleLen+1, strTitle);
}

// Create or open a log file
bool CLog::Open(LPTSTR fileName, bool overwrite) {
	BOOL retVal = FALSE;
	HANDLE hFile = NULL;
	SYSTEMTIME time = {0};
	CHAR logStr[255] = {0};
	DWORD bytesToWrite = 0;
	DWORD bytesWritten = 0;
	DWORD lastErr = 0;

	if (this->g_hLogFile != NULL) {
		// Log File already opened, close it
		if (wcscmp(fileName, this->g_strLogFile) != 0) this->Close();
		else
			// File already opened
			return true;
	}

	hFile = CreateFile(fileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, (overwrite ? CREATE_ALWAYS : OPEN_ALWAYS),
		FILE_ATTRIBUTE_NORMAL, NULL);
	lastErr = GetLastError();
	if (hFile == INVALID_HANDLE_VALUE)
		return false;

	if (lastErr == ERROR_ALREADY_EXISTS && overwrite == false) {
		retVal = SetFilePointer(hFile, 0, 0, FILE_END);
		if (retVal > 0) 
			// Don't autodelete log that already contains data
			g_bIsAutoDeleteLog = false;
	}
	
	// Mi memorizzo il nome del file
	if (!g_strLogFile)
		g_strLogFile = new TCHAR[MAX_PATH];
	wcscpy_s(g_strLogFile, MAX_PATH, fileName);

	GetLocalTime(&time);
	LPTSTR logTitle = this->g_strLogTitle;
	if (!logTitle) {
		// 20/02/2012 If there isn't a log title use CVersionInfo
		#ifdef LOGTITLE
			logTitle = LOGTITLE;
		#else
			LPTSTR prodName = NULL, companyName = NULL, verStr = NULL;
			logTitle = new TCHAR[0x100];
			CVersionInfo fileInfo;
			prodName = fileInfo.GetProductName();
			companyName = fileInfo.GetCompanyName();
			verStr = fileInfo.GetFileVersionString();
			wsprintf(logTitle, L"%s %s %s Log File", companyName, prodName, verStr);
			this->g_strLogTitle = logTitle;
		#endif
	}
	bytesToWrite = sprintf_s(logStr, 255, "%S\r\nExecution time: %02i/%02i/%02i - %02i:%02i\r\n", logTitle, 
		time.wDay, time.wMonth, time.wYear, time.wHour, time.wMinute) + 1;
	retVal = WriteFile(hFile, logStr, bytesToWrite - 1, &bytesWritten, NULL);
	this->g_bAtLeastOneWrite = false;

	if (retVal) {
		this->g_hLogFile = hFile;
		return true;
	} else {
		RtlZeroMemory(g_strLogFile, MAX_PATH * sizeof(TCHAR));
		return false;
	}
}

// Close this log file
void CLog::Close(bool WriteEnd) {
	if (!this->g_hLogFile || g_hLogFile == INVALID_HANDLE_VALUE) 
		return;

	bool deleteMe = false;
	if (!g_bAtLeastOneWrite && g_bIsAutoDeleteLog && !g_bImCopy)
		// Auto delete this log if there aren't any write
		deleteMe = true;

	if (WriteEnd && !g_bImCopy) WriteLine(L"Execution Ended!\r\n\r\n");
	CloseHandle(g_hLogFile); g_hLogFile = NULL;
	if (deleteMe) DeleteFile(g_strLogFile);

	if (g_strLogFile) 
		RtlZeroMemory(g_strLogFile, MAX_PATH * sizeof(TCHAR));
	
}


// Write a log line (NO parameters)
void CLog::WriteLine(LPTSTR dbgStr) {
	if (g_hLogFile) WriteCurTime();
	Write(dbgStr);
	Write(L"\r\n");
}

// Write a log line (4 parameters max)
void CLog::WriteLine(LPTSTR dbgStr, LPVOID arg1, LPVOID arg2, LPVOID arg3, LPVOID arg4) {
	if (g_hLogFile) WriteCurTime();
	Write(dbgStr, arg1, arg2, arg3, arg4);
	Write(L"\r\n");
}

// Write current time to log
void CLog::WriteCurTime() {
	TCHAR timeStr[20] = {0};
	SYSTEMTIME curTime = {0};
	GetLocalTime(&curTime);
	swprintf_s(timeStr, 20, L"%02i:%02i:%02i - ", curTime.wHour, curTime.wMinute, curTime.wSecond);
	Write(timeStr);
}

// Write a Unicode log string (NO parameters)
void CLog::Write(LPWSTR dbgStr) {
	DWORD bytesToWrite = 0;
	DWORD bytesWritten = 0;
	CHAR * logStr = NULL;			// String to write in file

	if (!g_hLogFile || g_hLogFile == INVALID_HANDLE_VALUE) {		// If I don't have opened a log file
		OutputDebugString(dbgStr);									// write to debug output
	} else {
		bytesToWrite = (DWORD)wcslen(dbgStr) + 1;
		logStr = new CHAR[bytesToWrite];
		sprintf_s(logStr, bytesToWrite, "%S", dbgStr);
		WriteFile(g_hLogFile, logStr, bytesToWrite - 1, &bytesWritten, NULL);			//BOOL retVal = 
		delete[] logStr;
	}
	g_bAtLeastOneWrite = true;
}

// Write a log string (4 parameters max)
void CLog::Write(LPTSTR dbgStr, LPVOID arg1, LPVOID arg2, LPVOID arg3, LPVOID arg4) {
	LPTSTR resStr = NULL;			// Formatted string

	// Format unicode original string
	resStr = new TCHAR[2048];
	swprintf_s(resStr, 2048, dbgStr, arg1, arg2, arg3, arg4);
	Write(resStr);
	if (resStr != dbgStr) delete[] resStr;
}

// Write an ANSI log string (NO parameters)
void CLog::Write(LPSTR dbgStr) {
	DWORD bytesToWrite = 0;
	DWORD bytesWritten = 0;

	if (!this->g_hLogFile || g_hLogFile == INVALID_HANDLE_VALUE) {		// If I don't have opened a log file
		OutputDebugStringA(dbgStr);										// write to debug output
	} else {
		bytesToWrite = (DWORD)strlen(dbgStr);
		WriteFile(g_hLogFile, dbgStr, bytesToWrite, &bytesWritten, NULL);
	}
	g_bAtLeastOneWrite = true;
}

// Write an ANSI log string (4 parameters max)
void CLog::Write(LPSTR dbgStr, LPVOID arg1, LPVOID arg2, LPVOID arg3, LPVOID arg4) {
	LPSTR resStr = NULL;			// Formatted string

	// Format ansi original string
	resStr = new CHAR[2048];
	sprintf_s(resStr, 2048, dbgStr, arg1, arg2, arg3, arg4);
	Write(resStr);
	delete[] resStr;
}


// Flush file to perform actual disk write
void CLog::Flush() {
	if (!this->g_hLogFile) return;
	FlushFileBuffers(g_hLogFile);
}

#pragma region Version Information Class functions
// Default constructor
CVersionInfo::CVersionInfo(): 
	g_bVerInfoBuff(NULL),
	iLangTableLen(0),
	pLangTable(NULL),
	g_LangStr(NULL),
	g_fVerStr(NULL)
	{
		GetModuleVersionInfo();
	}

// Constructor that accept a module name 
CVersionInfo::CVersionInfo(LPTSTR modName) {
	g_LangStr = NULL;
	g_fVerStr = NULL;
	GetModuleVersionInfo(modName);
}

// Constructor that accept a module handle
CVersionInfo::CVersionInfo(HMODULE hModule) {
	g_LangStr = NULL;
	g_fVerStr = NULL;
	GetModuleVersionInfo(hModule);
}

// Destructor
CVersionInfo::~CVersionInfo() {
	if (g_bVerInfoBuff) delete[] g_bVerInfoBuff;
	g_bVerInfoBuff = NULL;
	if (g_LangStr) delete[] g_LangStr;
	if (g_fVerStr) delete[] g_fVerStr;
}

// Get fixed Version Information
VS_FIXEDFILEINFO CVersionInfo::GetFixedVersion() {
	VS_FIXEDFILEINFO * pVerInfo = NULL;
	UINT verSize = 0;
	BOOL retVal = FALSE;
	if (!g_bVerInfoBuff) return VS_FIXEDFILEINFO();

	retVal = VerQueryValue((LPCVOID)g_bVerInfoBuff, L"\\", (LPVOID*)&pVerInfo, (PUINT)&verSize);
	if (retVal) return *pVerInfo;
	else return VS_FIXEDFILEINFO();
}

LPTSTR CVersionInfo::GetFileVersionString() {
	VS_FIXEDFILEINFO fixedVer = {0};
	if (!g_bVerInfoBuff) return NULL;

	fixedVer = GetFixedVersion();
	if (!g_fVerStr) g_fVerStr = new TCHAR[0x30];
	wsprintf(g_fVerStr, L"%i.%i", 
		(WORD)(fixedVer.dwFileVersionMS >> 16),
		(WORD)(fixedVer.dwFileVersionMS));
	return g_fVerStr;
}

// Helper function that Get a Language Code Page Version Value
LPTSTR CVersionInfo::VerQueryLangCpValue(LPTSTR value) {
	if (!g_bVerInfoBuff || !g_LangStr) return NULL;
	LPTSTR verValue = NULL;
	LPTSTR verLangStr = new TCHAR[0x40];
	UINT dwChars = 0;			
	BOOL retVal = FALSE;

	wcscpy_s(verLangStr, 0x40, g_LangStr);
	wcscat_s(verLangStr, 0x40, value);
	
	// Retrieve file description for language and code page "i". 
	retVal = VerQueryValue((LPCVOID)g_bVerInfoBuff, verLangStr, (LPVOID*)&verValue, &dwChars); 
	delete[] verLangStr;

	if (retVal) 
		return verValue;
	else
		return NULL;
}

LPTSTR CVersionInfo::GetProductName() {
	return VerQueryLangCpValue(L"ProductName");
}

LPTSTR CVersionInfo::GetCompanyName() {
	return VerQueryLangCpValue(L"CompanyName");
}

// Helper function that receive versione information of a specific module (NULL = this executable)
bool CVersionInfo::GetModuleVersionInfo(HMODULE hMod) {
	LPTSTR modFileName = NULL;				// Filename of module used to retrieve version information
	BOOL retVal = FALSE;

	modFileName = new TCHAR[MAX_PATH];
	retVal = GetModuleFileName(hMod, modFileName, MAX_PATH);
	if (!retVal) {
		delete modFileName;
		::WriteToLog(L"CLog::GetModuleVersion - Error while getting module filename...");
		return false;
	}
	retVal = GetModuleVersionInfo(modFileName);
	delete modFileName;
	return (retVal == TRUE);
}

bool CVersionInfo::GetModuleVersionInfo(LPTSTR modName) {
	DWORD dummy = 0;						// Dummy DWORD variable for GetFileVersionInfoSize
	DWORD verSize = 0;						// Version info size
	LPBYTE buff = NULL;						// Buffer
	BOOL retVal = FALSE;
	LPTSTR langStr = NULL;					// Lang and code page Version string
	if (!modName) return false;

	verSize = GetFileVersionInfoSize(modName, &dummy);
	if (!verSize) 
		return false;

	buff = new BYTE[verSize];
	retVal = GetFileVersionInfo(modName, dummy, verSize, (LPVOID)buff);

	if (retVal) {
		iLangTableLen = 0;
		pLangTable = NULL;
		if (g_LangStr) {delete g_LangStr; g_LangStr = NULL; }

		// Read the list of languages and code pages.
		retVal = VerQueryValue(buff, TEXT("\\VarFileInfo\\Translation"), (LPVOID*)&pLangTable, &iLangTableLen);

		langStr = new TCHAR[0x40];
		// Read the file description for each language and code page.
		for(int i = 0; i < (int)(iLangTableLen / sizeof(struct LANGANDCODEPAGE)); i++) 
			wsprintf(langStr, TEXT("\\StringFileInfo\\%04x%04x\\"), pLangTable[i].wLanguage, pLangTable[i].wCodePage);
		g_LangStr = langStr;
	}

	if (retVal) 
		this->g_bVerInfoBuff = buff;
	else 
		if (buff) delete buff;

	return (retVal == TRUE);
}
#pragma endregion

// ....
// One Log to rule them all!
// ....
