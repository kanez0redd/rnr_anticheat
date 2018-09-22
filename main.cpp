﻿#include "main.h"
#include <Windows.h>
#include <StrSafe.h>
#include <Shlwapi.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <stdlib.h>
#include <cstdint>

uint64_t g_steamID;
extern cvar_t *random;
extern cvar_t *logsfiles;
TCHAR g_settingsFileName[MAX_PATH];
typedef void *HOOKSERVERMSG(const char *pszMsgName, void *pfnCallback);
void(*g_pfnCL_ParseConsistencyInfo)();
FILE *g_pFile; 
extern int g_anticheckfiles;
extern char *g_anticheckfiles2[2048];


bool ParseListx(const char *str) {
	for (DWORD i = 0; i < g_anticheckfiles; i++) {
		if (!stricmp(str, g_anticheckfiles2[i])) {
			return true;
		}
	}
	return false;
}

bool IsEtaHuynya(const char *str1, const char *str2) {
	int len1 = strlen(str1), len2 = strlen(str2);
	if (len1 < len2)return false;
	return !_stricmp(&str1[len1 - len2], str2);
}
const char *StrStr_Hooked(char *str1, char *str2) {
	if (ParseListx(str1)) {
		if (logsfiles->value > 0) {
			ConsolePrintColor(30, 240, 150, "------<ADetect Hide file>------");
			ConsolePrintColor(205, 133, 63, _strdup(str1));
			ConsolePrintColor(255, 255, 255, "\n");
		}
		*(char *)&str1[strlen(str1) - 1] = -1;
	}
	else {
		if (logsfiles->value > 0) {
			ConsolePrintColor(205, 133, 63, _strdup(str1));
			ConsolePrintColor(255, 255, 255, "\n");
		}
	}
	return strstr(str1, str2);
}

void CL_ParseConsistencyInfo() {
	if (logsfiles->value > 0){
		ConsolePrintColor(30, 240, 150, "------<Start Check File>------");
		ConsolePrintColor(255, 255, 255, "\n");
	}
		(*g_pfnCL_ParseConsistencyInfo)();
	if (logsfiles->value > 0){
		ConsolePrintColor(30, 240, 150, "------<End Check File>------");
		ConsolePrintColor(255, 255, 255, "\n");
	}
}
#pragma comment(lib, "Shlwapi.lib")
cl_clientfunc_t *g_pClient = nullptr;
cl_enginefunc_t *g_pEngine = nullptr;
engine_studio_api_t *g_pStudio = nullptr;

cl_clientfunc_t g_Client;
cl_enginefunc_t g_Engine;
engine_studio_api_t g_Studio;

PUserMsg pUserMsgBase;
PEngineMsg pEngineMsgBase;
PColor24 Console_TextColor;

SCREENINFO g_Screen;

BYTE bPreType = 0;

ofstream logfile;
char* BaseDir;

DWORD WINAPI CheatEntry( LPVOID lpThreadParameter );

DWORD WINAPI ProcessReload( LPVOID lpThreadParameter )
{
	while ( true )
	{
		if ( FirstFrame )
		{
			offset.GetRenderType();

			if ( !offset.GetModuleInfo() )
				FirstFrame = false;
		}
		else
		{
			CreateThread( 0 , 0 , CheatEntry , 0 , 0 , 0 );
			
		}

		Sleep( 100 );
	}

	return 0;
}
string szDirFile2(char* pszName){
	string szRet = BaseDir;
	return (szRet + pszName);
}
DWORD WINAPI CheatEntry( LPVOID lpThreadParameter )
{
	static HANDLE hProcessReloadThread = 0;

	if ( hProcessReloadThread )
	{

		TerminateThread( hProcessReloadThread , 0 );
		CloseHandle( hProcessReloadThread );
	}
	
	BYTE counter_find = 0;

start_hook:

	if ( counter_find == 100 )
	{
		offset.Error(ERROR_FIND);
	}

	Sleep( 100 );
	counter_find++;

	if ( !offset.GetModuleInfo() )
	{
		goto start_hook;
	}

	DWORD ClientTable = offset.FindClientTable();

	if ( ClientTable )
	{
		g_pClient = (cl_clientfunc_t*)ClientTable;
		offset.CopyClient();

		if ( (DWORD)g_Client.Initialize )
		{
			DWORD EngineTable = offset.FindEngineTable();

			if ( EngineTable )
			{
				g_pEngine = (cl_enginefunc_t*)EngineTable;
				offset.CopyEngine();

				if ( (DWORD)g_Engine.V_CalcShake )
				{
					DWORD StudioTable = offset.FindStudioTable();

					if ( StudioTable )
					{
						g_pStudio = (engine_studio_api_t*)StudioTable;
						offset.CopyStudio();

						if ( (DWORD)g_Studio.StudioSetupSkin )
						{
							while ( !FirstFrame )
							{
								HookFunction();
								Sleep( 100 );
							}
							
							bPreType = offset.HLType;

							hProcessReloadThread = CreateThread( 0 , 0 , ProcessReload , 0 , 0 , 0 );
						}
						else
						{
							goto start_hook;
						}
					}
					else
					{
						goto start_hook;
					}
				}
				else
				{
					goto start_hook;
				}
			}
			else
			{
				goto start_hook;
			}
		}
		else
		{
			goto start_hook;
		}
	}
	else
	{
		goto start_hook;
	}

	return 0;
}

class BinaryPattern {
	uint8_t *pBytes;
	bool *pMarks;
	size_t byteCount;
public:
	BinaryPattern(const char *str) {
		size_t elemCount = strlen(str) / 2 + 1;
		pBytes = (decltype(pBytes))malloc(elemCount * sizeof(*pBytes));
		pMarks = (decltype(pMarks))malloc(elemCount * sizeof(*pMarks));

		byteCount = 0;
		for (const char *pch = str; *pch != '\0'; pch++) {
			if (*pch == ' ') {
				continue;
			}
			if (*pch == '?') {
				pBytes[byteCount] = 0;
				pMarks[byteCount] = false;
				byteCount++;

				if (*(pch + 1) == '?') {
					pch++;
				}

				continue;
			}

			pBytes[byteCount] = strtoul(pch, nullptr, 16);
			pMarks[byteCount] = true;
			byteCount++;

			pch++;
		}

		pBytes = (decltype(pBytes))realloc(pBytes, byteCount * sizeof(*pBytes));
		pMarks = (decltype(pMarks))realloc(pMarks, byteCount * sizeof(*pMarks));
	}

	bool IsMatch(uintptr_t ptr) {
		uint8_t *pBytesToCheck = (decltype(pBytesToCheck))ptr;

		for (size_t i = 0; i < byteCount; i++) {
			if (pMarks[i] && pBytesToCheck[i] != pBytes[i]) {
				return false;
			}
		}

		return true;
	}
};
class CallOpcode {
public:
	static uintptr_t GetDestination(uintptr_t callPtr) {
		return (callPtr + 5) + *(intptr_t *)(callPtr + 1);
	}
	static void SetDestination(uintptr_t callPtr, uintptr_t destPtr) {
		DWORD oldProt;
		VirtualProtect(LPVOID(callPtr + 1), sizeof(intptr_t), PAGE_EXECUTE_READWRITE, &oldProt);

		*(intptr_t *)(callPtr + 1) = destPtr - (callPtr + 5);

		VirtualProtect(LPVOID(callPtr + 1), sizeof(intptr_t), oldProt, &oldProt);
	}
	static void SetDestination(uintptr_t callPtr, void *destPtr) {
		SetDestination(callPtr, (uintptr_t)destPtr);
	}
};
class Module {
	uintptr_t moduleBase;
	IMAGE_NT_HEADERS32 *pNtHeaders;
public:
	Module(const char *moduleName) {
		moduleBase = (decltype(moduleBase))GetModuleHandleA(moduleName);

		IMAGE_DOS_HEADER *pDosHeader = (decltype(pDosHeader))moduleBase;
		pNtHeaders = (decltype(pNtHeaders))(moduleBase + pDosHeader->e_lfanew);
	}
	static bool IsLoaded(const char *moduleName) {
		return GetModuleHandleA(moduleName) != nullptr;
	}
	uintptr_t FindStringAddress(const char *str) const {
		const char *pData = (decltype(pData))(moduleBase + pNtHeaders->OptionalHeader.BaseOfData);

		while (true) {
			if (!strcmp(pData, str)) {
				return (uintptr_t)pData;
			}

			pData++;
		}

		return (uintptr_t)nullptr;
	}
	uintptr_t FindFirstUseOfString(const char *str) const {
		uintptr_t strPtr = FindStringAddress(str);

		IMAGE_BASE_RELOCATION *pBaseReloc = (decltype(pBaseReloc))(moduleBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		uintptr_t relocBase = (decltype(relocBase))pBaseReloc;

		while (pBaseReloc->SizeOfBlock) {
			uint16_t *pEnd = (decltype(pEnd))(relocBase + pBaseReloc->SizeOfBlock);
			uintptr_t base = (decltype(base))(moduleBase + pBaseReloc->VirtualAddress);

			for (uint16_t *pReloc = (decltype(pReloc))(relocBase + sizeof(*pBaseReloc)); pReloc != pEnd; pReloc++) {
				if (*pReloc >> 12 == 0) { // Bad type
					continue;
				}

				uintptr_t ptr = base + (*pReloc & 0xFFF); // Offset
				if (strPtr == *(uintptr_t *)ptr) {
					return ptr;
				}
			}

			pBaseReloc = (decltype(pBaseReloc))pEnd;
			relocBase = (decltype(relocBase))pBaseReloc;
		}

		return (uintptr_t)nullptr;
	}
	uintptr_t SearchUpForBinaryPattern(uintptr_t startPtr, BinaryPattern &binPattern) const {
		uintptr_t ptr = startPtr;

		while (true) {
			if (binPattern.IsMatch(ptr)) {
				return ptr;
			}

			ptr--;
		}

		return (uintptr_t)nullptr;
	}
	uintptr_t SearchDownForFirstCallToFunction(uintptr_t startPtr, uintptr_t funcPtr) {
		uintptr_t ptr = startPtr;

		while (true) {
			if (*(uint8_t *)ptr == 0xE8 && CallOpcode::GetDestination(ptr) == funcPtr) {
				return ptr;
			}

			ptr++;
		}

		return (uintptr_t)nullptr;
	}
	uintptr_t SearchUpForFirstCallToFunction(uintptr_t startPtr, uintptr_t funcPtr) {
		uintptr_t ptr = startPtr;

		while (true) {
			if (*(uint8_t *)ptr == 0xE8 && CallOpcode::GetDestination(ptr) == funcPtr) {
				return ptr;
			}

			ptr--;
		}

		return (uintptr_t)nullptr;
	}
};



int(*g_pfnSteam_GSInitiateGameConnection)(void *pData, int maxDataBytes, uint64_t steamID, uint32_t serverIP, uint16_t serverPort, bool isSecure);

revEmuTicket_t revEmuTicket;

const uint8_t g_hashSymbolTable[36] = {
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
	'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
	'U', 'V', 'W', 'X', 'Y', 'Z'
};


uint32_t RevHash(const char *str) {
	uint32_t hash = 0x4E67C6A7;
	for (const char *pch = str; *pch != '\0'; pch++) {
		hash ^= (hash >> 2) + (hash << 5) + *pch;
	}
	return hash;
}

int Steam_GSInitiateGameConnection_CallHook(void *pData, int maxDataBytes, uint64_t steamID, uint32_t serverIP, uint16_t serverPort, bool isSecure) {	
	int ret = (*g_pfnSteam_GSInitiateGameConnection)(pData, maxDataBytes, steamID, serverIP, serverPort, isSecure);
	memcpy(&revEmuTicket, pData, sizeof(revEmuTicket));
	if (random->value == 0) return ret;
	for (size_t i = 0; i < 7; i++) {
		revEmuTicket.hash[i] = g_hashSymbolTable[rand() % 94];
	}
	revEmuTicket.hash[7] = '\0';

	revEmuTicket.version = 'J';
	revEmuTicket.highPartAuthID = RevHash((const char *)revEmuTicket.hash) & 0x7FFFFFFF;
	revEmuTicket.signature = 'rev';
	revEmuTicket.secondSignature = 0;
	revEmuTicket.authID = RevHash((const char *)revEmuTicket.hash) << 1;
	revEmuTicket.thirdSignature = 0x01100001;
memcpy(pData, &revEmuTicket, sizeof(revEmuTicket));
return sizeof(revEmuTicket);
}
void CL_ReadDemoMessage_OLD_Cbuf_AddText_CallHook(const char *str){
	// Add your filters there

	//MessagePrintf("Demo tried to execute: %s", str);
}

void CL_ConnectionlessPacket_Cbuf_AddText_CallHook(const char *str){
	// Add your filters there
	//MessagePrintf("Server tried to execute via connectionless: %s", str);
}
void ModuleLoaded() {
	Module *pModule;
	if (Module::IsLoaded("hw.dll")) {
		pModule = new Module("hw.dll");
	}
	else if (Module::IsLoaded("sw.dll")) {
		pModule = new Module("sw.dll");
	}
	else {
		return;
	}
	
	uintptr_t ptr = pModule->FindFirstUseOfString("%c%c%c%cconnect %i %i \"%s\" \"%s\"\n");
	ptr = pModule->SearchUpForBinaryPattern(ptr, BinaryPattern("E8 ?? ?? ?? ?? 83 C4 1C 8B F8"));

	g_pfnSteam_GSInitiateGameConnection = (decltype(g_pfnSteam_GSInitiateGameConnection))CallOpcode::GetDestination(ptr);
	CallOpcode::SetDestination(ptr, &Steam_GSInitiateGameConnection_CallHook);
	/*
	ptr = pModule->FindFirstUseOfString("Error, bad server command %s\n");
	ptr = pModule->SearchUpForBinaryPattern(ptr, BinaryPattern("E8 ?? ?? ?? ?? 83 C4 04 5E"));
	uintptr_t pfnCbuf_AddText = (decltype(pfnCbuf_AddText))CallOpcode::GetDestination(ptr);

	ptr = pModule->FindFirstUseOfString("Tried to read a demo message with no demo file\n");
	ptr = pModule->SearchDownForFirstCallToFunction(ptr, pfnCbuf_AddText);
	CallOpcode::SetDestination(ptr, &CL_ReadDemoMessage_OLD_Cbuf_AddText_CallHook);

	ptr = pModule->FindFirstUseOfString("Redirecting connection to %s.\n");
	ptr = pModule->SearchUpForFirstCallToFunction(ptr, pfnCbuf_AddText);
	CallOpcode::SetDestination(ptr, &CL_ConnectionlessPacket_Cbuf_AddText_CallHook);
	*/
	delete pModule;
}
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved){
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		TCHAR moduleFileName[MAX_PATH];
		GetModuleFileName(hinstDLL, moduleFileName, ARRAYSIZE(moduleFileName));
		LoadLibrary(moduleFileName);/*
		LPCTSTR lpFileName = PathFindFileName(moduleFileName);
		LPCTSTR lpExtension = PathFindExtension(moduleFileName);
		TCHAR sFileName[MAX_PATH];
		StringCchCopyN(sFileName, ARRAYSIZE(sFileName), lpFileName, lpExtension - lpFileName);

		bool fPrefixDetected = false;
		for (PTCHAR pch = sFileName; *pch != '\0'; pch++) {
			if (*pch == 'm') {
				fPrefixDetected = true;
				break;
			}
		}
		StringCchCopyN(g_settingsFileName, ARRAYSIZE(g_settingsFileName), moduleFileName, lpExtension - moduleFileName);
		StringCchCat(g_settingsFileName, ARRAYSIZE(g_settingsFileName), TEXT(".ini"));
		if (!fPrefixDetected) {
			HCRYPTPROV hCryptProv;
			CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
			BYTE bRandBuf[8];
			CryptGenRandom(hCryptProv, 3, bRandBuf);
			size_t nPos = lpExtension - lpFileName;
			sFileName[nPos++] = TEXT('m');
			for (size_t n = 0; n < 3; n++) {
				size_t nRand = bRandBuf[n] % ('Z' - 'A' + 1 + '9' - '0' + 1);
				sFileName[nPos++] = (TCHAR)((nRand > 9) ? (nRand + 'A' - 10) : (nRand + '0'));
			}
			sFileName[nPos] = TEXT('\0');
			CryptReleaseContext(hCryptProv, 0);

			TCHAR sNewPath[MAX_PATH];
			StringCchCopyN(sNewPath, ARRAYSIZE(sNewPath), moduleFileName, lpFileName - moduleFileName);
			StringCchCat(sNewPath, ARRAYSIZE(sNewPath), sFileName);
			StringCchCat(sNewPath, ARRAYSIZE(sNewPath), lpExtension);

			//DebugMessage(TEXT("%s %s"), sDllName, sNewPath);

			//MoveFile(moduleFileName, sNewPath);

			StringCchCopyN(sNewPath, ARRAYSIZE(sNewPath), moduleFileName, lpFileName - moduleFileName);
			StringCchCat(sNewPath, ARRAYSIZE(sNewPath), sFileName);
			StringCchCat(sNewPath, ARRAYSIZE(sNewPath), TEXT(".ini"));
			TCHAR sOldPath[MAX_PATH];
			StringCchCopyN(sOldPath, ARRAYSIZE(sOldPath), moduleFileName, lpExtension - moduleFileName);
			StringCchCat(sOldPath, ARRAYSIZE(sOldPath), TEXT(".ini"));

			//MoveFile(sOldPath, sNewPath);
			StringCchCopy(g_settingsFileName, ARRAYSIZE(g_settingsFileName), sNewPath);
		}
		if(GetFileAttributes(g_settingsFileName) == (DWORD)-1){
			char cvarName[64];
			sprintf_s(cvarName, "Can't find ini file, delete %s", moduleFileName);
			MessageBox(NULL, cvarName, "Ok", MB_OK);
			return FALSE;
		}
			HMODULE hEngine = GetModuleHandle(TEXT("hw.dll"));
			if (hEngine == NULL) {
				hEngine = GetModuleHandle(TEXT("sw.dll"));
			}

			PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hEngine;
			PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((size_t)hEngine + pDosHeader->e_lfanew);

			const char *pData = (const char *)pNtHeaders->OptionalHeader.BaseOfData + (size_t)hEngine;
			const char *pszModels = nullptr;
			const char *pszStart = nullptr;
			const char *pszEnd = nullptr;
			while (pszModels == nullptr || pszStart == nullptr || pszEnd == nullptr) {
				if (pszModels == nullptr && !strcmp(pData, "models/")) {
					pszModels = pData;
				}
				if (pszStart == nullptr && !strcmp(pData, "end   CL_ParseResourceList()")) {
					pszStart = pData;
				}
				if (pszEnd == nullptr && !strcmp(pData, "Consistency:  server sent too many filenames\n")) {
					pszEnd = pData;
				}
				pData++;
			}

			PIMAGE_BASE_RELOCATION pBaseReloc = (PIMAGE_BASE_RELOCATION)((size_t)hEngine + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			void *pModelsUsing = nullptr;
			void *pStartUsing = nullptr;
			void *pEndUsing = nullptr;
			while (pBaseReloc->SizeOfBlock) {
				PWORD pEnd = (PWORD)((size_t)pBaseReloc + pBaseReloc->SizeOfBlock);

				void *pBase = (void *)((size_t)hEngine + pBaseReloc->VirtualAddress);

				for (PWORD pReloc = (PWORD)(pBaseReloc + 1); pReloc < pEnd; pReloc++) {
					if (*pReloc >> 12 == 0) {
						continue;
					}

					const char *p = *(const char **)((*pReloc & 0xFFF) + (size_t)pBase);

					if (pModelsUsing == nullptr && p == pszModels) {
						pModelsUsing = (void *)((*pReloc & 0xFFF) + (size_t)pBase);
					}
					if (pStartUsing == nullptr && p == pszStart) {
						pStartUsing = (void *)((*pReloc & 0xFFF) + (size_t)pBase);
					}
					if (pEndUsing == nullptr && p == pszEnd) {
						pEndUsing = (void *)((*pReloc & 0xFFF) + (size_t)pBase);
					}
				}

				if (pModelsUsing != nullptr && pStartUsing != nullptr && pEndUsing != nullptr) {
					break;
				}

				pBaseReloc = (PIMAGE_BASE_RELOCATION)((size_t)pBaseReloc + pBaseReloc->SizeOfBlock);
			}

			byte *pStart = (byte *)pModelsUsing + 4;
			while (*pStart != 0xE8) {
				pStart++;
			}
			void *pfnStrStr = (void *)((size_t)pStart + *(long *)(pStart + 1) + 5);

			pStart = (byte *)pEndUsing - 5;
			while (*pStart != 0xE8 || *(long *)(pStart + 1) != (long)pfnStrStr - (long)pStart - 5) {
				pStart--;
			}
			DWORD oldProt;
			VirtualProtect(pStart + 1, 4, PAGE_EXECUTE_READWRITE, &oldProt);
			*(long *)(pStart + 1) = (long)&StrStr_Hooked - (long)pStart - 5;
			VirtualProtect(pStart + 1, 4, oldProt, &oldProt);

			pStart = (byte *)pStartUsing + 4;
			while (*pStart != 0xE8 || *(pStart + 5) != 0x68) {
				pStart++;
			}
			g_pfnCL_ParseConsistencyInfo = (decltype(g_pfnCL_ParseConsistencyInfo))((long)pStart + *(long *)(pStart + 1) + 5);
			VirtualProtect(pStart + 1, 4, PAGE_EXECUTE_READWRITE, &oldProt);
			*(long *)(pStart + 1) = (long)&CL_ParseConsistencyInfo - (long)pStart - 5;
			VirtualProtect(pStart + 1, 4, oldProt, &oldProt);

			if (GetLastError() == ERROR_ALREADY_EXISTS)
				return TRUE;

			DisableThreadLibraryCalls(hinstDLL);

			BaseDir = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH);
			GetModuleFileNameA(hinstDLL, BaseDir, MAX_PATH);
			char* pos = BaseDir + native_strlen(BaseDir);
			while (pos >= BaseDir && *pos != '\\') --pos; pos[1] = 0;*/
			CreateThread(0, 0, CheatEntry, 0, 0, 0);
			ModuleLoaded();
			
			return TRUE;
	}
	return FALSE;
}