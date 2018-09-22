#include "anticheat.h"
#include "offset.h"
#include  <iostream>
#include  <iomanip>
#include "TOTP.h"
#include "sha1.h"
#include "client.h"
#include "NtpClient.h"

using namespace TOTP_Library;
bool InvalidClient;

CAntiCheat::CAntiCheat()
{
	// Create vThreads
	vThreads.push_back(CreateThread(0, 0, thread_CheckHotspots, (void*)this, 0, 0));
	//vThreads.push_back(CreateThread(0, 0, thread_ChecksumCode, (void*)this, 0, 0));
	//vThreads.push_back(CreateThread(0, 0, thread_CheckLoadedModules, (void*)this, 0, 0));
}

CAntiCheat::~CAntiCheat()
{
	FreeAllResources();
}

int CAntiCheat::FreeAllResources()
{
	// Stop vThreads
	std::vector<HANDLE>::iterator i;
	for (i = vThreads.begin(); i != vThreads.end(); ++i) {
		TerminateThread(*i, 0);
		CloseHandle(*i);
	}

	return 1;
}


// -------------------------------------------------------------------------------
// THREADS:
// -------------------------------------------------------------------------------

DWORD WINAPI CAntiCheat::thread_CheckHotspots(LPVOID param)
{
	CAntiCheat* p = (CAntiCheat*)param;

	while (1) {
		p->ThreadRequestResources();
		// 0x04A5F5BA-0x4a5f540

		/*if (p->ScanHotspot(HOTSPOT((char*)(offset.FindClientTable()+0x7A), 1, "\x00"))) {
			
		}*/
		/*if (p->ScanHotspot(HOTSPOT((char*)(offset.FindClientTable() + 0x7A), 0x33, "\x00")))
		{

		}*/
		
		if (p->ScanHotspot(HOTSPOT((char*)(offset.FindClientTable()), 0x100, "\x00")))
		{

		}
			/* TODO HAX DETECTED */
		if(!InvalidClient)
			p->GenerateToken();
		else
			g_Engine.pfnCvar_Set("rnr_auth", "bad");

		p->ThreadReleaseResources();
		Sleep(2000);
	}

	return TRUE;
}

DWORD WINAPI CAntiCheat::thread_ChecksumCode(LPVOID param)
{
	CAntiCheat* p = (CAntiCheat*)param;

	// wait for all modules to get loaded
	// Fixme: Check if a module is loaded before scanning it
	Sleep(2000);

	std::string message;

	while (1) {
		p->ThreadRequestResources();
		p->EnumerateThreads(&CAntiCheat::SuspendThreadById);

		if (!p->CodeHasValidChecksum()) {
			/* TODO HAX DETECTED */
		}
		else {
			message = "Code seems clean!";
		}
		
		p->EnumerateThreads(&CAntiCheat::ResumeThreadById);
		p->ThreadReleaseResources();
		Sleep(10000);
	}

	return TRUE;
}


void CAntiCheat::GenerateToken()
{
	char szString[128];
	sprintf(szString, "steamclient.dll:%d", revEmuTicket.secondSignature);
	auto MyConfig = TOTPConf(
		szString,                                              // The private key
		1024,                                                         // the blocksize
		0,                                                            // start of epoch, seconds since unix epoch when first time slot starts
		20,                                                           // interval between new time slots, this is the interval between new tokens
		5,                                                            // margin of error when validation tokens, in seconds.
		sha1                                                          // hashing algorithm to be used, function of type TOTP_Library::hasher_function
	);

	TOTP MyTokenGenerator(MyConfig);
	std::string token = MyTokenGenerator();
	g_Engine.Con_Printf("%d\n", time(NULL));
	g_Engine.pfnCvar_Set("rnr_auth", token.c_str());
	//LogText(std::to_string(ntpdate()));
	
}
DWORD WINAPI CAntiCheat::thread_CheckLoadedModules(LPVOID param)
{
	CAntiCheat* p = (CAntiCheat*)param;
	std::string s;

	while (1) {
		p->ThreadRequestResources();

		/* TODO HAX DETECTED */
		p->EnumerateModules();

		p->ThreadReleaseResources();
		Sleep(8000);

	}

	return TRUE;
}


int CAntiCheat::EnumerateModules()
{
	int ret = 1;
	std::string s;

	HANDLE hSnap;
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);

	MODULEENTRY32 me32;
	ZeroMemory((void*)&me32, sizeof(MODULEENTRY32));
	me32.dwSize = sizeof(MODULEENTRY32);

	Module32First(hSnap, &me32);
	static int count = 0;
	do {
		s = me32.szModule;		
		if (!ModuleIsSafe(s)) {
			if (ModuleIsBlack(s)) {
				//LogText(s);
			}
			else {
				//LogText(s);
			}
			
			ret = 0;
		}
	} while (Module32Next(hSnap, &me32));

	CloseHandle(hSnap);

	return ret;
}


int CAntiCheat::SuspendThreadById(DWORD threadId)
{
	if (threadId != GetCurrentThreadId()) {
		HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, 0, threadId);
		SuspendThread(hThread);
		CloseHandle(hThread);

		return 1;
	}

	return 0;
}

int CAntiCheat::ResumeThreadById(DWORD threadId)
{
	if (threadId != GetCurrentThreadId()) {
		HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, 0, threadId);
		ResumeThread(hThread);
		CloseHandle(hThread);

		return 1;
	}

	return 0;
}

int CAntiCheat::EnumerateThreads(int (CAntiCheat::*callback)(DWORD threadId))
{
	HANDLE hSnap;

	// returns a list of ALL processes' threads, must filter!
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (!hSnap) return 0;

	THREADENTRY32 te32;
	ZeroMemory((void*)&te32, sizeof(THREADENTRY32));
	te32.dwSize = sizeof(THREADENTRY32);

	if (!Thread32First(hSnap, &te32)) return 0;
	do {
		// DONT suspend all threads in the system O_O
		if (te32.th32OwnerProcessID == GetCurrentProcessId()) {
			(this->*callback)(te32.th32ThreadID);
		}
	} while (Thread32Next(hSnap, &te32));

	CloseHandle(hSnap);

	return 1;
}

DWORD CAntiCheat::GetCurrentThreadId()
{
	DWORD result;

	__asm mov eax, fs:[0x24] // Current thread id
		__asm mov result, eax

	return result;
}

int CAntiCheat::ModuleIsSafe(std::string moduleName)
{
	for (int k = 0; k < WHITELIST_LENGTH; ++k) {
		if (moduleWhitelist[k] == moduleName) {
			return 1;
		}
	}

	return 0;
}

int CAntiCheat::ModuleIsBlack(std::string moduleName)
{
	for (int k = 0; k < BLACKLIST_LENGTH; ++k) {
		if (moduleBlacklist[k] == moduleName) {
			return 1;
		}
	}

	return 0;
}

unsigned char ValidClient [] = { 0x0, 0x36, 0x0, 0x0, 0x0, 0x39, 0x0, 0x0, 0x0, 0x39, 0x0, 0x0, 0x30, 0x3A, 0x0, 0x0, 0x50, 0x3A, 0x0, 0x0, 0x70, 0x3A, 0x0, 0x0, 0x0, 0x35, 0x0, 0x0, 0x0, 0x35, 0x0, 0x0, 0x0, 0x35, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x40, 0x0, 0x0, 0x0, 0x50, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x70, 0x79, 0x0, 0x0, 0x70, 0x6B, 0x0, 0x0, 0x0, 0x6B, 0x0, 0x0, 0x0, 0x6C, 0x0, 0x0, 0x10, 0x60, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4E, 0x0, 0x0, 0x0, 0x52, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x53, 0x0, 0x0, 0x30, 0x0, 0x0, 0x0, 0x0, 0x39, 0x0, 0x0, 0x60, 0x4F, 0x0, 0x0, 0x0, 0x4F, 0x0, 0x0, 0x60, 0x51, 0x0, 0x0, 0x30, 0x4E, 0x0, 0x0, 0x0, 0x35, 0x0, 0x0, 0x0, 0x35, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x50, 0x54, 0x0, 0x0, 0x0, 0x5D, 0x0, 0x0, 0x0, 0x3A, 0x0, 0x0, 0x30, 0x3B, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x7F, 0x0, 0x0, 0x50, 0x3B, 0x0, 0x0, 0x70, 0x3B, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
unsigned char ValidClient2[] = { 0xFFFFFFE0, 0x36, 0xFFFFFFE0, 0x0, 0xFFFFFFA0, 0x39, 0xFFFFFFE0, 0x0, 0xFFFFFF90, 0x39, 0xFFFFFFE0, 0x0, 0x30, 0x3A, 0xFFFFFFE0, 0x0, 0x50, 0x3A, 0xFFFFFFE0, 0x0, 0x70, 0x3A, 0xFFFFFFE0, 0x0, 0xFFFFFFF0, 0x35, 0xFFFFFFE0, 0x0, 0xFFFFFFD0, 0x35, 0xFFFFFFE0, 0x0, 0xFFFFFFE0, 0x35, 0xFFFFFFE0, 0x0, 0xFFFFFFA0, 0xFFFFFFD9, 0xFFFFFFDE, 0x0, 0xFFFFFFE0, 0xFFFFFFD9, 0xFFFFFFDE, 0x0, 0x40, 0xFFFFFFDC, 0xFFFFFFDE, 0x0, 0x50, 0xFFFFFFE3, 0xFFFFFFDE, 0x0, 0xFFFFFFD0, 0xFFFFFFE1, 0xFFFFFFDE, 0x0, 0x70, 0x79, 0xFFFFFFE1, 0x0, 0x70, 0x6B, 0xFFFFFFE1, 0x0, 0xFFFFFFA0, 0x6B, 0xFFFFFFE1, 0x0, 0xFFFFFFE0, 0x6C, 0xFFFFFFE1, 0x0, 0x10, 0x60, 0xFFFFFFE1, 0x0, 0xFFFFFF80, 0xFFFFFFC5, 0xFFFFFFE2, 0x0, 0xFFFFFFB0, 0x4E, 0xFFFFFFE0, 0x0, 0xFFFFFFE0, 0x52, 0xFFFFFFE0, 0x0, 0xFFFFFFE0, 0xFFFFFF8E, 0xFFFFFFE2, 0x0, 0xFFFFFFF0, 0xFFFFFF8E, 0xFFFFFFE2, 0x0, 0x0, 0x53, 0xFFFFFFE0, 0x0, 0x30, 0xFFFFFFEC, 0xFFFFFFDC, 0x0, 0xFFFFFFB0, 0x39, 0xFFFFFFE0, 0x0, 0x60, 0x4F, 0xFFFFFFE0, 0x0, 0xFFFFFFB0, 0x4F, 0xFFFFFFE0, 0x0, 0x60, 0x51, 0xFFFFFFE0, 0x0, 0x30, 0x4E, 0xFFFFFFE0, 0x0, 0xFFFFFFC0, 0x35, 0xFFFFFFE0, 0x0, 0xFFFFFFA0, 0x35, 0xFFFFFFE0, 0x0, 0x40, 0x7C, 0xFFFFFF93, 0x24, 0xFFFFFFE0, 0x6F, 0xFFFFFFE1, 0x0, 0x50, 0x54, 0xFFFFFFE0, 0x0, 0xFFFFFFD0, 0x5D, 0xFFFFFFE0, 0x0, 0xFFFFFFA0, 0x3A, 0xFFFFFFE0, 0x0, 0x30, 0x3B, 0xFFFFFFE0, 0x0, 0xFFFFFFC0, 0xFFFFFF97, 0xFFFFFFE0, 0x0, 0x10, 0x7F, 0xFFFFFFDE, 0x0, 0x50, 0x3B, 0xFFFFFFE0, 0x0, 0x70, 0x3B, 0xFFFFFFE0, 0x0, 0x0, 0x0, 0xFFFFFFDC, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x1, 0x0, 0x0, 0x8, 0xFFFFFFCB, 0xFFFFFF97, 0x0, 0x1, 0x0, 0x0, 0x0, 0xFFFFFFE8, 0xFFFFFFCA, 0xFFFFFF97, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
int CAntiCheat::ScanHotspot(const HOTSPOT& hotspot)
{
	// return true if invalid code is found
	LogText("BEGIN START");
	for (unsigned int k = 0; k < hotspot.size; ++k)
	{
		/* special case for flatcheat */
		if (k == 139 && hotspot.address[k] == 'K')
		{
			InvalidClient = true;
		}
		if (!ValidClient[k] || k == 180)
		{
			continue;
		}
		if (hotspot.address[k] != ValidClient[k] && hotspot.address[k] != ValidClient2[k])
		{
			LogBegin();
			log << "Bad at \n" << k << std::endl;
			log << hotspot.address[k] << hex;
			LogEnd();
			//return 1;		
			char mystring[16];
			sprintf(mystring, "0x%X %d, ", ValidClient2[k], ValidClient2[k]);
			LogBegin();
			log << mystring;
			LogEnd();
			
			
			InvalidClient = true;
		}
		
	}
	//LogText("\nBEGIN END");
	return 0;
}

//const unsigned char  ValidEngine[] = { 0x2a, 0x08, 0x8, 0xf0, 0x3f, 0x5, 0x6b, 0x5b, 0x2c, 0x18, 0xd4, 0x00, 0x8d, 0x79, 0x74, 0x67, };
//const unsigned char  ValidStudio[] = { 0xaf, 0x7e, 0x93, 0x00, 0x90, 0xbe, 0x41, 0xf4, 0x68, 0x0, 0xf3, 0xf8, 0x5e, 0xb0, 0x46, 0x9b };

int CAntiCheat::CodeHasValidChecksum()
{
	int ret = 1;
	/*
	{
		DWORD ptr_offset = offset.FindStudioTable();
		DWORD ptr_size = 1024;
		MD5_CTX mdContext = MD5_Section(ptr_offset, ptr_size);
		bool hax;

		for (int k = 0; k < 16; ++k) {
			if (mdContext.digest[k] != ValidStudio[k])
			{			
				hax = true;
				break;
			}
		}
		if (hax)
		{
			LogText("HAX:");
			LogHash(ptr_offset, ptr_size, mdContext.digest);
		}
		else
		{
			LogText("OK!");
		}
	}
	{
		DWORD ptr_offset = offset.FindEngineTable();
		DWORD ptr_size = 128;
		MD5_CTX mdContext = MD5_Section(ptr_offset, ptr_size);
		bool hax;

		for (int k = 0; k < 16; ++k) {
			if (mdContext.digest[k] != ValidEngine[k])
			{
				hax = true;
				break;
			}
		}
		if (hax)
		{
			LogText("HAX:");
			LogHash(ptr_offset, ptr_size, mdContext.digest);
		}
		else
		{
			LogText("OK!");
		}
	}
	*/
	/*
	{
		DWORD ptr_offset = offset.FindClientTable();
		DWORD ptr_size = 0x1B;
		MD5_CTX mdContext = MD5_Section(ptr_offset, ptr_size);
		bool hax;

		for (int k = 0; k < 16; ++k) {
			if (mdContext.digest[k] != ValidEngine[k])
			{
				hax = true;
				break;
			}
		}
		if (hax)
		{
			LogText("TEST");
			LogHash(ptr_offset, ptr_size, mdContext.digest);
		}
		else
		{
			LogText("OK!");
		}
	}
	*/
	return ret;
}

MD5_CTX CAntiCheat::MD5_Section(int base, int size)
{
	DWORD dwOld = 0;
	VirtualProtect((void*)base, size, PAGE_EXECUTE_READWRITE, &dwOld);

	MD5_CTX mdContext;

	MD5Init(&mdContext);
	MD5Update(&mdContext, (unsigned char*)base, size);
	MD5Final(&mdContext);

	VirtualProtect((void*)base, size, dwOld, &dwOld);

	return mdContext;
}



int CAntiCheat::LogHash(int base, int size, unsigned char* hash)
{
	LogBegin();
	log << "MD5 of section 0x" << std::hex << base << " +0x" << std::hex << size << " requested." << std::endl;
	log << "Hash: {";
	for (int k = 0; k < 16; ++k) {
		log << "0x" << std::hex << static_cast<unsigned int>(hash[k]) << ", ";
	}
	log << "}" << std::endl << std::endl;
	LogEnd();

	return 1;
}


int CAntiCheat::LogBegin()
{
	log.open("anticheat.txt", std::ios::app);

	return 1;
}

int CAntiCheat::LogText(std::string s)
{
	LogBegin();
	log << s << std::endl;
	LogEnd();

	return 1;
}

int CAntiCheat::LogEnd()
{
	log.close();

	return 1;
}
