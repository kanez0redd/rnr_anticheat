#include "singleton.h"
#include "md5.h"
#include <tlhelp32.h>
#include "hotspot.h"
#include <vector>
#include "whitelist.h"
#include "blacklist.h"

#include <fstream>
#include <sstream>

class CAntiCheat;

class CAntiCheat : public CSingleton<CAntiCheat> {
public:
	// CONSTRUCTOR / DESTRUCTOR:
	CAntiCheat();
	~CAntiCheat();

	// THREADS:
	static DWORD WINAPI thread_CheckHotspots(LPVOID param);
	static DWORD WINAPI thread_ChecksumCode(LPVOID param);
	static DWORD WINAPI thread_CheckLoadedModules(LPVOID param);

	// ANTI-CHEAT:
	int ScanHotspot(const HOTSPOT& hotspot);
	int CodeHasValidChecksum();
	MD5_CTX MD5_Section(int base, int size);
	int ModuleIsSafe(std::string moduleName);
	int ModuleIsBlack(std::string moduleName);
	int EnumerateModules();
	DWORD GetCurrentThreadId();
	int SuspendThreadById(DWORD threadId);
	int ResumeThreadById(DWORD threadId);
	int EnumerateThreads(int (CAntiCheat::*callback)(DWORD threadId));

	void GenerateToken();

	// GENERAL:
	int FreeAllResources();
	int LogHash(int base, int size, unsigned char* hash);
	int LogBegin();
	int LogText(std::string s);
	int LogEnd();

	// THREADS:
	std::vector<HANDLE> vThreads; // Vector to keep track of vThreads

	// LOGGING:
	std::ofstream log;
};
