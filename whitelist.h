#ifndef INC_WHITELIST
#define INC_WHITELIST

#include <string>

struct WhitelistItem {
	std::string moduleName;
	unsigned int entryPoint;
};

// Fixme: Add module entry point or some other identifier, file hash maybe? too slow?
// At the moment this can be bypassed by injecting a module with the same name as one of these that
// isnt loaded at the time of injection

const int WHITELIST_LENGTH = 160;
const std::string moduleWhitelist[WHITELIST_LENGTH] = { 
											"hl.exe",
											"ntdll.dll",
											"KERNEL32.DLL",
											"KERNELBASE.dll",
											"apphelp.dll",
											"USER32.dll",
											"win32u.dll",
											"GDI32.dll",
											"gdi32full.dll",
											"ADVAPI32.dll",
											"msvcrt.dll",
											"sechost.dll",
											"RPCRT4.dll",
											"SspiCli.dll",
											"CRYPTBASE.dll",
											"bcryptPrimitives.dll",
											"WSOCK32.dll",
											"WS2_32.dll",
											"IMM32.DLL",
											"gameoverlayrenderer.dll",
											"ole32.dll",
											"combase.dll",
											"ucrtbase.dll",
											"PSAPI.DLL",
											"WINMM.dll",
											"WINMMBASE.dll",
											"cfgmgr32.dll",
											"filesystem_stdio.dll",
											"hw.dll",
											"DINPUT.dll",
											"DDRAW.dll",
											"VERSION.dll",
											"OPENGL32.dll",
											"vgui.dll",
											"mss32.dll",
											"SDL2.dll",
											"steam_api.dll",
											"OLEAUT32.dll",
											"msvcp_win.dll",
											"SHELL32.dll",
											"windows.storage.dll",
											"powrprof.dll",
											"shlwapi.dll",
											"kernel.appcore.dll",
											"shcore.dll",
											"profapi.dll",
											"GLU32.dll",
											"DCIMAN32.dll",
											"steamclient.dll",
											"CRYPT32.dll",
											"MSASN1.dll",
											"imagehlp.dll",
											"SETUPAPI.dll",
											"IPHLPAPI.DLL",
											"tier0_s.dll",
											"vstdlib_s.dll",
											"Secur32.dll",
											"crashhandler.dll",
											"WININET.dll",
											"uxtheme.dll",
											"clbcatq.dll",
											"XAudio2_5.dll",
											"dinput8.dll",
											"HID.DLL",
											"DEVOBJ.dll",
											"WINTRUST.dll",
											"XInput1_4.dll",
											"dwmapi.dll",
											"MSCTF.dll",
											"nvoglv32.DLL",
											"WTSAPI32.dll",
											"ntmarta.dll",
											"WINSTA.dll",
											"MMDevApi.dll",
											"PROPSYS.dll",
											"AUDIOSES.DLL",
											"wintypes.dll",
											"client.dll",
											"particleman.dll",
											"GameUI.dll",
											"vgui2.dll",
											"chromehtml.dll",
											"libcef.dll",
											"tier0.dll",
											"WINHTTP.dll",
											"COMDLG32.dll",
											"USP10.dll",
											"WINSPOOL.DRV",
											"COMCTL32.dll",
											"USERENV.dll",
											"urlmon.dll",
											"MSIMG32.dll",
											"bcrypt.dll",
											"iertutil.dll",
											"icudt.dll",
											"avcodec-53.dll",
											"avutil-51.dll",
											"avformat-53.dll",
											"NSI.dll",
											"NLAapi.dll",
											"dsound.dll",
											"avrt.dll",
											"AntiCheat.mix",
											"mssmp3.asi",
											"mssvoice.asi",
											"wdmaud.drv",
											"ksuser.dll",
											"msacm32.drv",
											"MSACM32.dll",
											"midimap.dll",
											"demoplayer.dll",
											"core.dll",
											"serverbrowser.dll",
											"vstdlib.dll",
											"mswsock.dll" };

#endif