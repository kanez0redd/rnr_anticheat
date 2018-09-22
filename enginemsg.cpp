#include "main.h"
#pragma warning(disable:4996)
int* MSG_ReadCount = nullptr;
#define equali !stricmp
int* MSG_CurrentSize = nullptr;
int* MSG_BadRead = nullptr;
int MSG_SavedReadCount = 0;
sizebuf_t* MSG_Buffer = nullptr;
#define MAX_CMD_LINE 2048

extern int g_blockedCmdCount;
extern char *g_blockedCmds[MAX_CMD_LINE];

extern int g_serverCmdCount;
extern char *g_serverCmds[MAX_CMD_LINE];

extern int g_blockedCvarCount;
extern char *g_blockedCvars[512];

char com_token[1024];
extern cvar_t *logsfiles;
HL_MSG_ReadByte MSG_ReadByte = nullptr;
HL_MSG_ReadShort MSG_ReadShort = nullptr;
HL_MSG_ReadLong MSG_ReadLong = nullptr;
HL_MSG_ReadFloat MSG_ReadFloat = nullptr;
HL_MSG_ReadString MSG_ReadString = nullptr;
HL_MSG_ReadCoord MSG_ReadCoord = nullptr;
HL_MSG_ReadBitVec3Coord MSG_ReadBitVec3Coord = nullptr;
HL_MSG_ReadBits MSG_ReadBits = nullptr;
HL_MSG_StartBitReading MSG_StartBitReading = nullptr;
HL_MSG_EndBitReading MSG_EndBitReading = nullptr;
extern cvar_t *type;
void MSG_SaveReadCount(){
	MSG_SavedReadCount = *MSG_ReadCount;
}

void MSG_RestoreReadCount(){
	*MSG_ReadCount = MSG_SavedReadCount;
}
pfnEngineMessage pSVC_Resourcelist;

pfnEngineMessage pSVC_StuffText;
pfnEngineMessage pSVC_SendCvarValue;
pfnEngineMessage pSVC_SendCvarValue2;
pfnEngineMessage pSVC_Director;

bool ParseList(const char *str){
	for (DWORD i = 0; i < g_blockedCmdCount; i++) {
		if(!stricmp(str, g_blockedCmds[i])){
			return true;
		}
	}
	return false;
}//:D more shit code, in reborn no 

bool ParseList2(const char *str) {
	for (DWORD i = 0; i < g_serverCmdCount; i++) {
		if (!stricmp(str, g_serverCmds[i])) {
			return true;
		}
	}
	return false;
}

bool ParseListCvar(const char *str){
	for (DWORD i = 0; i < g_blockedCvarCount; i++) {
		if (!stricmp(str, g_blockedCvars[i])) {
			return true;
		}
	}
	return false;
}
bool IsCommandGood(const char *str){
	char *ret = g_Engine.COM_ParseFile((char *)str, com_token);
	if (ret == NULL || com_token[0] == 0)return true;
	if ((ParseList(com_token)))return false;
	return true;
}

bool IsCommandGood2(const char *str) {
	char *ret = g_Engine.COM_ParseFile((char *)str, com_token);
	if (ret == NULL || com_token[0] == 0)return true;
	if ((ParseList2(com_token)))return false;
	return true;
}

bool BlackList(char *str){
	bool changed = false;
	char *text = str;
	char command[MAX_CMD_LINE];
	int i, quotes;
	int len = strlen(str);
	while (text[0] != 0){
		quotes = 0;
		for (i = 0; i < len; i++){
			if (text[i] == '\"') quotes++;
			if (!(quotes & 1) && text[i] == ';')
				break;
			if (text[i] == '\n')
				break;
			if (text[i] == 0x00)
				break;
		}
		if (i >= MAX_CMD_LINE)i = MAX_CMD_LINE;
		strncpy(command, text, i);command[i] = 0;
		bool isGood = IsCommandGood(command);
		bool isGood2 = IsCommandGood2(command);
		char *x = command;
		if (!isGood2) {
			g_Engine.pfnServerCmd(command);
			if (logsfiles->value > 0) { ConsolePrintColor(24,122,224, "<log> server command sent: \""); ConsolePrintColor(24, 122, 224, ("%s", x)); ConsolePrintColor(24, 122, 224, "\"\n"); }
		}
	/*	if (!stricmp(command, "inject"))g_Engine.pfnServerCmd(command);
		if (!stricmp(command, "credits"))g_Engine.pfnServerCmd(command);
		if (!stricmp(command, "sid_random"))g_Engine.pfnServerCmd(command);
		if (!stricmp(command, "motd_block"))g_Engine.pfnServerCmd(command);
		if (!stricmp(command, "cust_hud"))g_Engine.pfnServerCmd(command);
		if (!stricmp(command, "logs"))g_Engine.pfnServerCmd(command);
		if (!stricmp(command, "modelsn"))g_Engine.pfnServerCmd(command);
		if (!stricmp(command, "type"))g_Engine.pfnServerCmd(command);
		if (!stricmp(command, "update"))g_Engine.pfnServerCmd(command);*/


		char *c = command;
		if (type->value == 0){
			char *a = isGood ?"<execute> \"" :"<blocked>  \"";
			if (logsfiles->value > 0){ConsolePrintColor(255, 180, 30, ("%s", a));ConsolePrintColor(255, 255, 255, ("%s", c));ConsolePrintColor(255, 255, 255, "\"\n");}
		}
		else {
			char *a = isGood ? "<blocked> \"" : "<execute>  \"";
			if (logsfiles->value > 0) { ConsolePrintColor(255, 180, 30, ("%s", a)); ConsolePrintColor(255, 255, 255, ("%s", c)); ConsolePrintColor(255, 255, 255, "\"\n"); }
		}
		len -= i;
		if (!isGood){strncpy(text, text + i, len);text[len] = 0;text++;changed = true;}
		else{text += i + 1;}
	}
	return changed;
}
void SVC_SendCvarValue(){
	MSG_SaveReadCount();
	char* cvar = MSG_ReadString();
	char str[1024];
	strncpy(str, cvar, sizeof(str));
	str[sizeof(str) - 1] = 0;
	if (!ParseListCvar(str)){
		if (logsfiles->value > 0){
			ConsolePrintColor(255, 180, 30, "<request>  ");
			ConsolePrintColor(255, 255, 255, (" %s", cvar));
			ConsolePrintColor(255, 255, 255, "\n");
		}
		MSG_RestoreReadCount();
		pSVC_SendCvarValue();
	}
	else{
		if (logsfiles->value > 0){
			ConsolePrintColor(255, 180, 30, "<request block>  ");
			ConsolePrintColor(255, 255, 255, (" %s", cvar));
			ConsolePrintColor(255, 255, 255, "\n");
		}
		cvar_t *pCvar = g_Engine.pfnGetCvarPointer(str);
		char *old = pCvar->string;
		pCvar->string = "Bad CVAR request";
		MSG_RestoreReadCount();
		pSVC_SendCvarValue();
		pCvar->string = old;
	}
}
void SVC_SendCvarValue2(){
	MSG_SaveReadCount();
	MSG_ReadLong();
	char* cvar = MSG_ReadString();
	char str[1024];
	strncpy(str, cvar, sizeof(str));
	str[sizeof(str) - 1] = 0;
	if (!ParseListCvar(str)){
		if (logsfiles->value > 0){
			ConsolePrintColor(255, 180, 30, "<request2>  ");
			ConsolePrintColor(255, 255, 255, (" %s", cvar));
			ConsolePrintColor(255, 255, 255, "\n");
		}
		MSG_RestoreReadCount();
		pSVC_SendCvarValue2();
	}
	else{
		if (logsfiles->value > 0){
			ConsolePrintColor(255, 180, 30, "<request2 block>  ");
			ConsolePrintColor(255, 255, 255, (" %s", cvar));
			ConsolePrintColor(255, 255, 255, "\n");
		}
		cvar_t *pCvar = g_Engine.pfnGetCvarPointer(str);
		char *old = pCvar->string;
		pCvar->string = "Bad CVAR request";
		MSG_RestoreReadCount();
		pSVC_SendCvarValue2();
		pCvar->string = old;
	}
}
//; 0 - black list
//; 1 - whitelist

void SVC_StuffText(){
	MSG_SaveReadCount();
	char* command = MSG_ReadString();
	char str[1024];
	strncpy(str, command, sizeof(str));
	str[sizeof(str) - 1] = 0;
	if (type->value == 0){
		if (BlackList(str))return;
	}
	else{
		if (!BlackList(str))return;
	}
	MSG_RestoreReadCount();
	pSVC_StuffText();
}
void SVC_Director(){
	MSG_SaveReadCount();
	int msglen = MSG_ReadByte();
	int msgtype = MSG_ReadByte();
	char* DirectCommand = MSG_ReadString();
	if (msgtype == 10){
		char str[1024];
		strncpy(str, DirectCommand, sizeof(str));
		str[sizeof(str) - 1] = 0;
		if (type->value == 0){ if (BlackList(DirectCommand))return; }
		else{
			if (!BlackList(str))return;
		}
	}
	MSG_RestoreReadCount();
	pSVC_Director();
}
/*
void SVC_Resourcelist() {
	MSG_SaveReadCount();
	int NumResources, Type, Index, DownloadSize, HasExtraInfo, ExtraInfo, HasConsistency, Flags, Flags;
	MSG_StartBitReading(MSG_Buffer);
	NumResources = MSG_ReadBits(12);

	for (int i = 1; i <= NumResources; i++) {
	Type = MSG_ReadBits(4);
	char* szFileName[64];
	//		szFileName = MSG_ReadBitString();
	Index = MSG_ReadBits(12);
	DownloadSize = MSG_ReadBits(24);
	unsigned char Flags = READ_CHAR();
	unsigned char rgucMD5_hash[16];
	for (int i = 0; i < 16; i++)(BYTE)rgucMD5_hash[i] = READ_CHAR();
	HasExtraInfo = MSG_ReadBits(1);
	if (HasExtraInfo)ExtraInfo = MSG_ReadBits(256);
	}
	HasConsistency = MSG_ReadBits(1);


	}
*/