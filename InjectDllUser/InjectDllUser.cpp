#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
__declspec(dllimport) BOOL createLocalProcess();

#ifdef _WIN64
#define int_t __int64
#else
#define int_t unsigned int
#endif

BOOL enableDebugPrivilege();
HMODULE getProcessModuleHandle(DWORD pid, const TCHAR* moduleName) {
	MODULEENTRY32 me;
	HANDLE hModuleSnapshot = NULL;
	hModuleSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (!hModuleSnapshot) {
		CloseHandle(hModuleSnapshot);
		return NULL;
	}
	ZeroMemory(&me, sizeof(me));
	me.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(hModuleSnapshot, &me)) {
		CloseHandle(hModuleSnapshot);
		return NULL;
	}
	do {
		//printf("%s\t%x\n", me.szModule, me.hModule);
		if (!lstrcmp(me.szModule, moduleName)) {
			return me.hModule;
		}
	} while (Module32Next(hModuleSnapshot, &me));
	CloseHandle(hModuleSnapshot);
	return 0;
}
BOOL InjectDllProcess(DWORD targetId, LPCSTR dllPath) {
	HANDLE hProc = NULL;
	hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetId);
	if (hProc == NULL) {
		printf("[-]OpenProcess Failed");
		return FALSE;
	}
	LPTSTR psLibFileRemote = NULL;
	//使用VirtualAllocEx在远程进程内存地址分配DLL文件名的缓冲区
	psLibFileRemote = (LPTSTR)VirtualAllocEx(hProc, NULL, lstrlen(dllPath) + 1,MEM_COMMIT,PAGE_READWRITE);
	if (psLibFileRemote == NULL) {
		printf("[-]VirtualAllocEx Failed");
		CloseHandle(hProc);
		return FALSE;
	}
	//使用WriteProcessMemory
	if (WriteProcessMemory(hProc, psLibFileRemote, (void*)dllPath, lstrlen(dllPath) + 1, NULL) == 0) {
		printf("[-]WriteProcessMemory Failed");
		VirtualFreeEx(hProc, psLibFileRemote, lstrlen(dllPath) + 1, MEM_DECOMMIT);
		CloseHandle(hProc);
		return FALSE;
	}


	//计算LoadLibraryA的入口地址
	HMODULE hModule = getProcessModuleHandle(targetId, "KERNEL32.DLL");
	HMODULE hLocalModule = GetModuleHandle("Kernel32.dll");
	int_t localAddr=(int_t)GetProcAddress(hLocalModule, "LoadLibraryA");
	int_t offFunc = localAddr - (int_t)hLocalModule;
	PTHREAD_START_ROUTINE pfnStartAddr = (PTHREAD_START_ROUTINE)((int_t)hModule + offFunc);
	if (pfnStartAddr == NULL) {
		printf("[-] GetProcessAddress Failed");
		return FALSE;
	}

	//pfnStartAddr就是LoadLibraryA的入口地址
	HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, pfnStartAddr, psLibFileRemote, 0, NULL);

	if (hThread == NULL) {
		printf("[-] CreateRemoteThread Failed");
		VirtualFreeEx(hProc, psLibFileRemote, lstrlen(dllPath) + 1, MEM_DECOMMIT);
		CloseHandle(hProc);
		return FALSE;
	}
	printf("[*]Inject SuccessFull.");
	//clean
	WaitForSingleObject(hThread, INFINITE);
	VirtualFreeEx(hProc, psLibFileRemote, lstrlen(dllPath) + 1, MEM_DECOMMIT);
	CloseHandle(hThread);
	CloseHandle(hProc);
	return TRUE;
}

DWORD findProcessId(LPCSTR procName) {
	DWORD retProcId = 0;
	HANDLE hSnapShot=::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("[-]create process snapshot failed.\n");
		return retProcId;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	::Process32First(hSnapShot, &pe32);
	do {
		//printf("now:%s\t%d\n", pe32.szExeFile,pe32.th32ProcessID);
		if(!lstrcmp(pe32.szExeFile, procName)){
			retProcId = pe32.th32ProcessID;
			break;
		}
	} while (::Process32Next(hSnapShot, &pe32));
	::CloseHandle(hSnapShot);
	return retProcId;
}

int main() {
	enableDebugPrivilege();
	DWORD notepadProcId=findProcessId("notepad.exe");

	InjectDllProcess(notepadProcId, "D:/code/workProject/InjectDll/x64/Debug/InjectDll.dll");
	//printf("%d", notepadProcId);
	//createLocalProcess();
	return 0;
}

BOOL enableDebugPrivilege() {
	HANDLE TokenHandle = NULL;
	TOKEN_PRIVILEGES TokenPrivilege;
	LUID uID;
	//获得进程的令牌句柄
	if (!OpenProcessToken(
		GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&TokenHandle)) {
		return FALSE;
	}
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &uID)) {
		CloseHandle(TokenHandle);
		TokenHandle=INVALID_HANDLE_VALUE;
		return FALSE;
	}
	TokenPrivilege.PrivilegeCount = 1;
	TokenPrivilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	TokenPrivilege.Privileges[0].Luid = uID;
	//调整权限
	if (!AdjustTokenPrivileges(TokenHandle, FALSE, &TokenPrivilege, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		CloseHandle(TokenHandle);
		TokenHandle = INVALID_HANDLE_VALUE;
		return  FALSE;
	}
	CloseHandle(TokenHandle);
	TokenHandle = INVALID_HANDLE_VALUE;
	return TRUE;
}

