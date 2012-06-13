//////////////////////////////////////////////////
// HookTermProLib.cpp文件


#include <windows.h>
#include "APIHook.h"

#define API_NUM     5

int count = 0;
struct HOOK
{
	 CAPIHook *hooknode;
	 char *Funname;
}Hook;

HOOK g_TerminateProcess[API_NUM];
//extern CAPIHook g1_TerminateProcess;

// 自定义TerminateProcess函数
BOOL WINAPI Hook_TerminateProcess(HANDLE hProcess, UINT uExitCode)
{
	typedef BOOL (WINAPI *PFNTERMINATEPROCESS)(HANDLE, UINT);

	// 取得主模块的文件名称
	char szPathName[MAX_PATH];
	::GetModuleFileName(NULL, szPathName, MAX_PATH);

	// 构建发送给主窗口的字符串
	char sz[2048];
	wsprintf(sz, "\r\n 进程：（%d）%s\r\n\r\n 进程句柄：%X\r\n 退出代码%d",
		::GetCurrentProcessId(), szPathName, hProcess,uExitCode);

	// 发送这个字符串到主对话框
	COPYDATASTRUCT cds = { ::GetCurrentProcessId(), strlen(sz) + 1, sz };
	if(::SendMessage(::FindWindow(NULL, "进程保护器"), WM_COPYDATA, 0, (LPARAM)&cds) != -1)
	{
		// 如果函数的返回值不是－1，我们就允许API函数执行
		for(int i=0;i<API_NUM;i++)
		{
//			if(g_TerminateProcess[i].get_m_pfnOrig()==((PFNTERMINATEPROCESS)(PROC)g_TerminateProcess[i])(hProcess, uExitCode))
//				return ((PFNTERMINATEPROCESS)(PROC)g_TerminateProcess[i])(hProcess, uExitCode);
		}
	//	return ((PFNTERMINATEPROCESS)(PROC)Hook_TerminateProcess)(hProcess, uExitCode);//??????????
		return true;
	}
	return TRUE;
}

// 挂钩TerminateProcess函数
//CAPIHook g_TerminateProcess("kernel32.dll", "TerminateProcess", 
//						(PROC)Hook_TerminateProcess);
//CAPIHook g1_TerminateProcess("kernel32.dll", "CreateFileA", 
//						(PROC)Hook_TerminateProcess);


int HookAll()
{
HMODULE hMod = ::GetModuleHandle(NULL);

	IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)hMod;
	IMAGE_OPTIONAL_HEADER * pOptHeader =
		(IMAGE_OPTIONAL_HEADER *)((BYTE*)hMod + pDosHeader->e_lfanew + 24);

	IMAGE_IMPORT_DESCRIPTOR* pImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)
		((BYTE*)hMod + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while(pImportDesc->FirstThunk)
	{
		char* pszDllName = (char*)((BYTE*)hMod +pImportDesc->Name);
//		printf("\n模块名称：%s \n", pszDllName);
	
		
		// 一个IMAGE_THUNK_DATA就是一个双字，它指定了一个导入函数
		IMAGE_THUNK_DATA* pThunk = (IMAGE_THUNK_DATA*)
			((BYTE*)hMod + pImportDesc->OriginalFirstThunk);
		int n = 0;
		while(pThunk->u1.Function)
		{
			// 取得函数名称。hint/name表前两个字节是函数的序号，后4个字节是函数名称字符串的地址
			char* pszFunName = (char*)
				((BYTE*)hMod + (DWORD)pThunk->u1.AddressOfData + 2);
			// 取得函数地址。IAT表就是一个DWORD类型的数组，每个成员记录一个函数的地址
			PDWORD lpAddr = (DWORD*)((BYTE*)hMod + pImportDesc->FirstThunk) + n;
			if(count<API_NUM)
			{
	//			if(!(strcmp(pszFunName,"TerminateProcess")))
	//		CAPIHook *tmp= new CAPIHook("kernel32.dll","TerminateProcess", //??????????????????????????
	//					(PROC)Hook_TerminateProcess,true);
				g_TerminateProcess[count++].hooknode= new CAPIHook("kernel32.dll",pszFunName, //??????????????????????????
						(PROC)Hook_TerminateProcess,true);
				g_TerminateProcess[count++].Funname=pszFunName;
	
			}
			// 打印出函数名称和地址
	//		printf("  从此模块导入的函数：%-25s，", pszFunName);
	//		printf("函数地址：%X \n", lpAddr);
			n++; pThunk++;
		}
		
		pImportDesc++;
	}
	return 1;
}
//int a = HookAll();


///////////////////////////////////////////////////////////////////////////

#pragma data_seg("YCIShared")
HHOOK g_hHook = NULL;
#pragma data_seg()

static HMODULE ModuleFromAddress(PVOID pv) 
{
	MEMORY_BASIC_INFORMATION mbi;
	if(::VirtualQuery(pv, &mbi, sizeof(mbi)) != 0)
	{
		return (HMODULE)mbi.AllocationBase;
	}
	else
	{
		return NULL;
	}
}

static LRESULT WINAPI GetMsgProc(int code, WPARAM wParam, LPARAM lParam) 
{
	return ::CallNextHookEx(g_hHook, code, wParam, lParam);
}

BOOL WINAPI SetSysHook(BOOL bInstall, DWORD dwThreadId)
{
	BOOL bOk;
	if(bInstall) 
	{
		g_hHook = ::SetWindowsHookEx(WH_GETMESSAGE, GetMsgProc, 
						ModuleFromAddress(GetMsgProc), dwThreadId);
		bOk = (g_hHook != NULL);
	} 
	else 
	{
		bOk = ::UnhookWindowsHookEx(g_hHook);
		g_hHook = NULL;
	}
	return bOk;
}


BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{

	HMODULE hMod = ::GetModuleHandle(NULL);

	IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)hMod;
	IMAGE_OPTIONAL_HEADER * pOptHeader =
		(IMAGE_OPTIONAL_HEADER *)((BYTE*)hMod + pDosHeader->e_lfanew + 24);

	IMAGE_IMPORT_DESCRIPTOR* pImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)
		((BYTE*)hMod + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while(pImportDesc->FirstThunk)
	{
		char* pszDllName = (char*)((BYTE*)hMod +pImportDesc->Name);
//		printf("\n模块名称：%s \n", pszDllName);
	
		
		// 一个IMAGE_THUNK_DATA就是一个双字，它指定了一个导入函数
		IMAGE_THUNK_DATA* pThunk = (IMAGE_THUNK_DATA*)
			((BYTE*)hMod + pImportDesc->OriginalFirstThunk);
		int n = 0;
		while(pThunk->u1.Function)
		{
			// 取得函数名称。hint/name表前两个字节是函数的序号，后4个字节是函数名称字符串的地址
			char* pszFunName = (char*)
				((BYTE*)hMod + (DWORD)pThunk->u1.AddressOfData + 2);
			// 取得函数地址。IAT表就是一个DWORD类型的数组，每个成员记录一个函数的地址
			PDWORD lpAddr = (DWORD*)((BYTE*)hMod + pImportDesc->FirstThunk) + n;
			if(count<API_NUM)
			{
		//		if(!(strcmp(pszFunName,"TerminateProcess")))
		//		{
	//		CAPIHook *tmp= new CAPIHook("kernel32.dll","TerminateProcess", //??????????????????????????
	//					(PROC)Hook_TerminateProcess,true);
				if(count<3)
				{
					count++;
			
				}else
				{
				g_TerminateProcess[count].hooknode= new CAPIHook("kernel32.dll",pszFunName, //??????????????????????????
						(PROC)Hook_TerminateProcess,true);
				g_TerminateProcess[count++].Funname=pszFunName;
				}
		//		}
			}
			// 打印出函数名称和地址
	//		printf("  从此模块导入的函数：%-25s，", pszFunName);
	//		printf("函数地址：%X \n", lpAddr);
			n++; pThunk++;
		}
		
		pImportDesc++;
	}
	return 1;
}





