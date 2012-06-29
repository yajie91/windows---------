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
extern CAPIHook g1_TerminateProcess;
extern CAPIHook g2_TerminateProcess;
extern CAPIHook g_SHFileOperationW;
extern CAPIHook g_OpenFile;;
// 自定义TerminateProcess函数

BOOL WINAPI Hook_OpenFile(LPCSTR lpFileName,LPOFSTRUCT ipReOpenBuff,UINT uStyle)
{
typedef BOOL (WINAPI *PFNTERMINATEPROCESS)(LPCSTR lpFileName,LPOFSTRUCT ipReOpenBuff,UINT uStyle);

	// 取得主模块的文件名称
	char szPathName[MAX_PATH];
	::GetModuleFileName(NULL, szPathName, MAX_PATH);

	int nChNum = WideCharToMultiByte(CP_ACP,0,(LPCWSTR)(LPCWSTR)lpFileName,wcslen((LPCWSTR)(lpFileName)),NULL,0,NULL,NULL); 

	LPSTR lpstr = new char[nChNum + 1]; 
	WideCharToMultiByte(CP_ACP,0,(LPCWSTR)(LPCWSTR)lpFileName,wcslen((LPCWSTR)(lpFileName)),lpstr,nChNum,NULL,NULL); 
	lpstr[nChNum] = '\0'; 


	// 构建发送给主窗口的字符串
	char sz[2048];
	wsprintf(sz, "OpenFile-进程：（%d）%s    %s",
		::GetCurrentProcessId(),lpstr, szPathName);

	// 发送这个字符串到主对话框
	COPYDATASTRUCT cds = { ::GetCurrentProcessId(), strlen(sz) + 1, sz };
	if(::SendMessage(::FindWindow(NULL, "进程保护器"), WM_COPYDATA, 0, (LPARAM)&cds) != -1)
	{
		// 如果函数的返回值不是－1，我们就允许API函数执行
	//	return ((PFNTERMINATEPROCESS)(PROC)g2_TerminateProcess.m_pfnOrig)( hFile, lpBuffer,  nNumberOfBytesToWrite,
	//		lpNumberOfBytesWritten, lpOverlapped);
		return ((PFNTERMINATEPROCESS)(PROC)g2_TerminateProcess.m_pfnOrig)( lpFileName, ipReOpenBuff, uStyle);
	}
	return true;
}


BOOL WINAPI Hook_ExitProcess(HANDLE hProcess, UINT uExitCode)
{
	typedef BOOL (WINAPI *PFNTERMINATEPROCESS)(HANDLE, UINT);

	// 取得主模块的文件名称
	char szPathName[MAX_PATH];
	::GetModuleFileName(NULL, szPathName, MAX_PATH);

	// 构建发送给主窗口的字符串
	char sz[2048];
	wsprintf(sz, "ExitProcess-进程：（%d）%s 进程句柄：%X退出代码%d",
		::GetCurrentProcessId(), szPathName, hProcess,uExitCode);

	// 发送这个字符串到主对话框
	COPYDATASTRUCT cds = { ::GetCurrentProcessId(), strlen(sz) + 1, sz };
	if(::SendMessage(::FindWindow(NULL, "进程保护器"), WM_COPYDATA, 0, (LPARAM)&cds) != -1)
	{
		// 如果函数的返回值不是－1，我们就允许API函数执行
		return ((PFNTERMINATEPROCESS)(PROC)TerminateProcess)(hProcess, uExitCode);
	}
	return TRUE;
}

BOOL WINAPI Hook_CreateFileW(LPCWSTR lpFileName,DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
			 DWORD dwCreationDisposition,  DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	typedef BOOL (WINAPI *PFNTERMINATEPROCESS)(LPCWSTR lpFileName,DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
			 DWORD dwCreationDisposition,  DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

	// 取得主模块的文件名称
	char szPathName[MAX_PATH];
	::GetModuleFileName(NULL, szPathName, MAX_PATH);

	int nChNum = WideCharToMultiByte(CP_ACP,0,(LPCWSTR)(LPCWSTR)lpFileName,wcslen((LPCWSTR)(lpFileName)),NULL,0,NULL,NULL); 

	LPSTR lpstr = new char[nChNum + 1]; 
	WideCharToMultiByte(CP_ACP,0,(LPCWSTR)(LPCWSTR)lpFileName,wcslen((LPCWSTR)(lpFileName)),lpstr,nChNum,NULL,NULL); 
	lpstr[nChNum] = '\0'; 


	// 构建发送给主窗口的字符串
	char sz[2048];
	wsprintf(sz, "CreateFileW-进程：（%d）%s    %s",
		::GetCurrentProcessId(),lpstr, szPathName);

	// 发送这个字符串到主对话框
	COPYDATASTRUCT cds = { ::GetCurrentProcessId(), strlen(sz) + 1, sz };
	if(::SendMessage(::FindWindow(NULL, "进程保护器"), WM_COPYDATA, 0, (LPARAM)&cds) != -1)
	{
		// 如果函数的返回值不是－1，我们就允许API函数执行
	//	return ((PFNTERMINATEPROCESS)(PROC)g2_TerminateProcess.m_pfnOrig)( hFile, lpBuffer,  nNumberOfBytesToWrite,
	//		lpNumberOfBytesWritten, lpOverlapped);
		return ((PFNTERMINATEPROCESS)(PROC)g2_TerminateProcess.m_pfnOrig)(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
			  dwCreationDisposition, dwFlagsAndAttributes,  hTemplateFile);
	}
	return true;
}
BOOL WINAPI Hook_SHFileOperationW(LPSHFILEOPSTRUCTW ipFileOp)
{
	typedef BOOL (WINAPI *PFNTERMINATEPROCESS)(LPSHFILEOPSTRUCTW ipFileOp);

	// 取得主模块的文件名称
	char szPathName[MAX_PATH];
	::GetModuleFileName(NULL, szPathName, MAX_PATH);

	// 构建发送给主窗口的字符串
	char sz[2048];
	wsprintf(sz, "SHFileOperationW-进程：（%d）%s",
		::GetCurrentProcessId(), szPathName);

	// 发送这个字符串到主对话框
	COPYDATASTRUCT cds = { ::GetCurrentProcessId(), strlen(sz) + 1, sz };
	if(::SendMessage(::FindWindow(NULL, "进程保护器"), WM_COPYDATA, 0, (LPARAM)&cds) != -1)
	{
		// 如果函数的返回值不是－1，我们就允许API函数执行
	//	return ((PFNTERMINATEPROCESS)(PROC)g2_TerminateProcess.m_pfnOrig)( hFile, lpBuffer,  nNumberOfBytesToWrite,
	//		lpNumberOfBytesWritten, lpOverlapped);
		return ((PFNTERMINATEPROCESS)(PROC)g_SHFileOperationW.m_pfnOrig)(ipFileOp);
	}
	return true;
}

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

CAPIHook g1_TerminateProcess ("kernel32.dll","ExitProcess",(PROC)Hook_ExitProcess,true);
CAPIHook g2_TerminateProcess ("kernel32.dll","CreateFileW",(PROC)Hook_CreateFileW,true);
CAPIHook g_SHFileOperationW("shell32.dll","SHFileOperationW",(PROC)Hook_SHFileOperationW,true);
CAPIHook g_OpenFile("shell32.dll","OpenFile",(PROC)Hook_OpenFile,true);
//::SHFileOperationW(IPSHFILEOPSTRUCTW ipFileOp);
//::CreateFileA(LPCTSTR lpFileName,DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
//			 DWORD dwCreationDisposition,  DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
//::GetModuleHandle(LPCSTR lpModuleName);
//::GetStdHandle(DWORD nStdHandle);
//::WriteFile(
//　　HANDLE hFile, // 文件句柄
//　　LPCVOID lpBuffer, // 数据缓存区指针
//　　DWORD nNumberOfBytesToWrite, // 你要写的字节数
//　　LPDWORD lpNumberOfBytesWritten, // 用于保存实际写入字节数的存储区域的指针
//　　LPOVERLAPPED lpOverlapped // OVERLAPPED结构体指针
//  　　)

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

	//		char *tmp = "TerminateProcess";

	//				char sz[2048];
	//				int i= strcmp(pszFunName,tmp);
	//wsprintf(sz, "\r\nTerminateProces：(%d)%s\r\n\r\n ",i,pszFunName);

	//// 发送这个字符串到主对话框
	//COPYDATASTRUCT cds = { ::GetCurrentProcessId(), strlen(sz) + 1, sz };
	//::SendMessage(::FindWindow(NULL, "进程保护器"), WM_COPYDATA, 0, (LPARAM)&cds) ;


			//	if(!(strcmp(pszFunName,tmp)))
			//		{
	
	//			g_TerminateProcess[0].hooknode= new CAPIHook("kernel32.dll","TerminateProcess", //??????????????????????????
	//					(PROC)Hook_TerminateProcess,true);
	//			g_TerminateProcess[0].Funname=pszFunName;
	//			return 1;
		//		}
		//		}
			// 打印出函数名称和地址
	//		printf("  从此模块导入的函数：%-25s，", pszFunName);
	//		printf("函数地址：%X \n", lpAddr);
			n++; pThunk++;
		}
		
		pImportDesc++;
	}
	return 1;
}





