//////////////////////////////////////////////////
// HookTermProLib.cpp�ļ�


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
// �Զ���TerminateProcess����

BOOL WINAPI Hook_OpenFile(LPCSTR lpFileName,LPOFSTRUCT ipReOpenBuff,UINT uStyle)
{
typedef BOOL (WINAPI *PFNTERMINATEPROCESS)(LPCSTR lpFileName,LPOFSTRUCT ipReOpenBuff,UINT uStyle);

	// ȡ����ģ����ļ�����
	char szPathName[MAX_PATH];
	::GetModuleFileName(NULL, szPathName, MAX_PATH);

	int nChNum = WideCharToMultiByte(CP_ACP,0,(LPCWSTR)(LPCWSTR)lpFileName,wcslen((LPCWSTR)(lpFileName)),NULL,0,NULL,NULL); 

	LPSTR lpstr = new char[nChNum + 1]; 
	WideCharToMultiByte(CP_ACP,0,(LPCWSTR)(LPCWSTR)lpFileName,wcslen((LPCWSTR)(lpFileName)),lpstr,nChNum,NULL,NULL); 
	lpstr[nChNum] = '\0'; 


	// �������͸������ڵ��ַ���
	char sz[2048];
	wsprintf(sz, "OpenFile-���̣���%d��%s    %s",
		::GetCurrentProcessId(),lpstr, szPathName);

	// ��������ַ��������Ի���
	COPYDATASTRUCT cds = { ::GetCurrentProcessId(), strlen(sz) + 1, sz };
	if(::SendMessage(::FindWindow(NULL, "���̱�����"), WM_COPYDATA, 0, (LPARAM)&cds) != -1)
	{
		// ��������ķ���ֵ���ǣ�1�����Ǿ�����API����ִ��
	//	return ((PFNTERMINATEPROCESS)(PROC)g2_TerminateProcess.m_pfnOrig)( hFile, lpBuffer,  nNumberOfBytesToWrite,
	//		lpNumberOfBytesWritten, lpOverlapped);
		return ((PFNTERMINATEPROCESS)(PROC)g2_TerminateProcess.m_pfnOrig)( lpFileName, ipReOpenBuff, uStyle);
	}
	return true;
}


BOOL WINAPI Hook_ExitProcess(HANDLE hProcess, UINT uExitCode)
{
	typedef BOOL (WINAPI *PFNTERMINATEPROCESS)(HANDLE, UINT);

	// ȡ����ģ����ļ�����
	char szPathName[MAX_PATH];
	::GetModuleFileName(NULL, szPathName, MAX_PATH);

	// �������͸������ڵ��ַ���
	char sz[2048];
	wsprintf(sz, "ExitProcess-���̣���%d��%s ���̾����%X�˳�����%d",
		::GetCurrentProcessId(), szPathName, hProcess,uExitCode);

	// ��������ַ��������Ի���
	COPYDATASTRUCT cds = { ::GetCurrentProcessId(), strlen(sz) + 1, sz };
	if(::SendMessage(::FindWindow(NULL, "���̱�����"), WM_COPYDATA, 0, (LPARAM)&cds) != -1)
	{
		// ��������ķ���ֵ���ǣ�1�����Ǿ�����API����ִ��
		return ((PFNTERMINATEPROCESS)(PROC)TerminateProcess)(hProcess, uExitCode);
	}
	return TRUE;
}

BOOL WINAPI Hook_CreateFileW(LPCWSTR lpFileName,DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
			 DWORD dwCreationDisposition,  DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	typedef BOOL (WINAPI *PFNTERMINATEPROCESS)(LPCWSTR lpFileName,DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
			 DWORD dwCreationDisposition,  DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

	// ȡ����ģ����ļ�����
	char szPathName[MAX_PATH];
	::GetModuleFileName(NULL, szPathName, MAX_PATH);

	int nChNum = WideCharToMultiByte(CP_ACP,0,(LPCWSTR)(LPCWSTR)lpFileName,wcslen((LPCWSTR)(lpFileName)),NULL,0,NULL,NULL); 

	LPSTR lpstr = new char[nChNum + 1]; 
	WideCharToMultiByte(CP_ACP,0,(LPCWSTR)(LPCWSTR)lpFileName,wcslen((LPCWSTR)(lpFileName)),lpstr,nChNum,NULL,NULL); 
	lpstr[nChNum] = '\0'; 


	// �������͸������ڵ��ַ���
	char sz[2048];
	wsprintf(sz, "CreateFileW-���̣���%d��%s    %s",
		::GetCurrentProcessId(),lpstr, szPathName);

	// ��������ַ��������Ի���
	COPYDATASTRUCT cds = { ::GetCurrentProcessId(), strlen(sz) + 1, sz };
	if(::SendMessage(::FindWindow(NULL, "���̱�����"), WM_COPYDATA, 0, (LPARAM)&cds) != -1)
	{
		// ��������ķ���ֵ���ǣ�1�����Ǿ�����API����ִ��
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

	// ȡ����ģ����ļ�����
	char szPathName[MAX_PATH];
	::GetModuleFileName(NULL, szPathName, MAX_PATH);

	// �������͸������ڵ��ַ���
	char sz[2048];
	wsprintf(sz, "SHFileOperationW-���̣���%d��%s",
		::GetCurrentProcessId(), szPathName);

	// ��������ַ��������Ի���
	COPYDATASTRUCT cds = { ::GetCurrentProcessId(), strlen(sz) + 1, sz };
	if(::SendMessage(::FindWindow(NULL, "���̱�����"), WM_COPYDATA, 0, (LPARAM)&cds) != -1)
	{
		// ��������ķ���ֵ���ǣ�1�����Ǿ�����API����ִ��
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
//����HANDLE hFile, // �ļ����
//����LPCVOID lpBuffer, // ���ݻ�����ָ��
//����DWORD nNumberOfBytesToWrite, // ��Ҫд���ֽ���
//����LPDWORD lpNumberOfBytesWritten, // ���ڱ���ʵ��д���ֽ����Ĵ洢�����ָ��
//����LPOVERLAPPED lpOverlapped // OVERLAPPED�ṹ��ָ��
//  ����)

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
//		printf("\nģ�����ƣ�%s \n", pszDllName);
	
		
		// һ��IMAGE_THUNK_DATA����һ��˫�֣���ָ����һ�����뺯��
		IMAGE_THUNK_DATA* pThunk = (IMAGE_THUNK_DATA*)
			((BYTE*)hMod + pImportDesc->OriginalFirstThunk);
		int n = 0;
		while(pThunk->u1.Function)
		{
			// ȡ�ú������ơ�hint/name��ǰ�����ֽ��Ǻ�������ţ���4���ֽ��Ǻ��������ַ����ĵ�ַ
			char* pszFunName = (char*)
				((BYTE*)hMod + (DWORD)pThunk->u1.AddressOfData + 2);
			// ȡ�ú�����ַ��IAT�����һ��DWORD���͵����飬ÿ����Ա��¼һ�������ĵ�ַ
			PDWORD lpAddr = (DWORD*)((BYTE*)hMod + pImportDesc->FirstThunk) + n;

	//		char *tmp = "TerminateProcess";

	//				char sz[2048];
	//				int i= strcmp(pszFunName,tmp);
	//wsprintf(sz, "\r\nTerminateProces��(%d)%s\r\n\r\n ",i,pszFunName);

	//// ��������ַ��������Ի���
	//COPYDATASTRUCT cds = { ::GetCurrentProcessId(), strlen(sz) + 1, sz };
	//::SendMessage(::FindWindow(NULL, "���̱�����"), WM_COPYDATA, 0, (LPARAM)&cds) ;


			//	if(!(strcmp(pszFunName,tmp)))
			//		{
	
	//			g_TerminateProcess[0].hooknode= new CAPIHook("kernel32.dll","TerminateProcess", //??????????????????????????
	//					(PROC)Hook_TerminateProcess,true);
	//			g_TerminateProcess[0].Funname=pszFunName;
	//			return 1;
		//		}
		//		}
			// ��ӡ���������ƺ͵�ַ
	//		printf("  �Ӵ�ģ�鵼��ĺ�����%-25s��", pszFunName);
	//		printf("������ַ��%X \n", lpAddr);
			n++; pThunk++;
		}
		
		pImportDesc++;
	}
	return 1;
}





