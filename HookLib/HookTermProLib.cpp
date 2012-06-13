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
//extern CAPIHook g1_TerminateProcess;

// �Զ���TerminateProcess����
BOOL WINAPI Hook_TerminateProcess(HANDLE hProcess, UINT uExitCode)
{
	typedef BOOL (WINAPI *PFNTERMINATEPROCESS)(HANDLE, UINT);

	// ȡ����ģ����ļ�����
	char szPathName[MAX_PATH];
	::GetModuleFileName(NULL, szPathName, MAX_PATH);

	// �������͸������ڵ��ַ���
	char sz[2048];
	wsprintf(sz, "\r\n ���̣���%d��%s\r\n\r\n ���̾����%X\r\n �˳�����%d",
		::GetCurrentProcessId(), szPathName, hProcess,uExitCode);

	// ��������ַ��������Ի���
	COPYDATASTRUCT cds = { ::GetCurrentProcessId(), strlen(sz) + 1, sz };
	if(::SendMessage(::FindWindow(NULL, "���̱�����"), WM_COPYDATA, 0, (LPARAM)&cds) != -1)
	{
		// ��������ķ���ֵ���ǣ�1�����Ǿ�����API����ִ��
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

// �ҹ�TerminateProcess����
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
			if(count<API_NUM)
			{
	//			if(!(strcmp(pszFunName,"TerminateProcess")))
	//		CAPIHook *tmp= new CAPIHook("kernel32.dll","TerminateProcess", //??????????????????????????
	//					(PROC)Hook_TerminateProcess,true);
				g_TerminateProcess[count++].hooknode= new CAPIHook("kernel32.dll",pszFunName, //??????????????????????????
						(PROC)Hook_TerminateProcess,true);
				g_TerminateProcess[count++].Funname=pszFunName;
	
			}
			// ��ӡ���������ƺ͵�ַ
	//		printf("  �Ӵ�ģ�鵼��ĺ�����%-25s��", pszFunName);
	//		printf("������ַ��%X \n", lpAddr);
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
			// ��ӡ���������ƺ͵�ַ
	//		printf("  �Ӵ�ģ�鵼��ĺ�����%-25s��", pszFunName);
	//		printf("������ַ��%X \n", lpAddr);
			n++; pThunk++;
		}
		
		pImportDesc++;
	}
	return 1;
}





