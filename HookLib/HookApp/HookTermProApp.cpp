////////////////////////////////////////////////
// HookTermProApp.cpp�ļ�

#include "resource.h"
#include "HookTermProApp.h"
#include  "shlobj.h"

CMyApp theApp;

// DLL��������
BOOL WINAPI SetSysHook(BOOL bInstall, DWORD dwThreadId = 0)
{
	typedef BOOL (WINAPI *PFNSETSYSHOOK)(BOOL, DWORD);

	// ���Ե�ʱ�������������szDll[] = "..//09HookTermProLib//debug//09HookTermProLib.dll";
	char szDll[] = "E://My Files//VS2008 Project//windows�������//book_code//09HookTermProLib//Debug//09HookTermProLib.dll";
//	char szDll[] = "09HookTermProLib.dll";

	// ����09HookTermProLib.dllģ��
	BOOL bNeedFree = FALSE;
	HMODULE hModule = ::GetModuleHandle(szDll);
	if(hModule == NULL)
	{
		hModule = ::LoadLibrary(szDll);
		bNeedFree = TRUE;
	}

	// ��ȡSetSysHook�����ĵ�ַ
	PFNSETSYSHOOK mSetSysHook = (PFNSETSYSHOOK)::GetProcAddress(hModule, "SetSysHook");
	if(mSetSysHook == NULL) // �ļ�����ȷ?
	{
		if(bNeedFree)
			::FreeLibrary(hModule);
		return FALSE;
	}

	// ����SetSysHook����
	BOOL bRet = mSetSysHook(bInstall, dwThreadId);

	// ����б�Ҫ���ͷ�������ص�ģ��
	if(bNeedFree)
		::FreeLibrary(hModule);

	return bRet;
}

BOOL CMyApp::InitInstance()
{
	// ��װ����
	if(!SetSysHook(TRUE, 0))
		::MessageBox(NULL, "��װ���ӳ���", "09HookTermProApp", 0);
	// ��ʾ�Ի���
	CMainDialog dlg;
	m_pMainWnd = &dlg;
	dlg.DoModal();
	// ж�ع���
	SetSysHook(FALSE);

	return FALSE;
}

CMainDialog::CMainDialog(CWnd* pParentWnd):CDialog(IDD_MAINDLG, pParentWnd)
{
	App_count = 0;
	Hook_count = 0;
}
void CMainDialog::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST, m_list);
	DDX_Control(pDX, IDC_LIST1, m_list1);
}
BEGIN_MESSAGE_MAP(CMainDialog, CDialog)
ON_WM_COPYDATA()
ON_BN_CLICKED(IDC_BUTTON1, &CMainDialog::OnBnClickedchoose)
ON_NOTIFY(NM_CLICK, IDC_LIST, &CMainDialog::OnNMClickList)
END_MESSAGE_MAP()

BOOL CMainDialog::OnInitDialog()
{
	CDialog::OnInitDialog();
	::SetWindowPos(this->m_hWnd,HWND_BOTTOM,0,0,1100,600,SWP_NOZORDER);
	SetIcon(theApp.LoadIcon(IDI_MAIN), FALSE);
	m_list.SetExtendedStyle(LVS_EX_FLATSB
		|LVS_EX_FULLROWSELECT
		|LVS_EX_HEADERDRAGDROP
		|LVS_EX_ONECLICKACTIVATE
		|LVS_EX_GRIDLINES);
	
	m_list.InsertColumn(0,_T("��ѡ���Ӧ�ó���"),LVCFMT_LEFT,200,0);
	m_list1.InsertColumn(0,_T("���ӽ��"),LVCFMT_LEFT,200,0);
//	::SetWindowPos(m_hWnd, HWND_TOPMOST, 0, 0, 
//		0, 0, SWP_NOSIZE|SWP_NOREDRAW|SWP_NOMOVE);
	return TRUE;
}

BOOL CMainDialog::OnCopyData(CWnd* pWnd, COPYDATASTRUCT* pCopyDataStruct)
{
	GetDlgItem(IDC_HOOKINFO)->SetWindowText((char*)pCopyDataStruct->lpData);
	char *tmp = (char*)pCopyDataStruct->lpData;
	CString tmp_Data=tmp;
	LPTSTR  tmp_App=(LPTSTR)(LPCTSTR)SelectAPP;
	if(tmp_Data.Find(tmp_App)!=-1)
	{;
	if((Hook_count>0))
	{
		CString theString = m_list1.GetItemText(Hook_count-1,0);
		LPTSTR lpsz =(LPTSTR)(LPCTSTR)theString;
	if((strcmp(lpsz,tmp))){
	m_list1.InsertItem(Hook_count,_T(""));
	m_list1.SetItemText(Hook_count,0,_T(tmp));
	Hook_count++;
	}
	}else
	{
	m_list1.InsertItem(Hook_count,_T(""));
	m_list1.SetItemText(Hook_count,0,_T(tmp));
	Hook_count++;
	}
	}
	// ����Ƿ��ִֹ��
	BOOL bForbid = ((CButton*)GetDlgItem(IDC_FORBIDEXE))->GetCheck();
	if(bForbid)
		return -1;
	return TRUE;
}

int CALLBACK BrowseCallBackFun(HWND hwnd, UINT uMsg, LPARAM lParam, LPARAM lpData)  
{  
    switch(uMsg)  
    {  
    case BFFM_INITIALIZED:  //ѡ���ļ��жԻ����ʼ��  
        //����Ĭ��·��ΪlpData��'D:\'  
        ::SendMessage(hwnd, BFFM_SETSELECTION, TRUE, lpData);  
        //��STATUSTEXT������ʾ��ǰ·��  
        ::SendMessage(hwnd, BFFM_SETSTATUSTEXT, 0, lpData);  
        //����ѡ���ļ��жԻ���ı���  
        ::SetWindowText(hwnd, TEXT("�������ø�����Ŀ¼"));   
        break;  
    case BFFM_SELCHANGED:   //ѡ���ļ��б��ʱ  
        {  
            TCHAR pszPath[MAX_PATH];  
            //��ȡ��ǰѡ��·��  
            SHGetPathFromIDList((LPCITEMIDLIST)lParam, pszPath);  
            //��STATUSTEXT������ʾ��ǰ·��  
            ::SendMessage(hwnd, BFFM_SETSTATUSTEXT, TRUE, (LPARAM)pszPath);  
        }  
        break;  
    }  
    return 0;  
}  

void CMainDialog::OnBnClickedchoose()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	 TCHAR pszPath[MAX_PATH];  
    BROWSEINFO bi;   
    bi.hwndOwner      = this->GetSafeHwnd();  
    bi.pidlRoot       = NULL;  
    bi.pszDisplayName = NULL;   
    bi.lpszTitle      = TEXT("��ѡ��Ӧ�ó���");   
    bi.ulFlags        = BIF_RETURNONLYFSDIRS | BIF_STATUSTEXT|BIF_BROWSEINCLUDEFILES;  
    bi.lpfn           = BrowseCallBackFun;     //�ص�����  
    bi.lParam         = (LPARAM)TEXT("");  //�����ص������Ĳ���,����Ĭ��·��  
    bi.iImage         = 0;   
      
    LPITEMIDLIST pidl = SHBrowseForFolder(&bi);  
    if (pidl == NULL)  
    {  
        return;  
    }  
      
    if (SHGetPathFromIDList(pidl, pszPath))  
    {  
        AfxMessageBox(pszPath);  

	m_list.InsertItem(0,_T(""));
	m_list.SetItemText(0,0,_T(pszPath));
		UpdateData();
		UpdateWindow();
    }  
}

void CMainDialog::OnNMClickList(NMHDR *pNMHDR, LRESULT *pResult)
{
//	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<NMITEMACTIVATE>(pNMHDR);
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	for(int i=0;i<m_list.GetItemCount();i++)
	{
		if(m_list.GetItemState(i,LVIS_SELECTED) == LVIS_SELECTED)
		{
			SelectAPP = m_list.GetItemText(i,0);
			GetDlgItem(IDC_HOOKINFO)->SetWindowText(SelectAPP);
		}
	}
	
	*pResult = 0;
}
