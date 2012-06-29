////////////////////////////////////////////////
// HookTermProApp.cpp文件

#include "resource.h"
#include "HookTermProApp.h"
#include  "shlobj.h"

CMyApp theApp;

// DLL导出函数
BOOL WINAPI SetSysHook(BOOL bInstall, DWORD dwThreadId = 0)
{
	typedef BOOL (WINAPI *PFNSETSYSHOOK)(BOOL, DWORD);

	// 调试的时候可以这样设置szDll[] = "..//09HookTermProLib//debug//09HookTermProLib.dll";
	char szDll[] = "E://My Files//VS2008 Project//windows程序设计//book_code//09HookTermProLib//Debug//09HookTermProLib.dll";
//	char szDll[] = "09HookTermProLib.dll";

	// 加载09HookTermProLib.dll模块
	BOOL bNeedFree = FALSE;
	HMODULE hModule = ::GetModuleHandle(szDll);
	if(hModule == NULL)
	{
		hModule = ::LoadLibrary(szDll);
		bNeedFree = TRUE;
	}

	// 获取SetSysHook函数的地址
	PFNSETSYSHOOK mSetSysHook = (PFNSETSYSHOOK)::GetProcAddress(hModule, "SetSysHook");
	if(mSetSysHook == NULL) // 文件不正确?
	{
		if(bNeedFree)
			::FreeLibrary(hModule);
		return FALSE;
	}

	// 调用SetSysHook函数
	BOOL bRet = mSetSysHook(bInstall, dwThreadId);

	// 如果有必要，释放上面加载的模块
	if(bNeedFree)
		::FreeLibrary(hModule);

	return bRet;
}

BOOL CMyApp::InitInstance()
{
	// 安装钩子
	if(!SetSysHook(TRUE, 0))
		::MessageBox(NULL, "安装钩子出错！", "09HookTermProApp", 0);
	// 显示对话框
	CMainDialog dlg;
	m_pMainWnd = &dlg;
	dlg.DoModal();
	// 卸载钩子
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
	
	m_list.InsertColumn(0,_T("您选择的应用程序"),LVCFMT_LEFT,200,0);
	m_list1.InsertColumn(0,_T("监视结果"),LVCFMT_LEFT,200,0);
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
	// 检查是否禁止执行
	BOOL bForbid = ((CButton*)GetDlgItem(IDC_FORBIDEXE))->GetCheck();
	if(bForbid)
		return -1;
	return TRUE;
}

int CALLBACK BrowseCallBackFun(HWND hwnd, UINT uMsg, LPARAM lParam, LPARAM lpData)  
{  
    switch(uMsg)  
    {  
    case BFFM_INITIALIZED:  //选择文件夹对话框初始化  
        //设置默认路径为lpData即'D:\'  
        ::SendMessage(hwnd, BFFM_SETSELECTION, TRUE, lpData);  
        //在STATUSTEXT区域显示当前路径  
        ::SendMessage(hwnd, BFFM_SETSTATUSTEXT, 0, lpData);  
        //设置选择文件夹对话框的标题  
        ::SetWindowText(hwnd, TEXT("请先设置个工作目录"));   
        break;  
    case BFFM_SELCHANGED:   //选择文件夹变更时  
        {  
            TCHAR pszPath[MAX_PATH];  
            //获取当前选择路径  
            SHGetPathFromIDList((LPCITEMIDLIST)lParam, pszPath);  
            //在STATUSTEXT区域显示当前路径  
            ::SendMessage(hwnd, BFFM_SETSTATUSTEXT, TRUE, (LPARAM)pszPath);  
        }  
        break;  
    }  
    return 0;  
}  

void CMainDialog::OnBnClickedchoose()
{
	// TODO: 在此添加控件通知处理程序代码
	 TCHAR pszPath[MAX_PATH];  
    BROWSEINFO bi;   
    bi.hwndOwner      = this->GetSafeHwnd();  
    bi.pidlRoot       = NULL;  
    bi.pszDisplayName = NULL;   
    bi.lpszTitle      = TEXT("请选择应用程序");   
    bi.ulFlags        = BIF_RETURNONLYFSDIRS | BIF_STATUSTEXT|BIF_BROWSEINCLUDEFILES;  
    bi.lpfn           = BrowseCallBackFun;     //回调函数  
    bi.lParam         = (LPARAM)TEXT("");  //传给回调函数的参数,设置默认路径  
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
	// TODO: 在此添加控件通知处理程序代码
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
