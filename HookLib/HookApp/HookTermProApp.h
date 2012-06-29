///////////////////////////////////////////
// HookTermProApp.hÎÄ¼þ

#include <afxwin.h>	
#include "afxcmn.h"


class CMyApp : public CWinApp
{
public:
	BOOL InitInstance();
};

class CMainDialog : public CDialog
{
public:
	CMainDialog(CWnd* pParentWnd = NULL);
	CString SelectAPP;
	CListCtrl m_list;
	CListCtrl m_list1;
	int App_count;
	int Hook_count;
protected:
	virtual BOOL OnInitDialog();
	virtual void DoDataExchange(CDataExchange* pDX);
	afx_msg BOOL OnCopyData(CWnd* pWnd, COPYDATASTRUCT *pCopyDataStruct);
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedchoose();
	afx_msg void OnNMClickList(NMHDR *pNMHDR, LRESULT *pResult);
};