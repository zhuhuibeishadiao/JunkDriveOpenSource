
// AppDlg.cpp: 实现文件
//

#include "stdafx.h"
#include "App.h"
#include "AppDlg.h"
#include "afxdialogex.h"
#include <Windows.h>
#include <devioctl.h>

#define IOCTL_BASE  0x800
#define MY_CTL_CODE(i) CTL_CODE(FILE_DEVICE_NULL, IOCTL_BASE + i, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_TEST MY_CTL_CODE(0) 
#define IOCTL_HIDE_DRIVER MY_CTL_CODE(1)

HANDLE g_hDevice = NULL;

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CAppDlg 对话框



CAppDlg::CAppDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_APP_DIALOG, pParent)
    , m_szDrvName(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CAppDlg::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
    DDX_Text(pDX, IDC_EDIT1, m_szDrvName);
}

BEGIN_MESSAGE_MAP(CAppDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
    ON_BN_CLICKED(IDC_BUTTON1, &CAppDlg::OnBnClickedButton1)
    ON_BN_CLICKED(IDC_BUTTON2, &CAppDlg::OnBnClickedButton2)
END_MESSAGE_MAP()


// CAppDlg 消息处理程序

BOOL CAppDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

    g_hDevice = CreateFileA("\\\\.\\BLCheers",
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    if (g_hDevice == INVALID_HANDLE_VALUE)
    {
        CString str;
        str.Format(L"0x%p", GetLastError());
        AfxMessageBox(str);

    }

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CAppDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CAppDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CAppDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CAppDlg::OnBnClickedButton1()
{
    UpdateData(TRUE);

    if (m_szDrvName.IsEmpty())
    {
        AfxMessageBox(L"请填写要隐藏驱动名");
        return;
    }

    DWORD dwRet = 0;

    if (DeviceIoControl(g_hDevice, IOCTL_HIDE_DRIVER, m_szDrvName.GetBuffer(), m_szDrvName.GetLength() * 2, NULL, 0, &dwRet, NULL))
        this->SetWindowTextW(L"隐藏成功");
    else
        this->SetWindowTextW(L"隐藏失败");

}


void CAppDlg::OnBnClickedButton2()
{
#define IOCTRL_BASE_HIDE 0x800

#define MYIOCTRL_CODE_HIDE(i) \
    CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTRL_BASE_HIDE+i, METHOD_BUFFERED,FILE_ANY_ACCESS)

#define CTL_HELLO MYIOCTRL_CODE_HIDE(0)

    HANDLE hDevice = CreateFileA("\\\\.\\ntmodeldrv",
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        CString str;
        str.Format(L"0x%p", GetLastError());
        AfxMessageBox(str);
    }

    DWORD dwRet = 0;

    if (!DeviceIoControl(hDevice, CTL_HELLO, NULL, 0, NULL, 0, &dwRet, NULL))
        AfxMessageBox(L"通信失败");
    else
        AfxMessageBox(L"通信成功");

    CloseHandle(hDevice);
}
