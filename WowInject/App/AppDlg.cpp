
// AppDlg.cpp: 实现文件
//

#include "stdafx.h"
#include "App.h"
#include "AppDlg.h"
#include "afxdialogex.h"
#include <tlhelp32.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#include <devioctl.h>

#define IOCTL_SET_INJECT_X86DLL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

#define IOCTL_SET_INJECT_X64DLL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

#define IOCTL_SET_INJECT_PROCESSNAME \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

#define IOCTL_INJECT_PID \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

PVOID	dllx64Ptr = NULL;
PVOID	dllx86Ptr = NULL;

ULONG	dllx64Size = 0;
ULONG	dllx86Size = 0;

BOOLEAN g_bInited = FALSE;

PVOID MyReadFile(WCHAR* fileName, PULONG fileSize)
{
    HANDLE fileHandle = NULL;
    DWORD readd = 0;
    PVOID fileBufPtr = NULL;

    fileHandle = CreateFile(
        fileName,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        *fileSize = 0;
        return NULL;
    }

    *fileSize = GetFileSize(fileHandle, NULL);

    fileBufPtr = calloc(1, *fileSize);

    if (!ReadFile(fileHandle, fileBufPtr, *fileSize, &readd, NULL))
    {
        free(fileBufPtr);
        fileBufPtr = NULL;
        *fileSize = 0;
    }

    CloseHandle(fileHandle);
    return fileBufPtr;
}

DWORD findPidByName(const WCHAR* pname)
{
    HANDLE h;
    PROCESSENTRY32 procSnapshot;
    h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    procSnapshot.dwSize = sizeof(PROCESSENTRY32);

    do
    {
        if (!_wcsnicmp(procSnapshot.szExeFile, pname, wcslen(pname) * 2))
        {
            DWORD pid = procSnapshot.th32ProcessID;
            CloseHandle(h);
            return pid;
        }
    } while (Process32Next(h, &procSnapshot));

    CloseHandle(h);
    return 0;
}


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
    , m_strPid(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CAppDlg::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
    DDX_Text(pDX, IDC_EDIT1, m_strPid);
    DDX_Control(pDX, IDC_BUTTON2, m_initbut);
}

BEGIN_MESSAGE_MAP(CAppDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
    ON_BN_CLICKED(IDC_BUTTON1, &CAppDlg::OnBnClickedButton1)
    ON_BN_CLICKED(IDC_BUTTON2, &CAppDlg::OnBnClickedButton2)
END_MESSAGE_MAP()


HANDLE g_hDevice = NULL;
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

 
    g_hDevice = CreateFile(L"\\\\.\\loveyou",
        NULL,
        NULL,
        NULL,
        OPEN_EXISTING,
        NULL,
        NULL);

    if (g_hDevice == INVALID_HANDLE_VALUE)
    {
        AfxMessageBox(L"pls load driver.");
        ExitProcess(0);
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

typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
/*lint -save -e624 */  // Don't complain about different typedefs.
typedef NTSTATUS *PNTSTATUS;
/*lint -restore */  // Resume checking for different typedefs.

#if _WIN32_WINNT >= 0x0600
typedef CONST NTSTATUS *PCNTSTATUS;
#endif // _WIN32_WINNT >= 0x0600
#define STATUS_NOT_FOUND                 ((NTSTATUS)0xC0000225L)
#define STATUS_OBJECTID_EXISTS           ((NTSTATUS)0xC000022BL)

void CAppDlg::OnBnClickedButton1()
{
    UpdateData(TRUE);

    if (!g_bInited)
    {
        AfxMessageBox(L"未初始化");
        return;
    }

    DWORD pid = 0;

    if (m_strPid.IsEmpty())
    {
        AfxMessageBox(L"请输入进程名");
        return;
    }

    pid = findPidByName(m_strPid);

    if (pid == 0)
    {
        AfxMessageBox(L"请输入有效进程名");
        return;
    }

    ULONG x64Size = 0;
    PVOID x64InjceDll = MyReadFile(L"1.dll", &x64Size);


    if (x64InjceDll == NULL)
    {
        AfxMessageBox(L"请将你的dll改名为1.dll防止此exe同目录");
        return;
    }


    DWORD	returnLen;
    char	output;

    if (!DeviceIoControl(
        g_hDevice,
        IOCTL_SET_INJECT_X64DLL,
        x64InjceDll,
        x64Size,
        &output,
        sizeof(char),
        &returnLen,
        NULL))
    {
        AfxMessageBox(L"未知错误");
        return;
    }

    Sleep(500);

    if (DeviceIoControl(
        g_hDevice,
        IOCTL_INJECT_PID,
        &pid,
        4,
        &output,
        sizeof(char),
        &returnLen,
        NULL))
    {
        this->SetWindowTextW(L"inject success.");
    }
    else
    {
        CString str;
        
        auto dwError = GetLastError();
        if (dwError == ERROR_NOT_FOUND)
            str.Format(L"inject faild.-> no target thread 0x%x", dwError);
        else if (dwError == STATUS_OBJECTID_EXISTS) // 支持重复注入 取消
            str.Format(L"inject faild. -> 已经注入过了 0x%x", dwError);
        else
            str.Format(L"inject faild. 0x%x\n", dwError);

        this->SetWindowTextW(str);
    }
}


void CAppDlg::OnBnClickedButton2()
{
    DWORD	returnLen;
    char	output;

    dllx64Ptr = MyReadFile(L"gn2x64.dll", &dllx64Size);
    if (dllx64Ptr == NULL)
    {
        AfxMessageBox(L"no x64dll");
        ExitProcess(0);
    }

    dllx86Ptr = MyReadFile(L"gn2x86.dll", &dllx86Size);
    if (dllx86Ptr == NULL)
    {
        AfxMessageBox(L"no x86dll");
        ExitProcess(0);
    }

    auto result = DeviceIoControl(
        g_hDevice,
        IOCTL_SET_INJECT_X86DLL,
        dllx86Ptr,
        dllx86Size,
        &output,
        sizeof(char),
        &returnLen,
        NULL);

    if (result == FALSE)
        AfxMessageBox(L"x86 fail.");


    result = DeviceIoControl(
        g_hDevice,
        IOCTL_SET_INJECT_X64DLL,
        dllx64Ptr,
        dllx64Size,
        &output,
        sizeof(char),
        &returnLen,
        NULL);

    if (result == FALSE)
        AfxMessageBox(L"x64 fail.");

    UpdateData(TRUE);

    DWORD pid = 0;

    if (m_strPid.IsEmpty())
    {
        AfxMessageBox(L"请输入进程名");
        return;
    }

    pid = findPidByName(m_strPid);

    if (pid == 0)
    {
        AfxMessageBox(L"请输入有效进程名");
        return;
    }

    if (DeviceIoControl(
        g_hDevice,
        IOCTL_INJECT_PID,
        &pid,
        4,
        &output,
        sizeof(char),
        &returnLen,
        NULL))
    {
        m_initbut.SetWindowTextW(L"初始化成功");
        m_initbut.EnableWindow(FALSE);
        g_bInited = true;
    }
    else
    {
        m_initbut.SetWindowTextW(L"初始化失败");
    }
}
