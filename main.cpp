#include <iostream>
#include <Windows.h>
#include <Psapi.h>

#pragma comment (lib, "Psapi.lib")

using namespace std;

#define MAT_PATH_LENGTH 512

/**
要对一个任意进程（包括系统安全进程和服务进程）进行指定了写相关的访问权的OpenProcess操作，只要当前进程具有SeDeDebug权限就可以了。
要是一个用户是Administrator或是被给予了相应的权限，就可以具有该权限。
可是，就算我们用Administrator帐号对一个系统安全进程执行OpenProcess(PROCESS_ALL_ACCESS,FALSE, dwProcessID)还是会遇到“访问拒绝”的错误。
原来在默认的情况下进程的一些访问权限是没有被启用（Enabled）的，所以我们要做的首先是启用这些权限。
与此相关的一些API函数有OpenProcessToken、LookupPrivilegevalue、AdjustTokenPrivileges。
我们要修改一个进程的访问令牌，首先要获得进程访问令牌的句柄，这可以通过OpenProcessToken得到。
接着我们可以调用AdjustTokenPrivileges对这个访问令牌进行修改

函数名称：OpenProcessToken
函数功能：用来打开与进程相关联的访问令牌
函数参数：
    @ProcessHandle      要修改访问权限的进程句柄
    @DesiredAccess      要进行的操作类型，如要修改访问令牌的特权应设为TOKEN_ADJUST_PRIVILEGES 
    @TokenHandle        返回的访问令牌指针
BOOL OpenProcessToken(
    HANDLE ProcessHandle,   //要修改访问权限的进程句柄
    DWORD DesiredAccess,    //指定你要进行的操作类型
    PHANDLE TokenHandle     //返回的访问令牌指针
);

函数名称：LookupPrivilegeValue
函数功能：函数查看系统权限的特权值，返回信息到一个LUID结构体里
函数参数：
    @lpSystemName      所要查看的系统，本地系统直接用NULL
    @lpName            指向一个以零结尾的字符串，指定特权的名称，如在WinNT h头文件定义
    @lpLuid            用来接收所返回的制定特权名称的信息
BOOL LookupPrivilegeValue(
    LPCTSTR lpSystemName,
    LPCTSTR lpName,
    PLUID lpLuid
);

函数名称：AdjustTokenPrivileges
函数功能：启用或禁止指定访问令牌的特权
BOOL AdjustTokenPrivileges(
    HANDLE TokenHandle,                 //包含特权的句柄
    BOOL DisableAllPrivileges,          //禁用所有权限标志
    PTOKEN_PRIVILEGES NewState,         //新特权信息的指针(结构体)
    DWORD BufferLength,                 //缓冲数据大小,以字节为单位的PreviousState的缓存区(sizeof)
    PTOKEN_PRIVILEGES PreviousState,    //接收被改变特权当前状态的Buffer
    PDWORD ReturnLength                 //接收PreviousState缓存区要求的大小
);
**/
int main()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    DWORD processID;
    HANDLE hProcess;
    char path[MAT_PATH_LENGTH];
    char drive[MAT_PATH_LENGTH];
    char dir[MAT_PATH_LENGTH];
    char name[MAT_PATH_LENGTH];
    char ext[MAT_PATH_LENGTH];

    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
    
    AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);

    while(true)
    {
        cin>>processID;

        if(processID == 4)
        {
            cout<<"system"<<endl;
            continue;
        }

        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, false, processID);
        if(hProcess == NULL)
        {
            cout<<"error process"<<endl;
            continue;
        }

        GetModuleFileNameEx(hProcess, NULL, path, MAT_PATH_LENGTH);

        _splitpath(path, drive, dir, name, ext);
        cout<<path<<endl;
        cout<<drive<<endl;
        cout<<dir<<endl;
        cout<<name<<endl;
        cout<<ext<<endl;
    }
    return 0;
}