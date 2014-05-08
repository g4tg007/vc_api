#include <iostream>
#include <Windows.h>
#include <Psapi.h>

#pragma comment (lib, "Psapi.lib")

using namespace std;

#define MAT_PATH_LENGTH 512

/**
Ҫ��һ��������̣�����ϵͳ��ȫ���̺ͷ�����̣�����ָ����д��صķ���Ȩ��OpenProcess������ֻҪ��ǰ���̾���SeDeDebugȨ�޾Ϳ����ˡ�
Ҫ��һ���û���Administrator���Ǳ���������Ӧ��Ȩ�ޣ��Ϳ��Ծ��и�Ȩ�ޡ�
���ǣ�����������Administrator�ʺŶ�һ��ϵͳ��ȫ����ִ��OpenProcess(PROCESS_ALL_ACCESS,FALSE, dwProcessID)���ǻ����������ʾܾ����Ĵ���
ԭ����Ĭ�ϵ�����½��̵�һЩ����Ȩ����û�б����ã�Enabled���ģ���������Ҫ����������������ЩȨ�ޡ�
�����ص�һЩAPI������OpenProcessToken��LookupPrivilegevalue��AdjustTokenPrivileges��
����Ҫ�޸�һ�����̵ķ������ƣ�����Ҫ��ý��̷������Ƶľ���������ͨ��OpenProcessToken�õ���
�������ǿ��Ե���AdjustTokenPrivileges������������ƽ����޸�

�������ƣ�OpenProcessToken
�������ܣ������������������ķ�������
����������
    @ProcessHandle      Ҫ�޸ķ���Ȩ�޵Ľ��̾��
    @DesiredAccess      Ҫ���еĲ������ͣ���Ҫ�޸ķ������Ƶ���ȨӦ��ΪTOKEN_ADJUST_PRIVILEGES 
    @TokenHandle        ���صķ�������ָ��
BOOL OpenProcessToken(
    HANDLE ProcessHandle,   //Ҫ�޸ķ���Ȩ�޵Ľ��̾��
    DWORD DesiredAccess,    //ָ����Ҫ���еĲ�������
    PHANDLE TokenHandle     //���صķ�������ָ��
);

�������ƣ�LookupPrivilegeValue
�������ܣ������鿴ϵͳȨ�޵���Ȩֵ��������Ϣ��һ��LUID�ṹ����
����������
    @lpSystemName      ��Ҫ�鿴��ϵͳ������ϵͳֱ����NULL
    @lpName            ָ��һ�������β���ַ�����ָ����Ȩ�����ƣ�����WinNT hͷ�ļ�����
    @lpLuid            �������������ص��ƶ���Ȩ���Ƶ���Ϣ
BOOL LookupPrivilegeValue(
    LPCTSTR lpSystemName,
    LPCTSTR lpName,
    PLUID lpLuid
);

�������ƣ�AdjustTokenPrivileges
�������ܣ����û��ָֹ���������Ƶ���Ȩ
BOOL AdjustTokenPrivileges(
    HANDLE TokenHandle,                 //������Ȩ�ľ��
    BOOL DisableAllPrivileges,          //��������Ȩ�ޱ�־
    PTOKEN_PRIVILEGES NewState,         //����Ȩ��Ϣ��ָ��(�ṹ��)
    DWORD BufferLength,                 //�������ݴ�С,���ֽ�Ϊ��λ��PreviousState�Ļ�����(sizeof)
    PTOKEN_PRIVILEGES PreviousState,    //���ձ��ı���Ȩ��ǰ״̬��Buffer
    PDWORD ReturnLength                 //����PreviousState������Ҫ��Ĵ�С
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