#include <windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <Shlwapi.h>
#include <winternl.h>
#include <memory>
#pragma comment(lib, "shlwapi.lib")

using namespace std;

bool GetProcessCommandLine(HANDLE hProc)
{
	PEB peb;
	RTL_USER_PROCESS_PARAMETERS upps;
	HMODULE hModule = LoadLibrary(L"Ntdll.dll");
	typedef NTSTATUS(WINAPI* NtQueryInformationProcessFace)(HANDLE, DWORD, PVOID, ULONG, PULONG);
	NtQueryInformationProcessFace NtQueryInformationProcess = (NtQueryInformationProcessFace)GetProcAddress(hModule, "NtQueryInformationProcess");

	PROCESS_BASIC_INFORMATION pbi;
	NTSTATUS isok = NtQueryInformationProcess(hProc, ProcessBasicInformation, (PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), 0);
	if (BCRYPT_SUCCESS(isok))
	{
		if (ReadProcessMemory(hProc, pbi.PebBaseAddress, &peb, sizeof(PEB), 0))
		{
			if (ReadProcessMemory(hProc, peb.ProcessParameters, &upps, sizeof(RTL_USER_PROCESS_PARAMETERS), 0)) {
				shared_ptr<wchar_t> buffer(new wchar_t[upps.CommandLine.Length + 1]);

				ZeroMemory(buffer.get(), (upps.CommandLine.Length + 1) * sizeof(WCHAR));
				ReadProcessMemory(hProc, upps.CommandLine.Buffer, buffer.get(), upps.CommandLine.Length, 0);

				//printf("%ls\n", buffer.get());
				wstring cmd(buffer.get());
				if (cmd.find(L"type=utility") != string::npos)
				{
					return true;
				}
			}
		}
	}
	return false;
}

template <typename Fn>
DWORD inject(const wchar_t* name, Fn fn)
{
	HANDLE hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);//��ȡ���̿��վ��
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hProcSnap, &pe32))
	{
		do
		{
			if (!_wcsicmp(pe32.szExeFile, name))
			{
				HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
				if (INVALID_HANDLE_VALUE == hProc)
				{
					return false;
				}
				if (GetProcessCommandLine(hProc))
				{
					if (fn(hProc))
					{
						printf("inject ok %ls %d\n", name, pe32.th32ProcessID);
					}
					else
					{
						printf("inject err\n");
					}
				}
				CloseHandle(hProc);
			}
		} while (Process32Next(hProcSnap, &pe32));
	}
	CloseHandle(hProcSnap);
	return 0;
}

//Զ���߳�ע��
bool RemoteThreadInject(HANDLE hProcess)
{
	wchar_t tempPath[260]{ 0 };
	GetModuleFileNameW(nullptr, tempPath, 260);
	PathRemoveFileSpecW(tempPath);
	PathAppendW(tempPath, L"sslhook.dll");

	if (!PathFileExistsW(tempPath))
	{
		printf("dll�ļ�������!\n");
		return false;
	}
	//2.�����ڴ�,д��DLL·��
	int nLen = sizeof(WCHAR) * (wcslen(tempPath) + 1);
	LPVOID pBuf = VirtualAllocEx(hProcess, NULL, nLen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!pBuf)
	{
		printf("�����ڴ�ʧ�ܣ�\n");
		return false;
	}
	//3.д���ڴ�
	SIZE_T dwWrite = 0;
	if (!WriteProcessMemory(hProcess, pBuf, tempPath, nLen, &dwWrite))
	{
		printf("д���ڴ�ʧ�ܣ�\n");
		return false;
	}
	//4.����Զ���̣߳��öԷ�����LoadLibrary
	HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, NULL,
		(LPTHREAD_START_ROUTINE)LoadLibrary, pBuf, 0, 0);
	//5.�ȴ��߳̽�������,�ͷ���Դ
	WaitForSingleObject(hRemoteThread, -1);
	VirtualFreeEx(hProcess, pBuf, 0, MEM_FREE);
	return true;
}

void main()
{
	inject(L"chrome.exe", RemoteThreadInject);
	getchar();
}