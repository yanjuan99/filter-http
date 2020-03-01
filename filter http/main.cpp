#include <windows.h>
#include <iostream>
#include <processenv.h>
#include <thread>

#include <cassert>

#include <Shlobj.h>
#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")

#include <MinHook.h>
#pragma comment(lib, "libMinHook.lib")

#include <Shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

using namespace std;

#include <vector>
#include <regex>

void  __declspec(dllexport) add()
{
	return;
}

template <typename... Args>
bool Write_log(LPCSTR fmt, Args... args)
{
	wchar_t path[255];
	SHGetSpecialFolderPathW(0, path, CSIDL_DESKTOPDIRECTORY, 0);
	PathAppendW(path, L"X.log");
	assert(!PathFileExistsW(path));

	HANDLE hFile = CreateFile(path, GENERIC_ALL, NULL, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return false;
	}
	auto size = static_cast<SIZE_T>(snprintf(nullptr, 0, fmt, args...));
	if (!size) {
		return false;
	}
	++size;
	std::shared_ptr<CHAR>  formatted(new CHAR[size]);
	sprintf_s(formatted.get(), size, fmt, args...);

	if (SetFilePointer(hFile, 0, NULL, FILE_END) == -1)
	{
		return false;
	}

	DWORD wtlen = 0;
	WriteFile(hFile, formatted.get(), size - 1, &wtlen, NULL);
	CloseHandle(hFile);
	return (size - 1) == wtlen;
}

bool BBSearchPattern(IN const unsigned char* pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
{
	ULONG_PTR i, j;
	if (ppFound == NULL || pattern == NULL || base == NULL)
		return false;
	__try
	{
		for (i = 0; i < size - len; i++)
		{
			BOOLEAN found = TRUE;
			for (j = 0; j < len; j++)
			{
				if (pattern[j] != wildcard && pattern[j] != ((const unsigned char*)base)[i + j])
				{
					found = FALSE;
					break;
				}
			}

			if (found != FALSE)
			{
				*ppFound = (PUCHAR)base + i;
				return true;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}
	return false;
}

EXTERN_C __int64 GetRax(__int64 rcx);
/*
00203DF5B2288

rcx =[rbx + 18] + rbx + 18

RAX= top rcx
RBX= [RAX+10]
RCX= RAX + RBX + 10

RAX= [RCX+8] + RCX + 8

00200000=[0x00007FFF9117E4F8]
IF [0x00007FFF9117E4F8] < [RAX+4]
	RAX+=8

*/

typedef __int64(__fastcall* sub_183B0BC3AT)(__int64 a1, __int64 a2);
sub_183B0BC3AT old_fun = NULL;
/*
00007FFF73591C2E | 48:8B8E D8000000         | mov rcx,qword ptr ds:[rsi+D8]                          | top
00007FFF73591C35 | 48:8B01                  | mov rax,qword ptr ds:[rcx]                             |
00007FFF73591C38 | 4C:89F2                  | mov rdx,r14                                            | rdx 0006CFADFECA0
00007FFF73591C3B | FF50 10                  | call qword ptr ds:[rax+10]                             |
*/

template <typename T>
T read(__int64 a)
{
	__try
	{
		return *(T*)a;
	}
	__except (1)
	{
		return NULL;
	}
}

vector<string>  load_regex()
{
	vector<string> regex_list;
	wchar_t path[255];
	SHGetSpecialFolderPathW(0, path, CSIDL_DESKTOPDIRECTORY, 0);
	PathAppendW(path, L"filter.txt");
	//assert(!PathFileExistsW(path));

	HANDLE hFile = CreateFile(path, GENERIC_ALL, NULL, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		Write_log("filter.txt ²»´æÔÚ\n");
		return regex_list;
	}
	auto strlen = GetFileSize(hFile, NULL);
	shared_ptr<char> buffer(new char[strlen]);
	DWORD 	btread = 0;
	ReadFile(hFile, buffer.get(), strlen, &btread, NULL);
	CloseHandle(hFile);

	regex pattern("(.*?)\r\n");	   	smatch result;
	std::string  url_str(buffer.get());
	while (regex_search(url_str, result, pattern))
	{
		if (result.size() == 2)
		{
			regex_list.push_back(result[1].str());
		}
		url_str = result.suffix().str();
	}
	return 	  regex_list;
}

bool filter(const char* url)
{
	smatch result;
	std::string  url_str(url);

	for (auto& str : load_regex())
	{
		regex pattern(str.c_str());
		if (regex_search(url_str, result, pattern))
		{
			return true;
		}
	}
	return false;
}

__int64 __fastcall sub_183B0BC3A(__int64 a1, __int64 a2)
{
	auto br = read<__int64>(a1 + 8);
	if (br == NULL)
		return NULL;

	auto rcx = 0i64;
	auto rax = 0i64;
	auto rbx = GetRax(a2);

	auto tmp = read<__int64>(rbx + 0x18);  if (tmp == NULL) goto	end;
	rcx = tmp + rbx + 0x18;

	tmp = read<__int64>(rcx + 0x10); if (tmp == NULL) goto	end;
	rbx = tmp + rcx + 0x10;

	tmp = read<__int64>(rbx + 0x8);	 if (tmp == NULL) goto	end;
	rax = tmp + rbx + 0x8;

	tmp = read<__int32>(rax + 4);
	if (0x20000 > tmp)
	{
		rax += 8;
	}

	if (filter((char*)rax))
	{
		Write_log("%s ----kill\n", (char*)rax);
		return NULL;
	}
	else 
	{
		Write_log("%s\n", (char*)rax);
	}
end:
	return   old_fun(a1, a2);
}

VOID Main() {
	//Write_log("GetCurrentProcessId %d\n", GetCurrentProcessId());

	auto ch_module = GetModuleHandleW(L"chrome.dll");
	//Write_log("chrome.dll %p\n", ch_module);

	MODULEINFO ch_info{ 0 };
	PVOID httpscall = NULL;
	if (GetModuleInformation(GetCurrentProcess(), ch_module, &ch_info, sizeof(MODULEINFO)))
	{
		const unsigned	 char sig[] =
			"\xE8\xcc\xcc\xcc\xcc"
			"\x31\xED"
			"\x48\x8D\xB4\x24\xcc\xcc\xcc\xcc"
			"\x48\x89\x6E\x10"
			"\x0F\x57\xC0"
			"\x0F\x29\x06"
			"\x48\x89\xF1"
			"\xE8\xcc\xcc\xcc\xcc"
			"\x4C\x8D\xBC\x24\xcc\xcc\xcc\xcc"
			"\x4C\x89\xF9";
		if (BBSearchPattern(sig, 0xcc, sizeof(sig) - 1, ch_module, ch_info.SizeOfImage, &httpscall))
		{
			uintptr_t ads = (uintptr_t)httpscall - 0x9B;
			//Write_log("fun adds %p\n", ads);

			MH_Initialize();
			MH_CreateHook((PVOID)ads, sub_183B0BC3A, reinterpret_cast<PVOID*>(&old_fun));
			MH_EnableHook((PVOID)ads);
		}
	}
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved) {
	if (reason == DLL_PROCESS_ATTACH) {
		Main();
	}
	return TRUE;
}

//if (!_stricmp((char*)rax, "https://www.baidu.com/"))
//{
//	char my_url[] = "http://yanjuan.xyz/"; char buf[] = "\x00\x00\x10";

//	auto max_len = read<__int32>(rax - 8);
//	auto next_url = rax + max_len + 10;

//	*(int*)(rax - 4) = sizeof(my_url) - 1;
//	CopyMemory((char*)rax, my_url, sizeof(my_url));
//	CopyMemory((char*)(rax + sizeof(my_url) - 1), buf, 3);

//	*(int*)(next_url + 4) = sizeof(my_url) - 1;
//	CopyMemory((char*)(next_url + 8), my_url, sizeof(my_url));
//	CopyMemory((char*)(next_url + 8 + sizeof(my_url) - 1), buf, 3);
//}