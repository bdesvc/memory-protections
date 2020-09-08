#include <Windows.h>
#include <iostream>
#include <winternl.h>
#include <stdio.h>
#include <fstream>
#include <random>

using namespace std;

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
	BOOLEAN DebuggerEnabled;
	BOOLEAN DebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

struct protection_struct {

	struct alert_struct {
		void show_debug() {
			MessageBoxA(GetConsoleWindow(), ("*) One of the following has been found\n\n*)A blacklisted program\n*) A kernel debugger\n*) A assembly debugging attempt\n*) Attempted memory dump\n\nPlease contact a administrator before trying again!\n"), ("MemoryProtections - Akex#0001"), MB_ICONERROR | MB_OK);
			exit(0);
		}
	} *alert;

	bool initialize() {

		{ // anti dump

			antidump->erase_pe();

			antidump->raise_size();

		}

		return true;
	}

	struct kernel_struct {
		bool query_information() {
			const ULONG_PTR UserSharedData = 0x7FFE0000;

			const UCHAR KdDebuggerEnabledByte = *(UCHAR*)(UserSharedData + 0x2D4); 

			const BOOLEAN KdDebuggerEnabled = (KdDebuggerEnabledByte & 0x1) == 0x1;
			const BOOLEAN KdDebuggerNotPresent = (KdDebuggerEnabledByte & 0x2) == 0;

			if (KdDebuggerEnabled || !KdDebuggerNotPresent)
				return TRUE;

			return FALSE;
		}
	} *kernel;

	struct dump_struct {
		void erase_pe() {

			DWORD old;

			char* baseAddress = (char*)GetModuleHandle(NULL);


			VirtualProtect(baseAddress, 4096, PAGE_READWRITE, &old); // default size of x64 and x86 pages

			SecureZeroMemory(baseAddress, 4096);

		}
		void raise_size() {
			PPEB pPeb = (PPEB)__readgsqword(0x60);


			PLIST_ENTRY InLoadOrderModuleList = (PLIST_ENTRY)pPeb->Ldr->Reserved2[1];
			PLDR_DATA_TABLE_ENTRY tableEntry = CONTAINING_RECORD(InLoadOrderModuleList, LDR_DATA_TABLE_ENTRY, Reserved1[0]);
			PULONG pEntrySizeOfImage = (PULONG)&tableEntry->Reserved3[1];
			*pEntrySizeOfImage = (ULONG)((INT_PTR)tableEntry->DllBase + 0x100000);
		}
	} *antidump;
};
