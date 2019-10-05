#include <Windows.h>
#include <TlHelp32.h>
#include <string>

BOOL SetPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		//printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		//printf("AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		//printf("The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}



typedef LONG NTSTATUS;
typedef NTSTATUS(WINAPI* NTQUERYINFORMATIONTHREAD)(
	HANDLE ThreadHandle,
	ULONG ThreadInformationClass,
	PVOID ThreadInformation,
	ULONG ThreadInformationLength,
	PULONG ReturnLength);

typedef enum _THREADINFOCLASS {
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair_Reusable,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,   // Obsolete
	ThreadIsIoPending,
	ThreadHideFromDebugger,
	ThreadBreakOnTermination,
	ThreadSwitchLegacyState,
	ThreadIsTerminated,
	ThreadLastSystemCall,
	ThreadIoPriority,
	ThreadCycleTime,
	ThreadPagePriority,
	ThreadActualBasePriority,
	ThreadTebInformation,
	ThreadCSwitchMon,          // Obsolete
	ThreadCSwitchPmu,
	ThreadWow64Context,
	ThreadGroupInformation,
	ThreadUmsInformation,      // UMS
	ThreadCounterProfiling,
	ThreadIdealProcessorEx,
	MaxThreadInfoClass
} THREADINFOCLASS;

HMODULE hNtdll = LoadLibrary("ntdll.dll");
NTQUERYINFORMATIONTHREAD NtQueryInformationThread = (NTQUERYINFORMATIONTHREAD)
GetProcAddress(hNtdll, "NtQueryInformationThread");

uintptr_t GetThreadStartAddr(DWORD dwThreadId)
{
	if (!hNtdll && !NtQueryInformationThread)
	{
		return 0;
	}

	HANDLE ThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId);
	if (!ThreadHandle)
	{
		return 0;
	}

	DWORD dwStaAddr = NULL;
	DWORD dwReturnLength = 0;
	auto status = NtQueryInformationThread(ThreadHandle, ThreadQuerySetWin32StartAddress,
		&dwStaAddr, sizeof(dwStaAddr), &dwReturnLength);

	//printf("status %x\n", status);

	CloseHandle(ThreadHandle);
	return dwStaAddr;
}


std::string GetStartName(uintptr_t startAddress, DWORD PID)
{
	uintptr_t modBaseAddr = 0;
	uintptr_t cmp = 0;
	char fm[255];
	std::string retorno;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, PID);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(modEntry);
		if (Module32First(hSnap, &modEntry))
		{
			do
			{
				cmp = (uintptr_t)modEntry.modBaseAddr + modEntry.modBaseSize;
				if (startAddress > (uintptr_t)modEntry.modBaseAddr&& startAddress < cmp)
				{
					sprintf_s(fm, "+0x%X", cmp - startAddress);
					retorno = retorno + modEntry.szModule;
					retorno = retorno + fm;

					CloseHandle(hSnap);
					return(retorno);
				}
			} while (Module32Next(hSnap, &modEntry));

		}
	}
	CloseHandle(hSnap);
	return(retorno);
}


void ListThreads(DWORD PID)
{
	HANDLE handleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, PID);
	uintptr_t startaddress = 0;
	std::string ModuleName;
	if (handleSnap != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 TE;
		TE.dwSize = sizeof(TE);
		BOOL Retorno = Thread32First(handleSnap, &TE);
		printf("--------------------------------------------------------------------------------------------------------------\n ");
		while (Retorno)
		{
			if (PID == TE.th32OwnerProcessID)
			{
				startaddress = GetThreadStartAddr(TE.th32ThreadID);
				ModuleName = GetStartName(startaddress, PID);
				printf("| \tTID: %d  \t|\t StartAddress 0x%x  \t|\t name: %s \t |\n ", TE.th32ThreadID, startaddress, ModuleName.c_str());
			}

			Retorno = Thread32Next(handleSnap, &TE);
		}
		printf("-------------------------------------------------------------------------------------------------------------\n");
	}

	CloseHandle(handleSnap);
}


void suspend(DWORD processId)
{
	HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);

	Thread32First(hThreadSnapshot, &threadEntry);

	do
	{
		if (threadEntry.th32OwnerProcessID == processId)
		{
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE,
				threadEntry.th32ThreadID);

			if (SuspendThread(hThread) != 0xFFFFFFFF)
				//std::cout << "\n Sucesso \n";



				CloseHandle(hThread);


		}
	} while (Thread32Next(hThreadSnapshot, &threadEntry));

	CloseHandle(hThreadSnapshot);
}

void Resum(DWORD processId)
{
	HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);

	Thread32First(hThreadSnapshot, &threadEntry);

	do
	{
		if (threadEntry.th32OwnerProcessID == processId)
		{
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE,
				threadEntry.th32ThreadID);

			if (ResumeThread(hThread) != 0xFFFFFFFF)
				//std::cout << "\n Sucesso \n";



				CloseHandle(hThread);


		}
	} while (Thread32Next(hThreadSnapshot, &threadEntry));

	CloseHandle(hThreadSnapshot);
}

DWORD GetProcessID(const char* nome) {

	HANDLE handleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (handleSnap != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 PE;
		PE.dwSize = sizeof(PE);
		BOOL Retorno = Process32First(handleSnap, &PE);
		while (Retorno)
		{
			if (strcmp(PE.szExeFile, nome) == 0)
			{
				CloseHandle(handleSnap);
				return PE.th32ProcessID;
			}
			Retorno = Process32Next(handleSnap, &PE);
		}
	}
	return 0;
}