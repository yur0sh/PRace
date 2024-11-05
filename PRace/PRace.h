#ifndef _WIN32_WINNT
#define _WIN32_WINNT _WIN32_WINNT_WIN7
#endif

#include <Windows.h>

#define _CHANGE_TIMER_RES   1		// maximize timer resolution
#define _USE_ALL_CORES		1		// Is is strongly recommended not to define !!!
#define _RACE_THREADS		2		// Initial number of race threads for each core
#define _EXP_TIMEOUT		120		// Time to wait for exploitation (in seconds)

/******************************************************************************\
* EscalatePrivileges
*
* Escalates privileges for the specified process.
\******************************************************************************/
BOOL __stdcall EscalatePrivileges(DWORD dPid);
