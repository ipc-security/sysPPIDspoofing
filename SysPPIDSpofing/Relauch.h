#include<shellapi.h>
#include<winnt.h>

#define	MAXFILEPATHLEN	5000

void RelaunchSelf(void) {

	SHELLEXECUTEINFO info;
	WCHAR fileName[MAXFILEPATHLEN];
	DWORD pathLen = MAXFILEPATHLEN;

	// GetModuleFilename returns path of current process executable
	// https://msdn.microsoft.com/en-us/library/windows/desktop/ms683197(v=vs.85).aspx

	GetModuleFileName(NULL, fileName, pathLen);

	// Structure details https://msdn.microsoft.com/en-us/library/windows/desktop/bb759784(v=vs.85).aspx
	// Interestingly runas verb does not appear there :) 
	// https://blogs.msdn.microsoft.com/vistacompatteam/2006/09/25/elevate-through-shellexecute/

	info.cbSize = sizeof(SHELLEXECUTEINFO);
	info.fMask = SEE_MASK_DEFAULT;
	info.hwnd = NULL;
	info.lpVerb = _T("runas");
	info.lpFile = fileName;
	info.lpParameters = NULL;
	info.lpDirectory = NULL;
	info.nShow = SW_SHOWNORMAL;

	ShellExecuteEx(&info);  // Also try the simpler ShellExecute

}