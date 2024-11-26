# user2system
Upgrading from user to system does not require any UAC-like pop-ups


theory:
Standard User Privileges
     │
     ├── [UAC Bypass: Using fodhelper.exe]
     │       ├── Modify Registry Key (HKCU\Software\Classes\ms-settings\Shell\Open\command)
     │       │       └─ Set the path to the malicious executable
     │       ├── Execute fodhelper.exe (Automatically runs with elevated privileges)
     │       └── Malicious program runs as Administrator
     │
Administrator Privileges
     │
     ├── [Steal SYSTEM Token: Using winlogon.exe]
     │       ├── Locate a SYSTEM-level process (e.g., winlogon.exe)
     │       ├── Open a handle to the process (OpenProcess)
     │       ├── Retrieve the process token (OpenProcessToken)
     │       ├── Duplicate the token (DuplicateTokenEx)
     │       └── Create a new process with SYSTEM privileges (CreateProcessWithTokenW)
     │
SYSTEM Privileges
     │
     ├── [Execute Malicious Code]
     │       ├── Launch a malicious program (e.g., cmd.exe or payload.exe)
     │       ├── Inject malicious code into another high-privilege process
     │       │       └─ Use WriteProcessMemory + CreateRemoteThread
     │       └── Achieve full control of the system