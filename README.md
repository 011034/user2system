# user2system
Upgrading from user to system does not require any UAC-like pop-ups


theory:
Step 1: UAC Bypass

	•	Modify the registry key HKCU\Software\Classes\ms-settings\Shell\Open\command to point to the malicious executable.
	•	Launch fodhelper.exe, which runs with Administrator privileges, executing the malicious program.

Step 2: Stealing SYSTEM Token

	•	Locate a SYSTEM-level process like winlogon.exe and retrieve its process ID (PID).
	•	Use OpenProcess to get a handle to the process, then call OpenProcessToken to access its token.
	•	Duplicate the token using DuplicateTokenEx and create a new SYSTEM-level process with CreateProcessWithTokenW.

Step 3: Execute Malicious Code

	•	Launch the malicious program with SYSTEM privileges.
	•	Alternatively, inject code into another SYSTEM-level process using WriteProcessMemory and CreateRemoteThread.