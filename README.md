# Gopher

If a credential is there... Gopher will find it

Will search for low hanging fruits and useful information for escalation on a compromised workstation.

Plays nice with execute-assembly.

Digs the following holes:

* McAfee repository list files
* Cached GPP files
* Unattended installation files
* PowerShell history files
* AWS credential files
* Azure credential files
* Google Cloud credential files
* RDP sessions
* PuTTY sessions
* SuperPuTTY sessions
* WinSCP sessions
* FileZilla sessions
* VNC settings
* TeamViewer settings

# Detection
Consider placing SACLs to specific registry keys with the use of [Set-AuditRule](https://github.com/OTRF/Set-AuditRule)


# Author
[@eksperience](https://github.com/eksperience)
