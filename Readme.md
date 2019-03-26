# Windows Privilege Escalation

## Windows PE using CMD (.bat)

If you want to search for files and registry that could contain passwords, set to *yes* the *long* variable at the beginning of the script.

### Main checks

- [x] Systeminfo --SO version and patches-- (windows suggester)
- [x] Common Kernel exploits (2K, XP, 2K3, 2K8, Vista, 7)
- [x] UAC?? 
- [x] AV??
- [x] Mounted disks
- [x] WSUS vuln?? 
- [x] SCCM installed??
- [x] Interesting file permissions of binaries being executed 
- [x] Interesting file permissions of binaries run at startup
- [x] AlwaysInstallElevated??
- [x] Network info (see below)
- [x] Users info (see below)
- [x] Current user privileges 
- [x] Service binary permissions 
- [x] Check if permissions to modify any service registy
- [x] Unquoted Service paths  
- [x] Search for interesting writable files
- [x] Saved credentials  
- [x] Search for known files to have passwords inside
- [x] Search for known registry to have passwords inside
- [x] If *long*, search files with passwords inside 
- [x] If *long*, search registry with passwords inside 

### More enumeration

- [x] Date & Time
- [x] Env
- [x] Installed Software
- [x] Running Processes 
- [x] Current Shares 
- [x] Network Interfaces
- [x] Used Ports
- [x] Firewall
- [x] ARP
- [x] Routes
- [x] Hosts
- [x] Cached DNS
- [x] Info about current user (PRIVILEGES)
- [x] List groups (info about administrators)
- [x] Current logon users 


The script will use acceschk.exe if it is available (with that name). But it is not necessary, it also uses wmic + icacls.


Some of the tests in this script were extracted from **[here](https://github.com/enjoiz/Privesc/blob/master/privesc.bat)** and from **[here](https://github.com/codingo/OSCP-2/blob/master/Windows/WinPrivCheck.bat)**

# Binaries

Some interesting precompiled binaries for privesc in Windows.

By Polop(TM)
