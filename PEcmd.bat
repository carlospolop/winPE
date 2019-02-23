@echo off

echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [*] BASIC SYSTEM INFO ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] WINDOWS OS ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] Check for vulnerabilities for the OS version with the applied patches
systeminfo
echo.
wmic qfe get Caption,Description,HotFixID,InstalledOn | more

echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] DATE and TIME ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] You may need to adjust your local date/time to exploit some vulnerability
date /T
time /T

echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] MOUNTED DISKS ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] Maybe you find something interesting
(wmic logicaldisk get caption 2>nul | more) || (fsutil fsinfo drives 2>nul)

echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] ENVIRONMENT ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] Interesting information?"
set

echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] INSTALLED SOFTWARE ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] Some weird software? Check for vulnerabilities in unknow software installed
dir /b "C:\Program Files" "C:\Program Files (x86)" | sort
reg query HKEY_LOCAL_MACHINE\SOFTWARE

echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] RUNNING PROCESSES ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] Something unexpected is running? Check for vulnerabilities
tasklist /SVC

echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] RUN AT STARTUP ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] Check if you can modify any binary that is going to be executed by admin or if you can impersonate a not found binary
(autorunsc.exe -m -nobanner -a * -ct /accepteula 2>nul || wmic startup get caption,command 2>nul | more & ^
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run 2>nul & ^
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce 2>nul & ^
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run 2>nul & ^
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce 2>nul & ^
echo Looking inside "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" & ^
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul & ^
echo Looking inside "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" & ^
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul & ^
echo Looking inside "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" & ^
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul & ^
echo Looking inside "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" & ^
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul & ^
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab informa")
	
echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] AlwaysInstallElevated? ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] If '1' then you can install a .msi file with admin privileges ;)
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2> nul
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2> nul


echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^>[*] BASIC USER INFO ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] Check if you are inside the Administrators froup or if you have enabled any token that can be use to escalate privileges like SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebbugPrivilege
echo [I] ME

net users %username%
whoami /all
echo.
echo [I] USERS
net users
echo.
echo [I] GROUPS
net localgroup
echo.
echo [I] ADMINISTRATORS GROUP
net localgroup Administrators 2>nul
net localgroup Administradores 2>nul 


echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [*] SERVICES VULNERABILITIES ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] SERVICE PERMISSIONS WITH accesschk.exe FOR 'Authenticated users', Everyone, BUILTIN\Users, Todos and CURRENT USER ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] If Authenticated Users have SERVICE_ALL_ACCESS or SERVICE_CHANGE_CONFIG or WRITE_DAC or WRITE_OWNER or GENERIC_WRITE or GENERIC_ALL, you can modify the binary that is going to be executed by the service and start/stop the service
echo [i] If accesschk.exe is not in PATH, nothing will be found here
echo [I] AUTHETICATED USERS
accesschk.exe -uwcqv "Authenticated Users" * /accepteula 2>nul
echo [I] EVERYONE
accesschk.exe -uwcqv "Everyone" * /accepteula 2>nul
echo [I] BUILTIN\Users
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
echo [I] TODOS
accesschk.exe -uwcqv "Todos" * /accepteula 2>nul
echo [I] %USERNAME%
accesschk.exe -uwcqv %username% * /accepteula 2>nul
::echo.
::echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] SERVICE PERMISSIONS WITH accesschk.exe FOR * ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
::echo [i] Check for weird service permissions for unexpected groups"
::accesschk.exe -uwcqv * /accepteula 2>nul

echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] SERVICE BINARY PERMISSIONS WITH WMIC + ICACLS ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] Search for (W) or (F) inside a group where you belong to. By default only the path and first group is printed in console.
for /f "tokens=2 delims='='" %%a in ('wmic service list full ^| findstr /i "pathname" ^|findstr /i /v "system32"') do echo %%a >> %temp%\perm.txt
for /f eol^=^"^ delims^=^" %%a in (%temp%\perm.txt) do cmd.exe /c icacls "%%a" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos usuarios %username%"
del %temp%\perm.txt

echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] CHECK IF YOU CAN MODIFY ANY SERVICE REGISTRYS ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
for /f %%a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %%a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %%a

echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] UNQUOTED SERVICE PATHS" ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] When the path is not quoted (ex: C:\Program files\soft\new folder\exec.exe) Windows will try to execute first 'C:\Progam.exe', then 'C:\Program Files\soft\new.exe' and finally 'C:\Program Files\soft\new folder\exec.exe'. Try to create 'C:\Program Files\soft\new.exe'
wmic service get name,displayname,pathname,startmode | more | findstr /i /v "C:\\Windows\\system32\\" | findstr /i /v """


echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [*] INTERESTING WRITABLE FILES ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] Maybe you can take advantage of modifying/creating some binary in some of the following locations
echo [i] Search for (W) or (F) inside a group where you belong to. By default only the path and first group is printed in console.
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"


echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [*] CREDENTIALS ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] SAVED CREDENTIALS ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
cmdkey /list
echo Looking inside %appdata%\Microsoft\Credentials\
dir /b %appdata%\Microsoft\Credentials\ 2>nul 
echo Looking inside %localappdata%\Microsoft\Credentials\
dir /b %localappdata%\Microsoft\Credentials\ 2>nul

echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] Files that may contain credentials ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
echo [i] Searching specific files that may contains credentias. The password could be in clear text, Base64 or cPassword (use gpp-decrypt)
cd ..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..
dir /s/b /A -D sysprep.inf == sysprep.xml == unattend.xml == unattended.xml == *vnc* == groups.xml == services.xml == scheduledtasks.xml == printers.xml == drives.xml == datasources.xml == php.ini == https.conf == https-xampp.conf == httpd.conf == my.ini == my.cnf == access.log == error.log == server.xml == SiteList.xml == ConsoleHost_history.txt 2>nul
cd inetpub 2>nul && (dir /s/b web.config == *.log & cd ..)
reg query HKCU\Software\ORL\WinVNC3\Password 2>nul
reg query "HKLM\SYSTEM\Microsoft\Windows NT\Currentversion\WinLogon" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s 2>nul
reg query "HKCU\Software\TightVNC\Server" 2>nul
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s 2>nul

echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] FILES THAT CONTAINS THE WORD PASSWORD WITH EXTENSION: .xml .ini .txt ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
findstr /S/N/M /D:C:\ /si password *.xml *.ini *.txt 2>nul | findstr /v/i "\\AppData\\Local \\WinSxS ApnDatabase.xml \\UEV\\InboxTemplates \\Microsoft.Windows.Cloud \\Notepad\+\+\\ vmware cortana alphabet \\7-zip\\" 2>nul

echo.
echo _-_-_-_-_-_-_-_-_-_-_-_-_-_-_-^> [+] FILES WHOSE NAME CONTAINS THE WORD PASS CRED or .config not inside \Windows\ ^<_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
dir /s /b *pass* == *cred* == *.config* 2>nul | findstr /v /i "\\windows\\"





