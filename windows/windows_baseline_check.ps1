$ip =  (ipconfig|select-string "IPv4"|out-string).Split(":")[-1].Trim()
$name = $ip + ".ini"

SecEdit.exe /export /cfg "$name" /Quiet
"[Other Registry Values]" >> $name

function CatRegValue{
    
    param($path,$key,$keyname)

    $value = (Get-ItemProperty -Path "Registry::$path" -ErrorAction Stop).$key

    "$keyname = $value" >> $name
}

CatRegValue "HKEY_CURRENT_USER\Control Panel\Desktop\" "ScreenSaverIsSecure" "ScreenSaverIsSecure"
CatRegValue "HKEY_CURRENT_USER\Control Panel\Desktop\" "ScreenSaveTimeOut" "ScreenSaveTimeOut"
CatRegValue "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" "AutoAdminLogon" "AutoAdminLogon"
CatRegValue "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\" "NoDriveTypeAutoRun" "NoDriveTypeAutoRun"
CatRegValue "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\" "PortNumber" "PortNumber"
CatRegValue "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\W32Time\Parameters\" "Type" "Type"
CatRegValue "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\W32Time\Parameters" "NtpServer" "NtpServer"

CatRegValue "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" "SynAttackProtect" "SynAttackProtect"
CatRegValue "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" "TcpMaxPortsExhausted" "TcpMaxPortsExhausted"
CatRegValue "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" "TcpMaxHalfOpen" "TcpMaxHalfOpen"
CatRegValue "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" "TcpMaxHalfOpenRetried" "TcpMaxHalfOpenRetried"
CatRegValue "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" "EnableICMPRedirect" "EnableICMPRedirect"
CatRegValue "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" "EnableDeadGWDetect" "EnableDeadGWDetect"
CatRegValue "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" "DisableIPSourceRouting" "DisableIPSourceRouting"
CatRegValue "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\" "EnablePMTUDiscovery" "EnablePMTUDiscovery"

CatRegValue "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security\" "MaxSize" "SecurityMaxSize"
CatRegValue "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security\" "Retention" "SecurityRetention"
CatRegValue "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Application\" "MaxSize" "ApplicationMaxSize"
CatRegValue "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Application\" "Retention" "ApplicationRetention"
CatRegValue "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\System\" "MaxSize" "SystemMaxSize"
CatRegValue "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\System\" "Retention" "SystemRetention"


"[Other]" >> $name

function CmdResult{

    param($cmdname,$cmd)

    $result = (Invoke-Expression $cmd)

    "$cmdname = $result" >> $name
}

CmdResult "SystemVer" "cmd /c ver"
CmdResult "SpVer" "wmic os get ServicePackMajorVersion"
CmdResult "Hotfix" "wmic qfe get hotfixid,InstalledOn"
CmdResult "Hostname" "hostname"
#CmdResult "Ipconfig" "ipconfig /all"
#CmdResult "Route" "route print"
#CmdResult "OpenPort" "netstat -ano"
CmdResult "osVersion" "Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty Caption"
#CmdResult "NetShare" "net share"
CmdResult "Dep" "wmic OS Get DataExecutionPrevention_SupportPolicy"

CmdResult "Ipc" "cmd /c net share | findstr /i C:"

CmdResult "ServiceFax" "Get-Service Fax | findstr /i Fax"
CmdResult "ServiceSpooler" "Get-Service Spooler | findstr /i Spooler"
CmdResult "ServiceSCardSvr" "Get-Service SCardSvr | findstr /i SCardSvr"
CmdResult "ServiceShellHWDetection" "Get-Service ShellHWDetection | findstr /i ShellHWDetection"
CmdResult "ServiceRemoteRegistry" "Get-Service RemoteRegistry | findstr /i RemoteRegistry"
CmdResult "ServiceLanmanServer" "Get-Service LanmanServer | findstr /i LanmanServer"
CmdResult "Servicelmhosts" "Get-Service lmhosts | findstr /i lmhosts"
CmdResult "ServiceLanmanWorkstation" "Get-Service LanmanWorkstation | findstr /i LanmanWorkstation"
CmdResult "ServiceBrowser" "Get-Service Browser | findstr /i Browser"

CmdResult "KB" 'Get-HotFix | Select-Object -Property HotFixID | findstr /i "KB"'

CmdResult "AllUser" "Get-WmiObject -Class Win32_UserAccount | findstr /i ^Name"

CmdResult "FileSystem" "Get-WmiObject -Class Win32_LogicalDisk FileSystem | findstr /i FileSystem"

CmdResult "CaclsDisk" "cacls C:"
CmdResult "CaclsCmd" "cacls C:\Windows\System32\cmd.exe"
CmdResult "CaclsNet" "cacls C:\Windows\System32\net.exe"
CmdResult "CaclsNet1" "cacls C:\Windows\System32\net1.exe"
"Ip = $ip" >> $name