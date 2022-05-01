import configparser
from mailmerge import MailMerge
import xmltodict
import sys

#print(sys.argv[0],sys.argv[1])
template = sys.argv[1]
filename = sys.argv[2]

config = configparser.ConfigParser()
config.read(filename, encoding="utf-16")
#['Unicode', 'System Access', 'Event Audit', 'Registry Values', 'Privilege Rights', 'Version']
all = dict(config.items("Unicode") + config.items("System Access") + config.items("Event Audit") + config.items("Registry Values") + config.items("Privilege Rights") + config.items("Version") + config.items("Other Registry Values") + config.items("Other"))
all_result = {}
all_result["ip"] = all["ip"]

def KB():
    kb = all['kb']

    if kb != "":
        result = "[+]已经安装的补丁为：" + kb.replace(' ', '').replace('KB', ',KB')
        print(result)
        all_result["kb"] = "符合：" + result
    else:
        result = "[-]没有安装任何补丁"
        print(result)
        all_result["kb"] = "不符合：" + result

def OsVersion():
    osversion = all['osversion']
    if osversion.find("2008") != -1:
        result = "[-]系统版本为Windows 2008 ，目前此版本已经不在微软的服务支持列表，建议升级系统。"
        print(result)
        all_result["osversion"] = "不符合：" + result
    else:
        result = "[+]" + osversion
        print(result)
        all_result["osversion"] = "符合：" + result

def EnableGuestAccount():
    enableguestaccount = all['enableguestaccount']

    if enableguestaccount == '0':
        result = "[+]guest账户已经禁用"
        print(result)
        all_result["enableguestaccount"] = "符合：" + result
    elif enableguestaccount == '1':
        result = "[-]guest账号没有禁用"
        print(result)
        all_result["enableguestaccount"] = "不符合：" + result
    else:
        print("[*][!]出现非预期错误！enableguestaccount")

def NewAdministratorName():
    newadministratorname = all['newadministratorname']

    if newadministratorname == '"Administrator"':
        result = "[-]administrator账户没有重命名"
        print(result)
        all_result["newadministratorname"] = "不符合：" + result
    elif newadministratorname == None:
        print("[*][!]出现非预期错误！newadministratorname")
    else:
        result = "[+]administrator账户已重命名为" + newadministratorname
        print(result)
        all_result["newadministratorname"] = "符合：" + result        

def AllUser():
    alluser = all['alluser']
    result = "[+]当前计算机账户有：" + alluser.replace(' ', '')
    print(result)
    all_result['alluser'] = "符合：" + result

def PasswordComplexity():
    passwordcomplexity = all['passwordcomplexity']

    if passwordcomplexity == '1':
        result = "[+]密码复杂度已启用"
        print(result)
        all_result["passwordcomplexity"] = "符合：" + result
    elif passwordcomplexity == '0':
        result = "[-]密码复杂度没有启用"
        print(result)
        all_result["passwordcomplexity"] = "不符合：" + result
    else:
        print("[!]出现非预期错误！passwordcomplexity")

def MinimumPasswordLength():
    minimumpasswordlength = all['minimumpasswordlength']

    if int(minimumpasswordlength) >= 8:
        result = "[+]密码长度最小值符合，长度为" + minimumpasswordlength
        print(result)
        all_result["minimumpasswordlength"] = "符合：" + result
    elif int(minimumpasswordlength) < 8:
        result = "[-]密码长度最小值不符合，长度为" + minimumpasswordlength
        print(result)
        all_result["minimumpasswordlength"] = "不符合：" + result
    else:
        print("[!]出现非预期错误！minimumpasswordlength")

def PasswordAge():
    maximumpasswordage = all['maximumpasswordage']
    minimumpasswordage = all['minimumpasswordage']

    if (int(maximumpasswordage) <= 90) & (int(minimumpasswordage) == 0):
        result = "[+]密码使用期限符合，使用期限为" + minimumpasswordage + "-" + maximumpasswordage
        print(result)
        all_result["passwordage"] = "符合：" + result
    elif (int(maximumpasswordage) >= 90) & (int(minimumpasswordage) == 0):
        result = "[-]密码使用期限不符合，使用期限为" + minimumpasswordage + "-" + maximumpasswordage
        print(result)
        all_result["passwordage"] = "不符合：" + result
    else:
        print("[!]出现非预期错误！passwordage")

def PasswordHistorySize():
    passwordhistorysize = all['passwordhistorysize']

    if int(passwordhistorysize) <= 5:
        result = "[+]强制密码历史符合，个数为" + passwordhistorysize
        print(result)
        all_result["passwordhistorysize"] = "符合：" + result
    elif int(passwordhistorysize) >= 5:
        result = "[-]强制密码历史不符合，个数为" + passwordhistorysize
        print(result)
        all_result["passwordhistorysize"] = "不符合：" + result        
    else:
        print("[!]出现非预期错误！passwordhistorysize")

def ClearTextPassword():
    cleartextpassword = all['cleartextpassword']

    if int(cleartextpassword) == 0:
        result = "[+]可还原的加密来存储密码已禁用"
        print(result)
        all_result["cleartextpassword"] = "符合：" + result
    elif int(cleartextpassword) == 1:
        result = "[-]可还原的加密来存储密码没有禁用"
        print(result)
        all_result["cleartextpassword"] = "不符合：" + result
    else:
        print("[!]出现非预期错误！cleartextpassword")

def LockoutBadCount():
    lockoutbadcount = all['lockoutbadcount']

    if int(lockoutbadcount) == 0:
        result = "[-]帐户锁定阀值不符合,未开启"
        print(result)
        all_result["lockoutbadcount"] = "不符合：" + result
    elif 0< int(lockoutbadcount) <= 5:
        result = "[+]帐户锁定阀值符合，次数为" + lockoutbadcount
        print(result)
        all_result["lockoutbadcount"] = "符合：" + result
    elif int(lockoutbadcount) > 5:
        result = "[-]帐户锁定阀值不符合，次数为" + lockoutbadcount
        print(result)
        all_result["lockoutbadcount"] = "不符合：" + result
    else:
        print("[!]出现非预期错误！lockoutbadcount")

def ResetLockoutCount():
    if 'resetlockoutcount' in all:
        
        resetlockoutcount = all['resetlockoutcount']

        if int(resetlockoutcount) >= 15:
            result = "[+]重置帐户锁定计数器符合，时间为" + resetlockoutcount
            print(result)
            all_result["resetlockoutcount"] = "符合：" + result
        elif int(resetlockoutcount) < 15:
            result = "[-]重置帐户锁定计数器不符合，时间为" + resetlockoutcount
            print(result)
            all_result["resetlockoutcount"] = "不符合：" + result
        else:
            print("[!]出现非预期错误！")
    else:
        result = "[-]重置帐户锁定计数器不符合，未设置"
        print(result)
        all_result["resetlockoutcount"] = "不符合：" + result

def LockoutDuration():
    if 'lockoutduration' in all:

        lockoutduration = all['lockoutduration']

        if int(lockoutduration) >= 15:
            result = "[+]帐户锁定时间符合，时间为" + lockoutduration
            print(result)
            all_result["lockoutduration"] = "符合：" + result
        elif int(lockoutduration) < 15:
            result = "[-]帐户锁定时间不符合，时间为" + lockoutduration
            print(result)
            all_result["lockoutduration"] = "不符合：" + result
        else:
            print("[!]出现非预期错误！lockoutduration")
    else:
        result = "[-]帐户锁定时间不符合，未设置"
        print(result)
        all_result["lockoutduration"] = "不符合：" + result

def SeRemoteShutdownPrivilege():
    seremoteshutdownprivilege = all['seremoteshutdownprivilege']

    if seremoteshutdownprivilege == "*S-1-5-32-544":
        result = "[+]从远程系统强制关机符合"
        print(result)
        all_result["seremoteshutdownprivilege"] = "符合：" + result
    elif seremoteshutdownprivilege != "*S-1-5-32-544":
        result = "[-]从远程系统强制关机不符合，对象为" + seremoteshutdownprivilege
        print(result)
        all_result["seremoteshutdownprivilege"] = "不符合：" + result
    else:
        print("[!]出现非预期错误！seremoteshutdownprivilege")

def SeShutdownPrivilege():
    seshutdownprivilege = all['seshutdownprivilege']

    if seshutdownprivilege == "*S-1-5-32-544":
        result = "[+]关闭系统符合"
        print(result)
        all_result["seshutdownprivilege"] = "符合：" + result
    elif seshutdownprivilege != "*S-1-5-32-544":
        result = "[-]关闭系统不符合，对象为" + seshutdownprivilege
        print(result)
        all_result["seshutdownprivilege"] = "不符合：" + result
    else:
        print("[!]出现非预期错误！seshutdownprivilege")

def SeTakeOwnershipPrivilege():
    setakeownershipprivilege = all['setakeownershipprivilege']
    if setakeownershipprivilege == "*S-1-5-32-544":
        result = "[+]取得文件或其它对象的所有权符合"
        print(result)
        all_result["setakeownershipprivilege"] = "符合：" + result
    elif setakeownershipprivilege != "*S-1-5-32-544":
        result = "[-]取得文件或其它对象的所有权不符合，对象为" + setakeownershipprivilege
        print(result)
        all_result["setakeownershipprivilege"] = "不符合：" + result
    else:
        print("[!]出现非预期错误！setakeownershipprivilege")

def SeInteractiveLogonRight():
    seinteractivelogonright = all['seinteractivelogonright']
    if seinteractivelogonright == "*S-1-5-32-544,*S-1-5-32-545":
        result = "[+]允许本地登录符合"
        print(result)
        all_result["seinteractivelogonright"] = "符合：" + result
    elif seinteractivelogonright != "*S-1-5-32-544,*S-1-5-32-545":
        result = "[-]允许本地登录不符合，对象为" + seinteractivelogonright
        print(result)
        all_result["seinteractivelogonright"] = "不符合：" + result
    else:
        print("[!]出现非预期错误！seinteractivelogonright")

def SeNetworkLogonRight():
    senetworklogonright = all['senetworklogonright']
    if senetworklogonright == "*S-1-5-32-544,*S-1-5-32-545":
        result = "[+]从网络访问此计算机符合"
        print(result)
        all_result["senetworklogonright"] = "符合：" + result
    elif senetworklogonright != "*S-1-5-32-544,*S-1-5-32-545":
        result = "[-]从网络访问此计算机不符合，对象为" + senetworklogonright
        print(result)
        all_result["senetworklogonright"] = "不符合：" + result
    else:
        print("[!]出现非预期错误！senetworklogonright")

def ScreenSecure():
    screensaverissecure = all['screensaverissecure']
    screensavetimeout = all['screensavetimeout']

    #print(screensaverissecure,screensavetimeout)

    if screensaverissecure != '':
        if int(screensaverissecure) == 1:
            result = "[+]屏幕保护已经开启"
            print(result)
            all_result["screensaverissecure"] = "符合：" + result
            if int(screensavetimeout) != '':
                if int(screensavetimeout) >= 300:
                    result = "[+]等待时间符合，时间为：" + screensavetimeout
                    print(result)
                    all_result["screensavetimeout"] = "符合：" + result
                elif int(screensavetimeout) < 300:
                    result = "[-]等待时间不符合，时间为：" + screensavetimeout
                    print(result)
                    all_result["screensavetimeout"] = "不符合：" + result
            else:
                print("[!]出现非预期错误！screensavetimeout")
        elif int(screensaverissecure) == 0:
            result = "[-]屏幕保护没有开启"
            print(result) 
            all_result["screensaverissecure"] = "不符合：" + result
    else:
        result = "[-]屏幕保护没有开启"
        print(result) 
        all_result["screensaverissecure"] = "不符合：" + result

def RemoteConnectionHangs():
    value = all['machine\\system\\currentcontrolset\\services\\lanmanserver\\parameters\\autodisconnect'] #4,15
    if int(value.split(",",1)[1]) <= 15:
        result = "[+]Microsoft网络服务器：暂停会话前所需的空闲时间数量符合，时间为" + value.split(",",1)[1]
        print(result)
        all_result["remoteconnectionhangs"] = "符合：" + result
    elif int(value.split(",",1)[1]) > 15:
        result = "[-]Microsoft网络服务器：暂停会话前所需的空闲时间数量不符合，时间为" + value.split(",",1)[1]
        print(result)
        all_result["remoteconnectionhangs"] = "不符合：" + result
    else:
        print("[!]出现非预期错误！remoteconnectionhangs")

def AutoAdminLogon():
    autoadminlogon = all['autoadminlogon']

    if autoadminlogon == '':
        result = "[+]系统自动登录已经关闭"
        print(result)
        all_result["autoadminlogon"] = "符合：" + result
    else:
        result = "[-]系统自动登录没有关闭"
        print(result)
        all_result["autoadminlogon"] = "不符合：" + result        

def DontDisplayLastUserName():
    value = all['machine\\software\\microsoft\\windows\\currentversion\\policies\\system\\dontdisplaylastusername'] #4,0
    if int(value.split(",",1)[1]) == 1:
        result = "[+]隐藏最后登录名符合"
        print(result)
        all_result["dontdisplaylastusername"] = "符合：" + result
    elif int(value.split(",",1)[1]) == 0:
        result = "[-]隐藏最后登录名不符合"
        print(result)
        all_result["dontdisplaylastusername"] = "不符合：" + result
    else:
        print("[!]出现非预期错误！dontdisplaylastusername")

def NoDriveTypeAutoRun():
    nodrivetypeautorun = all['nodrivetypeautorun']
    if nodrivetypeautorun == '':
        result = "[-]关闭自动播放不符合"
        print(result)
        all_result["nodrivetypeautorun"] = "不符合：" + result
    elif int(nodrivetypeautorun) == 4:
        result = "[+]关闭自动播放符合"
        print(result)
        all_result["nodrivetypeautorun"] = "符合：" + result
    else:
        print("[!]出现非预期错误！nodrivetypeautorun")

def PortNumber():
    portnumber = all['portnumber']

    if portnumber == '':
        result = "[!]远程桌面服务端口未开启"
        print(result)
        all_result["portnumber"] = "符合：" + result
    elif portnumber != '':
        if int(portnumber) == 3389:
            result = "[-]远程桌面服务端口不符合，端口为：" + portnumber
            print(result)
            all_result["portnumber"] = "不符合：" + result
        elif int(portnumber) != 3389:
            result = "[+]远程桌面服务端口符合，端口为：" + portnumber
            print(result)
            all_result["portnumber"] = "符合：" + result        

def RemoteAccessRegistryPath(): #网络访问: 可远程访问的注册表路径和子路径
    value = all['machine\\system\\currentcontrolset\\control\\securepipeservers\\winreg\\allowedpaths\\machine']
    if value.split(",",1)[1] == None:
        result = "[+]可远程访问的注册表路径和子路径已关闭"
        print(result)
        all_result["remoteaccessregistrypath"] = "符合：" + result
    if value.split(",",1)[1] != None:
        result = "[-]可远程访问的注册表路径和子路径没有关闭"
        print(result)
        all_result["remoteaccessregistrypath"] = "不符合：" + result        

def EnableForcedLogOff():
    value = all['machine\\system\\currentcontrolset\\services\\lanmanserver\\parameters\\enableforcedlogoff']
    if int(value.split(",",1)[1]) == 1:
        result = "[+]登录时间过期后断开与客户端的连接符合"
        print(result)
        all_result["enableforcedlogoff"] = "符合：" + result
    if int(value.split(",",1)[1]) == 0:
        result = "[-]登录时间过期后断开与客户端的连接不符合"
        print(result)
        all_result["enableforcedlogoff"] = "不符合：" + result

def ClearPageFileAtShutdown():
    value = all['machine\\system\\currentcontrolset\\control\\session manager\\memory management\\clearpagefileatshutdown']
    if int(value.split(",",1)[1]) == 1:
        result = "[+]清除虚拟内存页面文件符合"
        print(result)
        all_result["clearpagefileatshutdown"] = "符合：" + result
    if int(value.split(",",1)[1]) == 0:
        result = "[-]清除虚拟内存页面文件不符合"
        print(result)
        all_result["clearpagefileatshutdown"] = "不符合：" + result

def NtpTime():
    ntp = all['type']
#    ntpserver = all['ntpserver']

    if "ntpserver" in all:
        ntpserver = all['ntpserver']
        if ntp == 'NTP':
            result = "[+]配置系统时间同步符合"
            print(result)
            all_result["ntptime"] = "符合：" + result
            result = "[+]NtpServer为：" + ntpserver.split(",",1)[0]
            print(result)
            all_result["ntpserver"] = result
        elif ntp == 'NoSync':
            result = "[-]配置系统时间同步不符合"
            print(result)
            all_result["ntptime"] = "不符合：" + result
        elif ntp == 'AllSync':
            result = "[-]配置系统时间同步不符合"
            print(result)
            all_result["ntptime"] = "不符合：" + result
    else:
        result = "[-]ntpserver未找到"
        print(result)
        all_result["ntptime"] = "不符合：" + result

def EnableDep():
    dep = all['dep']
    if dep.find('2'):
        result = "[+]数据执行保护已经开启（仅适用于Windows server 2003）"
        print(result)
        all_result["enabledep"] = "符合：" + result
    else:
        result = "[-]数据执行保护没有开启（仅适用于Windows server 2003）"
        print(result)
        all_result["enabledep"] = "不符合：" + result

def SystemService():
    #print("[!]优化服务待开发")
    servicefax = all['servicefax']
    servicespooler = all['servicespooler']
    servicescardsvr = all['servicescardsvr']
    serviceshellhwdetection = all['serviceshellhwdetection']
    serviceremoteregistry = all['serviceremoteregistry']
    servicelanmanserver = all['servicelanmanserver']
    servicelmhosts = all['servicelmhosts']
    servicelanmanworkstation =all['servicelanmanworkstation']
    servicebrowser = all['servicebrowser']

    if servicefax != "":
        if servicefax.find("Running"):
            result = "[-]Fax服务正在运行"
            print(result)
            all_result["servicefax"] = "不符合：" + result
        elif servicefax.find("Stopped"):
            result = "[+]Fax服务已经停止"
            print(result)
            all_result["servicefax"] = "符合：" + result
    else:
        result = "[+]Fax服务未找到"
        print(result)
        all_result["servicefax"] = "符合：" + result

    if servicespooler != "":
        if servicespooler.find("Running"):
            result = "[-]Print Spooler服务正在运行"
            print(result)
            all_result["servicespooler"] = "不符合：" + result
        elif servicespooler.find("Stopped"):
            result = "[+]Print Spooler服务已经停止"
            print(result)
            all_result["servicespooler"] = "符合：" + result
    else:
        result = "[+]Print Spooler服务未找到"
        print(result)
        all_result["servicespooler"] = "符合：" + result

    if servicescardsvr != "":
        if servicescardsvr.find("Running"):
            result = "[-]Smart Card服务正在运行"
            print(result)
            all_result["servicescardsvr"] = "不符合：" + result
        elif servicescardsvr.find("Stopped"):
            result = "[+]Smart Card服务已经停止"
            print(result)
            all_result["servicescardsvr"] = "符合：" + result
    else:
        result = "[+]Smart Card服务未找到"
        print(result)
        all_result["servicescardsvr"] = "符合：" + result

    if serviceshellhwdetection != "":
        if serviceshellhwdetection.find("Running"):
            result = "[-]Shell Hardware Detection服务正在运行"
            print(result)
            all_result["serviceshellhwdetection"] = "不符合：" + result
        elif serviceshellhwdetection.find("Stopped"):
            result = "[+]Shell Hardware Detection服务已经停止"
            print(result)
            all_result["serviceshellhwdetection"] = "符合：" + result            
    else:
        result = "[+]Shell Hardware Detection服务未找到"
        print(result)
        all_result["serviceshellhwdetection"] = "符合：" + result     

    if serviceremoteregistry != "":
        if serviceremoteregistry.find("Running"):
            result = "[-]Remote Registry服务正在运行"
            print(result)
            all_result["serviceremoteregistry"] = "不符合：" + result
        elif serviceremoteregistry.find("Stopped"):
            result = "[+]Remote Registry服务已经停止"
            print(result)
            all_result["serviceremoteregistry"] = "符合：" + result            
    else:
        result = "[+]Remote Registry服务未找到"
        print(result)
        all_result["serviceremoteregistry"] = "符合：" + result

    if servicelanmanserver != "":
        if servicelanmanserver.find("Running"):
            result = "[-]Server服务正在运行"
            print(result)
            all_result["servicelanmanserver"] = "不符合：" + result
        elif servicelanmanserver.find("Stopped"):
            result = "[+]Server服务已经停止"
            print(result)
            all_result["servicelanmanserver"] = "符合：" + result
    else:
        result = "[+]Server服务未找到"
        print(result)
        all_result["servicelanmanserver"] = "符合：" + result

    if servicelmhosts != "":
        if servicelmhosts.find("Running"):
            result = "[-]TCP/IP NetBIOS Helper服务正在运行"
            print(result)
            all_result["servicelmhosts"] = "不符合：" + result
        elif servicelmhosts.find("Stopped"):
            result = "[+]TCP/IP NetBIOS Helper服务已经停止"
            print(result)
            all_result["servicelmhosts"] = "符合：" + result
    else:
        result = "[+]TCP/IP NetBIOS Helper服务未找到"
        print(result)
        all_result["servicelmhosts"] = "符合：" + result

    if servicelanmanworkstation != "":
        if servicelanmanworkstation.find("Running"):
            result = "[-]Workstation服务正在运行"
            print(result)
            all_result["servicelanmanworkstation"] = "不符合：" + result
        elif servicelanmanworkstation.find("Stopped"):
            result = "[+]Workstation服务已经停止"
            print(result)
            all_result["servicelanmanworkstation"] = "符合：" + result
    else:
        result = "[+]Workstation服务未找到"
        print(result)
        all_result["servicelanmanworkstation"] = "符合：" + result

    if servicebrowser != "":
        if servicebrowser.find("Running"):
            result = "[-]Computer browser服务正在运行"
            print(result)
            all_result["servicebrowser"] = "不符合：" + result
        elif servicebrowser.find("Stopped"):
            result = "[+]Computer browser服务已经停止"
            print(result)
            all_result["servicebrowser"] = "符合：" + result
    else:
        result = "[+]Computer browser服务未找到"
        print(result)
        all_result["servicebrowser"] = "符合：" + result

def NetShare():
    #print("[!]关闭默认共享待开发")
    ipc = all['ipc']
    if ipc == '':
        result = "[+]默认共享已经关闭"
        print(result)
        all_result["ipc"] = "符合：" + result
    else:
        result = "[-]默认共享没有关闭"
        print(result)
        all_result["ipc"] = "不符合：" + result

def RestrictAnonymousSAM():
    value = all['machine\\system\\currentcontrolset\\control\\lsa\\restrictanonymoussam']
    if int(value.split(",",1)[1]) == 1:
        result = "[+]不允许 SAM 帐户的匿名枚举已经启用"
        print(result)
        all_result["restrictanonymoussam"] = "符合：" + result
    if int(value.split(",",1)[1]) == 0:
        result = "[-]不允许 SAM 帐户的匿名枚举没有启用"
        print(result)
        all_result["restrictanonymoussam"] = "不符合：" + result

def EveryoneIncludesAnonymous():
    value = all['machine\\system\\currentcontrolset\\control\\lsa\\everyoneincludesanonymous']
    if int(value.split(",",1)[1]) == 0:
        result = "[+]将everyone权限应用于匿名用户已经禁用"
        print(result)
        all_result["everyoneincludesanonymous"] = "符合：" + result
    if int(value.split(",",1)[1]) == 1:
        result = "[-]将everyone权限应用于匿名用户已经禁用没有"
        print(result)
        all_result["everyoneincludesanonymous"] = "不符合：" + result

def LimitBlankPasswordUse():
    value = all['machine\\system\\currentcontrolset\\control\\lsa\\limitblankpassworduse']
    if int(value.split(",",1)[1]) == 1:
        result = "[+]使用空密码的本地帐户只允许进行控制台登录已经启用"
        print(result)
        all_result["limitblankpassworduse"] = "符合：" + result
    if int(value.split(",",1)[1]) == 0:
        result = "[-]使用空密码的本地帐户只允许进行控制台登录没有启用"
        print(result)
        all_result["limitblankpassworduse"] = "不符合：" + result

def FileSystem():
    filesystem = all['filesystem']
    result = "[!]当前文件系统为：" + filesystem.replace(' ', '')
    print(result)
    all_result["filesystem"] = "符合：" + result

def CaclsDisk():
    caclsdisk = all['caclsdisk']
    result = "[!]C盘权限为：" + caclsdisk.replace(' ', '')
    print(result)
    all_result["caclsdisk"] = "符合：" + result

def CaclsCmd():
    caclscmd = all['caclscmd']
    result = "[!]cmd.exe权限为：" + caclscmd.replace(' ', '')
    print(result)
    all_result["caclscmd"] = "符合：" + result

def CaclsNet():
    caclsnet = all['caclsnet']
    result = "[!]caclsnet.exe权限为：" + caclsnet.replace(' ', '')
    print(result)
    all_result["caclsnet"] = "符合：" + result

def CaclsNet1():
    caclsnet1 = all['caclsnet1']
    result = "[!]caclsnet1.exe权限为：" + caclsnet1.replace(' ', '')
    print(result)
    all_result["caclsnet1"] = "符合：" + result

def EnhancedLog():
    securitymaxsize = all['securitymaxsize']
    securityretention = all['securityretention']
    applicationmaxsize = all['applicationmaxsize']
    applicationretention = all['applicationretention']
    systemmaxsize = all['systemmaxsize']
    systemretention = all['systemretention']

    if int(applicationmaxsize) >= 838860800 & int(applicationretention) == '0':
        result = "[+]应用程序日志符合"
        print(result)
        all_result["applicationmaxsize"] = "符合：" + result
    else:
        result = "[-]应用程序日志不符合"
        print(result)
        all_result["application"] = "不符合：" + result
    if int(securitymaxsize) >= 838860800 & int(securityretention) == '0':
        result = "[+]安全日志符合"
        print(result)
        all_result["security"] = "符合：" + result
    else:
        result = "[-]安全日志不符合"
        print(result)
        all_result["security"] = "不符合：" + result
    if int(systemmaxsize) >= 838860800 & int(systemretention) == '0':
        result = "[+]系统日志符合"
        print(result)
        all_result["system"] = "符合：" + result
    else:
        result = "[-]系统日志不符合"
        print(result)
        all_result["system"] = "不符合：" + result

def AuditPolicyCheckRes():
    auditsystemevents = all['auditsystemevents']
    auditlogonevents = all['auditlogonevents']
    auditobjectaccess = all['auditobjectaccess']
    auditprivilegeuse = all['auditprivilegeuse']
    auditpolicychange = all['auditpolicychange']
    auditaccountmanage = all['auditaccountmanage']
    auditprocesstracking = all['auditprocesstracking']
    auditdsaccess = all['auditdsaccess']
    auditaccountlogon = all['auditaccountlogon']

    if int(auditsystemevents) == int(auditlogonevents) == int(auditobjectaccess) == int(auditprivilegeuse) == int(auditpolicychange) == int(auditaccountmanage) == int(auditprocesstracking) == int(auditdsaccess) == int(auditaccountlogon) == 3:
        result = "[+]审核策略符合"
        print(result)
        all_result["auditpolicycheckres"] = "符合：" + result
    else:
        result = "[-]审核策略不符合"
        print(result)
        all_result["auditpolicycheckres"] = "不符合：" + result

def SynAttack():
    synattackprotect = all['synattackprotect']
    tcpmaxportsexhausted = all['tcpmaxportsexhausted']
    tcpmaxhalfopen = all['tcpmaxhalfopen']
    tcpmaxhalfopenretried = all['tcpmaxhalfopenretried']
    
    if (synattackprotect == '') & (tcpmaxportsexhausted == '') & (tcpmaxhalfopen == '') & (tcpmaxhalfopenretried == ''):
        result = "[-]SYN攻击保护没有启用"
        print(result)
        all_result["synattack"] = "不符合：" + result
    else:
        result = "[+]SYN攻击保护已经启用"
        print(result)
        all_result["synattack"] = "符合：" + result

def EnableICMPRedirect():
    enableicmpredirect = all['enableicmpredirect']

    if int(enableicmpredirect) == 1:
        result = "[-]ICMP攻击保护没有启用"
        print(result)
        all_result["enableicmpredirect"] = "不符合：" + result
    elif int(enableicmpredirect) == 0:
        result = "[+]ICMP攻击保护已经启用"
        print(result)
        all_result["enableicmpredirect"] = "符合：" + result

def EnableDeadGWDetect():
    enabledeadgwdetect = all['enabledeadgwdetect']

    if enabledeadgwdetect != '':
        if int(enabledeadgwdetect) == 0:
            result = "[+]SNMP攻击保护已经启用"
            print(result)
            all_result["enabledeadgwdetect"] = "符合：" + result
    else:
        result = "[-]SNMP攻击保护没有启用"
        print(result)
        all_result["enabledeadgwdetect"] = "不符合：" + result

def DisableIPSourceRouting():
    disableipsourcerouting = all['disableipsourcerouting']

    if disableipsourcerouting != '':
        if int(disableipsourcerouting) == 1:
            result = "[+]IP源路由已经禁用"
            print(result)
            all_result["disableipsourcerouting"] = "符合：" + result
    else:
        result = "[-]IP源路由没有禁用"
        print(result)
        all_result["disableipsourcerouting"] = "不符合：" + result        

def EnablePMTUDiscovery():
    enablepmtudiscovery = all['enablepmtudiscovery']

    if enablepmtudiscovery != '':
        if int(enablepmtudiscovery) == 1:
            result = "[+]碎片攻击保护已经启用"
            print(result)
            all_result["enablepmtudiscovery"] = "符合：" + result
    else:
        result = "[-]碎片攻击保护没有启用"
        print(result)
        all_result["enablepmtudiscovery"] = "符合：" + result


print("------------------------------")
print("1.系统信息")
all_result['systemver'] = all['systemver']
print("[+]系统版本：" + all['systemver'])
print("[+]SP版本："+ all['spver'])
all_result['spver'] = all['spver']
print("[+]Hotfix：" + all['hotfix'])
all_result['hotfix'] = all['hotfix']
print("[+]主机名：" + all['hostname'])
all_result['hostname'] = all['hostname']
print("[!]网络配置：输出不便，请自行查看（ipconfig /all）")
print("[!]路由表：输出不便，请自行查看（route print）")
print("[!]开放端口：输出不便，请自行查看（netstat -ano）")
OsVersion()
print("------------------------------")
print("2.补丁安装")
#print("[+]请手动查看系统补丁情况")
KB()
print("------------------------------")
print("3.账号口令")
EnableGuestAccount()
NewAdministratorName()
#print("[!]请自行判断是否有隐藏账户！！！")
AllUser()
PasswordComplexity()
MinimumPasswordLength()
PasswordAge()
PasswordHistorySize()
ClearTextPassword()
LockoutBadCount()
ResetLockoutCount()
LockoutDuration()
print("------------------------------")
print("4.授权")
SeRemoteShutdownPrivilege()
SeShutdownPrivilege()
SeTakeOwnershipPrivilege()
SeInteractiveLogonRight()
SeNetworkLogonRight()
print("------------------------------")
print("5.系统安全设置")
ScreenSecure()
RemoteConnectionHangs()
AutoAdminLogon()
DontDisplayLastUserName()
NoDriveTypeAutoRun()
PortNumber()
RemoteAccessRegistryPath()
EnableForcedLogOff()
ClearPageFileAtShutdown()
NtpTime()
EnableDep()
print("------------------------------")
print("6.优化服务")
SystemService()
NetShare()
RestrictAnonymousSAM()
EveryoneIncludesAnonymous()
LimitBlankPasswordUse()
print("------------------------------")
print("7.文件系统")
FileSystem()
CaclsDisk()
CaclsCmd()
CaclsNet()
CaclsNet1()
print("------------------------------")
print("8.日志审核")
EnhancedLog()
AuditPolicyCheckRes()
print("------------------------------")
print("9.IP协议安全入侵防范配置")
SynAttack()
EnableICMPRedirect()
EnableDeadGWDetect()
DisableIPSourceRouting()
EnablePMTUDiscovery()
#print(all_result.keys())


document = MailMerge(template)
#print("Fields included in {}: {}".format(template,document.get_merge_fields()))
document.merge(**all_result)
document.write(".\\" + all["ip"] + ".docx")
