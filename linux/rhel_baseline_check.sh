ExecXmlStartFun(){
	result=$(eval $2)

	echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" >> $ip.xml
	echo "<ip addres=\"$ip\">" >> $ip.xml
	echo "  <command>$1</command>" >> $ip.xml
	echo "    <result><![CDATA[$result]]></result>" >> $ip.xml
}

ExecXmlFun(){
	result=$(eval $2)

	echo "  <command>$1</command>" >> $ip.xml
	echo "    <result><![CDATA[$result]]></result>" >> $ip.xml
}

ExecXmlEndFun(){
	result=$(eval $2)

	echo "  <command>$1</command>" >> $ip.xml
	echo "    <result><![CDATA[$result]]></result>" >> $ip.xml
	echo "</ip>" >> $ip.xml
}

ip=$(ip a | grep inet | grep -v 127.0.0.1 | grep -v inet6 | awk '{print $2}' | sed 's#/24.*$##g')
eval rm $ip.xml

ExecXmlStartFun "1.1查看内核信息" "uname -a"
ExecXmlFun "1.1查看所有软件包" "rpm -qa"
ExecXmlFun "1.1查看主机名" "hostname"
ExecXmlFun "1.1查看网络配置" "ifconfig -a"
ExecXmlFun "1.1查看路由表" "netstat -rn"
ExecXmlFun "1.1查看开放端口" "netstat -an"
ExecXmlFun "1.1查看当前进程" "ps -aux | grep -v ']]>'"
ExecXmlFun "1.2系统coredump状态" "cat /etc/security/limits.conf"
ExecXmlFun "2.1检查弱口令" "echo 请手动排查！"
ExecXmlFun "2.2禁用无用账号" "awk -F : '{print \$1 \":\" \$NF}' /etc/passwd"
ExecXmlFun "2.3账号锁定策略" "cat /etc/pam.d/system-auth"
ExecXmlFun "2.4检查空口令账户和除root外uid为0的用户" "awk -F : '(\$2 == \"\")' /etc/shadow && awk -F : '(\$3 == 0)' /etc/passwd"
ExecXmlFun "2.5添加口令周期策略" "cat /etc/login.defs | grep PASS"
ExecXmlFun "2.6添加口令复杂度策略" "cat /etc/pam.d/system-auth | grep pam_cracklib.so"
ExecXmlFun "2.7限制root远程登录" "cat /etc/securetty | grep console"
ExecXmlFun "2.8检查grub密码" "cat /boot/grub2/grub.cfg /boot/efi/EFI/centos/grub.cfg /boot/grub2/user.cfg /boot/efi/EFI/centos/user.cfg | grep -E \"password|PASS\""
ExecXmlFun "2.9限制用户su" "cat /etc/pam.d/su"
ExecXmlFun "2.10snmp团体字" "cat /etc/snmp/snmpd.conf"
ExecXmlFun "3.1关闭不必要的服务" "systemctl list-unit-files | grep enable"
ExecXmlFun "3.2ssh服务安全配置" "cat /etc/ssh/sshd_config"
ExecXmlFun "3.3检查.rhosts和/etc/hosts.equiv文件" "find / -name .rhosts -print"
ExecXmlFun "3.4配置tcpwrapper访问控制" "cat /etc/hosts.allow && cat /etc/hosts.deny"
ExecXmlFun "3.5防止误使用ctrlaltdel重启系统" "cat /etc/inittab /usr/lib/systemd/system/ctrl-alt-del.target /etc/init/control-alt-delete.conf"
ExecXmlFun "3.6ftp服务安全配置" "cat /etc/vsftpd/vsftpd.conf"
ExecXmlFun "4.1网络参数" "sysctl -A"
ExecXmlFun "5.1重要目录和文件的权限设置" "ls -al /bin/rpm /etc/exports /etc/hosts.* /var/log/messages /etc/syslog.conf /var/log/wtmp /var/log/lastlog /etc/ftpusers /etc/passwd /etc/shadow /etc/pam.d /etc/lilo.conf /etc/securetty /etc/shutdown.allow /etc/sysconfig /etc/xinetd.conf /etc/inetd.conf /etc/rc.d/init.d/ /etc/rc.d/init.d/* /etc/crontab /etc/cron.* /etc/ssh /etc/sysctl.confg"
ExecXmlFun "5.2设置umask值" "umask"
ExecXmlFun "5.3bash历史命令" "cat /etc/profile | grep HISTSIZE="
ExecXmlFun "5.4设置登录超时" "cat /etc/profile | grep TMOUT"
ExecXmlFun "5.5检查root路径" "echo \$PATH"
ExecXmlFun "5.6查找未授权的suid/sgid文件" "find / -perm -04000;find / -perm -02000"
ExecXmlFun "5.7不存在任何人都有写权限的目录" "echo 待开发"
ExecXmlFun "5.8查找任何人都有写权限的文件" "echo 待开发"
ExecXmlFun "5.9检查没有属主的文件" "echo 待开发"
ExecXmlFun "5.10检查异常隐含文件" "echo 待开发"
ExecXmlFun "6.1syslogd认证相关记录" "cat /etc/rsyslog.conf | grep authpriv"
ExecXmlEndFun "6.2syslogd日志设置" "cat /etc/rsyslog.conf"