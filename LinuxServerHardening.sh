#!/bin/bash
# Author : Ghansham Mahajan
# Use : Hardening the RHEL 7/CentOS 7/Ubuntu 16.04 Servers

#Note : This script only support RHEL 6/RHEL 7/CentOS 7/CentOS 6/Ubuntu 16.04/

# Disable the Firewall
# Disable the SELinux
# SSH setting changes ( Port/PermitRoot/Banner )
# Password Policy set
# History setting
# Banner Setting
# Basic Package Installation
# WAAgent SWAP Space Setting
# Passwords remembered must be set to at least five (5). 
# Systems must be configured to “lockout” after ten (maximum) wrong password entries and shall not automatically unlock for at least one hour.
# Password Length 8 Character
# Password Complexity ( Upper case/Lower Case/Number/Non-alphanumeric characters, (!, @, #, $, etc.) 

###Pending Task###
#For user accounts with elevated privileges and where technically feasible, the screensaver lockout or re-authentication requirement must be set to 15 minutes.
#Exclude the patches while patching
#Delete .netrc files

#verify the OS Version and run the Hardening

#=================================================================
OS=`uname`
if [ "$OS" = "SunOS" ] ; then
        OS=Solaris
        ARCH=`uname -p`
        OSSTR="${OS} ${REV}(${ARCH} `uname -v`)"
        echo $OSSTR
    elif [ "$OS" = "AIX" ] ; then
        OSSTR="$OS `oslevel` (`oslevel -r`)"
        echo $OSSTR
    elif [ "$OS" = "Linux" ] ; then
        if [ -f /etc/redhat-release ] ; then
            DistroBasedOn='RedHat'
            DIST=`cat /etc/redhat-release |sed s/\ release.*//`
            PSUEDONAME=`cat /etc/redhat-release | sed s/.*\(// | sed s/\)//`
            REV=`cat /etc/redhat-release | sed s/.*release\ // | sed s/\ .*//`
            echo $DIST
        elif [ -f /etc/SuSE-release ] ; then
            DistroBasedOn='SuSe'
            PSUEDONAME=`cat /etc/SuSE-release | tr "\n" ' '| sed s/VERSION.*//`
            REV=`cat /etc/SuSE-release | tr "\n" ' ' | sed s/.*=\ //`
            echo $DIST
        elif [ -f /etc/mandrake-release ] ; then
            DistroBasedOn='Mandrake'
            PSUEDONAME=`cat /etc/mandrake-release | sed s/.*\(// | sed s/\)//`
            REV=`cat /etc/mandrake-release | sed s/.*release\ // | sed s/\ .*//`
            echo $DIST
        elif [ -f /etc/debian_version ] ; then
            DistroBasedOn='Debian'
            DIST=`cat /etc/lsb-release | grep '^DISTRIB_ID' | awk -F=  '{ print $2 }'`
            PSUEDONAME=`cat /etc/lsb-release | grep '^DISTRIB_CODENAME' | awk -F=  '{ print $2 }'`
            REV=`cat /etc/lsb-release | grep '^DISTRIB_RELEASE' | awk -F=  '{ print $2 }'`
            echo $DIST
        fi
        if [ -f /etc/UnitedLinux-release ] ; then
            DIST="${DIST}[`cat /etc/UnitedLinux-release | tr "\n" ' ' | sed s/VERSION.*//`]"
        fi
fi
if [[ "$DIST" = "Red Hat Enterprise Linux Server" ]] || [[ "$DIST" = "CentOS Linux" ]]; then
        echo "This is the $DIST $REV"
	if [ "$(id -u)" != "0" ]; then
   		echo "This script must be run as root" 1>&2  			# Check if script running by root or not
   		exit 1								#If it's not run by root then it will exit the script
	fi
	echo "***************stop and disable the Firewall***************"
		service firewalld stop
		service iptables stop
		systemctl disable firewalld
		chkconfig iptables off
	sleep 5

	echo "Backup of selinux config file"
		cp -iv /etc/selinux/config /etc/selinux/config-bkp-$(date +%Y%m%d-%H:%M)
	echo "Disabiling the selinux"
		sed -i "s/SELINUX=enforcing/SELINUX=disabled/" /etc/selinux/config
	echo "Changes Done"
	sleep 5
	echo "See the SELUNUX Config file content"
		cat /etc/selinux/config
		
	echo "***************Backup SSHD Config file...***************"
	sleep 5
		cp -iv /etc/ssh/sshd_config /etc/ssh/sshd_config-bkp-$(date +%Y%m%d-%H:%M)
	sleep 5
	echo "***************Backup Completed!***************"
	sleep 5
	echo "***************Making Changes in Port No,PermitRootLogin and Banner***************"
		#sed -i "s/Port 22/Port 2222/" /etc/ssh/sshd_config
		sed -i "s/PermitRootLogin yes/PermitRootLogin no/" /etc/ssh/sshd_config
		sed -i "s/PermitEmptyPasswords no/PermitEmptyPasswords no/" /etc/ssh/sshd_config
		sed -i "s/Banner none/Banner \/etc\/banner/g" /etc/ssh/sshd_config
	sleep 5
	echo "***************Changes Done. See the below Output***************"
		cat /etc/ssh/sshd_config | egrep "PermitRootLogin |Port |banner |PermitEmptyPasswords"
	echo "Restarting the SSH service"
	sleep 5
		service sshd restart
	echo "SSH Service restarted see the status"
	sleep 5
		service sshd status
	echo "Backing up login.def file..."
		cp -iv /etc/login.defs /etc/login.defs-bkp-$(date +%Y%m%d-%H:%M)
	sleep 5
	echo "Backup completed"
	echo "Changing the pasword policy"
	sleep 5
		sed -i "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\   90/g" /etc/login.defs
		sed -i "s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\   1/g" /etc/login.defs
		sed -i "s/^PASS_MIN_LEN.*/PASS_MIN_LEN\    8/g" /etc/login.defs
		sed -i "s/^PASS_WARN_AGE.*/PASS_WARN_AGE\   7/g" /etc/login.defs
	echo "Changes Done"
	sleep 5
	cat /etc/login.defs | grep "^PASS_"
	sleep 5
	echo "Backup bashrc file"
		cp -iv /etc/bashrc /etc/bashrc-bkp-$(date +%Y%m%d-%H:%M)
	sleep 5
	echo 'export HISTTIMEFORMAT="%d/%m/%y %T "' >> /etc/bashrc
	sleep 5
		touch /etc/banner
		rm -rf /etc/issue
		rm -rf /etc/issue.net
	echo '"Warning: Use of this System is Restricted to Authorized Users"' >> /etc/banner
	echo "This computer system is the private property of the Company and may be used only by those individuals authorized by the Company, in accordance with Company policy.  Unauthorized, illegal or improper use may result in disciplinary action and/or civil or criminal prosecution.  Your use of Company electronic systems is subject to monitoring and disclosure in accordance with Company policy and applicable law.  By continuing to access this system, you agree that your use of Company electronic systems is subject to the foregoing and that you have no expectation of privacy in regard to any files or data stored, accessed, transmitted or received on such systems." >> /etc/banner
	sleep 5
	echo "See the Banner file content"	
		cat /etc/banner
	sleep 5
		echo "Installating the packages"
	sleep 5
		yum install sysstat audit elinks nmap wget curl unzip ntp ntpstat azcopy -y
	sleep 5
	echo "creating swap space using waagent agnet"
		cp -iv /etc/waagent.conf /etc/waagent.conf-bkp--$(date +%Y%m%d-%H:%M)
	echo "waagent conf file backup completed"
		sed -i "s/ResourceDisk.Format=n/ResourceDisk.Format=y/" /etc/waagent.conf
		sed -i "s/ResourceDisk.EnableSwap=n/ResourceDisk.EnableSwap=y/" /etc/waagent.conf
		sed -i "s/ResourceDisk.SwapSizeMB=0/ResourceDisk.SwapSizeMB=8192/" /etc/waagent.conf
	echo "Restarting WAAGNET Service"
		systemctl restart waagent.service
		systemctl status waagent.service
	sleep 5
	
	echo "Backup of passwd file"
		cp -iv /etc/passwd /etc/passwd-$(date +%Y%m%d-%H:%M)
	#echo "Making change"
		#usermod -s /sbin/nologin root
		cat /etc/passwd | grep -i root
	echo "Creating Linux Admins Users"
		useradd -m -c "Ghansham Mahajan Linux Admin | $(date +%m-%d-%Y)" -s /bin/bash ghansham
	sleep 5
	echo "Adding in Wheel Group"
		usermod -aG wheel ghansham

	#timedatectl set-timezone America/New_York
	#ICMP redirection enabled - As per rapid 7 recommendation
	cp -iv /etc/sysctl.conf /etc/sysctl.conf-bkp-$(date +%Y%m%d-%H:%M)
	
	echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
	echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
	echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
	echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
	
	#Passwords remembered must be set to at least five (5).
	cp -iv /etc/pam.d/password-auth /etc/pam.d/password-auth-bkp-$(date +%Y%m%d-%H:%M)
	cp -iv /etc/pam.d/system-auth /etc/pam.d/system-auth-bkp-$(date +%Y%m%d-%H:%M)
	sed -i '/pam_pwquality.so/a password requisite     pam_pwhistory.so remember=5 use_authtok' /etc/pam.d/password-auth
	sed -i '/pam_pwquality.so/a password requisite     pam_pwhistory.so remember=5 use_authtok' /etc/pam.d/system-auth

	#Password Length 8 Character
	cp -iv /etc/security/pwquality.conf /etc/security/pwquality.conf-bkp-$(date +%Y%m%d-%H:%M)
	sed -i "s/minlen = 6/minlen = 8/" /etc/security/pwquality.conf

	#Remove all the entries in /etc/securetty except console, tty[0-9]* and vc\[0-9]*
	cp -iv /etc/securetty /etc/securetty-bkp-$(date +%Y%m%d-%H:%M)
	egrep 'console|vc/[0-9]$|tty[0-9]$' /etc/securetty | head -n 19 > /tmp/securetty.tmp
	mv -f /tmp/securetty.tmp /etc/securetty

	#Systems must be configured to “lockout” after ten (maximum) wrong password entries and shall not automatically unlock for at least one hour.
	cp -iv /etc/pam.d/password-auth /etc/pam.d/password-auth-bkp-$(date +%Y%m%d-%H:%M)
	cp -iv /etc/pam.d/system-auth /etc/pam.d/system-auth-bkp-$(date +%Y%m%d-%H:%M)
	sed -i "/pam_env.so/a auth        required      pam_faillock.so preauth silent audit deny=10 unlock_time=3600" /etc/pam.d/password-auth
	sed -i "/pam_env.so/a auth        required      pam_faillock.so preauth silent audit deny=10 unlock_time=3600" /etc/pam.d/system-auth

	sed -i "/pam_unix.so nullok/a auth        [default=die] pam_faillock.so authfail audit deny=10 unlock_time=3600" /etc/pam.d/password-auth
	sed -i "/pam_unix.so nullok/a auth        [default=die] pam_faillock.so authfail audit deny=10 unlock_time=3600" /etc/pam.d/system-auth

	sed -i "/required      pam_unix.so/a account     required      pam_faillock.so" /etc/pam.d/password-auth
	sed -i "/required      pam_unix.so/a account     required      pam_faillock.so" /etc/pam.d/system-auth

	#Password Complexity ( Upper case/Lower Case/Number/Non-alphanumeric characters, (!, @, #, $, etc.) 
	cp -iv /etc/security/pwquality.conf /etc/security/pwquality.conf-bkp-$(date +%Y%m%d-%H:%M)

	sed -e "s/# dcredit = 0/dcredit = -1/g" /etc/security/pwquality.conf
	sed -e "s/# ucredit = 0/ucredit = -1/g" /etc/security/pwquality.conf
	sed -e "s/# ocredit = 0/ocredit = -1/g" /etc/security/pwquality.conf
	sed -e "s/# lcredit = 0/lcredit = -1/g" /etc/security/pwquality.conf
	sed -e "s/# gecoscheck = 0/gecoscheck = -1/g" /etc/security/pwquality.conf
	sed -e "s/# maxclassrepeat = 0/maxclassrepeat = 3/g" /etc/security/pwquality.conf

	
elif [[ "$DIST" = "Ubuntu" ]] || [[ "$DIST" = "Debian" ]]; then
        echo "This is the $DIST $REV"
	if [ "$(id -u)" != "0" ]; then
   		echo "This script must be run as root" 1>&2  			# Check if script running by root or not
   		exit 1								#If it's not run by root then it will exit the script
	fi
	echo "***************stop and disable the Firewall***************"
		/etc/init.d/ufw stop
		ufw disable
	sleep 5
	echo "***************Backup SSHD Config file...***************"
	sleep 5
		cp -iv /etc/ssh/sshd_config /etc/ssh/sshd_config-bkp-$(date +%Y%m%d-%H:%M)
	sleep 5
	echo "***************Backup Completed!***************"
	sleep 5
	echo "***************Making Changes in Port No,PermitRootLogin and Banner***************"
	#	sed -i "s/Port 22/Port 2222/" /etc/ssh/sshd_config
		sed -i "s/PermitRootLogin prohibit-password/PermitRootLogin no/" /etc/ssh/sshd_config
		sed -i "s/#Banner none /Banner \/etc\/banner/g" /etc/ssh/sshd_config
	sleep 5
	echo "***************Changes Done. See the below Output***************"
		cat /etc/ssh/sshd_config | grep -E "PermitRootLogin |Port |Banner"
	echo "Restarting the SSH service"
	sleep 5
		service sshd restart
	echo "SSH Service restarted see the status"
	sleep 5
		service sshd status
	echo "Backing up login.def file..."
		cp -iv /etc/login.defs /etc/login.defs-bkp-$(date +%Y%m%d-%H:%M)
		cp -iv /etc/pam.d/common-password /etc/pam.d/common-password-bkp-$(date +%Y%m%d-%H:%M)
	sleep 5
	echo "Backup completed"
	echo "Changing the pasword policy"
	sleep 5
		sed -i "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\   90/g" /etc/login.defs
		sed -i "s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\   1/g" /etc/login.defs
		sed -i "s/^PASS_WARN_AGE.*/PASS_WARN_AGE\   7/g" /etc/login.defs
		sed -i '/ignore/ s/$/ remember=5/' /etc/pam.d/common-password
		sed -i '/ignore/ s/$/ minlen=8/' /etc/pam.d/common-password
	sleep 5
	echo "Changes Done"
		cat /etc/login.defs | grep "^PASS_"
		cat /etc/pam.d/common-password | grep -E "remember|minlen"
	sleep 5
	echo "Backup bashrc file"
		cp -iv /etc/bash.bashrc /etc/bash.bashrc-bkp-$(date +%Y%m%d-%H:%M)
	sleep 5
	echo 'export HISTTIMEFORMAT="%d/%m/%y %T "' >> /etc/bash.bashrc

	
		echo "Banner file creating and adding content"
		touch /etc/banner
		rm -rf /etc/issue
		rm -rf /etc/issue.net
		echo '"Warning: Use of this System is Restricted to Authorized Users"' >> /etc/banner
		echo "This computer system is the private property of the Company and may be used only by those individuals authorized by the Company, in accordance with Company policy.  Unauthorized, illegal or improper use may result in disciplinary action and/or civil or criminal prosecution.  Your use of Company electronic systems is subject to monitoring and disclosure in accordance with Company policy and applicable law.  By continuing to access this system, you agree that your use of Company electronic systems is subject to the foregoing and that you have no expectation of privacy in regard to any files or data stored, accessed, transmitted or received on such systems." >> /etc/banner
		sleep 5
		cat /etc/banner
		sleep 5
		
	echo "***************Disable Ctrl+Alt+Delete***************"
		systemctl mask ctrl-alt-del.target
		systemctl daemon-reload

	echo "***************Package Installation**************"
		apt-get install apt -y ; apt-get install curl -y ; apt-get install unzip -y ; apt-get install tar -y ; apt-get install wget -y ; apt-get install azcopy -y
	echo "Package Installation in progress 1...2...3..."
	sleep 5
	echo "Swap Space changes going on"
		cp -iv /etc/waagent.conf /etc/waagent.conf-$(date +%Y%m%d-%H:%M)
		sed -i "s/ResourceDisk.Format=n/ResourceDisk.Format=y/" /etc/waagent.conf
		sed -i "s/ResourceDisk.EnableSwap=n/ResourceDisk.EnableSwap=y/" /etc/waagent.conf
		sed -i "s/ResourceDisk.SwapSizeMB=0/ResourceDisk.SwapSizeMB=8192/" /etc/waagent.conf
	echo "WAAgent service restarting"
		service walinuxagent restart
	sleep 5
	echo "NTP Status"
		apt-get install ntp -y ; apt-get install ntpstat -y
		timedatectl status
		timedatectl set-ntp true
		service ntp restart
		timedatectl status
		ntpq -p
	sleep 5
	echo "service audit starting"
		apt-get install auditd -y
		service auditd status
		service auditd start
		service auditd status
	sleep 5
	echo "Changing root shell"
	echo "Backup of passwd file"
		cp -iv /etc/passwd /etc/passwd-$(date +%Y%m%d-%H:%M)
	#echo "Making change"
		#usermod -s /usr/sbin/nologin root
		cat /etc/passwd | grep -i root
	sleep 5
	echo "SAR command installation"
		apt-get install sysstat -y
		sed -i "s/false/true/" /etc/default/sysstat
		service sysstat restart
	echo "Creating Linux Admins Users"
	useradd -m -c "Ghansham Mahajan Linux Admin | $(date +%m-%d-%Y)" -s /bin/bash ghansham
	usermod -aG sudo ghansham
		
	#timedatectl set-timezone America/New_York
	cp -iv /etc/sysctl.conf /etc/sysctl.conf-bkp-$(date +%Y%m%d-%H:%M)	
	echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
	echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
	echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
	echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
	
	#Remove all the entries in /etc/securetty except console, tty[0-9]*
	cp -iv /etc/securetty /etc/securetty-bkp-$(date +%Y%m%d-%H:%M)
	egrep '^console|^tty[0-9]$' /etc/securetty > /tmp/securetty.tmp
	mv -f /tmp/securetty.tmp /etc/securetty
	
	#Systems must be configured to “lockout” after ten (maximum) wrong password entries and shall not automatically unlock for at least one hour.
	cp -iv /etc/pam.d/common-auth /etc/pam.d/common-auth-bkp-$(date +%Y%m%d-%H:%M)
	sed -i "/pam_unix.so/i auth    required           pam_tally2.so onerr=fail deny=10 unlock_time=3600 audit" /etc/pam.d/common-auth

	#Password Complexity ( Upper case/Lower Case/Number/Non-alphanumeric characters, (!, @, #, $, etc.) 
	apt-get -y install libpam-pwquality cracklib-runtime
	cp -iv /etc/pam.d/common-password /etc/pam.d/common-password-bkp--$(date +%Y%m%d-%H:%M)
	sed -i "s/pam_pwquality.so/pam_pwquality.so retry=3 minlen=8 maxrepeat=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 difok=3 gecoscheck=1 reject_username/" /etc/pam.d/common-password

fi
