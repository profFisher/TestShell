#! /bin/sh


project=SCA
splunk=/opt/splunk
symav=/opt/Symantec/symantec_antivirus
host=`hostname -f`
kernel=`uname -r`

# SCA technical assessment
	header () {
		echo -e "\n-----------------------------------\n$1"
		}

	header "*** CUI//ISVI//FEDCON  ***"
	date
	echo -e "$host\n"

		header "=== DEVICE INFORMATION"
		date
		echo "$host\n"
		echo $kernel

# check release information

		echo Check the release information to identify distribution
		ls /etc/*-release
		cat /etc/*-release
	
header "=== WARNING BANNER"
	date
	echo -e "$host\n"

	echo find issue or issue.net warning banner
	
	if [ -f /etc/issue ]; then
		cat /etc/issue
	else
		if [ -f /etc/issue.net ]; then
			cat /etc/issue.net
		else
			echo NO SSH WARNING BANNER IDENTIFIED
		fi
	fi

	if [ -f /etc/dconf/db/gdm.d/ ]; then
		echo GNOME WARNING BANNER
		cat /etc/dconf/db/gdm.d/01-banner-message
	else
		echo NO GNOME WARNING BANNER IDENTIFIED
	fi

header "=== FAILED LOGIN ATTEMPTS"
	date
	echo -e "$host\n"

		echo /var/log/secure
		grep -h ailed /var/log/secure{-*,} | egrep -v 'reset|release' | ( found=false; while read line; do echo $line; found=true; done; if ! $found; then echo nothing found; fi )

	header "=== LOGROTATE"
	date
	echo -e "$host\n"

		echo /etc/logrotate.conf
		cat /etc/logrotate.conf

	header "=== AUDIT RULES"
	date
	echo -e "$host\n"

		echo audit rules that are in the auditd.conf file
		echo /etc/audit/auditd.conf
		cat /etc/audit/auditd.conf

header

		echo audit rules that are running
		echo auditctl -l
		auditctl -l

header

		echo /etc/audit/audit.rules
		cat /etc/audit/audit.rules

	header "=== CENTRAL LOGGING OF SECURITY EVENTS"
	date
	echo -e "$host\n"

		echo /etc/rsyslog.conf
		cat /etc/rsyslog.conf

		if [ -d $splunk -o -d ${splunk}forwarder ]; then
			if [ -d ${splunk}forwarder ]; then
				echo Splunk Forwarder installed
			else
				echo Splunk Server installed
			fi
			ps -ef | grep splunk | egrep -v 'grep|runner'

			if [ -d ${splunk}forwarder ]; then
				echo "\nSplunk forwarded logs"
				cat ${splunk}forwarder/etc/apps/Splunk_TA_nix/local/inputs.conf
			fi
		else
			echo Splunk forwarder NOT installed
		fi

	header "=== VALIDATE MALICIOUS CODE PROTECTION"
	date
	echo -e "$host\n"

		if [ -d $symav ]; then
			echo SEP installed

			echo -n version:" "
			$symav/sav info -p

			echo -n definitions:" "
			$symav/sav info -d

			echo -n autoprotect:" "
			if chkconfig autoprotect; then
				$symav/sav info -a
			else
				echo Disabled
			fi

			$symav/sav info -s
		else
			echo No SEP - check ClamAV

			if [ -f /usr/bin/clamscan ]; then
				echo ClamAV appears to be installed. Verify CLAMVER results.
				
				echo clamscan -V
				/usr/bin/clamscan -V

header
				
				echo Is there a weekly cron job defined for clamscan
				ls -l /etc/cron.weekly

header

				echo review the tail of the clamscan log, if possible

				if [ -f /var/log/clamscan.log ]; then
					echo clamscan log
					tail /var/log/clamscan.log
                else
                    if [ -d /var/log/clamav ]; then
                        echo tail /var/log/clamav/clamav.log
                        tail /var/log/clamav/clamav.log
					fi
				fi
			else
				echo No Symantec or ClamAV found
			fi
		fi

	header "=== UPDATES INSTALLED"
	date
	echo -e "$host\n"

#		echo /var/log/yum.log
#		cat /var/log/yum.log

		echo yum history
		yum history

	header "=== USERS AND GROUPS"
	date
	echo -e "$host\n"

		echo /etc/passwd
		cat /etc/passwd

header

		echo -e "\n/etc/group"
		cat /etc/group 

	header "=== REMOTE USER SETTINGS (SSH)"
	date
	echo -e "$host\n"

		echo /etc/ssh/sshd_config
        cat /etc/ssh/sshd_config

		if [ -d /etc/sssd ]; then
header
           	echo /etc/sssd/sssd.conf
           	cat /etc/sssd/sssd.conf
		else
header
			echo NO SSSD configuration
		fi

	header "=== LOCAL FIREWALL"
	date
	echo -e "$host\n"

		if [ -f /etc/sysconfig/iptables ]; then
			echo /etc/sysconfig/iptables
			cat /etc/sysconfig/iptables

header

			echo -e "\n/etc/sysconfig/ip6tables"
			cat /etc/sysconfig/ip6tables
		
		else
			echo check firewalld or other application
		fi

header
		
		ps -ef | grep firewalld | grep -v grep

		echo -e "\n/etc/firewalld/zones/*.xml"
		cat /etc/firewalld/zones/*.xml

	header "=== PASSWORD SETTINGS"
	date
	echo -e "$host\n"

		if [ -f /etc/security/pwquality.conf ]; then
			echo /etc/security/pwquality.conf
			cat /etc/security/pwquality.conf
		else
			echo no pwquality.conf
		fi

header

		echo -e "\n/etc/pam.d/password-auth"
		cat /etc/pam.d/password-auth

header

		echo -e "\n/etc/pam.d/system-auth"
		cat /etc/pam.d/system-auth

header

		echo -e "\n/etc/shadow (passwords suppressed)"
		awk -F : '{ if ( $2 != "*" && $2 != "!!" && $2 != "x" ) $2="<password suppressed>"; printf "%s:%s:%s:%s:%s:%s:%s:%s:\n", $1, $2, $3, $4, $5, $6, $7, $8 }' /etc/shadow 

header

		if [ -f /etc/pam.d/sshd ]; then
			echo -e "\n/etc/pam.d/sshd"
			cat /etc/pam.d/sshd
		else
			echo NO PAM.D SSHD
		fi

header

		if [ -f /etc/pam.d/sshd ]; then
			echo -e "\n/etc/pam.d/sudo"
			cat /etc/pam.d/sudo
		else
			echo NO PAM.D SUDO
		fi

header

		if [ -f /etc/pam.d/sssd ]; then
			echo -e "\n/etc/pam.d/sssd"
			cat /etc/pam.d/sssd
		else
			echo NO PAM.D SSSD
		fi

	header "=== Verify BigFix agent"
	date	
	echo -e "$host\n"

		rpm -q BESAgent

	header "=== What is running"
	date	
	echo -e "$host\n"
		
		echo -e "systemctl --type=service"

		systemctl --type=service

	header "=== NETSTAT results"
	date
	echo -e "$host\n"

		echo -e "netstat -ape"

		netstat -ape

#		echo Linux distributions are switching from netstat to ss
#		echo â€œss -apeâ€
#
#		ss -ape
#
	header "*** CUI//ISVI//FEDCON  ***"
