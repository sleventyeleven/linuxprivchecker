#!/bin/bash

###################################80 Columns###################################
#                   Linux Privilege Escalation Check Script
#
# [Details:] 
## Originally forked from the linuxprivchecker.py (Mike Czumak), this script
## is intended to be executed locally on a Linux box to enumerate basic system 
## info and search for common privilege escalation vectors such as word 
## writable files, misconfigurations, clear-text password and applicable 
## exploits.
#
# [Original Author]: Mike Czumak (T_v3rn1x) -- @SecuritySift
# [Contributors]:
## Mike Merrill (linted) -- https://github.com/linted
## James Hogan (5aru) -- https://github.com/5aru
#
# [Modification, Distribution, and Attribution]:
## Permission is herby granted, free of charge, to any person obtaining a copy
## of this software and the associated documentation files (the "Software"),
## to use, copy, modify, merge, publish, distribute, and/or sublicense copies
## of the Software, and to permit persons to whom the Software is furnished to
## do so, subject to the following conditions:
##
## The software must maintain original author attribution and may not be sold
## or incorporated into any commercial offering.
##
## THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
## IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
## FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
## AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
## LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
## FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
## DEALINGS IN THE SOFTWARE.
##################################80 Columns####################################

### Useful functions

PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games"

TITLE_LINE=$(printf "%*s\n" "80" | tr ' ' "=")
SECTION_LINE=$(printf "%*s\n" "80" | tr ' ' "-")

function formatCommand(){
	eval $1 | sed 's|^|    |'
}

echo ${TITLE_LINE}
echo "LINUX_PRIVILEGE ESCALATION CHECKER"
echo ${TITLE_LINE}

echo -e "\n[*] GETTING BASIC SYSTEM INFO...\n"

echo "[+] Operating System"
formatCommand "cat /etc/issue"

echo -e "\n[+] Kernel"
formatCommand "cat /proc/version"

echo -e "\n[+] Hostname/FQDN"
formatCommand "hostname -f"

echo -ne "\n${SECTION_LINE}\n"
echo -e "[*] GETTING NETWORKING INFO...\n"

echo "[+] Route"

if [ -x "$(command -v route)" ]; then
	formatCommand "route -n"
else
	formatCommand "ip route"
fi

echo -e "\n[+] Interfaces"

if [ -x "$(command -v ifconfig)" ]; then
	formatCommand "ifconfig -a"
else
	formatCommand "ip addr show"
fi

echo -e "\n[+] Network Connections"

if [ -x "$(command -v netstat)" ]; then
	formatCommand "netstat -tupan | grep -v TIME_WAIT"
else
	formatCommand "ss -tupan | grep -v CLOSE_WAIT"
fi

echo -ne "\n${SECTION_LINE}\n"
echo -e "[*] GETTING FILESYSTEM INFO...\n"

echo -e "\n[+] Mount Results"
formatCommand "mount"

echo -e "\n[+] fstab Entries"
formatCommand "cat /etc/fstab 2>/dev/null"

echo -e "\n[+] Scheduled cron jobs"
formatCommand "ls -al /etc/cron* 2>/dev/null"

echo -e "\n[+] Writable cron directories"
formatCommand "ls -aRl /etc/cron* 2>/dev/null | awk '$1 ~ /w.$' 2>/dev/null"

echo -ne "\n${SECTION_LINE}\n"
echo -e "[*] ENUMERATING USER AND ENVIRONMENTAL INFO...\n"
echo -e "\n[+] Current User"
formatCommand "whoami"

echo -e "\n[+] Current User ID"
formatCommand "id"

echo -e "\n[+] All users"
formatCommand "cat /etc/passwd"

echo -e "\n[+] Super Users Found"
formatCommand "grep -v -E '^#' /etc/passwd | awk -F: '\$3 == 0{print \$1}'"

echo -e "\n[+] Root and current user history (depends on privs)"
formatCommand "ls -al ~/.*_history; ls -la /root/.*_history 2>/dev/null"

echo -e "\n[+] Environment Variables"
formatCommand "env 2>/dev/null | grep -v 'LS_COLORS'"

echo -e "\n[+] Sudoers (Privileged) [/etc/sudoers]"
formatCommand "cat /etc/sudoers 2>/dev/null | grep -v '#' 2>/dev/null"

echo -e "\n[+] Sudoers Files (Privileged) [/etc/sudoers.d/*]"
formatCommand "cat /etc/sudoers.d/* 2>/dev/null | grep -v '#' 2>/dev/null"

echo -e "\n[+] Logged in User Activity"
formatCommand "w 2>/dev/null"

echo -ne "\n${SECTION_LINE}\n"
echo -e "[*] ENUMERATING FILE AND DIRECTORY PERMISSIONS/CONTENTS...\n"

echo -e "\n[+] World Writable Directories for User/Group 'root'"
formatCommand "find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep root"

echo -e "\n[+] World Writable Directories for User other than 'root'"
formatCommand "find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null"

echo -e "\n[+] World Writable Files"
formatCommand "find / \( -wholename '/home/homedir/*' -prune -o -wholename '/proc/*' -prune \) -o \( -type f -perm -0    002 \) -exec ls -l '{}' ';' 2>/dev/null"

echo -e "\n[+] SUID/GUID Files and Directories"
formatCommand "find / \( -perm -2000 -o -perm -4000 \) -exec ls -ld {} \; 2>/dev/null"

echo -e "\n[+] Checking if root's home folder is accessible"
formatCommand "ls -ahlR /root 2>/dev/null"

echo -e "\n[+] Logs containing keyword 'password'"
formatCommand "find /var/log -name '*.log' 2>/dev/null | xargs -l10 egrep 'pwd|password' 2>/dev/null"

echo -e "\n[+] Config files containing keyword 'password'"
formatCommand "find /etc -name '*.c*' 2>/dev/null | xargs -l10 egrep 'pwd|password' 2>/dev/null"

echo -e "\n[+] Shadow Files (Privileged)"
formatCommand "cat /etc/shadow 2>/dev/null"

echo -ne "\n${SECTION_LINE}\n"
echo -e "[*] ENUMERATING PROCESSES AND APPLICATIONS...\n"

echo -e "[+] Installed Packages"
if [ -x "$(command -v dpkg)" ]; then
	formatCommand "dpkg -l | awk '{\$1=\$4=\"\"; print \$0}'"
elif [ -x "$(command -v dnf)" ]; then
	formatCommand "dnf -qa | sort -u"
elif [ -x "$(command -v rpm)" ]; then
	formatCommand "rpm -qa | sort -u"
fi

echo -e "\n[+] Current Processes"
formatCommand "ps aux | awk '{print \$1,\$2,\$9,\$10,\$11}'"

echo -e "\n[+] Sudo Version"
formatCommand "sudo -V | grep version 2>/dev/null"

echo -e "\n[+] Apache Version and Modules"
formatCommand "apache2 -v 2>/dev/null; apache2ctl -M 2>/dev/null; httpd -v 2>/dev/null; apachectl -l 2>/dev/null"

echo -e "\n[+] Apache Config File"
formatCommand "cat /etc/apache2/apache2.conf 2>/dev/null"

echo -ne "\n${SECTION_LINE}\n"
echo -e "[*] IDENTIFYING PROCESSES AND PACKAGES RUNNING AS ROOT OR OTHER SUPERUSER...\n"

# Need to figure out how I want to do this section

echo -ne "\n${SECTION_LINE}\n"
echo -e "[*] ENUMERATING INSTALLED LANGUAGES/TOOLS FOR SPLOIT BUILDING..."

echo -e "\n[+] Installed Tools"
formatCommand "which awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp 2>/dev/null"

echo -e "\n[+] Related Shell Escape Sequences"
if [ -x "$(command -v vi)" ]; then
	formatCommand "echo -ne \"vi-->\t:!bash\n\""
	formatCommand "echo -ne \"vi-->\t:set shell=/bin/bash:shell\n\""
fi

if [ -x "$(command -v vim)" ]; then
	echo -ne "vim-->\t:!bash\n" | sed 's|^|    |'
	echo -ne "vim-->\t:set shell=/bin/bash:shell\n" | sed 's|^|    |'
fi

if [ -x "$(command -v awk)" ]; then
	echo -ne "awk-->\tawk 'BEGIN {system(\"/bin/bash\")}'\n" | sed 's|^|    |'
fi

if [ -x "$(command -v perl)" ]; then
	echo -ne "perl-->\tperl -e 'exec \"/bin/bash\";'\n" | sed 's|^|    |'
fi

if [ -x "$(command -v python)" ]; then
	echo -ne "python-->\tpython -c '__import__(\"os\").system(\"/bin/bash\")'\n" | sed 's|^|    |'
fi

if [ -x "$(command -v find)" ]; then
	echo -ne "find->\tfind / -exec /usr/bin/awk 'BEGIN {system(\"/bin/bash\")}' \\;\n" | sed 's|^|    |'
fi

if [ -x "$(command -v nmap)" ]; then
	echo -ne "nmap-->\t--interactive\n" | sed 's|^|    |'
fi

echo -ne "\n${SECTION_LINE}\n"
echo -e "[*] FINDING RELEVANT PRIVILEGE ESCALATION EXPLOITS..."

# We're gonna do this section a little different


echo "Finished"
echo "${TITLE_LINE}"
