

# Linuxprivchecker.py
## A Linux Privilege Escalation Check Script
###  Orginal Author: Mike Czumak (T_v3rn1x) -- @SecuritySift
###  Current Maintainer: Michael Contino (@Sleventyeleven)

This script is intended to be executed locally on a Linux box to enumerate basic system info and
search for common privilege escalation vectors such as world writable files, misconfigurations, clear-text
passwords and applicable exploits.

Linuxprivchecker is designed to identify potential areas to investigate further, not provide direct action or exploitation.
This is to help users further learn how these privilege escalations work and keep it in line with the rules,
for self directed exploitation, laid out for the OSCP, HTB, and other CTFs/exams.

We will try our best to addtional information and reference where possible. As the current Maintainer,
I also plan to accompany new feature adds, with a post on my blog (hackersvanguard.com) to further explain
each potential area for privilege escalation and what criteria may be required.

## Command Options and arguments

If the system your testing has Python 2.6 or high and/or argparser installed, you can utilize the following options.
If importing argparser does not work, all checks will be run and no log file will be written.
However, you can still use terminal redirection to create a log, such as 'python linuxprivchecker.py > linuxprivchecker.log.'

=======================================================================================

    __    _                  ____       _       ________              __
   / /   (_)___  __  ___  __/ __ \_____(_)   __/ ____/ /_  ___  _____/ /_____  _____
  / /   / / __ \/ / / / |/_/ /_/ / ___/ / | / / /   / __ \/ _ \/ ___/ //_/ _ \/ ___/
 / /___/ / / / / /_/ />  </ ____/ /  / /| |/ / /___/ / / /  __/ /__/ ,< /  __/ /
/_____/_/_/ /_/\__,_/_/|_/_/   /_/  /_/ |___/\____/_/ /_/\___/\___/_/|_|\___/_/


=======================================================================================
usage: linuxprivchecker.py [-h] [-s] [-w] [-o OUTFILE]

Try to gather system information and find likely exploits

optional arguments:
  -h, --help            show this help message and exit
  -s, --searches        Skip time consumming or resource intensive searches
  -w, --write           Wether to write a log file, can be used with -0 to
                        specify name/location
  -o OUTFILE, --outfile OUTFILE
                        The file to write results (needs to be writable for
                        current user)



**Warning**

This script comes as-is with no promise of functionality or accuracy.  I have no plans to maintain updates,
I did not write it to be efficient and in some cases you may find the functions may not produce the desired
results.  For example, the function that links packages to running processes is based on keywords and will
not always be accurate.  Also, the exploit list included in this function will need to be updated over time.
Feel free to change or improve it any way you see fit.

## Modification, Distribution, and Attribution

You are free to modify and/or distribute this script as you wish.  I only ask that you maintain original
author attribution and not attempt to sell it or incorporate it into any commercial offering (as if it's
worth anything anyway :)
