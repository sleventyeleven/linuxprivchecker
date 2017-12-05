

# Linuxprivchecker.py
## A Linux Privilege Escal:ation Check Script
### Author: Mike Czumak (T_v3rn1x) -- @SecuritySift

This script is intended to be executed locally on a Linux box to enumerate basic system info and
search for common privilege escalation vectors such as world writable files, misconfigurations, clear-text
passwords and applicable exploits.

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
