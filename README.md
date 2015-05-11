# sapmdbret
This is a functional exploit proof of concept program to aid in exploiting systems vulnerable to CVE 2008-0244.  

This vulnerability specifically relates to issues in how the SAP MaxDB protocol handles specially crafted packets.  It is possible to execute system level commands remotely.

Please note that some values (such as attacker IP, and the commands being executed) are hard-coded.  This was designed as a proof of concept and thus some conveniences are not afforded to the end user.  Review the code in detail to understand exactly what is transpiring before running it against your victim machine..

Usage: python sapmdbret.py TARGETIP PORT

As with all my projects, use of this code is intended for legitimate, authorized, and research purposes only. 
