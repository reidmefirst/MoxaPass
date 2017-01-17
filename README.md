This is a sample exploit for CVE-2016-9361. It retrieves the SNMP community string and 'admin' password for many kinds of Moxa device.

It uses Moxa's UDP/4800 proprietary management protocol. The protocol lacks security, and using the 'unlock' function code does not require a password.

This exploit is known to affect all Moxa NPort 5xxx series, MGate MB3170 (and likely other MGate devices), and some OnCell devices.

The issue was first reported to Moxa in July 2015, and remains unfixed as of January 2017.

This script is for educational and noncommercial purposes only. Do not use it on systems which you are not authorized to test.
