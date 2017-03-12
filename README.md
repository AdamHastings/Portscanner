# Portscanner
A general-usage portscanner. Can perform various scans on mulitple hosts and ports

How to use:

	python portscanner.py \<target IPs\> -p \<ports\> \<special flags\>?  

Results are printed to Portscanner_Report.html

## Target IPs

Give an IP address, a range of IP addresses, or a subnet to be portscanned.

Examples:  
		192.168.207.101  
		192.168.207.117-119  
		192.168.207.0/24  

## Ports

Use the "-p", and then specify which ports are to be scanned. Separate ports by commas.

Examples:
		-p 80  
		-p 20,21,22  

## Special Flags

Use additional flags to specify special types of scans. Default (no flag) is TCP scan.

		-sU:	UDP scan
		-sX:	Xmas scan
		-sS:	Stealthmode scan

## Example Usage

		192.168.207.41 -p 41  
		192.168.207.0/24 -p 80,22  
		192.168.207.122-127 -p 22,23,80,443 -sS  

