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

## Point Breakdown

The following includes work accomplished and expected score

1. Allow command-line switches to specify a host and present a simple response -- 40 points
2. Allow more than one host to be scanned (range and subnet) -- 10 points
3. Allow multiple ports to be specified
4. Use of more than one protocol (ICMP and UDP) -- 15 points
5. User experience results (HTML file) -- 10 points
6. Other ideas or concepts (Stealthmode, Xmas scan) -- 20 points

Total: 105 points

