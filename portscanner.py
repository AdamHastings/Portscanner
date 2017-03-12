#!/usr/bin/python
# Use this for reference
# https://github.com/interference-security/Multiport/blob/master/multiport.py
import logging
import sys
import socket
logging.getLogger("scapy").setLevel(1)
from scapy.all import *

def printHelpScreen():
	print "ERROR. See usage options with \"-help\" flag"


# Perform a standard TCP port scan on a specified IP Address
# and port. Returns the status of the port.
def checkPort_TCP(dst_ip, dst_port):
	tcp_scan = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=1, verbose=0)
	if(str(type(tcp_scan))=="<type 'NoneType'>"):
		return "Closed"
	elif(tcp_scan.haslayer(TCP)):
		if(tcp_scan.getlayer(TCP).flags == 0x12):
			send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=1, verbose=0)
			return "Open"
		elif(tcp_scan.getlayer(TCP).flags == 0x14):
			return "Closed"
	else:
		return "Something went wrong..."

# Perform a stealthy TCP port scan of a specified IP Address
# and port. Instead of sending the RST+ACK flags after the server send
# the SYN+ACK, it only sends back the RST flag. This is to avoid detection
# from firewalls. Returns the status of the port.
def checkPort_stealthmode(dst_ip, dst_port):
	src_port = RandShort()
	stealth_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=10, verbose=0)
	if(str(type(stealth_scan_resp))=="<type 'NoneType'>"):
		return "Filtered"
	elif(stealth_scan_resp.haslayer(TCP)):
		if(stealth_scan_resp.getlayer(TCP).flags == 0x12):
			send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="R"),timeout=10, verbose=0)
			return "Open"
		elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
			return "Closed"
	elif(stealth_scan_resp.haslayer(ICMP)):
		if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
			return "Filtered"
	else:
		return "Something went wrong..."

# Perform a standard UDP port scan on a specified IP Address
# and port. Returns the status of the port.
def checkPort_UDP(dst_ip,dst_port):
    udp_scan_resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=10, verbose=0)
    if (str(type(udp_scan_resp))=="<type 'NoneType'>"):
        retrans = []
        for count in range(0,3):
            retrans.append(sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=10, verbose=0))
        for item in retrans:
            if (str(type(item))!="<type 'NoneType'>"):
                checkPort_UDP(dst_ip,dst_port,dst_timeout)
        return "Open|Filtered"
    elif (udp_scan_resp.haslayer(UDP)):
        return "Open"
    elif(udp_scan_resp.haslayer(ICMP)):
        if(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code)==3):
            return "Closed"
        elif(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code) in [1,2,9,10,13]):
            return "Filtered"
    else:
        return "Something went wrong..."

# Perform a standard Xmas port scan on a specified IP Address
# and port. Returns the status of the port.
def checkPort_XMAS(dst_ip,dst_port):
    xmas_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="FPU"),timeout=10, verbose=0)
    if (str(type(xmas_scan_resp))=="<type 'NoneType'>"):
        return "Open|Filtered"
    elif(xmas_scan_resp.haslayer(TCP)):
        if(xmas_scan_resp.getlayer(TCP).flags == 0x14):
            return "Closed"
    elif(xmas_scan_resp.haslayer(ICMP)):
        if(int(xmas_scan_resp.getlayer(ICMP).type)==3 and int(xmas_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            return "Filtered"
    else:
        return "Something went wrong..."

# Parse the user input. Parse input IP addresses and ports.
# Place the data into lists and return the lists of IPs and ports
def checkArgs():
	if (len(sys.argv)) < 4:
		printHelpScreen();
		sys.exit(0)
	if (str(sys.argv[2]) != "-p"):
		print "ERROR. See usage options with \"-help\" flag"
		sys.exit(0)
	ip_addrs = []
	ip_args = str(sys.argv[1])
	try:
		address, network = ip_args.split('/')
		a,b,c,d = address.split('.')
		if (network == "24"):
			print "network"
			a,b,c,d = ip_args.split('.')
			for i in range(1,256):
				ip_str = str(a) + "." + str(b) + "." + str(c) + "." + str(i)
				ip_addrs.append(ip_str)
		else:
			print "Sorry, that CIDR code is not supported"
			sys.exit(0)
	except ValueError:
			try:
				a,b,c,d = ip_args.split('.')
				low, high = d.split('-')
				for i in range (int(low), int(high)+1):
					ip_str = str(a) + "." + str(b) + "." + str(c) + "." + str(i)
					ip_addrs.append(ip_str)
			except ValueError:
				try:
					a,b,c,d = ip_args.split('.')
					ip_addrs.append(ip_args)
				except:
					print "IP addresses in incorrect format"
					sys.exit(0)
	ports = []
	portArg = str(sys.argv[3])
	portArg = portArg.split(",")
	for arg in portArg:
		ports.append(arg)
	return ip_addrs, ports

# Check for user-specified scan flags:
# Check for xmas scan (-sX)
# Check for UDP scan (-sU)
# Check for Stealth scan (-sS)
# Default is a TCP scan (if no flag specified)
def checkMoreArgs():

	if (len(sys.argv) == 4):
		return "-tcp"
	if (len(sys.argv) == 5):
		return str(sys.argv[4])
	elif (len(sys.argv) > 5):
		print "ERROR. See usage options with \"-help\" flag"
		sys.exit(0)
	else:
		return "-tcp"

# Open or create an HTML to be written to. By default, the file is 
# "Portscanner_Report.html". This can be changed by the user, if desired
def openHTML():
	Html_file= open("Portscanner_Report.html","w")
	Html_file.write("""<!doctype html>

	<html lang="en">
	<head>
	  <meta charset="utf-8">

	  <title>The HTML5 Herald</title>
	  <meta name="description" content="The HTML5 Herald">
	  <meta name="author" content="SitePoint">

	  <link rel="stylesheet" href="css/styles.css?v=1.0">

	  <!--[if lt IE 9]>
	    <script src="https://cdnjs.cloudflare.com/ajax/libs/html5shiv/3.7.3/html5shiv.js"></script>
	  <![endif]-->
	</head>

	<body>
		<h1>Portscanner Report</h1>
	""")
	return Html_file

# Close the HTML opened previously
def closeHTML():
	Html_file.write("""
	</body>
	</html>""")
	Html_file.close

# Run the scan specified by the user on the ports and IPs 
# specified by the user
def runScans():
	for ip in addresses:
		Html_file.write("<h4>")
		Html_file.write(str(ip))
		Html_file.write("</h4>")
		Html_file.write("<p>")
		for port in ports:
			if (scanType == "-tcp"):
				try:
					socket.inet_aton(str(ip))
					msg = checkPort_TCP(str(ip), int(port))
					Html_file.write("Port " + port + ":		" + msg + " (tcp)" + "<br>") 
				except:
					print ip
					print "ERROR: not a valid IP or IP range"
					sys.exit(0)
			elif (scanType == "-sX"):
				try:
					socket.inet_aton(str(ip))
					msg = checkPort_XMAS(str(ip), int(port))
					Html_file.write("Port " + port + ":		" + msg + " (xmas)" + "<br>") 
				except:
					print ip
					print "ERROR: not a valid IP or IP range"
					sys.exit(0)
			elif (scanType == "-sU"):
				try:
					socket.inet_aton(str(ip))
					msg = checkPort_UDP(str(ip), int(port))
					Html_file.write("Port " + port + ":		" + msg + " (udp)" + "<br>") 
				except:
					print ip
					print "ERROR: not a valid IP or IP range"
					sys.exit(0)
			elif (scanType == "-sS"):
				try:
					socket.inet_aton(str(ip))
					msg = checkPort_stealthmode(str(ip), int(port))
					Html_file.write("Port " + port + ":		" + msg + " (stealth)" + "<br>") 
				except:
					print ip
					print "ERROR: not a valid IP or IP range"
					sys.exit(0)
			else:
				print "ERROR: Incorrect usage of flags"
				sys.exit(0)
		Html_file.write("</p>")


# Main code execution
Html_file = openHTML()
src_port = 30000
addresses, ports = checkArgs()
scanType = checkMoreArgs()
runScans()
closeHTML()
# Done!
