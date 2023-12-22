#import scapy.all as scapy
#目標 多layer嘗試的scanner can step by step try to 確認對方是否活著

from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.layers.inet import TCP, UDP
from scapy.layers.l2 import Ether,ARP,arping
from scapy.sendrecv import sr1
import ipaddress
import threading
#arpscan
#netsh interface ip delete arpcache
def arp_scan(s_ip):
    #result=scapy.arping(ip) 
    ip_list=[str(ip) for ip in ipaddress.IPv4Network(str(s_ip))]
    for  ip in ip_list:
        print(ip)
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
        arp_request_broadcast = broadcast/arp_request 
        answered_list = sr(arp_request_broadcast,timeout=1, verbose=False)
        #answered_list,unans = scapy.srp(arp_request_broadcast,timeout=0.01, verbose=False)  # timeout very small dangerous!!!
        #print(arp_request_broadcast.show())
        print(answered_list)

    return (answered_list)
#PRO  不會拘限SUBNET  and i dont know why if i use 無線網卡 i must use ping to update arp cache
def ping_scan(ip):
    packet = IP(dst=ip)/ICMP()
    results,unans = sr(packet, timeout=0.1, verbose=0)
    print(results)
    for ele in results:
        print(ele)
        #print(ele[0].show())#request
        #print(ele[1].show())#reply
    for ele in unans:
        print(ele)
        #print(ele[0].show())#request
        #print(ele[1].show())#reply
    if results:
        print(f"Host {ip} is up")
#CON 會拘限於防火牆的設定



def tcp_syn_scan(ip, port):
    packet = IP(dst=ip)/TCP(dport=port, flags="S")#syn建立請求 3-way handshake
    response,Noresponse = sr(packet, timeout=1)
    print(response)
    for ele in response:
        print(ele)
        print(ele[0].show())#request
        print(ele[1].show())#reply   in my test RA RESET ACK 有3-WAY到但PORT沒開
    print(Noresponse)
    for ele in Noresponse:
        print(ele)
        print(ele[0].show())#request
        print(ele[1].show())#reply
    for ele in response:
        print(ele) 
        
def udp_scan(ip, port):
    packet = IP(dst=ip)/UDP(dport=port)
    response,Noresponse = sr(packet, timeout=1)
    response = sr1(packet, timeout=1)
    print(response)
    # for ele in response:
    #     print(ele)
    #     print(ele[0].show())#request
    #     print(ele[1].show())#reply   
    if response:
        print(f"Host {ip} is up")
        print(f"Port {port} is open")
        pass
    else:
        print(f"Host {ip} is down")


# 掃描子網路範圍內的所有IP
# for i in range(1, 255):
#     ip = f"192.168.0.{i}"
#     ping_scan(ip)

#ping_scan('192.168.0.3')

#以上icmp scan

# 掃描子網路範圍內的所有IP
# port = 3000
# for i in range(1, 255):
#     ip = f"192.168.0.{i}"
#     ping_scan(ip,port)

# tcp_syn_scan('192.168.0.101',port)
#以上tcp 3-way


# 掃描子網路範圍內的所有IP  在我這沒用
# for i in range(1, 255):
#     ip = f"192.168.0.{i}"
#     arp_scan(ip)

#arp_scan('192.168.0.159')

#以上ARP scan


#udp_scan('192.168.0.159',80)
#以上udp

threads = []
max_threads = 5

for i in range(1, 255):
    ip = f"192.168.0.{i}"
    while threading.active_count() > max_threads:
        time.sleep(1)
    t = threading.Thread(target=ping_scan, args=(ip,))
    threads.append(t)
    t.start()

for t in threads:
    t.join()
    
#last thing to do 
#if arp失敗
#try icmp if icmp失敗
#try udp else tcp