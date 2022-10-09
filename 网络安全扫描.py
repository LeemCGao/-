#-*-coding:utf-8-*-
'''
File Name:扫描.py

Create File Time:2022/9/2 16:26

Author:Leemc-GAO

'''
import socket
from random import randint
from scapy.all import *
import whois
import time
def main():
    print("请输入目标ip")
    ip=input()
    print('''请输入使用功能:
    1、使用tcp扫描判断主机是否存活
    2、使用udp扫描判断主机是否存活
    3、使用tcp全开放扫描特定端口
    4、使用tcp半开放扫描特定端口''')
    number=input()
    dport=randint(1,65535)
    # 判断主机是否存活tcp扫描
    if(number=='1'):
        packet=IP(dst=ip)/TCP(flags="A",dport=dport)
        response=sr1(packet,timeout=1.0,verbose=0)
        if response:
            if int(response[TCP].flags)==4:
                time.sleep(0.5)
                print(ip+" is up")
            else:
                print(ip+" is down2")
        else:
            print(ip+" is down1")
    elif(number=='2'):
        ans,uans=sr(IP(dst=ip)/UDP(dport=80))
        for snd,rcv in ans:
            print(rcv.sprintf("%IP.src% is up"))
    elif(number=='3'):
        #tcp全开放扫描,有可能被主机日志记录下来
        print("请输入目标port")
        port=int(input())
        packet2=IP(dst=ip)/TCP(sport=12345,dport=port,flags="S")
        resp=sr1(packet2,timeout=20)
        if(str(type(resp))=="<type 'NoneType'>"):
            print("port %s is closed"%(port))
        elif(resp.haslayer(TCP)):
            if(resp.getlayer(TCP).flags==0x12):
                #标志位改为R就是半开放扫描，主机不会记录
                send_rst=sr(IP(dst=ip)/TCP(sport=12345,dport=port,flags="AR"),timeout=20)
                print("port %s is open"%(port))
            elif(resp.getlayer(TCP).flags==0x14):
                print("port %s is down"%(port))
    elif(number=='4'):
        print("请输入目标port")
        port = int(input())
        packet2 = IP(dst=ip) / TCP(sport=12345, dport=port, flags="S")
        resp = sr1(packet2, timeout=20)
        if (str(type(resp)) == "<type 'NoneType'>"):
            print("port %s is closed" % (port))
        elif (resp.haslayer(TCP)):
            if (resp.getlayer(TCP).flags == 0x12):
                # 标志位改为R就是半开放扫描，主机不会记录
                send_rst = sr(IP(dst=ip) / TCP(sport=12345, dport=port, flags="AR"), timeout=20)
                print("port %s is open" % (port))
            elif (resp.getlayer(TCP).flags == 0x14):
                print("port %s is down" % (port))
    else:
        print("输入数据错误")
        exit(1)
    pass

if __name__=="__main__":
    main()
