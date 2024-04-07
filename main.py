import argparse
from scapy.all import *
import nmap

def arp_scan(ip):
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    ans, unans = srp(request, timeout=2, retry=1)
    result = []
    for element in ans:
        device_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        result.append(device_dict)
    return result

def icmp_echo_ping(ip):
    print("ICMP Echo Ping Scan:")
    scanner = nmap.PortScanner()
    scanner.scan(hosts=ip, arguments='-PE')
    hosts = scanner.all_hosts()
    if hosts:
        return hosts
    else:
        return None

def icmp_echo_ping_sweep(ip):
    print("ICMP Echo Ping Sweep Scan:")
    scanner = nmap.PortScanner()
    scanner.scan(hosts=ip, arguments='-PS')
    hosts = scanner.all_hosts()
    if hosts:
        return hosts
    else:
        return None

def icmp_timestamp_ping(ip):
    print("ICMP Timestamp Ping Scan:")
    scanner = nmap.PortScanner()
    scanner.scan(hosts=ip, arguments='-PP')
    hosts = scanner.all_hosts()
    if hosts:
        return hosts
    else:
        return None

def icmp_address_mask_ping(ip):
    print("ICMP Address Mask Ping Scan:")
    scanner = nmap.PortScanner()
    scanner.scan(hosts=ip, arguments='-PM')
    hosts = scanner.all_hosts()
    if hosts:
        return hosts
    else:
        return None


def udp_port_scan(ip,ports):
    print("UDP Port Scan:")
    for port in ports:
        resp = sr1(IP(dst=ip)/UDP(sport=RandShort(),dport=port), timeout=2, verbose=False)
        if resp != None:
            if resp.haslayer(UDP):
                print('Port {} is Open.'.format(port))
            elif int(resp[ICMP].type)==3 and int(resp[ICMP].code)==3:
                print('Port {} is Closed'.format(port))
        else:
            print('Port {} is Filtered'.format(port))
    


def tcp_scan(ip, ports):
    print("SYN SCAN")
    try:
        syn = IP(dst=ip) / TCP(dport=ports, flags="S")
    except socket.gaierror:
        raise ValueError('Hostname {} could not be resolved.'.format(ip))

    ans, unans = sr(syn, timeout=2, retry=1)
    result = []

    for sent, received in ans:
        if received[TCP].flags == "SA":
            result.append(received[TCP].sport)

    return result

def tcp_scan_xmas(ip, ports):
    print('Xmas Scan')
    try:
        syn = IP(dst=ip) / TCP(sport=RandShort(),dport=ports, flags="FPU")
    except socket.gaierror:
        raise ValueError('Hostname {} could not be resolved.'.format(ip))

    ans= sr1(syn, timeout=2, retry=1)

    if ans !=None:
        if ans.haslayer(TCP):
            if ans[TCP].flags==4:
                print("Closed")
            else:
                print("Filtered")
    else:
        print("Open|Filtered",'Port {}.'.format(ports))
    
def tcp_scan_fin(ip, ports):
    print('FIN Scan')
    try:
        syn = IP(dst=ip) / TCP(sport=RandShort(),dport=ports, flags="F")
    except socket.gaierror:
        raise ValueError('Hostname {} could not be resolved.'.format(ip))

    ans= sr1(syn, timeout=2, retry=1)

    if ans !=None:
        if ans.haslayer(TCP):
            if ans[TCP].flags==4:
                print("Closed")
            elif int(ans[ICMP].type)==3 and int(scan[ICMP].code) in [1,2,3,9,10,13]:
                print("Filtered")
    else:
        print("Open|Filtered",'Port {}.'.format(ports))
    

def tcp_scan_null(ip, ports):
    print('NULL Scan')
    try:
        syn = IP(dst=ip) / TCP(sport=RandShort(),dport=ports, flags="")
    except socket.gaierror:
        raise ValueError('Hostname {} could not be resolved.'.format(ip))

    ans= sr1(syn, timeout=2, retry=1)
    if ans !=None:
        if ans.haslayer(TCP):
            if ans[TCP].flags==20:
                print("Closed")
            elif int(ans[ICMP].type)==3 and int(scan[ICMP].code) in [1,2,3,9,10,13]:
                print("Filtered")
    else:
        print("Open|Filtered",'Port {} is open.'.format(ports))
    
def tcp_scan_ack(ip, ports):
    print('ACK Scan')
    try:
        syn = IP(dst=ip) / TCP(sport=RandShort(),dport=ports, flags="A")
    except socket.gaierror:
        raise ValueError('Hostname {} could not be resolved.'.format(ip))

    ans= sr1(syn, timeout=2, retry=1)

    if ans !=None:
        if ans.haslayer(TCP):
            if ans[TCP].flags==20:
                print("Closed")
            elif int(ans[ICMP].type)==3 and int(scan[ICMP].code) in [1,2,3,9,10,13]:
                print("Filtered")
    else:
        print("Open|Filtered",'Port {} is open.'.format(ports))
    

def IP_SCAN(ip):
    print("IP Protocol Ping Scan:")
    protocols = { 0: "IP" ,1: "ICMP", 6: "TCP"}  
    for proto, name in protocols.items():
        resp = sr1(IP(dst=ip)/IP(proto=proto), timeout=2, verbose=False)
        if resp:
            print("Protocol", name, "is supported")
        else:
            print("Protocol", name, "is not supported")


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(
        dest="command", help="Command to perform.", required=True
    )

    arp_subparser = subparsers.add_parser(
        'ARP', help='Perform a network scan using ARP requests.'
    )
    arp_subparser.add_argument(
        'IP', help='An IP address (e.g. 192.168.1.1) or address range (e.g. 192.168.1.1/24) to scan.'
    )

    tcp_subparser = subparsers.add_parser(
        'TCP', help='Perform a TCP scan using SYN packets.'
    )
    tcp_subparser.add_argument('IP', help='An IP address or hostname to ip.')
    tcp_subparser.add_argument(
        'ports', nargs='+', type=int,
        help='Ports to scan, delimited by spaces. When --range is specified, scan a range of ports. Otherwise, scan individual ports.'
    )
    tcp_subparser.add_argument(
        '--range', action='store_true',
        help='Specify a range of ports. When this option is specified, <ports> should be given as <low_port> <high_port>.'
    )
    udp_subparser = subparsers.add_parser(
        'UDP', help='Perform a UDP scan.'
    )
    udp_subparser.add_argument(
        'IP', help='An IP address or hostname to ip.'
    )
    udp_subparser.add_argument(
        'ports', nargs='+', type=int,
        help='Ports to scan, delimited by spaces. When --range is specified, scan a range of ports. Otherwise, scan individual ports.'
    )
    udp_subparser.add_argument(
        '--range', action='store_true',
        help='Specify a range of ports. When this option is specified, <ports> should be given as <low_port> <high_port>.'
    )
    icmp_subparser = subparsers.add_parser(
        'ICMP', help='Perform a ICMP scan.'
    )
    icmp_subparser.add_argument(
        'IP', help='An IP address or hostname to ip.'
    )
    ip_subparser = subparsers.add_parser(
        'IP', help='Perform a IP scan.'
    )
    ip_subparser.add_argument(
        'IP', help='An IP address or hostname to ip.'
    )
    args = parser.parse_args()

    if args.command == 'ARP':
        result = arp_scan(args.IP)
        print("IP Address\t\tMAC Address")
        print("-----------------------------------------")
        for device in result:
            print(device["ip"] + "\t\t" + device["mac"])
    elif args.command == 'TCP':
        if args.range:
            ports = tuple(args.ports)
        else:
            ports = args.ports
        
        try:
            result = tcp_scan(args.IP, ports)
            for port in result:
                print('Port {} is open.'.format(port))
            tcp_scan_xmas(args.IP, ports)
            tcp_scan_fin(args.IP, ports)
            tcp_scan_null(args.IP, ports)
            tcp_scan_ack(args.IP, ports)
        except ValueError as error:
            print(error)
            exit(1)
        

    elif args.command=='UDP':
        if args.range:
            ports=tuple(args.ports)
        else:
            ports=args.ports


        try:
            udp_port_scan(args.IP,ports)
        except ValueError as error:
            print(error)
            exit(1)
    elif args.command=='ICMP':
        try:
            result=icmp_echo_ping(args.IP)
            if result:
                for r in result:
                    print(r)
            else:
                print("No hosts found.")
            result=icmp_echo_ping_sweep(args.IP)
            if result:
                for r in result:
                    print(r)
            else:
                print("No hosts found.")
            result=icmp_timestamp_ping(args.IP)
            if result:
                for r in result:
                    print(r)
            else:
                print("No hosts found.")
            result=icmp_address_mask_ping(args.IP)
            if result:
                for r in result:
                    print(r)
            else:
                print("No hosts found.")
        except ValueError as error:
            print(error)
            exit(1)
    elif args.command=='IP':
        IP_SCAN(args.IP)


        


if __name__ == '__main__':
    main()