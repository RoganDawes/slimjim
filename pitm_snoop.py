#!/usr/bin/env python3

import dpkt
import pcap
import socket
import binascii
import struct
import ipaddress
from pyroute2 import IPRoute
from pyroute2.netlink.rtnl import ndmsg

def format_mac(address):
    return "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB",address)

def format_ip(address):
    return str(ipaddress.IPv4Address(address))

def format_ipv6(address):
    return str(ipaddress.IPv6Address(address))

def get_set(table, key):
    if key in table:
        s = table[key]
    else:
        s = set()
        table[key] = s
    return s

def add_entry(table, key, value):
    s = get_set(table, key)
    if value not in s:
        s.add(value)
        return True
    return False

def analyze_packet(_timestamp, packet):
    """
    Main analysis loop for pcap.
    """
    eth = dpkt.ethernet.Ethernet(packet)
    try:
        if isinstance(eth.data, dpkt.ip.IP):
            parse_ip_packet(eth)
        elif isinstance(eth.data, dpkt.arp.ARP):
            parse_arp_packet(eth)
    except Exception as e:
        print(e)
        pass

def update_arp(mac, ip):
    if mac == 'ff:ff:ff:ff:ff:ff':
        return
    if ip.startswith("239.") or ip.startswith("240.") or ip.startswith("255."):
        return
    if add_entry(arptable, mac, ip):
        print("arp add %s addr %s" % (ip, mac))
        ipr.neigh('replace', dst=ip, lladdr=mac, ifindex=idx, state=ndmsg.states['permanent'])
        ipr.route("replace", dst=ip, mask=32, scope=253, oif=idx)

def parse_arp_packet(eth):
    """
    Parse body of ARP packets
    """
    a = eth.data
    if a.op == dpkt.arp.ARP_OP_REPLY and a.hln == 6 and a.pln == 4:
        ip = format_ip(a.spa)
        mac = format_mac(a.sha)
        update_arp(mac, ip)

        ip = format_ip(a.tpa)
        mac = format_mac(a.tha)
        update_arp(mac, ip)

    pass

def parse_dns(ip):
    """
    Extracts the payload from a UDP packet, then parses it as a DNS response
    """
    udp = ip.data
    try:
        dns = dpkt.dns.DNS(udp.data)
        if dns.opcode != dpkt.dns.DNS_QUERY:
            return
        if dns.qr != dpkt.dns.DNS_R or dns.rcode != dpkt.dns.DNS_RCODE_NOERR:
            return
        qd = dns.qd
        if len(qd) < 1:
            return
        name = qd[0].name
        addresses = set()
        names = set()
        names.add(name)
        for rr in dns.an:
            if rr.cls == 1:
                if rr.type == dpkt.dns.DNS_A:
                    addresses.add(format_ip(rr.ip))
                    names.add(rr.name)
#                elif rr.type == dpkt.dns.DNS_AAAA:
#                    addresses.add(format_ipv6(rr.ip6))
#                    names.add(rr.name)
                elif rr.type == dpkt.dns.DNS_CNAME:
                    names.add(rr.name)
        if len(addresses) > 0:
            content = "\n".join(addr + "\t" + " ".join(names) for addr in addresses)
            print(content)
            try:
                f = open("/tmp/pitm/hostsdir/" + name, "w")
                f.write(content)
                f.close()
            except:
                pass
            nameserver = format_ip(ip.src)
            if nameserver not in nameservers:
                nameservers.add(nameserver)
                print("\n".join("nameserver " + s for s in nameservers))
                try:
                    f = open("/tmp/pitm/resolv.conf", "w")
                    f.write("\n".join("nameserver " + s for s in nameservers))
                    f.write("\n")
                    f.close()
                except Exception as e:
                    print(e)
                    pass

    except Exception as e:
        print(e)

def update_route(mac, ip):
    addr = next(iter(arptable[mac])) if (mac in arptable) else None
    if (addr != None) and (addr != ip) and add_entry(routetable, addr, ip):
        # add a routing table entry for ip via addr
        print("route add %s gw %s" % (ip, addr))
        ipr.route("replace", dst=ip+"/32", gateway=addr, oif=idx)
        pass

def parse_ip_packet(eth):
    """
    Parses IP packet.
    """
    ip = eth.data
    if isinstance(ip.data, dpkt.udp.UDP) or isinstance(ip.data, dpkt.tcp.TCP):
        update_route(format_mac(eth.src), format_ip(ip.src))
        update_route(format_mac(eth.dst), format_ip(ip.dst))
    if isinstance(ip.data, dpkt.udp.UDP) and ip.data.sport == 53:
        parse_dns(ip)

def start_listening(interface, cap_filter):
    """
    Starts the listening process with an optional filter.
    """
    try:
        capture = pcap.pcap(name=interface)
        capture.setfilter(cap_filter)
    except OSError as exception:
        print('[-] Issue: {0}'.format(exception))
        sys.exit(-1)
    while True:
        print('[+] Listening on {0}'.format(capture.name))
        capture.loop(0, analyze_packet)
        print('[-] Capture stopped unexpectedly, restarting...')

def main():
    """
    Main program loop.
    """
    global arptable
    global routetable
    global ipr
    global idx
    global nameservers
    arptable = {}
    routetable = {}
    cap_filter="(tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)) or udp or arp"
    interface="pitm"
    ipr = IPRoute()
    idx = ipr.link_lookup(ifname=interface)[0]
    nameservers = set()
    start_listening(interface, cap_filter)

if __name__ == "__main__":
    main()


