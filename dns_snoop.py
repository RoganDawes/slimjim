#!/usr/bin/env python3

import dpkt
import pcap
import socket
from dnslib import DNSRecord, QTYPE, RCODE
import binascii

def list_interfaces():
    """
    Prints out all available interfaces with IP adresses, when possible.
    """
    i = 0
    for name in pcap.findalldevs():
        prettydevicename = ''
        queryname = name
        if name.startswith(r'\Device\NPF_'):
            queryname = name[12:]
        if name.endswith('}'):
            prettydevicename = 'eth{0} '.format(i)
            i += 1
        try:
            import netifaces
            print('{1}{0} {2}'.format(name, prettydevicename,
                                      netifaces.ifaddresses(queryname)
                                      [netifaces.AF_INET][0]['addr']))
        except ImportError:
            print('{0}{1}'.format(prettydevicename, name))


def analyze_packet(_timestamp, packet):
    """
    Main analysis loop for pcap.
    """
    eth = dpkt.ethernet.Ethernet(packet)
    if isinstance(eth.data, dpkt.ip.IP):
        try:
            parse_ip_packet(eth.data)
        except:
            pass

def parse_ip_packet(ip):
    """
    Parses IP packet.
    """
    if isinstance(ip.data, dpkt.udp.UDP) and len(ip.data.data):
        parse_udp_dns_packet(ip)

def parse_udp_dns_packet(ip):
    """
    Parses UDP DNS packet.
    """
    d = DNSRecord.parse(ip.data.data)
    q = str(d.q.qname).strip(".")
    if QTYPE[d.q.qtype] == 'A' and d.header.rcode == RCODE.NOERROR and d.header.a > 0:
        fn = q
        content = ''
        for a in d.rr:
            if QTYPE[a.rtype] == "CNAME":
                q = q + " " + str(a.rdata).strip(".")
            elif QTYPE[a.rtype] == 'A':
                content = content + str(a.rdata) + " " + q + "\n"
        if content != '':
            try:
                f = open("/tmp/pitm/hostsdir/" + fn, "w")
                f.write(content)
                f.close()
            except:
                pass
            print("%s" % (fn))
    else:
        print("Skipped QTYPE %s q=%s RCODE %s Answer = %d" % (QTYPE[d.q.qtype], q, RCODE[d.header.rcode], d.header.a))
    # print(d)

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
    cap_filter="port 53"
    interface="pitm"
    start_listening(interface, cap_filter)

if __name__ == "__main__":
    main()


