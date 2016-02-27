import struct
import socket
import binascii
import os

TCP = 6
UDP = 17

def read_udp_header(data):
    udp_header = struct.unpack("!4H", data[:8])
    source_port = udp_header[0]
    destination_port = udp_header[1]
    length = udp_header[2]
    checksum = udp_header[3]
    data = data[8:]
    print "===============UDP HEADER================="
    print "\tSource: %hu"       % source_port
    print "\tDestination: %hu"  % destination_port
    print "\tLength: %hu"       % length
    print "\tChecksum: %hu"     % checksum

    return data

def read_tcp_header(data):
    tcp_header = struct.unpack("!2H2I4H ", data[:20])
    source_port = tcp_header[0]
    destination_port = tcp_header[1]
    sequence_number = tcp_header[2]
    acknowledgment_number = tcp_header[3]
    data_offset = tcp_header[4] >> 12
    reserved = (tcp_header[4] >> 6) & 0x03ff
    flags = tcp_header[4] & 0x003f
    urg = flags & 0x0020
    ack = flags & 0x0010
    psh = flags & 0x0008
    rst = flags & 0x0004
    syn = flags & 0x0002
    fin = flags & 0x0001
    window = tcp_header[5]
    checksum = tcp_header[6]
    urg_pointer = tcp_header[7]
    data = data[20:]

    print "===============TCP HEADER================="
    print "\tSource: %hu"       % source_port
    print "\tDestination: %hu"  % destination_port
    print "\tSeq: %hu"          % sequence_number
    print "\tAck: %hu"          % acknowledgment_number
    print "\tFlags:"
    print "\t\tURG: %d"         % urg
    print "\t\tACK: %d"         % ack
    print "\t\tPSH: %d"         % psh
    print "\t\tRST: %d"         % rst
    print "\t\tSYN: %d"         % syn
    print "\t\tFIN: %d"         % fin
    print "\tWindow: %hu"       % window
    print "\tChecksum: %hu"     % checksum

    return data


def read_ip_header(data):
    ip_header = struct.unpack("!6H4s4s", data[:20])
    version = ip_header[0] >> 12
    ihl = (ip_header[0] >> 8) & 0x0f
    type_of_service = ip_header[0] & 0x00ff
    total_length = ip_header[1]
    identification  = ip_header[2]
    flags = ip_header[3] >> 13
    flag_offset = ip_header[3] & 0x1fff
    time_to_live = ip_header[4] >> 8
    protocol = ip_header[4]  & 0x00ff
    header_checksum = ip_header[5]
    source_address = socket.inet_ntoa(ip_header[6])
    destination_address = socket.inet_ntoa(ip_header[7])

    no_frag = flags >> 1
    more_frag = flags & 0x1

    print "===============IP  HEADER================="
    print "\tVersion: %hu"            % version
    print "\tIHL: %hu"                % ihl
    print "\tType of service: %hu"    % type_of_service
    print "\tLength: %hu"             % total_length
    print "\tID: %hu"                 % identification
    print "\tNo Frag: %hu"            % no_frag
    print "\tMore Frag: %hu"          % more_frag
    print "\tOffset: %hu"             % flag_offset
    print "\tTime to live: %hu"       % time_to_live
    print "\tNext protocol: %hu"      % protocol
    print "\tChecksum: %hu"           % header_checksum
    print "\tSource address: %s"      % source_address
    print "\tDestination address: %s" % destination_address

    data = data[20:]
    return data, protocol

def read_ether_header(data):
    eth_header = struct.unpack("!6s6sH", data[:14])
    destination_mac = binascii.hexlify(eth_header[0])
    source_mac = binascii.hexlify(eth_header[1])
    protocol = eth_header[2] >> 8

    print "===============ETH HEADER================="
    print "\tDestination MAC: %s:%s:%s:%s:%s:%s" % (
        destination_mac[0:2], destination_mac[2:4], 
        destination_mac[4:6], destination_mac[6:8], 
        destination_mac[8:10], destination_mac[10:12]) 

    print "\tSource MAC: %s:%s:%s:%s:%s:%s" % (
        source_mac[0:2], source_mac[2:4], 
        source_mac[4:6], source_mac[6:8], 
        source_mac[8:10], source_mac[10:12]) 

    print "\tProtocol: %s" % hex(protocol)

    data = data[14:]
    return data, is_ip_packet(protocol)

def is_ip_packet(protocol):
    return protocol == 0x08

def main():
    sniffer_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    recv_data = sniffer_socket.recv(2048)
    os.system("clear")
    data, is_ip = read_ether_header(recv_data)
    if not is_ip:
        return
    data, next_proto = read_ip_header(data)

    if next_proto == TCP:
        data = read_tcp_header(data)
    elif next_proto == UDP:
        data = read_udp_header(data)
    else:
        return

while True:
    main()
