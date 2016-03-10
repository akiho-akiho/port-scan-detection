import dpkt
# from dpkt import pcap

from struct import pack,unpack
from ip import print16
from ip import str_to_addr
from ip import addr_to_strn
from ip import addr_to_strh
import sys


SIZE_OF_HEADER = 24
SIZE_OF_RECORD = 48

pcap_file_header = ['majic','version_major','version_minor','zone','max_len','time_stamp','link_type']

pcap_header = ['gmt_time','micro_time','pcap_len','len']

# ip_header = ['version', 'header_length','tos','tot_len','id','frag_off','ttl', 'protocol', 'protocol','saddr','daddr']
ip_header = ['version_header_length', 'dsf','total_len', 'id', 'flags', 'frag_off', 'ttl',  'protocol', 'checksum','src_ip', 'dst_ip']

netflow_data = ['version', 'count', 'sys_up_time', 'current_secs', 'current_nsecs', 'flow_sequence', ]

pdu_data = ['scr_addr', 'dst_addr', 'next_hop', 'input_int', 'output_int', 'packets', 'octets', 'start_time', 'end_time','src_port', 'dst_port', 'padding','tcp_flags', 'protocol']

        
    

def print_mac_head(skb):
    pass

def print_ip_head(skb):
    # head = unpack('!BBHHHBBHII',skb[0:20])
    head = unpack('!BBHHBBBBHII',skb[0:20])
    # print "%x,%x,%x,%x,%x,%x,%x,%x,%x,%x" % (head)
    skb_head = dict(zip(ip_header,head))
    for key in skb_head.keys():
        if(key == 'src_ip' or key == 'dst_ip'):
            pass
            # print key,addr_to_strh(skb_head[key])
            # print addr_to_strh(skb_head[key])
        else:
            pass
            # print key,skb_head[key]
            # print skb_head[key]

def print_netflow_head(skb):
    count = 0
    try:
        netflow = unpack('!HHIIII',skb[0:20])
        (version, count) = unpack('!HH',skb[8:12])
        # print "%x, %x, %x, %x, %x, %x" % (netflow)
        skb_netflow_data = dict(zip(netflow_data, netflow))
        for key in skb_netflow_data.keys():
            if (key == 'count'):
                count = skb_netflow_data[key]
                print '1:' + str(count),
        	# print key,skb_netflow_data[key]
            # print skb_netflow_data[key]
    except Exception, e:
        raise



    octets = 0
    packets = 0
    for i in range(0, count):
        index = 24
        lenth = 48
        start = index + i*lenth
        # print_netflow_pdu(skb[start:])
        (ret_oct, ret_pkt, duration, tcp) = print_netflow_pdu(skb[start:])
        octets += ret_oct
        packets += ret_pkt
    oct_per_cnt = octets / count
    oct_per_pkt = octets / packets
    oct_per_sec = octets / float(duration)
    pkt_per_sec = packets / float(duration)
    tcp_per_flow = tcp / float(count)
    print '2:'+ str(octets), '3:' + str(oct_per_cnt), '4:' + str(packets), '5:' + str(oct_per_pkt), '6:' + str(duration), '7:' + str(oct_per_sec*1000), '8:' + str(pkt_per_sec*1000), '9:' + str(tcp_per_flow)



# def print_netflow_pdu(skb):
#     index = 0
#     try:
#         pdu = unpack('!IIIHHIIIIHHBBB', skb[index:index+39])
#         index += 48
#          # print "%x, %x, %x, %x, %x, %x, %x, %x, %x, %x, %x, %x, %x, %x," % (pdu)
#         skb_pdu_data = dict(zip(pdu_data, pdu))
#         for key in skb_pdu_data.keys():
#             # print key,skb_pdu_data[key]
#             if(key == 'dst_addr' or key == 'scr_addr' or key == 'next_hop'):
#                 print key, addr_to_strh(skb_pdu_data[key])
#             else:
#                 print key, skb_pdu_data[key]
#     except Exception, e:
#         # print e
#         pass


def print_netflow_pdu(skb):
    index = 0
    octets = 0
    packets = 0
    end_time = 0
    start_time = 0
    duration = 0
    tcp = 0
    try:
        pdu = unpack('!IIIHHIIIIHHBBB', skb[index:index+39])
        index += 48
         # print "%x, %x, %x, %x, %x, %x, %x, %x, %x, %x, %x, %x, %x, %x," % (pdu)
        skb_pdu_data = dict(zip(pdu_data, pdu))
        i = 0
        
        for key in skb_pdu_data.keys():
            # print key,skb_pdu_data[key]
            if(key == 'dst_addr' or key == 'scr_addr' or key == 'next_hop'):
                # print key, addr_to_strh(skb_pdu_data[key])
                pass
            elif(key == 'octets'):
                octets = skb_pdu_data[key]
                # print key, skb_pdu_data[key]
            elif(key == 'packets'):
                packets = skb_pdu_data[key]
            elif(i == 0 and key == 'start_time'):
                start_time = skb_pdu_data[key]
                i = i + 1
            elif(key == 'end_time'):
                end_time = skb_pdu_data[key]
            elif(key == 'protocol'):
                if(skb_pdu_data[key] == 6):
                    tcp = tcp + 1
            else:
                pass
    except Exception, e:
        print e
    if (packets == 0):
        packets = 1

    duration = end_time - start_time
    if (duration == 0):
        duration = 1
    return octets, packets, duration, tcp



def main():

    if(len(sys.argv) != 3):
        print 'Usage: ./pcap.py file.pcap +1/-1'
    else:
    	filename = sys.argv[1]
        f = open(filename)
        pcap = dpkt.pcap.Reader(f)
        label = sys.argv[2]


    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        netflow = tcp.data
        # print "=============="
        # print len(tcp)
        print label, 
        ip = str(ip)
        tcp = str(tcp)
        netflow = str(netflow)
        # print_mac_head(skb[:14])
        print_ip_head(ip[0:])
        print_netflow_head(netflow[0:])

    f.close()


if __name__ == '__main__':
    main()
