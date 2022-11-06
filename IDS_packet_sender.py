from optparse import OptionParser
import subprocess
#import scapy.all as scapy
from scapy.all import *
#from scapy import *

data="jokes"
parser=OptionParser()

ids_packet_type=0
def send_keylogging_packets(pkt_count,destination_mac,destination_ip):

    d=0

def send_scans_packets(pkt_count,destination_mac,destination_ip):
    t=0 



def send_exfiltration_packets(pkt_count,destination_mac,destination_ip):
    for i in range(pkt_count):
        ip = IP(dst=destination_ip, )
        print(ip.summary())
    #   ip = IP(src=src_ip, dst=dst_ip, id=ip_id, flags=ip_flags)
        tcp = ip / TCP(sport=8080, dport=21, flags='PA',
                    seq=71, ack=67) / data
    
        send(tcp)

    #    ip=IP()
    #    packet=scapy.
    #    scapy.send(packet,verbose=False)



parser.add_option('-t', dest = 'packet_type',
                      type = 'int',
                      help = '1: Exfiltration, 2: Keylogging, 3: Scans',
                      default=0)    

parser.add_option('-c', dest = 'packet_count',
                      type = 'int',
                      help = 'number of packets to be sent',
                      default=1)      

parser.add_option('-d', dest = 'dest_ip',
                      type = 'string',
                      help = 'destination ip',
                      default='10.0.2.15')

parser.add_option('-m', dest = 'dest_mac',
                      type = 'string',
                      help = 'destination mac address',
                      default='08:00:27:10:b8:d0')
                     



(options, args) = parser.parse_args()


ids_packet_type=options.packet_type
pkt_count=options.packet_count
destination_ip=options.dest_ip
destination_mac=options.dest_mac

print(options)

if ids_packet_type==1:
    send_exfiltration_packets(pkt_count,destination_mac,destination_ip)
elif ids_packet_type==2:
    send_keylogging_packets(pkt_count,destination_mac,destination_ip)
elif ids_packet_type==3:
    send_scans_packets(pkt_count,destination_mac,destination_ip)  
elif ids_packet_type==0:  #default is to send all 3
    send_exfiltration_packets(pkt_count,destination_mac,destination_ip)
    send_keylogging_packets(pkt_count,destination_mac,destination_ip)
    send_scans_packets(pkt_count,destination_mac,destination_ip)
else:
    print("Invalid Option")
    exit()


