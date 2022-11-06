from optparse import OptionParser
import subprocess
#import scapy.all as scapy
from scapy.all import *
#import IP

parser=OptionParser()

ids_packet_type=0
def send_keyloggin_packets():

    d=0

def send_scans_packets():
    t=0 



def send_exfiltration_packets(src_ip,dest,ip,ip_flags,src_port,dest_port,tcp_flags):
    #for i in range(exfiltration):
    #    ip = IP(src=src_ip, dst=dst_ip, id=ip_id, flags=ip_flags)
    #    tcp = ip / TCP(sport=src_port, dport=dst_port, flags='PA',
                    #seq=seq_n, ack=ack_n) / test_content
    t=0

    #    ip=IP()
    #    packet=scapy.
    #    scapy.send(packet,verbose=False)



parser.add_option('-t', dest = 'packet_type',
                      type = 'int',
                      help = '1: Exfiltration, 2: Keyloggin, 3: Scans',
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
    send_keyloggin_packets()
elif ids_packet_type==3:
    send_scans_packets()        
