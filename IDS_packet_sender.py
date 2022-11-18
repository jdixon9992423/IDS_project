from optparse import OptionParser
import subprocess
#import scapy.all as scapy
from scapy.all import *
from scapy.layers import *
#from scapy import *
import time

#data="trying to send null flags packet with this"
parser=OptionParser()

ids_packet_type=0
def send_keylogging_packets(pkt_count,destination_mac,destination_ip,protocol,src_port,dest_port,window_,tcp_flag,length):
    for i in range(pkt_count):
        ip = IP(dst=destination_ip)
        
        src_port=80
        dest_port=80
        tcp_flag='0x000'
        window_=1024
        length=256
    #   ip = IP(src=src_ip, dst=dst_ip, id=ip_id, flags=ip_flags)
        data=Raw(RandString(size=length))
        #data="Jokes"
        tcp_flago=int(tcp_flag,16)
        
        print(tcp_flago)
        print(window_)

        packet = ip / TCP(sport=src_port, dport=dest_port, flags=tcp_flago,window=window_) / data

        send(packet)    
        time.sleep(0.5)    
    

def send_scans_packets(pkt_count,destination_mac,destination_ip,protocol,src_port,dest_port,window_,tcp_flag,length):
    for i in range(pkt_count):
        ip = IP(dst=destination_ip)
        
        src_port=0
        dest_port=0
        tcp_flag='0x000'
        window_=1024
        length=300
    #   ip = IP(src=src_ip, dst=dst_ip, id=ip_id, flags=ip_flags)
        data=Raw(RandString(size=length))
        #data="Jokes"
        tcp_flago=int(tcp_flag,16)
        
        print(tcp_flago)
        print(window_)

        packet = ip / TCP(sport=src_port, dport=dest_port, flags=tcp_flago,window=window_) / data

        send(packet)

        time.sleep(0.5)



def send_exfiltration_packets(pkt_count,destination_mac,destination_ip,protocol,src_port,dest_port,window_,tcp_flag,length):
    for i in range(pkt_count):
        ip = IP(dst=destination_ip)
        
    #   ip = IP(src=src_ip, dst=dst_ip, id=ip_id, flags=ip_flags)
        data=Raw(RandString(size=length))
        #data="Jokes"
        tcp_flago=int(tcp_flag,16)
        
        print(tcp_flago)
        print(window_)

        packet = ip / TCP(sport=src_port, dport=dest_port, flags=tcp_flago,window=window_) / data


        send(packet)

        time.sleep(0.5)

 



parser.add_option('-t', dest = 'packet_type',
                      type = 'int',
                      help = '1: Exfiltration, 2: Keylogging, 3: Scans',
                      default=0)    

parser.add_option('-c', dest = 'packet_count',
                      type = 'int',
                      help = 'set number of packets to be sent',
                      default=1)      

parser.add_option('-d', dest = 'dest_ip',
                      type = 'string',
                      help = 'set destination ip',
                      default='10.0.2.15')

parser.add_option('-s', dest = 'source_port',
                      type = 'int',
                      help = 'set source port',
                      default=80)

parser.add_option('-l', dest = 'dest_port',
                      type = 'int',
                      help = 'set destination port',
                      default=8080)

parser.add_option('-m', dest = 'dest_mac',
                      type = 'string',
                      help = 'set destination mac address',
                      default='08:00:27:10:b8:d0')    

parser.add_option('-w', dest = 'window_size',
                      type = 'int',
                      help = 'set window size',
                      default=1024)    

parser.add_option('-j', dest = 'tcp_flags',
                      type = 'string',
                      help = 'set window size',
                      default='0x000')                       
                     
parser.add_option('-k', dest = 'protocol',
                      type = int,
                      help = 'set layer 4 protocol 1: TCP  2:UDP',
                      default=1)       

parser.add_option('-v', dest = 'pkt_length',
                      type = int,
                      help = 'set packet length',
                      default=400)                          


(options, args) = parser.parse_args()


ids_packet_type=options.packet_type
pkt_count=options.packet_count
destination_ip=options.dest_ip
destination_mac=options.dest_mac

protocol=options.protocol
sport=options.source_port
dport=options.dest_port
windows=options.window_size
tcp_flag=options.tcp_flags
length=options.pkt_length


print(options)

if ids_packet_type==1:
    send_exfiltration_packets(pkt_count,destination_mac,destination_ip,protocol,sport,dport,windows,tcp_flag,length)
elif ids_packet_type==2:
    send_keylogging_packets(pkt_count,destination_mac,destination_ip,protocol,sport,dport,windows,tcp_flag,length)
elif ids_packet_type==3:
    send_scans_packets(pkt_count,destination_mac,destination_ip,protocol,sport,dport,windows,tcp_flag,length)  
elif ids_packet_type==0:  #default is to send all 3
    send_exfiltration_packets(pkt_count,destination_mac,destination_ip,protocol,sport,dport,windows,tcp_flag,length)
    send_keylogging_packets(pkt_count,destination_mac,destination_ip,protocol,sport,dport,windows,tcp_flag,length)
    send_scans_packets(pkt_count,destination_mac,destination_ip,protocol,sport,dport,windows,tcp_flag,length)
else:
    print("Invalid Option")
    exit()


