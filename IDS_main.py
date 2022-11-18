import sklearn
import scapy.all as scapy
from scapy.layers import http  #packet sniffing

import pandas as pd
import matplotlib.pyplot as plt

import pickle
import os
from ast import literal_eval
import math
import time #could use it to calculate throughtput???



models=[None,None,None]#0:exfiltration,1:keylogging,2:scans this will contain the 3 models used for identifying exfiltration, keylogging and scans

def load_models():
    folder_path = os.path.dirname(os.path.abspath(__file__)) #get the current directory the python file is in, just place all teh other files in this folder
    exfiltration_model_file = os.path.join(folder_path, 'decision_tree_filtration_nov17.pickle')
   
    try:
        with open(exfiltration_model_file, 'rb') as f:
            models[0] = pickle.load(f)
    except FileNotFoundError:
        print("File not Found Error: Exfiltration Model File not found in folder, please add the file to same path as the script")        
        exit()

    try:
        keylogging_model_file = os.path.join(folder_path, 'decision_tree_keylogging_nov17.pickle')
        with open(keylogging_model_file, 'rb') as g:
            models[1] = pickle.load(g)

    except FileNotFoundError:
        print("File not Found Error: Keylogging Model File not found in folder1, please add the file to same path as the script")
        #exit()

    try:    
        scans_model_file = os.path.join(folder_path, 'mlp_OSSCAN_nov17.pickle')
        with open(scans_model_file, 'rb') as h:
            models[2] = pickle.load(h)    
    except FileNotFoundError:
        print("File not Found Error: Scans Model File not found in folder, please add the file to same path as the script")
        #exit()

def sniff(interface):
	scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


flagsy = {
		'F': 0x01,
		'S': 0x02,
		'R': 0x04,
		'P': 0x08,
		'A': 0x10,
		'U': 0x20,
		'E': 0x40,
		'C': 0x80,
			}

def convert_tcp_flags(string_flags):
    #####this block of code converts tcp flags from character/strings to numbers
    #string_flags=packet['TCP'].flags
    sum=0X00
    for t in string_flags:
        sum=flagsy[t] | sum    
    tcp_flags=sum

    return tcp_flags

def process_sniffed_packet(packet):
    global models
    global flagsy
    if 'TCP' in packet:
        #print(packet['TCP'].sport)
        #print(packet['TCP'].dport)
        #print(packet['TCP'].flags)
        #print(packet['IP'].len)


        #packet_df=({'sport':[packet['TCP'].sport],
        #    'dport':[packet['TCP'].dport],
        #    'TCP Flag':[packet['TCP'].flags],
        #    'Frame length on the wire':[packet['IP'].len],
        
        #})
        

        
        tcp_flags=convert_tcp_flags(packet['TCP'].flags)
        #if tcp_flags==0X000 or tcp_flags==0x1FF or tcp_flags==0x003 or tcp_flags==0x006 or tcp_flags==0x005 or  tcp_flags==0x001 or tcp_flags==0x008 or tcp_flags==0x020: #packet is suspicious
        #    file1=open("/home/kali/Documents/project/suspected_packets_log.txt",'a')
        #    file1.write(str(packet.time)+"Flag Attack, Possible Scan: "+packet.summary()+"\n")
        #    file1.close()
            
        #    return

        #some data cleaning, check if NaN is present, and put 0 in its place, convert tcp flags
        #if math.isnan(packet['TCP'].dport):
        #    dport=0
        #else:

        length=packet['IP'].len
        dport=packet['TCP'].dport

        #if math.isnan(packet['TCP'].sport):
        #    sport=0
        #else:
        sport=packet['TCP'].sport


        #####this block of code converts tcp flags from character/strings to numbers       
        
        


        #if math.isnan(tcp_flags):
        #    tcp_flags=0
        

        
        #if math.isnan(packet['IP'].len):
        #    length=0
        #else:
        #length=packet['IP'].len


        window=packet['TCP'].window

        #sport=packet['TCP'].sport
        #flags=packet['TCP'].flags
        #frame_length=packet['IP'].len
        ttl=packet['IP'].ttl

        protocol=4#protocol 4 is tcp

        data_exfiltration = [[sport,dport,protocol,length,window,tcp_flags]]
        data_keylogging = [[sport,dport,protocol,window,length,tcp_flags]] #4 represents tcp protocol in trained model, this is constant since its filtered out 
        data_osscan=[[sport,dport,protocol,length,tcp_flags,ttl]]
        #data_os_scan=[[sport,dport,tcp_flags,length]]

        

        packet_df_exfiltration=pd.DataFrame(data_exfiltration,columns=['sport','dport','Protocol','Length','window','TCP Flag'])# convert data to dataframe
        packet_df_keylogging=pd.DataFrame(data_keylogging,columns=['sport','dport','Protocol','Window','Length','TCP Flag'])# convert data to dataframe
        packet_df_os_scan=pd.DataFrame(data_osscan,columns=['sport','dport','Protocol','Length','TCP_Flags','time to live'])# convert data to dataframe
        
        print("")
        print("")
        print("")
        #print(packet_df_keylogging.head())
        #packet_df['sport']=packet_df['sport'].fillna(0)
        #packet_df['dport']=packet_df['dport'].fillna(0)
        #packet_df['TCP Flag']=packet_df['TCP Flag'].fillna('0x000')
        
        #packet_df['Frame length on the wire']=packet_df['Frame length on the wire'].fillna(0)

        exfiltration_prediction=models[0].predict(packet_df_exfiltration.values)#make prediction
        keylogging_prediction=models[1].predict(packet_df_keylogging.values)#make prediction
        os_scan_prediction=models[2].predict(packet_df_os_scan.values)#make prediction

        print("")
        print("")
        print("#######################################################################")
        print(packet.summary())
        if exfiltration_prediction==1 and (sport==4444 and dport==49160 or sport==49160 or dport==4444):
            print("Exfiltration Detected")
            file1=open("/home/kali/Documents/project/suspected_packets_log.txt",'a')
            file1.write(str(packet.time)+" Exfiltration: "+packet.summary()+"\n")
            file1.close()
            
        else:# exfiltration_prediction==0:
            print("Not Exfiltration")  
        #else:
        #    print("Something not right")      
        #    exit()

        print("")

        print(packet.summary())
        print("Keylogging prediction value: "+str(keylogging_prediction[0]))
        print(packet_df_keylogging.head())

        if keylogging_prediction[0]==1 and length<=400 and sport==80:  #keyloggin usually length==296, tcp flag 0x000, window 1024, dport and sport 80
            print("Keylogging Detected")
            file1=open("/home/kali/Documents/project/suspected_packets_log.txt",'a')
            file1.write(str(packet.time)+" Keylogging: "+packet.summary()+"\n")
            file1.close()
            
        else:# keylogging_prediction==0 or (keylogging_prediction==1 and length>400):
            print("Not Keylogging")  
        #else:
        #    print("Something not right")      
        #    exit()

        print("")
        print("")    

        print(packet.summary())
        print("Os scan prediction value: "+str(os_scan_prediction[0]))
        print(packet_df_os_scan.head())
        if os_scan_prediction[0]==1 and length<1600 and (sport==0 or sport==80):
            print("OS Scan Detected")
            file1=open("/home/kali/Documents/project/suspected_packets_log.txt",'a')
            file1.write(str(packet.time)+" OS Scan: "+packet.summary()+"\n")
            file1.close()
        else:# os_scan_prediction==0:
            print("Not OS Scan")  
        #else:
        #    print("Something not right")      
        #    exit()    

        print("######################################################")
	#if packet.haslayer(http.HTTPRequest):
		#print(packet)
	#	print(packet.show())
	#	if packet.haslayer(scapy.Raw):
	#		print(packet[scapy.Raw].load)

    elif 'UDP' in packet:#keylogging packets are all TCP, not sure about os scan and exfiltration yet
        print("UDP")
        dport_udp=packet['UDP'].dport
        sport_udp=packet['UDP'].dport
        length_udp=packet['IP'].len
        window_udp=0
        tcp_flags_udp=0
        ttl_udp=packet['IP'].ttl
        protocol_udp=5#protocol 5 is udp


        data_osscan_udp=[[sport_udp,dport_udp,protocol_udp,length_udp,tcp_flags_udp,ttl_udp]]
        packet_df_os_scan_udp=pd.DataFrame(data_osscan_udp,columns=['sport','dport','Protocol','Length','TCP_Flags','time to live'])# convert data to dataframe
        os_scan_prediction_udp=models[2].predict(packet_df_os_scan_udp.values)#make prediction

        print(packet_df_os_scan_udp.head())
        if os_scan_prediction_udp==1 and sport_udp==365: #most attack udp are sport 365, dport 565, length 60 and tcp flag 0x000
            print("OS Scan Detected(UDP)")
            file1=open("/home/kali/Documents/project/suspected_packets_log.txt",'a')
            file1.write(str(packet.time)+" UDP OS Scan: "+packet.summary()+"\n")
            file1.close()
        else:
            print("Not OS Scan(UDP)")



load_models()


print("Welcome to IDS Project:")
print("Select Mode:")
print("1...........Continuous Monitoring")
print("2...........Instance Check")




choice=input()

if choice=='1':#continuous monitoring
    #while(True):
     #   k=0'
    print("")
    print("Select interface: ")
    print("1..........eth0")
    print("2..........wlan")
    choice2=input()
    if choice2=='1': 
        sniff("eth0")
    elif choice2=='2':
        sniff("wlan")  
    else:
        print("Invalid selection")
        exit()      
elif choice=='2':
    d=0
else:
    print("Invalid selection")   
    exit()



