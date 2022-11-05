import sklearn
import scapy.all as scapy
from scapy.layers import http  #packet sniffing

import pandas as pd
import matplotlib.pyplot as plt

import pickle
import os
from ast import literal_eval
import math



models=[None,None,None]#0:exfiltration,1:keylogging,2:scans this will contain the 3 models used for identifying exfiltration, keylogging and scans

def load_models():
    folder_path = os.path.dirname(os.path.abspath(__file__)) #get the current directory the python file is in, just place all teh other files in this folder
    exfiltration_model_file = os.path.join(folder_path, 'knn_data_exfiltration_firstdataset_randomstate.pickle')
   
    try:
        with open(exfiltration_model_file, 'rb') as f:
            models[0] = pickle.load(f)
    except FileNotFoundError:
        print("File not Found Error: Exfiltration Model File not found in folder, please add the file to same path as the script")        
        exit()

    try:
        keylogging_model_file = os.path.join(folder_path, 'keylog_model.pickle')
        with open(keylogging_model_file, 'rb') as f:
            models[1] = pickle.load(f)

    except FileNotFoundError:
        print("File not Found Error: Keylogging Model File not found in folder, please add the file to same path as the script")
        #exit()

    try:    
        scans_model_file = os.path.join(folder_path, 'scans_model.pickle')
        with open(scans_model_file, 'rb') as f:
            models[2] = pickle.load(f)    
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


        if math.isnan(packet['TCP'].dport):
            dport=0
        else:
            dport=packet['TCP'].dport

        if math.isnan(packet['TCP'].sport):
            sport=0
        else:
            sport=packet['TCP'].sport


        string_flags=packet['TCP'].flags
        sum=0X00
        for t in string_flags:
            sum=flagsy[t] | sum    
        tcp_flags=sum
        if math.isnan(tcp_flags):
            tcp_flags=0
        

        
        if math.isnan(packet['IP'].len):
            frame_length=0
        else:
            frame_length=packet['IP'].len

        #sport=packet['TCP'].sport
        #flags=packet['TCP'].flags
        #frame_length=packet['IP'].len

        data = [[sport,dport,tcp_flags,frame_length]]


        

        packet_df=pd.DataFrame(data,columns=['sport','dport','TCP Flag','Frame length on the wire'])
        

        #packet_df['sport']=packet_df['sport'].fillna(0)
        #packet_df['dport']=packet_df['dport'].fillna(0)
        #packet_df['TCP Flag']=packet_df['TCP Flag'].fillna('0x000')
        
        #packet_df['Frame length on the wire']=packet_df['Frame length on the wire'].fillna(0)

        prediction=models[0].predict(packet_df.values)

        print(packet.summary())
        if prediction==1:
            print("Exfiltration Detected")
        elif prediction==0:
            print("Normal Packet")  
        else:
            print("Something not right")      
            exit()



	#if packet.haslayer(http.HTTPRequest):
		#print(packet)
	#	print(packet.show())
	#	if packet.haslayer(scapy.Raw):
	#		print(packet[scapy.Raw].load)


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



