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



models=[[None,None,None,None],[None,None,None,None],[None,None,None,None],[None,None,None,None]]#0:exfiltration,1:keylogging,2:scans this will contain the 3 models used for identifying exfiltration, keylogging and scans


def make_prediction(models_array,dataframevalues):#use 4 models, if all predict the same thing, then accept that as the prediction
    #model_prediction_array=[None,None,None,None]
    for t in models_array:
        prediction=t.predict(dataframevalues)
        if prediction==1:
            continue    
        else:
            return 0    #if at least one predicts 0, then prediction is 0 
    return 1    #if all predict 1 then final prediction is 1


def load_models():
    folder_path = os.path.dirname(os.path.abspath(__file__)) #get the current directory the python file is in, just place all teh other files in this folder
    exfiltration_model_files=[None,None,None,None]
    exfiltration_model_files[0] = os.path.join(folder_path, 'svm_exfiltration_dec04.pickle')
    exfiltration_model_files[1] = os.path.join(folder_path, 'adaboost_exfiltration_dec04.pickle')
    exfiltration_model_files[2] = os.path.join(folder_path, 'decision_tree_filtration_dec04.pickle')
    exfiltration_model_files[3] = os.path.join(folder_path, 'mlp_exfiltration_dec04.pickle') 
    try:
        for i in range(0,len(exfiltration_model_files)):
            with open(exfiltration_model_files[i], 'rb') as f:
                models[0][i] = pickle.load(f)

    except FileNotFoundError:
        print("File not Found Error: Exfiltration Model File not found in folder, please add the file to same path as the script")        
        exit()



    keylogging_model_files=[None,None,None,None]
    keylogging_model_files[0] = os.path.join(folder_path, 'svm_keylogging_dec04.pickle')
    keylogging_model_files[1] = os.path.join(folder_path, 'adaboost_keylogging_dec04.pickle')
    keylogging_model_files[2] = os.path.join(folder_path, 'decision_tree_keylogging_dec04.pickle')
    keylogging_model_files[3] = os.path.join(folder_path, 'mlp_keylogging_dec04.pickle')
    try:
        #keylogging_model_file = os.path.join(folder_path, 'decision_tree_keylogging_nov17.pickle')
        for i in range(0,len(keylogging_model_files)):
            with open(keylogging_model_files[i], 'rb') as g:
                models[1][i] = pickle.load(g)

    except FileNotFoundError:
        print("File not Found Error: Keylogging Model File not found in folder1, please add the file to same path as the script")
        #exit()



    os_scan_model_files=[None,None,None,None]
    os_scan_model_files[0] = os.path.join(folder_path, 'svm_OSSCAN_dec04.pickle')
    os_scan_model_files[1] = os.path.join(folder_path, 'adaboost_OSSCAN_dec04.pickle')
    os_scan_model_files[2] = os.path.join(folder_path, 'decission_tree_OSSCAN_dec04.pickle')
    os_scan_model_files[3] = os.path.join(folder_path, 'mlp_OSSCAN_dec04.pickle')
    try:    
        for i in range(0,len(os_scan_model_files)):
            with open(os_scan_model_files[i], 'rb') as h:
                models[2][i] = pickle.load(h)    
    except FileNotFoundError:
        print("File not Found Error: OS Scans Model File not found in folder, please add the file to same path as the script")



    service_scan_model_files=[None,None,None,None]
    service_scan_model_files[0] = os.path.join(folder_path, 'svm_SERVICE_SCAN_dec04.pickle')
    service_scan_model_files[1] = os.path.join(folder_path, 'adaboost_SERVICE_SCAN_dec04.pickle')
    service_scan_model_files[2] = os.path.join(folder_path, 'decission_tree_SERVICE_SCAN_dec04.pickle')
    service_scan_model_files[3] = os.path.join(folder_path, 'mlp_SERVICE_SCAN_dec04.pickle')
    try:    
        for i in range(0,len(service_scan_model_files)):    
            with open(service_scan_model_files[i], 'rb') as h:
                models[3][i] = pickle.load(h)    
    except FileNotFoundError:
        print("File not Found Error: Serice Scans Model File not found in folder, please add the file to same path as the script")    
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
           

        
        tcp_flags=convert_tcp_flags(packet['TCP'].flags)
       
        length=packet['IP'].len
        dport=packet['TCP'].dport   
        sport=packet['TCP'].sport

        window=packet['TCP'].window

        ttl=packet['IP'].ttl

        protocol=4#protocol 4 is tcp

        data_exfiltration = [[sport,dport,protocol,length,window,tcp_flags]]
        data_keylogging = [[sport,dport,protocol,window,length,tcp_flags]] #4 represents tcp protocol in trained model, this is constant since its filtered out 
        data_osscan=[[sport,dport,protocol,length,tcp_flags,ttl]]
        data_service_scan=[[sport,dport,protocol,length,tcp_flags,ttl]]
        #data_os_scan=[[sport,dport,tcp_flags,length]]

        

        packet_df_exfiltration=pd.DataFrame(data_exfiltration,columns=['sport','dport','Protocol','Length','window','TCP Flag'])# convert data to dataframe
        packet_df_keylogging=pd.DataFrame(data_keylogging,columns=['sport','dport','Protocol','Window','Length','TCP Flag'])# convert data to dataframe
        packet_df_os_scan=pd.DataFrame(data_osscan,columns=['sport','dport','Protocol','Length','TCP_Flags','time to live'])# convert data to dataframe
        packet_df_service_scan=pd.DataFrame(data_service_scan,columns=['sport','dport','Protocol','Length','TCP_Flags','time to live'])# convert data to dataframe
        
        print("")
        print("")
        print("")
        #print(packet_df_keylogging.head())
        #packet_df['sport']=packet_df['sport'].fillna(0)
        #packet_df['dport']=packet_df['dport'].fillna(0)
        #packet_df['TCP Flag']=packet_df['TCP Flag'].fillna('0x000')
        
        #packet_df['Frame length on the wire']=packet_df['Frame length on the wire'].fillna(0)

        #exfiltration_prediction=models[0].predict(packet_df_exfiltration.values)#make prediction
        exfiltration_prediction=make_prediction(models[0],packet_df_exfiltration.values)
        keylogging_prediction=make_prediction(models[1],packet_df_keylogging.values)#models[1].predict(packet_df_keylogging.values)#make prediction
        os_scan_prediction=make_prediction(models[2],packet_df_os_scan.values)#models[2].predict(packet_df_os_scan.values)#make prediction
        service_scan_predication=make_prediction(models[3],packet_df_service_scan.values)#models[3].predict(packet_df_service_scan.values)#make prediction

        print("")
        print("")
        print("#######################################################################")
        print(packet.summary())
        if exfiltration_prediction==1 :#and (sport==4444 and dport==49160 or sport==49160 or dport==4444):
            print("Exfiltration Detected(TCP)")
            file1=open("/home/kali/Documents/project/suspected_packets_log.txt",'a')
            file1.write(str(packet.time)+" Exfiltration: "+packet.summary()+"\n")
            file1.close()
            
        else:# exfiltration_prediction==0:
            print("Not Exfiltration(TCP)")  
        #else:
        #    print("Something not right")      
        #    exit()

        print("")

        print(packet.summary())
        #print("Keylogging prediction value: "+str(keylogging_prediction))
        #print(packet_df_keylogging.head())

        if keylogging_prediction==1 :#and length<400 and sport==80:  #keyloggin usually length==296, tcp flag 0x000, window 1024, dport and sport 80
            print("Keylogging Detected(TCP)")
            file1=open("/home/kali/Documents/project/suspected_packets_log.txt",'a')
            file1.write(str(packet.time)+" Keylogging: "+packet.summary()+"\n")
            file1.close()
            
        else:# keylogging_prediction==0 or (keylogging_prediction==1 and length>400):
            print("Not Keylogging(TCP)")  
        #else:
        #    print("Something not right")      
        #    exit()

        print("")
        print("")    

        print(packet.summary())
        #print("Os scan prediction value: "+str(os_scan_prediction))
        #print(packet_df_os_scan.head())
        if os_scan_prediction==1 :#and length<1600:
            print("OS Scan Detected(TCP)")
            file1=open("/home/kali/Documents/project/suspected_packets_log.txt",'a')
            file1.write(str(packet.time)+" OS Scan: "+packet.summary()+"\n")
            file1.close()
        else:# os_scan_prediction==0:
            print("Not OS Scan(TCP)")  
        #else:
        #    print("Something not right")      
        #    exit()    

        

        if service_scan_predication==1:
            print("Service Scan Detected(TCP)")    
            file1=open("/home/kali/Documents/project/suspected_packets_log.txt",'a')
            file1.write(str(packet.time)+" OS Scan: "+packet.summary()+"\n")
            file1.close()
        else:
            print("Not Service Scan(TCP)")    
        #if packet.haslayer(http.HTTPRequest):
            #print(packet)
        #	print(packet.show())
        #	if packet.haslayer(scapy.Raw):
        #		print(packet[scapy.Raw].load)
        print("######################################################")

    elif 'UDP' in packet:#keylogging packets and exfiltration are all TCP, only scans have udp
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
        packet_df_service_scan_udp=pd.DataFrame(data_osscan_udp,columns=['sport','dport','Protocol','Length','TCP_Flags','time to live'])# convert data to dataframe
        
        os_scan_prediction_udp=make_prediction(models[2],packet_df_os_scan_udp.values)#models[2].predict(packet_df_os_scan_udp.values)#make prediction
        service_scan_prediction_udp=make_prediction(models[3],packet_df_service_scan_udp.values)#models[3].predict(packet_df_service_scan_udp.values)#make prediction

        print(packet_df_os_scan_udp.head())
        if os_scan_prediction_udp==1 :#and sport_udp==365: #most attack udp are sport 365, dport 565, length 60 and tcp flag 0x000
            print("OS Scan Detected(UDP)")
            file1=open("/home/kali/Documents/project/suspected_packets_log.txt",'a')
            file1.write(str(packet.time)+" UDP OS Scan: "+packet.summary()+"\n")
            file1.close()
        else:
            print("Not OS Scan(UDP)")


        if service_scan_prediction_udp==1:
            print("Service Scan Detected(UDP)")    
            file1=open("/home/kali/Documents/project/suspected_packets_log.txt",'a')
            file1.write(str(packet.time)+" OS Scan: "+packet.summary()+"\n")
            file1.close()
        else:
            print("Not Service Scan(UDP)")   
            



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



