import pyshark
import pickle
import os
import pandas as pd
#import sklearn
#from sklearn.preprocessing import StandardScaler


capture = pyshark.LiveCapture(interface="eth0")
#capture.set_debug()
#capture.sniff(timeout=50)

folder_path = os.path.dirname(os.path.abspath(__file__)) #get the current directory the python file is in, just place all teh other files in this folder
exfiltration_model_file = os.path.join(folder_path, 'decision_tree_efiltration_dec06_n_scaled.pickle')
with open(exfiltration_model_file,'rb') as g:
    exfiltration_model=pickle.load(g)

e_standard_scaler_file=os.path.join(folder_path,'exfiltration_scaler_.pkl')
with open(e_standard_scaler_file,'rb') as j:
    exfiltration_scaler=pickle.load(j)  


keylogging_model_file = os.path.join(folder_path, 'svm_keylogging_dec07_scaled.pickle')
with open(keylogging_model_file,'rb') as g:
    keylogging_model=pickle.load(g)

k_standard_scaler_file=os.path.join(folder_path,'keylogging_scaler_.pkl')
with open(k_standard_scaler_file,'rb') as j:
    keylogging_scaler=pickle.load(j)  


os_scan_model_file = os.path.join(folder_path, 'decission_tree_OSSCAN_dec08_scaled.pickle')
with open(os_scan_model_file,'rb') as g:
    os_scan_model=pickle.load(g)

o_standard_scaler_file=os.path.join(folder_path,'os_scan_scaler_.pkl')
with open(o_standard_scaler_file,'rb') as j:
    os_scan_scaler=pickle.load(j)  


service_scan_model_file = os.path.join(folder_path, 'decission_tree_SERVICE_SCAN_dec08_scaled.pickle')
with open(service_scan_model_file,'rb') as g:
    service_scan_model=pickle.load(g)

s_standard_scaler_file=os.path.join(folder_path,'service_scan_scaler_.pkl')
with open(s_standard_scaler_file,'rb') as j:
    service_scan_scaler=pickle.load(j)  



for packet in capture.sniff_continuously():
    if hasattr(packet, 'tcp'):
    #print(packet)
    #print("bytes_flight_")
        #print(packet)
        
        #print("\nFrame Delta")
        #print(packet.frame_info.time_delta_displayed)#this works!!!

        #print("\nTCP Delta")
        #print(packet['TCP'].time_delta)

        #print("\ntime since first tcp in this stream")
        #print(packet['TCP'].time_relative)


        time_since_previous_frame_in_stream=packet['TCP'].time_delta
        time_since_first_frame_in_stream= packet['TCP'].time_relative
        
        #print(dir(packet['TCP']))
        sport=packet['TCP'].srcport
        dport=packet['TCP'].dstport   
        protocol=4#packet.transport_layer
        length=packet['TCP'].len
        window=packet['TCP'].window_size
        tcp_flags=packet['TCP'].flags
         
        tcp_flags=int(tcp_flags,16)
        
        

        try:
            #print("\n rtt: round trip time to ack segment ")
            #print(dir(packet[packet.transport_layer]))
            #print(packet[packet.transport_layer].analysis_ack_rtt)
            ack_rtt=packet[packet.transport_layer].analysis_ack_rtt
        except AttributeError:
            print("No rtt attribute")    
            ack_rtt=0

        try:
            #print("\n initial rtt ")
            #print(packet[packet.transport_layer].analysis_intial_rtt)
            initial_rtt=packet[packet.transport_layer].analysis_intial_rtt
        except AttributeError:
            print("No initial rtt")
            initial_rtt=0

        try:
            #print("\n bytes in flight ")
            #print(packet[packet.transport_layer].analysis_bytes_in_flight)
            bytes_in_flight=packet[packet.transport_layer].analysis_bytes_in_flight
        except AttributeError:
            print("No bytes in flight")
            bytes_in_flight=0

        try:
            #print("\n push bytes sent ")
            #print(packet[packet.transport_layer].analysis_push_bytes_sent)
            push_bytes_sent=packet[packet.transport_layer].analysis_push_bytes_sent
        except AttributeError:
            print("No push bytes ")
            push_bytes_sent=0



        
        #sc=StandardScaler()
        #X=sc.fit_transform(X)
        

        exfiltration_df=[[sport,dport,protocol,length,window,tcp_flags,bytes_in_flight,push_bytes_sent,time_since_previous_frame_in_stream]]
        keylogging_df=[[sport,dport,protocol,length,window,tcp_flags,bytes_in_flight,time_since_previous_frame_in_stream]]
        os_scan_df=[[sport,dport,protocol,length,window,tcp_flags,bytes_in_flight,time_since_previous_frame_in_stream,0]]
        service_scan_df=[[sport,dport,protocol,length,window,tcp_flags,bytes_in_flight,time_since_previous_frame_in_stream,0]]
        #exfiltration_df=[[80,80,4,296,1024,0,242,14520,0.040332]]# this is detected
        #exfiltration_df=[[80,80,4,296,1024,0,242,14520565,0.040332]]

        
        packet_df_exfiltration=pd.DataFrame(exfiltration_df,columns=['sport','dport','Protocol','Length','window','TCP Flag','Bytes in flight','Bytes sent since last PSH flag','Time since previous frame in this TCP stream(TCP)'])
        packet_df_keylogging=pd.DataFrame(keylogging_df,columns=['sport','dport','Protocol','Length','window','TCP Flag','Bytes in flight','Time since previous frame in this TCP stream(TCP)'])
        packet_df_os_scan=pd.DataFrame(os_scan_df,columns=['sport','dport','Protocol','Length','window','TCP Flag','Bytes in flight','Time since previous frame in this TCP stream(TCP)','time_since__frame_udp'])
        packet_df_service_scan=pd.DataFrame(service_scan_df,columns=['sport','dport','Protocol','Length','window','TCP Flag','Bytes in flight','Time since previous frame in this TCP stream(TCP)','time_since__frame_udp'])
        #print(packet_df_os_scan)
        print(packet_df_service_scan)
        #print('\n pre scaling keylogging dataframe')
        #print(packet_df_keylogging)

        
        packet_df_exfiltration=exfiltration_scaler.transform(packet_df_exfiltration.values)
        packet_df_keylogging=keylogging_scaler.transform(packet_df_keylogging.values)
        packet_df_os_scan=os_scan_scaler.transform(packet_df_os_scan.values)
        packet_df_service_scan=service_scan_scaler.transform(packet_df_service_scan.values)
        
        #print("\n post scaling keylogging dataframe")
        #print(packet_df_keylogging)
        
        exfiltration_prediction=exfiltration_model.predict(packet_df_exfiltration)[0]
        keylogging_prediction=keylogging_model.predict(packet_df_keylogging)[0]
        os_scan_prediction=os_scan_model.predict(packet_df_os_scan)[0]
        service_scan_prediction=service_scan_model.predict(packet_df_service_scan)[0]

        #print(packet_df_exfiltration)
        if exfiltration_prediction==1:
            print("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
            print("Exfiltration Detected\n")
        elif exfiltration_prediction==0:
            print("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
            print("Normal Packet(Not Exfiltration)\n")
        else:
            print("Something wrong")    



        #print(packet_df_keylogging)
        if keylogging_prediction==1:
            print("\n&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
            print("Keylogging Detected\n")
        elif keylogging_prediction==0:
            print("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
            print("Normal Packet(Not Keylogging)\n")
        else:
            print("Something wrong")    


        #print(os_scan_df)

        if os_scan_prediction==1:
            print("\n&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
            print("OS Scan Detected\n")
        elif os_scan_prediction==0:
            print("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
            print("Normal Packet(Not OS Scan)\n")
        else:
            print("Something wrong")        

        
        
        
        if service_scan_prediction==1:
            print("\n&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
            print("Service Scan Detected\n")
        elif service_scan_prediction==0:
            print("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
            print("Normal Packet(Not Service Scan)\n")
        else:
            print("Something wrong")    

        print("")
        print("")
        print("")

        
        #print("\nrtt")
        #print(packet['TCP'].irtt)

        #protocol = packet.transport_layer
        #source_address = packet.ip.src
        #source_port = packet[packet.transport_layer].srcport
        #destination_address = packet.ip.dst
        #destination_port = packet[packet.transport_layer].dstport
        #print(f'{protocol}  {source_address}:{source_port} --> {destination_address}:{destination_port}')
    elif hasattr(packet, 'udp'):
        time_since_previous_frame_in_stream=0#packet['TCP'].time_delta
        time_since_first_frame_in_stream=0#packet['TCP'].time_relative
        time_since_first_frame_udp=packet['UDP'].time_relative
        
        #print(dir(packet['TCP']))
        sport=packet['UDP'].srcport
        dport=packet['UDP'].dstport   
        protocol=5#packet.transport_layer
        length=packet['UDP'].length
        window=0#packet['TCP'].window_size

        tcp_flags='0x000'#packet['TCP'].flags
        time_since_previous_frame_in_stream=0 
        tcp_flags=int(tcp_flags,16)
        bytes_in_flight=0

        os_scan_df=[[sport,dport,protocol,length,window,tcp_flags,bytes_in_flight,time_since_previous_frame_in_stream,time_since_first_frame_udp]]
        service_scan_df=[[sport,dport,protocol,length,window,tcp_flags,bytes_in_flight,time_since_previous_frame_in_stream,time_since_first_frame_udp]]
        
        packet_df_os_scan=pd.DataFrame(os_scan_df,columns=['sport','dport','Protocol','Length','window','TCP Flag','Bytes in flight','Time since previous frame in this TCP stream(TCP)','time_since_first_frame_udp'])
        packet_df_service_scan=pd.DataFrame(service_scan_df,columns=['sport','dport','Protocol','Length','window','TCP Flag','Bytes in flight','Time since previous frame in this TCP stream(TCP)','time_since_first_frame_udp'])
        print(packet_df_service_scan)

        packet_df_os_scan=os_scan_scaler.transform(packet_df_os_scan.values)
        packet_df_service_scan=service_scan_scaler.transform(packet_df_service_scan.values)

        os_scan_prediction_udp=os_scan_model.predict(packet_df_os_scan)[0]
        service_scan_prediction_udp=service_scan_model.predict(packet_df_service_scan)[0]


        if os_scan_prediction_udp==1:
            print("\n&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
            print("OS Scan Detected(UDP)\n")
        elif os_scan_prediction_udp==0:
            print("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
            print("Normal Packet(Not OS Scan-UDP)\n")
        else:
            print("Something wrong")     



        if service_scan_prediction_udp==1:
            print("\n&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
            print("Service Scan Detected(UDP)\n")
        elif service_scan_prediction_udp==0:
            print("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
            print("Normal Packet(Not Service Scan-UDP)\n")
        else:
            print("Something wrong")       




        print("")
        print("")
        print("")    