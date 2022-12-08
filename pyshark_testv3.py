import pyshark
import pickle
import os
import pandas as pd

from optparse import OptionParser
#import sklearn
#from sklearn.preprocessing import StandardScaler



#capture.set_debug()
#capture.sniff(timeout=50)

parser=OptionParser()

prediction_model=[None,None,None,None]
scaler_model=[None,None,None,None]

def load_models():


    folder_path = os.path.dirname(os.path.abspath(__file__)) #get the current directory the python file is in, just place all teh other files in this folder
    exfiltration_model_file = os.path.join(folder_path, 'decision_tree_efiltration_dec06_n_scaled.pickle')
    with open(exfiltration_model_file,'rb') as g:
        prediction_model[0]=pickle.load(g)
        
    e_standard_scaler_file=os.path.join(folder_path,'exfiltration_scaler_.pkl')
    with open(e_standard_scaler_file,'rb') as j:
        scaler_model[0]=pickle.load(j)  


    keylogging_model_file = os.path.join(folder_path, 'svm_keylogging_dec07_scaled.pickle')
    with open(keylogging_model_file,'rb') as g:
        prediction_model[1]=pickle.load(g)

    k_standard_scaler_file=os.path.join(folder_path,'keylogging_scaler_.pkl')
    with open(k_standard_scaler_file,'rb') as j:
        scaler_model[1]=pickle.load(j)  


    os_scan_model_file = os.path.join(folder_path, 'decission_tree_OSSCAN_dec08_scaled.pickle')
    with open(os_scan_model_file,'rb') as g:
        prediction_model[2]=pickle.load(g)

    o_standard_scaler_file=os.path.join(folder_path,'os_scan_scaler_.pkl')
    with open(o_standard_scaler_file,'rb') as j:
        scaler_model[2]=pickle.load(j)  


    service_scan_model_file = os.path.join(folder_path, 'decission_tree_SERVICE_SCAN_dec08_scaled.pickle')
    with open(service_scan_model_file,'rb') as g:
        prediction_model[3]=pickle.load(g)

    s_standard_scaler_file=os.path.join(folder_path,'service_scan_scaler_.pkl')
    with open(s_standard_scaler_file,'rb') as j:
        scaler_model[3]=pickle.load(j)  


        

def intrusion_detection_sniffing(interface_):
    capture = pyshark.LiveCapture(interface=interface_)

    for packet in capture.sniff_continuously():
        if hasattr(packet, 'tcp'):

            time_since_previous_frame_in_stream=packet['TCP'].time_delta
            time_since_first_frame_in_stream= packet['TCP'].time_relative
            
            #print(dir(packet['TCP']))
            sport=packet['TCP'].srcport
            dport=packet['TCP'].dstport   
            protocol=4#packet.transport_layer
            length=packet.length#packet['TCP'].len
            window=packet['TCP'].window_size
            tcp_flags=packet['TCP'].flags
            
            tcp_flags=int(tcp_flags,16)
            
            

            try:
                ack_rtt=packet[packet.transport_layer].analysis_ack_rtt
            except AttributeError:
                print("No rtt attribute")    
                ack_rtt=0

            try:
                initial_rtt=packet[packet.transport_layer].analysis_intial_rtt
            except AttributeError:
                print("No initial rtt")
                initial_rtt=0

            try:
                bytes_in_flight=packet[packet.transport_layer].analysis_bytes_in_flight
            except AttributeError:
                print("No bytes in flight")
                bytes_in_flight=0

            try:
                push_bytes_sent=packet[packet.transport_layer].analysis_push_bytes_sent
            except AttributeError:
                print("No push bytes ")
                push_bytes_sent=0


            exfiltration_df=[[sport,dport,protocol,length,window,tcp_flags,bytes_in_flight,push_bytes_sent,time_since_previous_frame_in_stream]]
            keylogging_df=[[sport,dport,protocol,length,window,tcp_flags,bytes_in_flight,time_since_previous_frame_in_stream]]
            os_scan_df=[[sport,dport,protocol,length,window,tcp_flags,bytes_in_flight,time_since_previous_frame_in_stream,0]]
            service_scan_df=[[sport,dport,protocol,length,window,tcp_flags,bytes_in_flight,time_since_previous_frame_in_stream,0]]
                        
            packet_df_exfiltration=pd.DataFrame(exfiltration_df,columns=['sport','dport','Protocol','Length','window','TCP Flag','Bytes in flight','Bytes sent since last PSH flag','Time since previous frame in this TCP stream(TCP)'])
            packet_df_keylogging=pd.DataFrame(keylogging_df,columns=['sport','dport','Protocol','Length','window','TCP Flag','Bytes in flight','Time since previous frame in this TCP stream(TCP)'])
            packet_df_os_scan=pd.DataFrame(os_scan_df,columns=['sport','dport','Protocol','Length','window','TCP Flag','Bytes in flight','Time since previous frame in this TCP stream(TCP)','time_since__frame_udp'])
            packet_df_service_scan=pd.DataFrame(service_scan_df,columns=['sport','dport','Protocol','Length','window','TCP Flag','Bytes in flight','Time since previous frame in this TCP stream(TCP)','time_since__frame_udp'])
        
            print(packet_df_service_scan)
            
            packet_df_exfiltration=scaler_model[0].transform(packet_df_exfiltration.values)
            packet_df_keylogging=scaler_model[1].transform(packet_df_keylogging.values)
            packet_df_os_scan=scaler_model[2].transform(packet_df_os_scan.values)
            packet_df_service_scan=scaler_model[3].transform(packet_df_service_scan.values)
            
            exfiltration_prediction=prediction_model[0].predict(packet_df_exfiltration)[0]
            keylogging_prediction=prediction_model[1].predict(packet_df_keylogging)[0]
            os_scan_prediction=prediction_model[2].predict(packet_df_os_scan)[0]
            service_scan_prediction=prediction_model[3].predict(packet_df_service_scan)[0]

            if exfiltration_prediction==1:
                print("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
                print("Exfiltration Detected\n")
            elif exfiltration_prediction==0:
                print("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
                print("Normal Packet(Not Exfiltration)\n")
            else:
                print("Something wrong")    


            if keylogging_prediction==1:
                print("\n&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
                print("Keylogging Detected\n")
            elif keylogging_prediction==0:
                print("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
                print("Normal Packet(Not Keylogging)\n")
            else:
                print("Something wrong")    


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

        elif hasattr(packet, 'udp'):
            time_since_previous_frame_in_stream=0#packet['TCP'].time_delta
            time_since_first_frame_in_stream=0#packet['TCP'].time_relative
            time_since_first_frame_udp=packet['UDP'].time_relative
            
            sport=packet['UDP'].srcport
            dport=packet['UDP'].dstport   
            protocol=5#packet.transport_layer
            length=packet.length#packet['UDP'].length
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

            packet_df_os_scan=scaler_model[2].transform(packet_df_os_scan.values)
            packet_df_service_scan=scaler_model[3].transform(packet_df_service_scan.values)

            os_scan_prediction_udp=prediction_model[2].predict(packet_df_os_scan)[0]
            service_scan_prediction_udp=prediction_model[3].predict(packet_df_service_scan)[0]


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

def instance_check(pkt_index,pkt_file_path):
    
    capture=pyshark.FileCapture(pkt_file_path)
    
    if (pkt_index-1)<0:
        print("Invalid packet index")
        exit()
    packet=capture[pkt_index-1]

    print(packet.length)

    if hasattr(packet, 'tcp'):

        time_since_previous_frame_in_stream=packet['TCP'].time_delta
        time_since_first_frame_in_stream= packet['TCP'].time_relative
        
        #print(dir(packet['TCP']))
        sport=packet['TCP'].srcport
        dport=packet['TCP'].dstport   
        protocol=4#packet.transport_layer
        length=packet.length#packet['TCP'].len
        window=packet['TCP'].window_size
        tcp_flags=packet['TCP'].flags
        
        tcp_flags=int(tcp_flags,16)
        
        

        try:
            ack_rtt=packet[packet.transport_layer].analysis_ack_rtt
        except AttributeError:
            print("No rtt attribute")    
            ack_rtt=0

        try:
            initial_rtt=packet[packet.transport_layer].analysis_intial_rtt
        except AttributeError:
            print("No initial rtt")
            initial_rtt=0

        try:
            bytes_in_flight=packet[packet.transport_layer].analysis_bytes_in_flight
        except AttributeError:
            print("No bytes in flight")
            bytes_in_flight=0

        try:
            push_bytes_sent=packet[packet.transport_layer].analysis_push_bytes_sent
        except AttributeError:
            print("No push bytes ")
            push_bytes_sent=0


        exfiltration_df=[[sport,dport,protocol,length,window,tcp_flags,bytes_in_flight,push_bytes_sent,time_since_previous_frame_in_stream]]
        keylogging_df=[[sport,dport,protocol,length,window,tcp_flags,bytes_in_flight,time_since_previous_frame_in_stream]]
        os_scan_df=[[sport,dport,protocol,length,window,tcp_flags,bytes_in_flight,time_since_previous_frame_in_stream,0]]
        service_scan_df=[[sport,dport,protocol,length,window,tcp_flags,bytes_in_flight,time_since_previous_frame_in_stream,0]]
                    
        packet_df_exfiltration=pd.DataFrame(exfiltration_df,columns=['sport','dport','Protocol','Length','window','TCP Flag','Bytes in flight','Bytes sent since last PSH flag','Time since previous frame in this TCP stream(TCP)'])
        packet_df_keylogging=pd.DataFrame(keylogging_df,columns=['sport','dport','Protocol','Length','window','TCP Flag','Bytes in flight','Time since previous frame in this TCP stream(TCP)'])
        packet_df_os_scan=pd.DataFrame(os_scan_df,columns=['sport','dport','Protocol','Length','window','TCP Flag','Bytes in flight','Time since previous frame in this TCP stream(TCP)','time_since__frame_udp'])
        packet_df_service_scan=pd.DataFrame(service_scan_df,columns=['sport','dport','Protocol','Length','window','TCP Flag','Bytes in flight','Time since previous frame in this TCP stream(TCP)','time_since__frame_udp'])
    
        print(packet_df_service_scan)
        
        packet_df_exfiltration=scaler_model[0].transform(packet_df_exfiltration.values)
        packet_df_keylogging=scaler_model[1].transform(packet_df_keylogging.values)
        packet_df_os_scan=scaler_model[2].transform(packet_df_os_scan.values)
        packet_df_service_scan=scaler_model[3].transform(packet_df_service_scan.values)
        
        exfiltration_prediction=prediction_model[0].predict(packet_df_exfiltration)[0]
        keylogging_prediction=prediction_model[1].predict(packet_df_keylogging)[0]
        os_scan_prediction=prediction_model[2].predict(packet_df_os_scan)[0]
        service_scan_prediction=prediction_model[3].predict(packet_df_service_scan)[0]

        if exfiltration_prediction==1:
            print("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
            print("Exfiltration Detected\n")
        elif exfiltration_prediction==0:
            print("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
            print("Normal Packet(Not Exfiltration)\n")
        else:
            print("Something wrong")    


        if keylogging_prediction==1:
            print("\n&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
            print("Keylogging Detected\n")
        elif keylogging_prediction==0:
            print("&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&")
            print("Normal Packet(Not Keylogging)\n")
        else:
            print("Something wrong")    


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

    elif hasattr(packet, 'udp'):
        time_since_previous_frame_in_stream=0#packet['TCP'].time_delta
        time_since_first_frame_in_stream=0#packet['TCP'].time_relative
        time_since_first_frame_udp=packet['UDP'].time_relative
        
        sport=packet['UDP'].srcport
        dport=packet['UDP'].dstport   
        protocol=5#packet.transport_layer
        length=packet.length#packet['UDP'].length
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

        packet_df_os_scan=scaler_model[2].transform(packet_df_os_scan.values)
        packet_df_service_scan=scaler_model[3].transform(packet_df_service_scan.values)

        os_scan_prediction_udp=prediction_model[2].predict(packet_df_os_scan)[0]
        service_scan_prediction_udp=prediction_model[3].predict(packet_df_service_scan)[0]


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

    






load_models()

parser.add_option('-m', dest = 'mode',
                      type = 'int',
                      help = '1: Continuous Monitoring, 2: Instance Check',
                      default=1)   


parser.add_option('-f', dest = 'file_path',
                      type = 'string',
                      help = 'File path of the pcap file being refernced for instance check',
                      default='./')#current file path is default  is this the correct way to do it?


parser.add_option('-p', dest = 'packet_number',
                      type = 'int',
                      help = 'Packet number in pcap file, first packet is 1',
                      default=1)#current file path is default  is this the correct way to do it?


parser.add_option('-i', dest = 'interface',
                      type = 'int',
                      help = 'interface: 1->eth0, 2->wlan',
                      default=1)

#print("Welcome to IDS Project_V2:")
#print("Select Mode:")
#print("1...........Continuous Monitoring")
#print("2...........Instance Check")

(options, args) = parser.parse_args()

run_mode=options.mode
pkt_index=options.packet_number
pkt_file_path=options.file_path
interface_=options.interface


if run_mode==1:#continuous monitoring
    #while(True):
     #   k=0'
    if interface_==1: 
        intrusion_detection_sniffing("eth0")
    elif interface_==2:
        intrusion_detection_sniffing("wlan")  
    else:
        print("Invalid selection")
        exit()      
elif run_mode==2:
    instance_check(pkt_index,pkt_file_path)
else:
    print("Invalid selection")   
    exit()



#intrusion_detection_sniffing()