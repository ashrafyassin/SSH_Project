#Packet sniffer in python
#For Linux - Sniffs all incoming and outgoing packets :)
#Silver Moon (m00n.silv3r@gmail.com)

import socket, sys ,os
from struct import *

#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b

#create a AF_PACKET type raw socket (thats basically packet level)
#define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()


f1 = open('server-data.txt','wb', os.O_NONBLOCK)
f2 = open('client-data.txt','wb', os.O_NONBLOCK) 
start_encrypt_client=False
start_encrypt_Server=False
first_time_s=True
first_time_c=True

	
# receive a packet
while True:
    packet = s.recvfrom(65565)

    #packet string from tuple
    packet = packet[0]

    #parse ethernet header
    eth_length = 14

    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
   ##### print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)

    #Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8 :
        #Parse IP header
        #take first 20 characters for the ip header
        ip_header = packet[eth_length:20+eth_length]

        #now unpack them :)
        iph = unpack('!BBHHHBBH4s4s' , ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4

        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);

    #####    print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)

        #TCP protocol
        if protocol == 6 :
            t = iph_length + eth_length
            tcp_header = packet[t:t+20]

            #now unpack them :)
            tcph = unpack('!HHLLBBHHH' , tcp_header)

            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4

        #####    print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + '   		Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)

            #get data from the packet

	    h_size = eth_length + iph_length + tcph_length * 4
            data_size = len(packet) - h_size			
            data = packet[h_size:]
	    #print 'data size = ' + str(data_size)
            result =  repr(data[4:-8])
	  
	   
	    if result.find("\\n\\x15\\x00\\x00") != -1:# new keys were sent
	       start_encrypt_client=True
	       start_encrypt_Server=True

	    index=0
	    if data_size != 0 :
		if source_port == 22 and start_encrypt_Server :
		     if first_time_s :
			first_time_s=False
			f1.write(data[-8+-64:-8])
		     else :
			
			while data_size > 0 :
	 			packet_len = (16**6)*ord(data[0]) + (16**4)*ord(data[1])+ (16**2)*ord(data[2]) + ord(data[3])
				single_data = data[4:4+packet_len]
				data_size -= 4+8+packet_len
				index = 4+8+packet_len
				data = data[index:]		        	
				f1.write(single_data)
				f1.flush()
		elif s_addr=='132.68.60.104' and dest_port==22 and start_encrypt_client  :
		     if first_time_c :
			first_time_c=False
		     else :
			while data_size > 0 :
	 			packet_len = (16**6)*ord(data[0]) + (16**4)*ord(data[1])+ (16**2)*ord(data[2]) + ord(data[3])
				single_data = data[4:4+packet_len]
				data_size -= 4+8+packet_len
				index = 4+8+packet_len
				data = data[index:]		        	
				f2.write(single_data)
				f2.flush()	      

