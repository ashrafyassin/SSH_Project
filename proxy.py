
#!/usr/bin/python2.7

import sys ,os
import socket
import threading

f1,f2='',''
start_encrypt_client=False
start_encrypt_Server=False
first_time_s=True
first_time_c=True

def server_loop(local_host,local_port,remote_host,remote_port):
    
    # create the server object
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # lets see if we can stand up the server
    try:
        server.bind((local_host,local_port))
    except:
        print "[!!] Failed to listen on %s:%d" % (local_host, local_port)
        print "[!!] Check for other listening sockets or correct permissions"
        sys.exit(0)
    
    # listen with 5 backlogged--queued--connections
    server.listen(5)
    
    while True:
        client_socket, addr = server.accept()
        
        # print out the local connection information 
        print"[+] Received incomming connections from %s:%d" % (addr[0],addr[1])
        
        # start a new thread to talk to the remote host
        proxy_thread = threading.Thread(target=clinet_handler,args=(client_socket,remote_host,remote_port))
        
        proxy_thread.start()
        
def clinet_handler(client_socket,remote_host,remote_port):
 try:
	# open server-proxy connection 
	server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server_socket.connect((remote_host,remote_port))
	# make it non-blocking sockets
	server_socket.setblocking(0)
	client_socket.setblocking(0)
	client_data = ''
	server_reply = ''
	#transfer data between client-server
	while True:
		#ask the client for the keys 
		#client_socket.send("do you want do do")
		#recieve all the client data 
		while True:
			try:
				c_data = client_socket.recv(2048)
			except socket.error:
				break
			client_data+=c_data
		if(len(client_data)>0):
			clien_flush(client_data)
			server_socket.send(client_data)
			client_data = ''

		#recieve all the server data 
		while True:
			try:
				s_reply = server_socket.recv(2048)
			except socket.error:
				break
			server_reply+=s_reply
		if(len(server_reply)>0):
			server_flush(server_reply)
			client_socket.send(server_reply)
			server_reply = ''
	
	#close the server and client socket
 except KeyboardInterrupt:
	client_socket.close()
	server_socket.close()
	os.system("sudo pkill python \n")
	sys.exit(0)
def clien_flush(data):
	global start_encrypt_client,start_encrypt_Server,f2
	global first_time_s,first_time_c
	data_size = len(data)			
	result =  repr(data[4:-8])

	if start_encrypt_client  :
	     if first_time_c :
		first_time_c=False
	     else :
		while data_size > 0 :
			packet_len = (16**6)*ord(data[0]) + (16**4)*ord(data[1])+ (16**2)*ord(data[2]) + ord(data[3])
			single_data = data[:4+packet_len]
			data_size -= 4+8+packet_len
			index = 4+8+packet_len
			data = data[index:]		        	
			f2.write(single_data)
			#sys.stdout.write(single_data)
			f2.flush()	      
def server_flush(data):
	global start_encrypt_client,start_encrypt_Server,f1
	global first_time_s,first_time_c
	data_size = len(data)			
	result =  repr(data[4:-8])

	if result.find("\\n\\x15\\x00\\x00") != -1:# new keys were sent
		start_encrypt_client=True
		start_encrypt_Server=True

	if start_encrypt_Server :
	     if first_time_s :
		first_time_s=False
		f1.write(data[-8+-68:-8])
		f1.flush()
	     else :
	
		while data_size > 0 :
			packet_len = (16**6)*ord(data[0]) + (16**4)*ord(data[1])+ (16**2)*ord(data[2]) + ord(data[3])
			#print "s len in prox" +str(packet_len)
			single_data = data[:4+packet_len]
			data_size -= 4+8+packet_len
			index = 4+8+packet_len
			data = data[index:]		        	
			f1.write(single_data)
			#sys.stdout.write(single_data)
			f1.flush()

def main():
    # cursory check of command line args
    if len(sys.argv[1:]) != 4:
        print "Usage: ./proxy.py [localhost] [localport] [remotehost] [remoteport]"
        print "Example: ./proxy.py 127.0.0.1 9000 10.11.132.1 9000"
        sys.exit(0)
    
    # set up listening parameters
    local_host = sys.argv[1]
    local_port = int(sys.argv[2])
    
    # set up remote targets
    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])
    
    # this tells our proxy to connect and receive data before sending to the remote host

    # now spin up our listening socket
    global f1,f2	
    try:
	f1 = open('server-data.txt','wb', os.O_NONBLOCK)
	f2 = open('client-data.txt','wb', os.O_NONBLOCK)
  	server_loop(local_host,local_port,remote_host,remote_port)
    except KeyboardInterrupt:
	os.system("sudo pkill python \n")
	sys.exit(0)
    
if __name__ == "__main__":
 main()
