import os,sys
from subprocess import call


if __name__ == "__main__" :

	print "\033[96m"+ "you want to connect to proxy ?"
	sys.stdout.write("(yes/no)...  "+"\033[91m")
	ans= raw_input()

	if ans=="yes" :
		print "\033[0m"+"connecting to Proxy Server"
		call(['sudo' ,'iptables', '-t' ,'nat', '-A' ,'OUTPUT', '-p', 'tcp' ,'--dport' ,'22' ,'-j' ,'DNAT' ,'--to-destination' ,'132.68.60.103'])
		call(['./ssh',sys.argv[1],'-c','aes128-ctr'])


	else:
		print "\033[0m"+"connecting to Server directly"
		call(['sudo' ,'iptables', '-t' ,'nat', '-D' ,'OUTPUT', '-p', 'tcp' ,'--dport' ,'22' ,'-j' ,'DNAT' ,'--to-destination' ,'132.68.60.103'])
		call(['ssh',sys.argv[1]])
