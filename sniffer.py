import nfqueue, socket
from scapy.all import *
import os

os.system('iptables -t mangle -A PREROUTING -j NFQUEUE --queue-num 0')
##iptables -t nat -A POSTROUTING -o tun1 -j SNAT –to-source 175.45.14.88:2000

count = 0

def cb(payload):
	global count
	count +=1
	data = payload.get_data()
	p = IP(data) 
	
	if TCP in p:
		print(str(count) + ": " + p.src + "=>" + p.dst)
		print(" : Protocol=" + str(p.proto) + " --SPORT==" + str(p[TCP].sport) + " --DPORT==" + str(p[TCP].dport))
		#p[IP].summary()
	else:
		print(str(count) + ": " + p.src + "=>" + p.dst)
		#p[IP].summary()

	payload.set_verdict(nfqueue.NF_ACCEPT)


q = nfqueue.queue()
q.open()
q.unbind(socket.AF_INET)
q.bind(socket.AF_INET)
q.set_callback(cb)
q.create_queue(0)

try:
	q.try_run()

except KeyboardInterrupt, e:
	os.system('iptables -t mangle -F')
	print "interruption"
	q.unbind(socket.AF_INET)
	q.close()