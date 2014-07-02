import nfqueue, socket
from scapy.all import *
import os

#Adding iptables rule
os.system('iptables -t mangle -A PREROUTING -j NFQUEUE --queue-num 1')

#To dissect DIAG_RES packets
class DIAG_RES(Packet):
    name = "DIAG_RESPONSE"
    fields_desc=[ ByteField("REQ_ID", 0),
           	  IntEnumField("STATUS", None, { 0:"FAIL", 1:"SUCCESS"}),
                  IntEnumField("ERROR" , 0, { 0:"NO_ERROR", 1:"NOT_FOUND", 2:"BAD_INDEX", 3:"NextSF_NOT_FOUND", 4:"NextSFLocator_NOT_FOUND", 5:"OUT_OF_RESSOURCES", 6:"UNKNOWN"})]


#To build DIAG_REQ packets
class DIAG_REQ(Packet):
    name = "DIAG_REQUEST"
    fields_desc=[ ByteField("REQ_ID", 0),
                  ShortField("SF_Map_Index", None),
                  FieldLenField("SF_ID_Len", None, length_of="SF_ID"), 
                  StrLenField("SF_ID", "", length_from=lambda pkt:pkt.SF_ID_Len),
                  FieldLenField("ES_SF_ID_Len", None, length_of="ES_SF_ID"), 
                  StrLenField("ES_SF_ID", "", length_from=lambda pkt:pkt.ES_SF_ID_Len),
                  ByteField("TestPacket", 0)]

bind_layers(IP, DIAG_REQ, proto=253)
bind_layers(DIAG_REQ, IP, TestPacket=1)
bind_layers(DIAG_REQ, DIAG_RES)
bind_layers(DIAG_RES, IP)

#Case1: Troubleshooting of a specific SF Function (SF_Map_Index==0)
	#Case1: SF Function not supported (SF_ID="NA")
p = IP(proto=253, dst="10.10.0.99")/DIAG_REQ(SF_ID="NA", TestPacket=0)
	#Case2: SF Function supported (SF_ID="NAT")
p = IP(proto=253, dst="10.10.0.99")/DIAG_REQ(SF_ID="NAT", TestPacket=0)

#Case2: Troubleshooting of a specific SF Map (SF_Map_Index>=1)
	#Case1: SF Function not in the specified SF Map (SF_Map_Index, SF_ID)
p = IP(proto=253, dst="10.10.0.99")/DIAG_REQ(SF_Map_Index=7, SF_ID="NAT", TestPacket=0)
	#Case2: SF Function involved in the specified SF Map (SF_Map_Index, SF_ID)
p = IP(proto=253, dst="10.10.0.99")/DIAG_REQ(SF_Map_Index=2, SF_ID="SF1", TestPacket=0)

#Case3: Troubleshooting of all SF Maps (SF_Map_Index==1)

p = IP(proto=253, dst="10.3.0.3")/DIAG_REQ(SF_Map_Index=2, SF_ID="SF1", ES_SF_ID="SF3", TestPacket=0)
#p.show2()
send(p)


def cb(p, payload):
	data = payload.get_data()
	p = IP(data)
	if DIAG_REQ in p:
		print "Answer received"
		res = p[DIAG_REQ]
		res.show()
		payload.set_verdict(nfqueue.NF_DROP)
	else:
		#print "No answer"
		payload.set_verdict(nfqueue.NF_DROP)

q = nfqueue.queue()
q.set_callback(cb)
q.open()
q.create_queue(1) #Same queue number of the rule
q.set_queue_maxlen(50000)

try:
	q.try_run()
except KeyboardInterrupt, e:
	print "interruption"
	os.system('iptables -t mangle -F')
	q.unbind(socket.AF_INET)
	q.close()