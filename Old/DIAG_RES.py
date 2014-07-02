import nfqueue, socket
from scapy.all import *
import os, MySQLdb

#Adding iptables rule
#os.system('iptables -t mangle -A PREROUTING -j NFQUEUE --queue-num 1')
os.system('iptables -t mangle -A INPUT -j NFQUEUE --queue-num 1')

# Open database connection
db = MySQLdb.connect("localhost","sfcuser","sfc123","SFC")
# prepare a cursor object using cursor() method
cursor = db.cursor()

class DIAG_RES(Packet):
    name = "DIAG_RESPONSE"
    fields_desc=[ ByteField("REQ_ID", 0),
           	  IntEnumField("STATUS", None, { 0:"FAIL", 1:"SUCCESS"}),
                  IntEnumField("ERROR" , 0, { 0:"NO_ERROR", 1:"NOT_FOUND", 2:"BAD_INDEX", 3:"OUT_OF_RESSOURCES", 4:"UNKNOWN"})]

class DIAG_REQ(Packet):
    name = "DIAG_REQUEST"
    fields_desc=[ ByteField("REQ_ID", 0),
                  ShortField("SF_Map_Index", None),
                  FieldLenField("SF_ID_Len", None, length_of="SF_ID"), 
                  StrLenField("SF_ID", "", length_from=lambda pkt:pkt.SF_ID_Len),
                  ByteField("TestPacket", 0)]

bind_layers(IP, DIAG_REQ, proto=253)
bind_layers(DIAG_REQ, IP, TestPacket=1)
bind_layers(DIAG_REQ, DIAG_RES)
bind_layers(DIAG_RES, IP)



def cb1(payload):
	data = payload.get_data()
	p = IP(data)
	if DIAG_REQ in p:
		p=p[DIAG_REQ]
		if IP in p:
			p = p[IP]

			p.show()
			print "Test packet extracted"
			payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(p), len(p))
		else:
			print "Error: No Test packet in DIAG_REQ"
			payload.set_verdict(nfqueue.NF_ACCEPT)
	else:
		print "Warning: No DIAG_REQ"
		payload.set_verdict(nfqueue.NF_ACCEPT)

def cb(payload):
	data = payload.get_data()
	p = IP(data)
	if DIAG_REQ in p:
		test=p[DIAG_REQ]
		if IP in test:
			print "Test packet extracted"
			test = test[IP]
			dst = p.dst
			test.show()
			#sys.exit(0)

		else:
			print "No Test packet in DIAG_REQ"


		print "SF_Map_Index: " + str(p[DIAG_REQ].SF_Map_Index)
		#Case1: Diagnostic of a specific SF Function
		if p[DIAG_REQ].SF_Map_Index==0: 
			print "Dignostic of a specific SF Function"
			try:
				sql = "SELECT SF FROM LocalSFs WHERE SF='%s'" % (p[DIAG_REQ].SF_ID)
				cursor.execute(sql)
				result = cursor.fetchone()

				#Preparing the DIAG_RES
				#Case1: SF Function not supported
				if result is None:
					print "SF Function not supported"
					req_id = p[DIAG_REQ].REQ_ID
					status = 0
					error = 1
					dest = p.src 
					res = IP(dst=dest)/p[DIAG_REQ]/DIAG_RES(REQ_ID = req_id, STATUS = status, ERROR=error)
					res.show2()
					send(res, verbose=0)
					payload.set_verdict(nfqueue.NF_DROP)

				#Case2: SF Function supported
				else:
					print "SF Function supported"
					print "Applying diagnostic on the specified SF Function"
					p.show2()
					#preparing the Diagnostic and sending the response
					payload.set_verdict(nfqueue.NF_DROP)
			except:
		   		print "Error: unable to fecth data"
				payload.set_verdict(nfqueue.NF_DROP)

		#Case2: Diagnostic of a specific SF Map
		elif p[DIAG_REQ].SF_Map_Index!=1:
			print "Dignostic of a specific SF Map"
			try:
				sql = "SELECT id FROM SFCRoutingTable WHERE SF_MAP_INDEX=%d" % (p[DIAG_REQ].SF_Map_Index)
				cursor.execute(sql)
				result = cursor.fetchone()

				#Preparing the DIAG_RES
				#Case1: SF Function not in the specified SF Map
				if result is None:
					print "SF Function not in the specified SF Map"
					req_id = p[DIAG_REQ].REQ_ID
					status = 0
					error = 2
					dest = p.src 
					res = IP(dst=dest)/p[DIAG_REQ]/DIAG_RES(REQ_ID = req_id, STATUS = status, ERROR=error)
					res.show2()
					send(res, verbose=0)
					payload.set_verdict(nfqueue.NF_DROP)

				#Case2: SF Function involved in the specified SF Map
				else:
					print "Applying diagnostic on the specified SF Function"
					#preparing the Diagnostic and sending the response
					
					sql = "SELECT nextSF FROM SFCRoutingTable WHERE SF_MAP_INDEX=%d" % (p[DIAG_REQ].SF_Map_Index)
					cursor.execute(sql)
					result = cursor.fetchone()
					if result is not None:
						req_id = p[DIAG_REQ].REQ_ID
						status = 1
						error = 0
						dest = p.src 
						res = IP(dst=dest)/p[DIAG_REQ]/DIAG_RES(REQ_ID = req_id, STATUS = status, ERROR=error)
						res.show2()
						send(res, verbose=0)
						payload.set_verdict(nfqueue.NF_DROP)
					payload.set_verdict(nfqueue.NF_DROP)
			except:
		   		print "Error: unable to fecth data"
				payload.set_verdict(nfqueue.NF_DROP)
			payload.set_verdict(nfqueue.NF_DROP)

		#Case2: Diagnostic of all SF Maps
		else: 
			print "Dignostic of all SF Maps"
			payload.set_verdict(nfqueue.NF_DROP)
	else:
		payload.set_verdict(nfqueue.NF_ACCEPT)

q = nfqueue.queue()
q.set_callback(cb)
q.open()
q.create_queue(1)

try:
	q.try_run()

except KeyboardInterrupt, e:
	print "interruption"
	os.system('iptables -t mangle -F')
	q.unbind(socket.AF_INET)
	q.close()



