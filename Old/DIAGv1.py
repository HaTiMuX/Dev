import nfqueue, socket
from scapy.all import *
#from DIAG_Funcs import *
import os, MySQLdb

#Adding iptables rule
os.system('iptables -t mangle -A INPUT -j NFQUEUE --queue-num 1')

# Open database connection
db = MySQLdb.connect("localhost","sfcuser","sfc123","SFC")
# prepare a cursor object using cursor() method
cursor = db.cursor()

diag=1
PDP_IP="10.10.0.1"

class DIAG_RES(Packet):
    name = "DIAG_RESPONSE"
    fields_desc=[ ByteField("REQ_ID", 0),
           	  IntEnumField("STATUS", None, { 0:"FAIL", 1:"SUCCESS"}),
                  IntEnumField("ERROR" , 0, { 0:"NO_ERROR", 1:"NOT_FOUND", 2:"BAD_INDEX", 3:"NextSF_NOT_FOUND", 4:"NextSFLocator_NOT_FOUND", 5:"OUT_OF_RESSOURCES", 6:"UNKNOWN"})]

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

def MSG_DIAG_RES(dest, old_req, req_id, status, error):
	res = IP(dst=dest)/old_req/DIAG_RES(REQ_ID=req_id, STATUS=status, ERROR=error)
	#res.show2()
	send(res, verbose=0)


def MSG_DIAG_REQ(dest, req_id, index, sf, es_sf, test_packet):
	res = IP(dst=dest)/DIAG_REQ(REQ_ID=req_id, SF_Map_Index=index, SF_ID=sf, ES_SF_ID=es_sf, TestPacket=test_packet)
	send(res, verbose=0)

def Verify_SF(SF):
	error=0
	res = None
	try:
		sql = "SELECT SF FROM LocalSFs WHERE SF='%s'" % (SF)
		cursor.execute(sql)
		res = cursor.fetchone()
		return res, error

	except:
   		print "Error: unable to fecth data (Verifying Local SF)"
		error=1
		#sys.exit(0)
		return res, error

def Verify_SFMap(index):
	error=0
	res = None
	try:
		sql = "SELECT id FROM SFCRoutingTable WHERE SF_MAP_INDEX=%d" % (index)
		cursor.execute(sql)
		res = cursor.fetchone()
		return res, error

	except:
   		print "Error: unable to fecth data (Checking if the local SF is involved in the SF Map)"
		error=1
		#sys.exit(0)
		return res, error

def Select_NextSF(index):
	error=0
	SF = None
	try:
		sql = "SELECT nextSF FROM SFCRoutingTable WHERE SF_MAP_INDEX=%d" % (index)
		cursor.execute(sql)
		SF = cursor.fetchone()
		return SF[0], error

	except:
   		print "Error: unable to fecth data (Reading the next SF - SF Map Troubleshooting)"
		error=1
		#sys.exit(0)
		return SF, error


def Get_Locator(SF):
	error=0
	locator=None
	try:
		sql = "SELECT Locator FROM LocalLocators WHERE SF='%s'" % (SF)
		cursor.execute(sql)
		locator = cursor.fetchone()
		return locator, error

	except:
   		print "Error: unable to fecth data (Looking of the locator of the next SF - SF Map Troubleshooting)"
		payload.set_verdict(nfqueue.NF_DROP)
		error=1
		#sys.exit(0)
		return locator, error


def cb(payload):
	data = payload.get_data()
	p = IP(data)

	if DIAG_REQ in p:

		#Extracting the Test Packet if it exists
		test=p[DIAG_REQ]
		if IP in test:
			print "Test packet extracted"
			test = test[IP]
			dst = p.dst
			test.show()
			#sys.exit(0)
		else:
			print "No Test packet in DIAG_REQ"

		##################Troubleshooting##################
		print "SF_Map_Index: " + str(p[DIAG_REQ].SF_Map_Index) + "\n"

		#Case1: Troubleshooting a specific SF Function
		if p[DIAG_REQ].SF_Map_Index==0: 
			print "Troubleshooting a specific SF Function"
			print "SF Identifier = %s\n" % p[DIAG_REQ].SF_ID
			result, error = Verify_SF(p[DIAG_REQ].SF_ID) #Verifying if the indicated SF is supported by the Node
			payload.set_verdict(nfqueue.NF_DROP)

			#Case1-1: SF Function supported
			if result is not None:
				print "SF Function supported"
				print "Applying diagnostic on the specified SF Function"

				#Troubleshooting Local SF succeeded
				if diag==1:
					print "Troubleshooting local SF succeeded"
					MSG_DIAG_RES(p.src, p[DIAG_REQ], p[DIAG_REQ].REQ_ID, 1, 0) #SUCCESS

				#Error in Troubleshooting the Local SF
				else:
					print "Error Troubleshooting local SF"
					MSG_DIAG_RES(p.src, p[DIAG_REQ], p[DIAG_REQ].REQ_ID, 0, 6) #UNKOWN

			#Case1-2: SF Function not supported
			else:
				print "SF Function not supported"
				MSG_DIAG_RES(p.src, p[DIAG_REQ], p[DIAG_REQ].REQ_ID, 0, 1) #SF_NOT_FOUND


		#Case2: Troubleshooting a specific SF Map
		elif p[DIAG_REQ].SF_Map_Index!=1 and p[DIAG_REQ].ES_SF_ID=="":
			print "Troubleshooting a specific SF Map"
			result, error = Verify_SFMap(p[DIAG_REQ].SF_Map_Index) #Check if the Local SF is involved in the specifyed Map
			payload.set_verdict(nfqueue.NF_DROP)

			#Case2-1: SF Function not in the specified SF Map
			if result is None:
				print "SF Function not involved in the specified SF Map, DIA_RES to the PDP"
				MSG_DIAG_RES(PDP_IP, p[DIAG_REQ], p[DIAG_REQ].REQ_ID, 0, 2) #BAD_INDEX

			#Case2-2: SF Function involved in the specified SF Map
			else:
				result, error = Verify_SF(p[DIAG_REQ].SF_ID) #Verifying if the indicated SF is supported by the Node

				#Case2-2-1: SF Function supported
				if result is not None:
					print "SF Function supported"
					print "Applying Troubleshooting tests on the specified SF Function"
					#Troubleshooting Local SF succeded 
					if diag==1:
						nextSF, error = Select_NextSF(p[DIAG_REQ].SF_Map_Index) #Select the next SF to which forward the DIAG_REQ
						print "Next SF = %s, error = %d" % (nextSF, error)

						#The Node is not the last in the SF Map
						if nextSF is not None:
							locator, error = Get_Locator(SF)
							#NextSFLocator Found
							if locator is not None:
								print "Forwarding DIAG_REQ to the next SF"
								MSG_DIAG_REQ(locator, p[DIAG_REQ].REQ_ID, p[DIAG_REQ].SF_Map_Index, nextSF, p[DIAG_REQ].ES_SF_ID , 0) #DIAG_REQ to nextSF

							#NextSFLocator Not Found
							elif (locator is None) or (error==1):
								print "NextSF Locator Not Found, DIA_RES to the PDP"
								MSG_DIAG_RES(PDP_IP, p[DIAG_REQ], p[DIAG_REQ].REQ_ID, 0, 4) #NextSFLocator_Not_Found

						#NextSF Not Found
						elif error==1:
							print "NextSF Not Found, DIA_RES to the PDP"
							MSG_DIAG_RES(PDP_IP, p[DIAG_REQ], p[DIAG_REQ].REQ_ID, 0, 3) #NextSF_Not_Found

						#The Node is the last in the SF Map
						else:
							print "The Node is the last in the SF Map, DIA_RES to the PDP"
							MSG_DIAG_RES(PDP_IP, p[DIAG_REQ], p[DIAG_REQ].REQ_ID, 1, 0) #NO_ERROR

					#Error in Troubleshooting the Local SF
					else:
						print "Error troubleshooting local SF, DIA_RES to the PDP"
						MSG_DIAG_RES(PDP_IP, p[DIAG_REQ], p[DIAG_REQ].REQ_ID, 0, 6) #UNKONWN

				#Case2-2-2: SF Function not supported
				else:
					print "SF Function %s not supported" % p[DIAG_REQ].SF_ID
					MSG_DIAG_RES(p.src, p[DIAG_REQ], p[DIAG_REQ].REQ_ID, 0, 1) #SF_NOT_FOUND

		#Case3: Troubleshooting a sequence in a specific SF Map
		elif p[DIAG_REQ].SF_Map_Index!=1 and p[DIAG_REQ].ES_SF_ID!="":
			print "Troubleshooting a sequence in a specific SF Map"
			print "Sequence end = %s" % p[DIAG_REQ].ES_SF_ID
			result, error = Verify_SFMap(p[DIAG_REQ].SF_Map_Index) #Check if the Local SF is involved in the sequence
			payload.set_verdict(nfqueue.NF_DROP)

			#Case3-1: SF Function involved in the specified sequence
			if result is not None:
				result, error = Verify_SF(p[DIAG_REQ].SF_ID) #Verifying if the indicated SF is supported by the Node

				#SF Function supported
				if result is not None:
					print "SF Function supported"
					print "Applying Troubleshooting tests on the specified SF Function"

					#Troubleshooting Local SF succeded 
					if diag==1:
						nextSF, error = Select_NextSF(p[DIAG_REQ].SF_Map_Index) #Select the next SF to which forward the DIAG_REQ
						print "Next SF = %s, error = %d" % (nextSF, error)

						#The Node is not the last in the SF Map
						if nextSF is not None:
							locator, error = Get_Locator(SF)
							#NextSFLocator Found
							if locator is not None:
								print "Forwarding DIAG_REQ to the next SF"
								MSG_DIAG_REQ(locator, p[DIAG_REQ].REQ_ID, p[DIAG_REQ].SF_Map_Index, nextSF, p[DIAG_REQ].ES_SF_ID , 0) #DIAG_REQ to nextSF

							#NextSFLocator Not Found
							elif (locator is None) or (error==1):
								print "NextSF Locator Not Found, DIA_RES to the PDP"
								MSG_DIAG_RES(PDP_IP, p[DIAG_REQ], p[DIAG_REQ].REQ_ID, 0, 4) #NextSFLocator_Not_Found

						#NextSF Not Found
						elif (nextSF is None) or (error==1):
							print "NextSF in the sequence Not Found, DIA_RES to the PDP\n"
							MSG_DIAG_RES(PDP_IP, p[DIAG_REQ], p[DIAG_REQ].REQ_ID, 0, 3) #NextSF_Not_Found


						#The Node is the last in the sequence
						elif nextSF==p[DIAG_REQ].ES_SF_ID:
							print "The Node is the last in the sequence, DIA_RES to the PDP"
							MSG_DIAG_RES(PDP_IP, p[DIAG_REQ], p[DIAG_REQ].REQ_ID, 1, 0) #NO_ERROR

					#Error in Troubleshooting the Local SF
					else:
						print "Error troubleshooting local SF, DIA_RES to the PDP"
						MSG_DIAG_RES(PDP_IP, p[DIAG_REQ], p[DIAG_REQ].REQ_ID, 0, 6) #UNKONWN

				#SF Function not supported
				else:
					print "SF Function %s not supported" % p[DIAG_REQ].SF_ID
					MSG_DIAG_RES(p.src, p[DIAG_REQ], p[DIAG_REQ].REQ_ID, 0, 1) #SF_NOT_FOUND

			#Case3-2: SF Function not in the sequence
			else:
				print "SF Function not involved in the sequence, DIA_RES to the PDP"
				MSG_DIAG_RES(PDP_IP, p[DIAG_REQ], p[DIAG_REQ].REQ_ID, 0, 2) #BAD_INDEX

		#Case4: Troubleshooting all SF Maps that involve the specified SF Function
		else: 
			print "Troubleshooting all SF Maps that involve SF Function %s" % p[DIAG_REQ].SF_ID
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