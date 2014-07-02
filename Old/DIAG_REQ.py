from scapy.all import *

#To dissect DIAG_RES packets
class DIAG_RES(Packet):
    name = "DIAG_RESPONSE"
    fields_desc=[ ByteField("REQ_ID", 0),
           	  IntEnumField("STATUS", None, { 0:"FAIL", 1:"SUCCESS"}),
                  IntEnumField("ERROR" , 0, { 0:"NO_ERROR", 1:"NOT_FOUND", 2:"BAD_INDEX", 3:"OUT_OF_RESSOURCES", 4:"UNKNOWN"})]


#To build DIAG_REQ packets
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


p = IP(proto=253, dst="10.10.0.99")/DIAG_REQ(SF_ID="NAT", TestPacket=1)/IP()
send(p)
