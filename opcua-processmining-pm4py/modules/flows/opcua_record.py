"""
A module containing classes for describing OPC-UA PCAP records and flows.
"""

from collections import namedtuple
import hashlib
import json
import pandas as pd
from ipaddress import ip_address
from modules.flows.ipfix_template import MqttIpfix
from modules.flows.flow_record import FlowRecord

#servicenodeid_numeric bestimmt um welche Art von Nachricht es sich handelt
ServiceNode_ids = {446: "OpenSecureChannelRequest", 449: "OpenSecureChannelResponse",
            631: "ReadRequest", 634: "ReadResponse",
            673: "WriteRequest", 676: "WriteResponse",
            826: "PublishRequest", 829: "PublishResponse"}

"""
Einige mögliche Pyshark OPCUA-Infos:
'transport_type', 'transport_chunk', 'transport_size', 'transport_scid', 
'security_tokenid', 'security_seq', 'security_rqid', '', 
'servicenodeid_encodingmask', 'servicenodeid_nsid', 'servicenodeid_numeric', 
'timestamp', 'requesthandle', 'serviceresult', 
'diag_mask', 'diag_has_symbolic_id', 'diag_has_namespace', 'diag_has_localizedtext', 
'diag_has_locale', 'diag_has_additional_info', 'diag_has_inner_statuscode', 'diag_has_inner_diagnostic_code', 
'variant_arraysize', 'expandednodeid_mask', 'nodeid_encodingmask', 
'expandednodeid_has_server_index', 'expandednodeid_has_namespace_uri', 
'nodeid_numeric', 'extobj_mask', 'extobj_has_binary_body', 'extobj_has_xml_body', 
'datavalue_mask', 'datavalue_has_value', 'datavalue_has_statuscode', 'datavalue_has_source_timestamp', 
'datavalue_has_server_timestamp', 'datavalue_has_source_picoseconds', 'datavalue_has_server_picoseconds', 
'variant_has_value', 'int32' 
"""


"OPCU Header -> Future Work"
class OpcuaFixedHeader():
    """
    A class for describing the fixed header of a OPC-UA PCAP record.
    """

    def __init__(self, packet):
        pass

    def __str__(self):
        return json.dumps(self.__dict__, default=str)

    def __get_client_ids(self, packet) -> dict:
        """
        Handles the client id of a OPC-UA PCAP record.
        """
        pass

    def __find_client_id(self, key: str) -> str or None:
        """
        Finds the client id of a OPC-UA PCAP record.
        """
        pass

    def get_mqtt_fixed_header(self) -> dict:
        """
        Returns a dictionary containing the fixed header of a OPC-UA PCAP record.
        """
        pass

"OPCU Header -> Future Work"
class OpcuaVariableHeader():
    """
    A class for describing the variable header of a OPC-UA PCAP record.
    """

    def __init__(self, packet, control_type: int, qos: int):
        pass

    def __str__(self):
        return json.dumps(self.__dict__, default=str)

    def __parse_correlation_data(self, tcp_payload: str, control_type: int, qos: int) -> str or None:
        pass

    def __find_correlation_data(self, properties: bytearray, current_offset: int) -> bytearray or None:
        pass

    def get_mqtt_variable_header(self) -> dict:
        """
        Returns a dictionary containing the variable header of a OPC-UA PCAP record.
        """
        pass


class OpcuaRecord(FlowRecord):
    """
    A class for describing OPC-UA PCAP records and flows.
    """        
    def __init__(self, packet, counter: int, activity_dict: dict):
        # general fields layer 3 and 4
        self.timestamp = packet.sniff_time
        self.source_ip = ip_address(packet.ip.src)
        self.source_port = int(packet.tcp.srcport)
        self.destination_ip = ip_address(packet.ip.dst)
        self.destination_port = int(packet.tcp.dstport)
        self.protocol = int(packet.ip.proto)
               
        #ID that defines Msg-Type (Read/Write/Publish/OpenSecureChannel + -Request/-Response)
        self.servicenodeID = packet.opcua.servicenodeid_numeric
       
        
        #recordID that is definde with a 5-Tuple (IP's, Ports and Protocol)
        self.record_id = self.__get_record_id()
        
        #Defines the corresponding Response to a Request
        self.requesthandle = packet.opcua.requesthandle
        self.timestamps = {}
        self.flow_id = 0
        self.pack_id = counter
        self.dict_node_strings = {}          
        #save pack_id in list
        self.dict_node_strings[1] = self.pack_id


        
        
#set node_string variable
        #either set node_string with pack_length +  node_strings (f.ex. WriteRequest or ReadRequest)       
        if hasattr(packet.opcua, 'nodeid_string'):            
                self.node_string = packet.captured_length
                self.node_string += str(packet.opcua.nodeid_string.all_fields)
        #or with WriteResponse Values           
        elif self.servicenodeID == '676':
                self.response_string = 'WriteResp'
                index=0
                while index < len(packet.opcua.results.all_fields):
                    if '0x00000000' in str(packet.opcua.results.all_fields[index]):
                        self.response_string += '[GOOD]'
                        index +=1
                    else:
                        self.response_string += '[BadTypeMismatch]'
                        index += 1
            
                self.node_string = self.response_string
        else:
                self.node_string = 'NULL'
                
        
        #Or with Handshake + Handshake Value       
        if hasattr(packet.opcua, 'variant_has_value') and hasattr(packet.opcua, 'nodeid_string'):
            if 'HANDSHAKE.CONFIRM' in packet.opcua.nodeid_string or 'Handschacke.CONFIRM' in packet.opcua.nodeid_string or 'Handschake.CONFIRM' in packet.opcua.nodeid_string:
                
                self.node_string = ''
                
                index=0
                while index < len(packet.opcua.nodeid_string.all_fields):
                        self.node_string += str(packet.opcua.nodeid_string.all_fields[index])
                        index += 1
                self.node_string += packet.opcua.Boolean

        
#insert or update activity (node_strings) into activity_dict and change pack-node-string to corresponding key
        if self.node_string in activity_dict.values():
              key = [k for k, v in activity_dict.items() if v == self.node_string][0]
              self.node_string = key     
           
        elif not self.node_string in activity_dict.values():   
            last_key = len(activity_dict)
            activity_dict[last_key+1] = self.node_string
            self.node_string = last_key+1
        else:
            print("Could not update or insert into activity_dict")



 

#if counter (same as in probe-> should be set to max number of packs) reached, export the activity-list to excel-sheet
        if counter == 24444:
            df_actlist = pd.DataFrame([activity_dict])
        
            df_actlist = df_actlist.T
            path = r"PM4PY-activity_dict.xlsx"
            with pd.ExcelWriter(path) as engine:
                df_actlist.to_excel(excel_writer=engine, sheet_name="activity_dict")
                
        self.csv_string = f'{self.pack_id},{self.timestamp},{self.source_port},{self.servicenodeID},{self.record_id},{self.node_string}'


    def __get_record_id(self):
        """
        Get the record id of a OPC-UA PCAP record.
        """
        
        
        
        FlowTuple = namedtuple("FlowTuple", ["src_ip", "src_port", "dst_ip",
                                             "dst_port", "protocol"])
        
        
        
        # normal control flow
        if int(self.servicenodeID) in (446, 631, 673, 826):
            quintuple = FlowTuple(src_ip=self.source_ip,
                                  src_port=self.source_port,
                                  dst_ip=self.destination_ip,
                                  dst_port=self.destination_port,
                                  protocol=self.protocol,
                                  )

        # reversed control flow
        else:
            quintuple = FlowTuple(src_ip=self.destination_ip,
                                  src_port=self.destination_port,
                                  dst_ip=self.source_ip,
                                  dst_port=self.source_port,
                                  protocol=self.protocol,
                                  )

        return hashlib.sha256(repr(quintuple).encode('utf-8')).hexdigest()
    
    
    def get_max_flows(self):
        """
        May be used in future work for flow builiding.
        """
        pass

    def get_ipfix_rep(self) -> dict:
        """
        May be used in future work for ipdix representation
        Returns the IPFIX representation of the record
        """
        ipfix_object = MqttIpfix()
        ipfix_object.source_ipv4_address = self.layer3_and_4.source_ip
        ipfix_object.destination_ipv4_address = self.layer3_and_4.destination_ip
        ipfix_object.protocol_identifier = self.layer3_and_4.protocol
        ipfix_object.source_transport_port = self.layer3_and_4.source_port
        ipfix_object.destination_transport_port = self.layer3_and_4.destination_port     
        ipfix_object.opcua_servicenodeID = self.servicenodeID
        ipfix_object.opcua_requesthandle = self.requesthandle
        
        return ipfix_object.get_dict()
