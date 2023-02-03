"""
A module containing classes for describing generic layers of records and flows.
"""
from ipaddress import ip_address
import json


class FlowRecord():
    """
    A class for describing OPC-UA PCAP records and flows.
    """

    def __init__(self, packet):
        self.layer3_and_4 = Layer3And4(packet)

    def __str__(self):
        return json.dumps(self.__dict__, default=str)

    def __get_record_id(self):
        """
        Get the record id of a OPC-UA PCAP record.
        """
        pass

    def get_max_flows(self):
        """
        Set the maximum number of flows for the current record.
        """
        pass

    def get_ipfix_rep(self) -> dict:
        """
        Returns the IPFIX representation of the record
        """
        pass

class Layer3And4():
    """
    A class for describing Layer 3 and 4 of a MQTT PCAP record.
    """

    def __init__(self, packet):
        self.timestamp = packet.sniff_time
        self.source_ip = ip_address(packet.ip.src)
        self.source_port = int(packet.tcp.srcport)
        self.destination_ip = ip_address(packet.ip.dst)
        self.destination_port = int(packet.tcp.dstport)
        self.protocol = int(packet.ip.proto)

    def __str__(self):
        return json.dumps(self.__dict__, default=str)

    def get_layer3_and_3(self) -> dict:
        """
        Returns a dictionary containing the layer 3 and 4 of a MQTT PCAP record.
        """
        return {
            "timestamp": self.timestamp,
            "source_ip": str(self.source_ip),
            "source_port": self.source_port,
            "destination_ip": str(self.destination_ip),
            "destination_port": self.destination_port,
            "protocol": self.protocol
        }
