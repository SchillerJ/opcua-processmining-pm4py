"""
A module containing classes for describing CoAP PCAP records and flows.
"""

from asyncio.log import logger
from modules.flows.flow_record import FlowRecord


class CoapFixedHeader():
    """
    A class for describing the fixed header of a CoAP PCAP record.
    """

    def __init__(self, packet):
        pass

    def __str__(self):
        return json.dumps(self.__dict__, default=str)

    def __get_client_ids(self, packet) -> dict:
        """
        Handles the client id of a CoAP PCAP record.
        """
        pass

    def __find_client_id(self, key: str) -> str or None:
        """
        Finds the client id of a CoAP PCAP record.
        """
        pass

    def get_mqtt_fixed_header(self) -> dict:
        """
        Returns a dictionary containing the fixed header of a CoAP PCAP record.
        """
        pass


class CoapVariableHeader():
    """
    A class for describing the variable header of a CoAP PCAP record.
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
        Returns a dictionary containing the variable header of a CoAP PCAP record.
        """
        pass


class CoapRecord(FlowRecord):
    """
    A class for describing CoAP PCAP records and flows.
    """

    def __init__(self, packet):
        super(CoapRecord,self).__init__(packet)

    def __get_record_id(self):
        """
        Get the record id of a CoAP PCAP record.
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
