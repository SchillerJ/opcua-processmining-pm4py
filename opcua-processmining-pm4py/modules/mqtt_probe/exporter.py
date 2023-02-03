"""
A module for creating and exporting MQTT-IPFIX/CoAP-IPFIX/OPC-UA flows.
"""

import socket
import ipfix.ie
import ipfix.message
import ipfix.template
from modules.flows.ipfix_template import IpfixTemplate
from modules.flows.mqtt_record import MqttRecord, control_types_mapping
from modules.flows.coap_record import CoapRecord
from modules.flows.opcua_record import OpcuaRecord

# initialize socket for sending IPFIX flows to collector
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


class MqttIpfixExporter():
    """
    An exporter for exporting MQTT-based IPFIX messages to a collector.
    """

    def __init__(self, collector_ip, port, logger):
        self.collector_ip = collector_ip
        self.port = port
        self.logger = logger

    def get_ipfix_template(self):
        """
        Initializes an IPFIX template
        """
        for index, info_ele in enumerate(IpfixTemplate.iot_specific_ipfix_ies, start=1):
            ie_string = f"{info_ele[1]}(9999/{index})<{info_ele[2]}>"
            if info_ele[2] == "string":
                ie_string += "[255]"
            ipfix.ie.for_spec(ie_string)
        ipfix.ie.use_iana_default()
        ipfix.ie.use_5103_default()
        return ipfix.template.from_ielist(256, ipfix.ie.spec_list(IpfixTemplate.get_current_ipfix_template()))

    def __get_ipfix_message_buffer(self):
        """
        Initializes an IPFIX message buffer based on the IPFIX template provided in
        >>> self.__get_ipfix_template()
        """
        ipfix_message = ipfix.message.MessageBuffer()
        ipfix_message.begin_export(odid=2)
        ipfix_message.add_template(self.get_ipfix_template(), export=True)
        ipfix_message.export_ensure_set(256)
        return ipfix_message

    # send IPFIX message to collector
    def export_mqtt_ipfix(self, flow: MqttRecord):
        """
        Sends an IPFIX message to the collector.
        """
        ipfix_message_buffer = self.__get_ipfix_message_buffer()
        flow_ipfix = flow.get_ipfix_rep()
        ipfix_message_buffer.export_namedict(flow_ipfix)
        s.sendto(ipfix_message_buffer.to_bytes(), (self.collector_ip, self.port))
        self.logger.info('\033[0;36m' +
                         f"IPFIX message ({control_types_mapping[flow.fixed_header.control_type]}) sent to {self.collector_ip}:{self.port}" +
                         '\033[0m')

class MqttIpfixExporter():
    """
    An exporter for exporting MQTT-based IPFIX messages to a collector.
    """

    def __init__(self, collector_ip, port, logger):
        self.collector_ip = collector_ip
        self.port = port
        self.logger = logger

    def get_ipfix_template(self):
        """
        Initializes an IPFIX template
        """
        for index, info_ele in enumerate(IpfixTemplate.iot_specific_ipfix_ies, start=1):
            ie_string = f"{info_ele[1]}(9999/{index})<{info_ele[2]}>"
            if info_ele[2] == "string":
                ie_string += "[255]"
            ipfix.ie.for_spec(ie_string)
        ipfix.ie.use_iana_default()
        ipfix.ie.use_5103_default()
        return ipfix.template.from_ielist(256, ipfix.ie.spec_list(IpfixTemplate.get_current_ipfix_template()))

    def __get_ipfix_message_buffer(self):
        """
        Initializes an IPFIX message buffer based on the IPFIX template provided in
        >>> self.__get_ipfix_template()
        """
        ipfix_message = ipfix.message.MessageBuffer()
        ipfix_message.begin_export(odid=2)
        ipfix_message.add_template(self.get_ipfix_template(), export=True)
        ipfix_message.export_ensure_set(256)
        return ipfix_message

    # send IPFIX message to collector
    def export_mqtt_ipfix(self, flow: OpcuaRecord):
        """
        Sends an IPFIX message to the collector.
        """
        ipfix_message_buffer = self.__get_ipfix_message_buffer()
        flow_ipfix = flow.get_ipfix_rep()
        ipfix_message_buffer.export_namedict(flow_ipfix)
        s.sendto(ipfix_message_buffer.to_bytes(), (self.collector_ip, self.port))
        #self.logger.info('\033[0;36m' +
         #                f"IPFIX message ({control_types_mapping[flow.fixed_header.control_type]}) sent to {self.collector_ip}:{self.port}" +
         #                '\033[0m')

