"""
A module containing classes for describing MQTT flows in IPFIX.
"""

import json
from modules.netflow_tmp.ipfix import IPFIXFieldTypes


class IpfixTemplate():
    """
    A class for describing an IPFIX template for IoT flows.
    """
    iot_specific_ipfix_ies = [
        (32769, "mqttQoS", "unsigned16"),
        (32770, "mqttControlType", "unsigned16"),
        (32771, "mqttPacketId", "unsigned16"),
        (32772, "mqttTopic", "string"),
        (32773, "mqttSrcClientId", "string"),
        (32774, "mqttDstClientId", "string"),
        (32775, "mqttCorrelationData", "string"),
        (32776, "opcuaservicenodeID", "string"),
        (32777, "opcuarequesthandle", "string") ]

    @classmethod
    def add_iot_ies_to_netflow_lib(cls):
        """
        Add IoT specific IPFIX IEs to the IPFIX library.
        """
        for ipfix_ie in cls.iot_specific_ipfix_ies:
            IPFIXFieldTypes.iana_field_types.append(ipfix_ie)

    @classmethod
    def get_current_ipfix_template(cls):
        """
        Get the current IPFIX template for IoT flows.
        """
        return OpcuaIpfix().get_dict().keys()


class MqttIpfix():
    """
    A class for describing an IPFIX template for MQTT flows.
    """

    # pylint: disable=too-many-instance-attributes
    def __init__(self):
        self.source_ipv4_address = None
        self.destination_ipv4_address = None
        self.protocol_identifier = None
        self.source_transport_port = None
        self.destination_transport_port = None
        self.flow_start_nanoseconds = None
        self.flow_end_nanoseconds = None
        self.flow_duration_microseconds = None
        self.mqtt_qos = None
        self.mqtt_control_type = None
        self.mqtt_packet_id = None
        self.mqtt_topic = None
        self.mqtt_src_client_id = None
        self.mqtt_dst_client_id = None
        self.mqtt_correlation_data = None

    def __str__(self):
        return json.dumps(self.__dict__, default=str)

    def get_dict(self) -> dict:
        """
        Convert the MQTT IPFIX object to a dictionary.
        """
        return {
            "sourceIPv4Address": self.source_ipv4_address,
            "destinationIPv4Address": self.destination_ipv4_address,
            "protocolIdentifier": self.protocol_identifier,
            "sourceTransportPort": self.source_transport_port,
            "destinationTransportPort": self.destination_transport_port,
            "flowStartNanoseconds": self.flow_start_nanoseconds,
            "flowEndNanoseconds": self.flow_end_nanoseconds,
            "flowDurationMicroseconds": self.flow_duration_microseconds,
            "mqttQoS": self.mqtt_qos,
            "mqttControlType": self.mqtt_control_type,
            "mqttPacketId": self.mqtt_packet_id,
            "mqttTopic": self.mqtt_topic,
            "mqttSrcClientId": self.mqtt_src_client_id,
            "mqttDstClientId": self.mqtt_dst_client_id,
            "mqttCorrelationData": self.mqtt_correlation_data
        }

# TODO
class CoapIpfix():
    """
    A class for describing an IPFIX template for CoAP flows.
    """

     # pylint: disable=too-many-instance-attributes
    def __init__(self):
        pass

    def __str__(self):
        return json.dumps(self.__dict__, default=str)

    def get_dict(self) -> dict:
        pass

# TODO
class OpcuaIpfix():
    """
    A class for describing an IPFIX template for OPC-UA flows.
    """

    # pylint: disable=too-many-instance-attributes
    def __init__(self):
        self.source_ipv4_address = None
        self.destination_ipv4_address = None
        self.protocol_identifier = None
        self.source_transport_port = None
        self.destination_transport_port = None
        self.opcua_servicenodeID = None
        self.opcua_requesthandle = None

    def __str__(self):
        return json.dumps(self.__dict__, default=str)

    def get_dict(self) -> dict:
        """
        Convert the OPCUA IPFIX object to a dictionary.
        """
        return {
            "sourceIPv4Address": self.source_ipv4_address,
            "destinationIPv4Address": self.destination_ipv4_address,
            "protocolIdentifier": self.protocol_identifier,
            "sourceTransportPort": self.source_transport_port,
            "destinationTransportPort": self.destination_transport_port,

        }
    
    
"""
            "opcuaservicenodeID": self.opcua_servicenodeID,
            "opcuarequesthandle": self.opcua_requesthandle

             self.flow_start_nanoseconds = None
             self.flow_end_nanoseconds = None
             self.flow_duration_microseconds = None

            "flowStartNanoseconds": self.flow_start_nanoseconds,
            "flowEndNanoseconds": self.flow_end_nanoseconds,
            "flowDurationMicroseconds": self.flow_duration_microseconds,
"""