"""
Module for sniffing PCAP traffic, extract MQTT flows, and export them as IPFIX netflows.
"""

import argparse
import logging
import pyshark
from modules.flows.coap_record import CoapRecord
from modules.flows.mqtt_record import MqttRecord
from modules.flows.opcua_record import OpcuaRecord
from modules.mqtt_probe.flow_table import FlowTable

# logging
logger = logging.getLogger('mind2_probe')
ch = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

protocols = {"MQTT": 1, "CoAP": 2, "OPC-UA": 3}

class MIND2Probe:
    """
    A probe to sniff and export IoT traffic
    """
    def __init__(self, interface: str, capture_filter: str, sys_topic: bool, protocol: str, flows_table: FlowTable):
        self.__capture = None
        self.interface = interface
        self.capture_filter = capture_filter
        self.sys_topic = sys_topic
        self.protocol = protocol
        self.__flow_table = flows_table

    def run(self):
        """
        Sniffs MQTT traffic and process each packet.
        """
        logger.info(f'Probing {self.protocol.upper()} traffic in live capturing mode...')
        # capture packets
        print('Probe starts sniffing traffic or PCAP-File...')
        
        #pyshark methode zum capturen einer batchdate und filter auf opcua
        self.__capture = pyshark.FileCapture('batchdata.pcap', display_filter="opcua")
        
        #counter f.ex. used to give packets a unique, ongoing number
        counter = 1;
        #activity dict used in opcua_record to get a list with every activity
        activity_dict = {}
        
        for packet in self.__capture:
            # get mqtt or opcua packet
           iot_packet = self.__retrieve_packet(packet, counter, activity_dict)
            #filter out
           if iot_packet is None:
            continue
            #pcap to flow conversion
           self.__flow_table.process_flow(iot_packet)
           
           #Complete Batchdata is equivalent to Counter 24444
           if counter == 24444:
               print("Going into Panda Method to export Data to local file")
               self.__flow_table.panda()
               break
           counter +=1
           
    def stop(self):
        """
        Stops the capturing of packets.
        """
        self.__capture.close()

    # get packet and filter out protocol
    def __retrieve_packet(self, packet, counter: int, activity_dict: dict) -> MqttRecord:
        """
        Converts packets to MQTT packets. None-MQTT packets are filtered out.
        If the packet is a SYS topic, it is filtered out when the sys-topic flag is set to false.
        """
        # check if packet is a mqtt packet
        if hasattr(packet, 'mqtt') and self.protocol == "mqtt":
            mqtt_packet = MqttRecord(packet) 
                # check if config allows the capturing of SYS topcis
            if (mqtt_packet.variable_header.sys_topic is True and self.sys_topic) or (mqtt_packet.variable_header.sys_topic is False):
                return mqtt_packet
        elif self.protocol == "coap":
            logger.info(f'{self.protocol.upper()} to be implemented in the future')
            # return CoapRecord(packet)           
        elif self.protocol == "opcua":
            opcua_packet = OpcuaRecord(packet, counter, activity_dict)   
            return opcua_packet

        return None


if __name__ == "mind2-probe.probe":
    logger.error("The probe is currently meant to be used as a CLI tool only.")
    logger.error("Use 'python3 -m mqtt-probe.probe -h' in your console for additional help.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="A probe for sniffing and exporting MQTT traffic.")
    # required arguments
    parser.add_argument("--interface", "-i", help="The interface to sniff on.", required=True)
    parser.add_argument("--collector", "-c", help="IP of the collector to use for exporting flows.", required=True)
    parser.add_argument("--port", "-p", help="Port of the collector to use for exporting flows.", required=True)
    parser.add_argument("--protocol", "-iot", help="The IoT protocol to filter (mqtt, coap or opcua).", required=True)
    # optional arguments
    parser.add_argument("--filter", "-f", default="", help="The filter to use for sniffing.")
    parser.add_argument("--sys-topic", "-s", action="store_true", help="Allow the capturing of SYS topics.")
    parser.add_argument("--log-level", "-l", help="The log level to use.", default="INFO")

    # parse arguments
    args = parser.parse_args()

    # set log level
    logger.setLevel(args.log_level)
    ch.setLevel(args.log_level)

    try:
        # initializing the flow table
        logger.debug('Setting up flow table')
        flow_table = FlowTable(args.collector, int(args.port), logger)
        # start sniffing
        sniffer = MIND2Probe(args.interface, args.filter, args.sys_topic, args.protocol, flow_table)
        sniffer.run()
    except KeyboardInterrupt:
        logger.info("Received KeyboardInterrupt, exiting...")
        sniffer.stop()
