"""
A module for a flow table that stores the flows
"""
import pickle
import csv
from modules.flows.mqtt_record import  MqttRecord, incomplete_control_types, control_types_mapping
from modules.flows.opcua_record import OpcuaRecord
from modules.mqtt_probe.exporter import MqttIpfixExporter
import argparse
import sys
import pandas as pd


class FlowTable():


    def __init__(self, collector, port, logger):
        #currently used flows for every record id
        self.flow_table = {}
        #sorted out flows/packets
        self.lost_flows = {}
        #all flows with their flowID
        self.all_ordered_flows = {}
        self.flowcount = 1
        self.collector = collector
        self.port = port
        self.logger = logger
        self.exporter = MqttIpfixExporter(self.collector, self.port, logger)
        #dataframes for exporting sorted out flows/packets and all flows with flowID
        self.df_LostInTransit = pd.DataFrame([self.lost_flows])
        self.df_all = pd.DataFrame([self.all_ordered_flows])
        
    def process_flow(self, flow: OpcuaRecord):
        """
        Processes a opcua packet and updates the flow table.
        If the packet fits an existing flow, the flow is updated. If not, a new entry in the flow table is created.
        If the packet completes an existing flow, the flow is exported to the collector.
        """


        if self.__find(flow) is None:  # check if flow is already listed in flow table:
            self.__insert(flow)  # insert new flow into flow table

        else:
            self.all_ordered_flows[flow.pack_id] = flow
            self.__update(flow)  # update existing flow in flow table
            
            
    def __insert(self, flow: OpcuaRecord):
        """
        Inserts a new flow record into the flow table.
        The position of the flow record in the flow table is determined by the record id of the packet.
        """

        
        
        if flow.servicenodeID == '826':
            self.all_ordered_flows[flow.pack_id] = flow
            self.flow_table[flow.record_id] = flow  # insert new flow into flow table
            self.logger.debug("Inserted flow: %s (%s)", flow.record_id, flow.servicenodeID) 
            
        else:           
            self.lost_flows[len(self.lost_flows)+1] = flow

        
        
    def __find(self, packet: OpcuaRecord) -> OpcuaRecord or None:
        """
        Retrieves a flow record from the flow table based on its record id.
        """
        return self.flow_table[packet.record_id] if packet.record_id in self.flow_table else None
    


            
            
                

    def __update(self, flow: OpcuaRecord):
        """
        Updates a existing flow. If the updated flow record is completed, it gets deleted and exported for new __insert with corresponding record_id.
        """

        #if Flow-Closing publish-response with requesthandle corresponding to flow-starting publish-request
        if ((self.flow_table[flow.record_id].requesthandle == flow.requesthandle) and (flow.servicenodeID == '829')):
            
            #get the length of the dict and add last pack_id to starting pack
            length_lis = len(self.flow_table[flow.record_id].dict_node_strings)
            self.flow_table[flow.record_id].dict_node_strings[length_lis+1] = flow.pack_id
            #then set flow_count
            self.flow_table[flow.record_id].flow_id = self.flowcount
            

            
            looper = 1
            
            
            while looper <= length_lis+1:
                #get Index to iterate                              
                keyIndex = self.flow_table[flow.record_id].dict_node_strings[looper]
                #set the other flowcounts
                self.all_ordered_flows[keyIndex].flow_id = self.flowcount
                
                #add flow_id to csv-string and then overwrite opcua_record-object with csv-string
                self.all_ordered_flows[keyIndex].csv_string = f"{self.flowcount},{self.all_ordered_flows[keyIndex].csv_string}"
                self.all_ordered_flows[keyIndex] = self.all_ordered_flows[keyIndex].csv_string

                looper = looper + 1
            

            self.flowcount = self.flowcount + 1   
            

            #then delete just exportert flow with key, for new flow to start over again with insert-method  
            del self.flow_table[flow.record_id]
            
        
        else:
            #if no flow-ending packet just update information in start-packet
            length_list = len(self.flow_table[flow.record_id].dict_node_strings)

            self.flow_table[flow.record_id].dict_node_strings[length_list+1] = flow.pack_id

        
    
    
    def panda(self):
        #check for false format, then export into excel-sheets

        
       #Check all flows for false format (false format means not complete)
        for key in self.all_ordered_flows:
            self.all_ordered_flows = {key:val for key, val in self.all_ordered_flows.items() if not hasattr(val, 'timestamp')}
            
       
        
       
        self.df_LostInTransit = pd.DataFrame([self.lost_flows])
        self.df_LostInTransit = self.df_LostInTransit.T
        
        
        self.df_all = pd.DataFrame([self.all_ordered_flows])           
        self.df_all = self.df_all.T
        

        
        print("...export Data...")
        path = r"PM4PY-Input.xlsx"
        with pd.ExcelWriter(path) as engine:
    
            
            self.df_all.to_excel(excel_writer=engine, sheet_name="PM4PY-Input (rows)")
            self.df_LostInTransit.to_excel(excel_writer=engine, sheet_name="df_LostInTransit")
        
        print("Data exported to Excel-Sheet")
        print("Format is the following with pack_id as key:")
        print("flow_id,pack_id,timestamp,source_port,servicenodeID,record_id,node_string")

    def __export_and_remove(self, flow: MqttRecord):
        """
        May be used for future work
        Exports a flow record to the collector.
        """
        print("Ausführen von Methode __export_and_remove")
        "servicenodeid in logger debug statt control type eingefügt"
        self.logger.debug("Exported flow: %s (%s)", flow.record_id, flow.servicenodeID)
        self.exporter.export_mqtt_ipfix(flow)  # export flow to collector via ipfix exporter
        del self.flow_table[flow.record_id]  # remove flow from flow table

    def get_flow_table_length(self) -> int:
        """
        May be used for future work
        Get the count of flows held within the flow table.
        """
        return len(self.flow_table)
