""

import pandas as pd
import pm4py
from pm4py import *
from pm4py.objects.conversion import *
import datetime
from pm4py.algo.filtering.dfg import dfg_filtering
from pm4py.visualization.dfg import visualizer as dfg_visualizer

def petri_net_inductive_miner(data_frame, noise_threshold):
    """
    Process mining based on inductive miner with a petri net as output.
    """
    net, initial_marking, final_marking = pm4py.discover_petri_net_inductive(data_frame, noise_threshold=noise_threshold)
    pm4py.view_petri_net(net, initial_marking, final_marking)

  
    
def petri_net_heuristic_miner(data_frame: pd.DataFrame, dependency_threshold: float ):
    """
    Process mining based on heuristic miner with a petri net as output.
    """
    net, initial_marking, final_marking = pm4py.discover_petri_net_heuristics(data_frame, dependency_threshold=dependency_threshold)
    gviz = pm4py.visualization.petri_net.visualizer.apply(
        net,
        initial_marking,
        final_marking,
        variant=pm4py.visualization.petri_net.visualizer.Variants.PERFORMANCE,
        parameters={"format": "svg"})
    pm4py.visualization.petri_net.visualizer.view(gviz)
    return (net, initial_marking, final_marking)


#Dateiname von CSV-Datensatz
file_path = "Analyse_Reinigung.csv"


df = pm4py.format_dataframe(pd.read_csv(file_path, sep=','),case_id="flow_id", activity_key='node_string', timestamp_key='timestamp', timest_format='%Y-%m-%d %H:%M:%S%z' )
log = pm4py.convert_to_event_log(df)
print(df)

process_tree=pm4py.discover_process_tree_inductive(log)
bpmn_model = pm4py.discover_bpmn_inductive(log)


#Outputs (nach Bedarf auskommentieren):

#BPMN-Model PM4PY-------------------------------------------------------------------
#pm4py.view_bpmn(bpmn_model)



#Process-Tree PM4PY------------------------------------------------------------------
#pm4py.view_process_tree(process_tree)



#Petri-Net PM4PY--------------------------------------------------------------------
#net1, im1, fm1 = pm4py.convert_to_petri_net(process_tree)
#pm4py.view_petri_net(net1,im1,fm1)


#Heuristic Miner---------------------------------------------------
_net, _im, _fm = petri_net_heuristic_miner(log, 0.9)


#Inductive Miner--------------------------------------------------
#petri_net_inductive_miner(log, 0.9)

                         

#ALPHA Miner------------------------------------------------------------------
"""
net, initial_marking, final_marking = pm4py.discover_petri_net_alpha(log)
gviz = pm4py.visualization.petri_net.visualizer.apply(
    net,
    initial_marking,
    final_marking,
    variant=pm4py.visualization.petri_net.visualizer.Variants.PERFORMANCE,
    parameters={"format": "svg"})
pm4py.visualization.petri_net.visualizer.view(gviz)
"""