import os
import sys
from pylogix import PLC
from time import sleep
    
def read_plc(ip_addr, tag):
    with PLC() as comm:
        comm.IPAddress = ip_addr
        ret = comm.Read(tag)        
        return (ret.TagName, ret.Value, ret.Status)


def write_tag(ip_addr, tag, value):
    with PLC() as comm:
        comm.IPAddress = ip_addr
        comm.Write(tag, value)
        
    return 1



def main():
    PLC_IP = { 
              'plc1': '192.168.1.10',
    # 'tag_plc1':['HMI_LIT101.Pv','AI_FIT_101_FLOW', 'HMI_LIT101.Sim_Pv'],
    'plc2': '192.168.1.20',
    'plc3': '192.168.1.30',
    # 'tag_plc3':['HMI_LIT301.Pv','AI_FIT_301_FLOW'],
    'plc4': '192.168.1.40',
    # 'tag_plc4':['HMI_LIT401.Pv','AI_FIT_401_FLOW'],
    'plc5': '192.168.1.50',
    'plc6': '192.168.1.60',
    'plc1r': '192.168.1.11',
    'plc2r': '192.168.1.21',
    'plc3r': '192.168.1.31',
    'plc4r': '192.168.1.41',
    'plc5r': '192.168.1.51',
    'plc6r': '192.168.1.61',}
    
    #Attack 1:
    #When the water level of the tank reaches the LIT=800mm
    #Monitor the water level MAX
    #write_tag(PLC_IP['plc1'], 'HMI_LIT101.Sim', True)
    #if 
    #for i in range(1, 15):
        
    
    #LIT
    #write_tag(PLC_IP['plc1'], 'HMI_LIT101.Sim', True)
    #write_tag(PLC_IP['plc1'], 'HMI_LIT101.Sim_PV', 200)
    #print('successfully Changed to Manual')
    #sleep(5)
    #write_tag(PLC_IP['plc1'], 'HMI_LIT101.Sim', False)
    
    #write_tag(PLC_IP['plc5'], 'HMI_FIT501.Sim', True)
    #write_tag(PLC_IP['plc5'], 'HMI_FIT501.Sim_PV', 500)
    #sleep(5)
    #write_tag(PLC_IP['plc5'], 'HMI_FIT501.Sim', False)
    
    
    #Pump
    
    # write_tag(PLC_IP['plc4'], 'HMI_UV401.Auto', False)
    # write_tag(PLC_IP['plc4'], 'HMI_UV401.Cmd', 1)
    # sleep(10)
    # write_tag(PLC_IP['plc1'], 'HMI_P101.Auto', True)
    # '''
    # write_tag(PLC_IP['plc3'], 'HMI_P301.Auto', False)
    # write_tag(PLC_IP['plc3'], 'HMI_P301.Cmd', 2)
    # sleep(10)
    # write_tag(PLC_IP['plc3'], 'HMI_P301.Auto', True)
    # '''
    
    #Motorised Valve
    #write_tag(PLC_IP['plc1'], 'HMI_MV101.Auto', False)
    #write_tag(PLC_IP['plc1'], 'HMI_MV101.Cmd', 1)
    #sleep(5)
    #write_tag(PLC_IP['plc1'], 'HMI_MV101.Auto', True)

    # print('Changed MV201 to CLOSED')
    # write_tag(PLC_IP['plc2'], 'HMI_MV201.Auto',False) 
    # write_tag(PLC_IP['plc2'], 'HMI_MV201.Cmd', 1)
    # sleep(10) 
    # write_tag(PLC_IP['plc2'], 'HMI_MV201.Auto',True) 

    #AIT

    # print('Change AIT201 to 300.0')
    # write_tag(PLC_IP['plc2'], 'HMI_AIT201.Sim',True) 
    # write_tag(PLC_IP['plc2'], 'HMI_AIT201.Sim_PV',300)
    # sleep(5) 
    # write_tag(PLC_IP['plc2'], 'HMI_AIT201.Sim',False) 

    # #P301

    # print('Changed P301 to OFF')
    # write_tag(PLC_IP['plc3'], 'HMI_P301.Auto',False) 
    # write_tag(PLC_IP['plc3'], 'HMI_P301.Cmd', 1)
    # sleep(10)
    # write_tag(PLC_IP['plc3'], 'HMI_P301.Auto',True)     

    #DPIT  
    # print('DPIT301 change to 100')
    # write_tag(PLC_IP['plc3'], 'HMI_DPIT301.Sim',True) 
    # write_tag(PLC_IP['plc3'], 'HMI_DPIT301.Sim_PV',100)
    # sleep(5) 
    # write_tag(PLC_IP['plc3'], 'HMI_DPIT301.Sim',False) 
    
    
    # #LIT401
    # print('LIT401 attacked change to 500')
    # write_tag(PLC_IP['plc4'], 'HMI_LIT401.Sim',True) 
    # write_tag(PLC_IP['plc4'], 'HMI_LIT401.Sim_PV',500)
    # sleep(10) 
    # write_tag(PLC_IP['plc4'], 'HMI_LIT401.Sim',False) 
    
    #FIT501
    #print('FIT501 attacked change to 15')
    #write_tag(PLC_IP['plc5'], 'HMI_FIT501.Sim',True) 
    #write_tag(PLC_IP['plc5'], 'HMI_FIT501.Sim_PV',15)
    #sleep(10) 
    #write_tag(PLC_IP['plc5'], 'HMI_FIT501.Sim',False) 
    
    
    
if __name__ == "__main__":
    main()
