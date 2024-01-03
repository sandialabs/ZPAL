from zpal.api import RequestsHandler
import getpass
import time
'''
This module creates and applies a MSTP instance with instances 0 and 1. VLANS 4,5,6 are placed in instance 1 with a priority of 20k.
'''

#Default settings to push to ZPE
SWITCH_GLOBAL = {'jumbo_frame_size': '9000', 'stp_hello_time': '2', 'stp_forward_delay': '15', 'stp_max_age': '20', 
                 'stp_tx_hold_count': '5', 'mstp_region_name': 'DOM', 'mstp_revision': '0', 
                 'lag_load_balance': 'source_and_destination_mac', 'stp_status': 'enabled', 'stp_mode': 'mstp', 
                 'dhcp_snooping_status': 'disabled'}
MSTP_INSTANCE = {'vlan': '4-6', 'mst_instance_id': '1', 'mstp_priority': '20480'}
MSTP_UPDATE = {'vlan': '4-6', 'mstp_priority': '20480'}
CORRECT_MSTP = {'vlan_list': '4-6', 'mst_instance': '1', 'mstp_priority': '20480'}
DISABLE_MSTP = {'stp_status': 'disabled'}


def mstp(user: str, password: str, revert: str, ip: str):
    zpe = RequestsHandler(ip=ip, user=user, password=password)
    #Disable MSTP if user indicates
    if revert == 'y':
        with zpe:
            zpe.put_network_switch_global(DISABLE_MSTP)
            if zpe.status_code != 200:
                print(f'Failed to disable MSTP on {ip}\n')
        return
    
    with zpe:
            vlan_dict = {'tagged_ports': ['sfp0']}
            vlans = ['4', '5', '6']
            #Post all VLANS to ZPE.
            for x in vlans:
                zpe.post_network_switch_vlan({"vlan": x})
                conf = zpe.get_network_switch_vlan(x)
                zpe.put_network_switch_vlan(vlan=x, data=vlan_dict)
    #Update DOM region and post MSTP instance to ZPE.
    with zpe:
        zpe.put_network_switch_global(SWITCH_GLOBAL)
        update = False
        for x in zpe.get_network_switch_mstp_instance_interfaces():
            if x['mst_instance'] == MSTP_INSTANCE['mst_instance_id']:
                update = True
                break
        if update:
            if zpe.put_network_switch_mstp_instance_vlan_priority(data=MSTP_UPDATE, 
                                                                  instance=MSTP_INSTANCE['mst_instance_id']) != 200:
                if {'vlan_list': '4-6', 'mst_instance': '1', 'mstp_priority': '20480'} not in zpe.get_network_switch_mstp_instance_interfaces():
                    print(f'Failed to post MSTP instance to {ip}')
            else: print(f'Successfully updated MSTP on {ip}')
        else:
            if zpe.post_network_switch_mstp(data=MSTP_INSTANCE) != 200:
                if {'vlan_list': '4-6', 'mst_instance': '1', 'mstp_priority': '20480'} not in zpe.get_network_switch_mstp_instance_interfaces():
                    print(f'Failed to post MSTP instance to {ip}')
            else: print(f'Successfully posted MSTP on {ip}')
        lag = zpe.get_network_switch_lag()
        #Enable MSTP on LAG uplink
        for x in lag:
            if x['ports'] == 'sfp0':
                zpe.put_network_switch_lag(lag=x['name'], data={'mstp_status': 'enabled'})
                break
        #Sleep to allow time for MSTP convergence.
        time.sleep(30)
        mstp_tracking = zpe.get_tracking_network_mstp()
        mstp_instance_1 = zpe.get_tracking_network_mstp(instance='0')
        mstp_instance_1 = zpe.get_tracking_network_mstp(instance='1')
        for x in mstp_instance_1.copy():
            if 'lacp' in x['interface']:
                mstp_instance_1 = x
                break
        #Throw error
        if CORRECT_MSTP not in mstp_tracking:
            print(f'MSTP not successfully posted to {ip}')
        if mstp_instance_1['mst_role'] != 'Root':
            print(f'MSTP root not correct for instance 1 on {ip}')


if __name__ == '__main__':
    #Check if user wants to revert changes
    user = input('What is the username? ')
    secret = getpass.getpass("What is the pass? ")
    revert = input('Revert changes? (y/n) ').lower()
    while revert != 'y':
        if revert == 'n':
            break
        else: input('Input not understood. Please type "y" or "n". ').lower()
    ip = input('What device would you like to update? (provide IP/DNS) ')
    mstp(user=user, password=secret, revert=revert, ip=ip)
