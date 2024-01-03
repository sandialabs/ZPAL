from zpal.api import RequestsHandler
import getpass
'''
This module enables MSTP on the network edge ports in slot 1. 
'''
#Interfaces to update
INTERFACES = [f'netS1-{x}' for x in range (1,17)]


def mstp_edge_ports(user: str, password: str, ip: str):
    zpe = RequestsHandler(ip=ip, user=user, password=password)
    with zpe:
        for x in INTERFACES.copy():
            try:
                zpe.put_network_switch_interfaces(interface=x, data={'mstp_status': 'enabled'})
            except:
                print(f'Failed to update interface {x} on {ip}')
        conf = zpe.get_network_switch_interfaces()
        for x in conf:
            if x['interface'] in ['sfp0', 'sfp1']:
                continue
            if x['mstp_status'] != 'enabled' and x['interface'] in INTERFACES:
                print(f'Failed to enable MSTP on {x["interface"]} on {ip}.')
    return 200

if __name__ == '__main__':

    user = input('What is the username? ')
    secret = getpass.getpass("What is the pass? ")
    ip = input('What device would you like to update? (provide IP/DNS) ')
    if mstp_edge_ports(user=user, password=secret, ip=ip) != 200:
        print(f'Failed to enable MSTP on edge ports on {ip}')
