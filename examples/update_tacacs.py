from zpal.api import RequestsHandler
import getpass
import copy
import logging
'''
This module copies a TACACS configuration from a good device to another device. It will delete the existing configuration
on the targeted device and replace it with the "golden configuration".
'''

TACACS_KEY = getpass.getpass("What is the TACACS string? ")
SECRET = getpass.getpass("What is the admin password? ")


def get_golden_config(ip: str) -> list:
    '''
    Grabs a pristine TACACS configuration from a ZPE with a good TACACS configuration.
    '''
    zpe = RequestsHandler(ip=ip, user="admin", password=SECRET)
    with zpe:
        authentication = zpe.get_security_authentication()
        golden_config = []
        for x in authentication:
            if x['method'] == 'tacacs+':
                result = zpe.get_security_authentication(x['id'])
                result['tacacs_plus_secret'] = TACACS_KEY
                result['tacacs_plus_confirm_secret'] = TACACS_KEY
                golden_config.append(result)
    return golden_config


def post_tacacs(ip: str, config: list) -> int:
    '''
    Uses the provided list of TACACS servers/configurations to update the configuration on another device.
    '''
    tacacs_config = copy.deepcopy(config)
    try:
        zpe_host = RequestsHandler(ip, "admin", SECRET)
        with zpe_host:
            authentication2 = zpe_host.get_security_authentication()
            index_to_delete = []
            for x in authentication2:
                if x['method'] == 'tacacs+':
                    #Deleting out all old ZPE Tacacs configurations to make sure we only have the correct Tacacs
                    index_to_delete.append(x['id'])
            delete_dict = {"indexes": index_to_delete}
            zpe_host.delete_security_authentication(delete_dict)
            for x in tacacs_config:
                zpe_host.post_security_authentication(x)
    except Exception as e:
        print(f'Failed to update TACACS on {ip}')
    return 200

if __name__ == '__main__':
    logging.basicConfig(filename='zpal_global.log', level=logging.DEBUG)
    logger = logging.getLogger("zpal")
    logger.setLevel(logging.DEBUG)
    tacacs_config = get_golden_config('zpe1.domain.com')
    if post_tacacs(ip='zpe2.domain.com', config=tacacs_config) != 200:
        print('Failed to make some TACACS changes on the device.')
