from zpal.api import RequestsHandler
import getpass
import logging
'''
This module compares the user provided NodegridOS version against the target device's currently installed OS.
The script will upgrade the device if the versions do not match and the user specifies the ISO.
'''


def compare_version(ip, version_to_check, do_upgrade, username, password):
    #Create RequestsHandler object
    zpe = RequestsHandler(ip = ip, 
                          user= username, 
                          password = password, 
                          verify = False)
    with zpe:
        #Get version info from ZPE
        version = zpe.get_system_about()['version']
        #Trim version info down.
        version = version.split('(')[0].replace('v', '').strip()
        #Check version returned against version user specified
        if version_to_check == version:
            print(f"{ip} already on {version_check}")
        else:
            print(f"{ip} not on {version_to_check}. Current version: {version}")
            if do_upgrade != '':
                #Upgrade from local file in /var/sw
                data = {"image_location":"upgrade-local", "if_downgrading":"restore", "filename": f'{do_upgrade}'}
                print(data["filename"])
                #You can alias function names to make references easier!
                upgrade = zpe.post_system_toolkit_upgrade
                response = upgrade(data)

if __name__ == '__main__':
    #Implement global logger at the debug level.
    logging.basicConfig(filename='zpal_global.log', level=logging.DEBUG)
    logger = logging.getLogger("zpal")
    logger.setLevel(logging.DEBUG)
    #Gather user input for login and destination node.
    my_user = input('What is your username? ')
    my_pass = getpass.getpass('What is your password? ')
    ip = input('What device would you like to check? ')
    version_check = input('What version to check for? E.g. "5.6.13" ')
    upgrade = input('Enter a local ISO to upgrade to if you would like to upgrade the ZPE. Otherwise, press enter. ')
    compare_version(ip=ip, version_to_check=version_check, do_upgrade=upgrade, username=my_user, password=my_pass)
