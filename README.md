# ZPAL
Welcome to the **Z**PE A**P**I **A**bstraction **L**ayer package! 

## Description
ZPAL is a Python SDK API wrapper designed to streamline API calls for ZPE Systems network devices. Network automation engineers utilizing ZPE devices are the intended audience for the SDK.

## Getting started
The API wrapper is contained in the api.RequestsHandler class. This class handles all API endpoints using the **requests** package.

All ZPE API endpoints have their own functions named after the endpoint and method. For example, you would call the _get_system_about_ function to request the _system_about_ page with the _GET_ method. All ZPAL API calls use the RequestsHandler's _do_ function to prepare their API request. Return values for most functions follow the standard below:
1. All successful _GET_, _POST_, _PUT_, and _DELETE_ calls (those returning a 200 HHTP status code) return JSON encoded data from the response object. This may be an empty list.
2. All unsuccessful calls return the associated HTTP status code for debugging by the developer.

**You can access the HTTP status code of the last API request under the _RequestsHandler.status_code_ variable. This allows for manual validation of HTTP 200 codes--which is useful in _POST/PUT/DELETE_ operations. You may have issues with this method if you are making asynchronous/multiple API calls. 

To write a simple script that would add VLAN 23 to a ZPE after first checking if it exists already, follow the steps below.

## Required Imports
```python
from zpal.api import RequestsHandler
import getpass
import logging
```
## Creating a RequestsHandler Instance
```python
zpe = RequestsHandler(ip = 'zpe.domain.com', 
                        user= input('What is the username you would like to use to connect? '), 
                        password = getpass.getpass('What is the associated password? '), 
                        verify = False)
```
## Configure Logging
```python
logging.basicConfig(filename='zpal_global.log', level=logging.DEBUG)
logger = logging.getLogger("zpal")
logger.setLevel(logging.DEBUG)
```

## Checking if VLAN 23 already exists on the ZPE
```python
with zpe:
    vlans = zpe.get_network_switch_vlan()
    vlan_exists = False
    for x in vlans:
        if x['id'] == '23': 
            vlan_exists = True
            break
```

## Posting and updating VLAN 23 configuration
```python
if not vlan_exists:
#You can alias function names to reduce verbosity.
    add_vlan = zpe.post_network_switch_vlan
    vlan = {"vlan": '23'}
    result = add_vlan(data = vlan)

    if zpe.status_code != 200:
        print('Failed to add VLAN 23 to ZPE.')
    else: print('Successfully added VLAN 23 to ZPE.')

else: print('VLAN 23 already exists on ZPE.')
    port_config = {'tagged_ports': ['sfp0', 'sfp1'], 'untagged_ports': ['netS3-4']}
    zpe.put_network_switch_vlan(vlan = '23', data = port_config)
    
    if zpe.status_code != 200:
        print('Failed to update switchport configuration for VLAN 23.')
    else: print('Successfully update port config for VLAN 23.')
```
By now, the script will have added VLAN 23 (if it didn't exist on the ZPE) and updated the associated switchport configuration.
## Installation
- Move the entire ZPAL folder into your Python site-packages folder. 
- CD inside the root ZPAL folder. 
- Run "python setup.py install" or your preferred PIP install command. 

## Example Scripts
Example scripts are contained in the Examples folder. 

## Logging
ZPAL fully supports logging. The example script above implements a logger at the debug level. Successful RequestsHandler actions are logged at the DEBUG level, failures at the WARNING level, and exceptions at the ERROR level.

## Nice to knows
ZPAL supports all ZPE login methods. View the RequestsHandler parameters to see additional options such as API keys. 

You can call the _RequestsHandler.connect_change_password_ function to change the password during first time login on a ZPE.

Access the last API response status_code under _RequestsHandler.status_code_ or _RequestsHandler.r.status_code_.

## Python Supported Versions
ZPAL is designed for use with Python versions 3.6 and above.

## Nodegrid OS supported versions
ZPAL v1.0.0 is designed for use with Nodegrid OS versions 5.4.10 and above. Version compatibility and validation will be the target of future updates. The package may still work with additional versions above 5, but testing has not been done on versions before 5.4.10.

## Authors and acknowledgment
Sarah Ashley, Roscoe Hill, Francis Oroyan, and Simon Reeser led the development of ZPAL.
