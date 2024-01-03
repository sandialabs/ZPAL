import requests
import logging
from json import JSONDecodeError
import zpal.exceptions


class RequestsHandler:
    def __init__(self, ip: str, user: str, password: str = None, api_key: str = None, verification_code: str = None, 
                 protocol: str = 'https', proxy_use_environment_variables: bool = False, proxy: str = None, 
                 proxy_secure: bool = True, content: str = "application/json", accept: str = "application/json", 
                 verify: str = None, connection_timeout: int = 15, logger: logging.Logger = None):
        '''
        Creates ZPE object. Pass IP, user, and password OR api_key as strings. Optionally specify verification_code for 
        OTP. 
        
        Specify proxy_use_environment_variables = True if you would prefer that the requests package default to
        using your OS's environment variables. Specify your HTTP proxy under 'proxy' or your HTTPS proxy under
        proxy_secure. Only one proxy type (insecure/secure) is supported at a time. 

        The arguments: content, accept, verify, and connection_timeout are all requests parameters.
        '''
        self.ip = ip
        self.url = f'{protocol}://{self.ip}/api/v1/'
        self.auth = {"username": user, "password": password}
        if verification_code: self.auth['verification_code'] = verification_code
        self.timeout = connection_timeout
        #Create and update Session object parameters
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": content, "accept": accept})
        if api_key:
            self.session.headers.update({"username": user, "api_key": api_key})
        self.session.verify = verify
        #Prepare proxy settings. Defaults to no proxy settings. Use requests environment variables if specified.
        if not proxy_use_environment_variables:
            if not proxy: self.proxy = {'https': '', 'http': ''}
            elif proxy_secure: self.proxy = {'https': proxy}
            else: self.proxy = {'http': proxy}
        else:
            self.proxy = requests.utils.getproxies()
        #Session proxies variable behaves differently than expected as mentioned in github.com/psf/requests/pull/6068
        self.session.proxies.update(self.proxy)
        #Use logger specified by user or create one based on module name (zpal).
        self._logger = logger or logging.getLogger(__name__)
    
    def do(self, http_method: str, endpoint: str, ep_params: dict = None, json: dict = None):
        '''
        Sends a request to the specified API endpoint.
        '''
        self.full_url = self.url + endpoint
        #Prepare log info with URL and method.
        self.prepare_log = f'URL={self.full_url},METHOD={http_method}'
        try:
            self.r = self.session.request(method = http_method, url = self.full_url, params = ep_params, 
                                                json = json, timeout = self.timeout, proxies = self.session.proxies)
            self.status_code = self.r.status_code
            #Handle good response. Try to transform data to JSON and raise Zpal exception if JSON errors occur.
            if self.r.status_code == 200:
                self.success_log = f'SUCCESS,{self.prepare_log},RESPONSE={self.r.status_code},MESSAGE={self.r.reason}'
                self._logger.debug(msg=self.success_log)
                try:
                    self.return_data = self.r.json()
                except (ValueError, JSONDecodeError) as e:
                    self.failed_log = f'EXCEPTION,{self.prepare_log},EXCEPTION:{e}'
                    self._logger.exception(msg=self.failed_log)
                    raise zpal.exceptions.JSONError(f'Error processing JSON in API response.') from e
                return self.r.json()
            #Handle all non 200 responses. Log at the warning level instead of intentionally crashing API handler.
            else:
                self.failed_log = f'FAILED,{self.prepare_log},RESPONSE={self.r.status_code},MESSAGE={self.r.reason}'
                #Allow connect/disconnect functions to handle their own failed API calls.
                if 'Session' not in self.full_url:
                    self._logger.warning(msg=self.failed_log)
                return self.r.status_code
        except Exception as e:
            self.failed_log = f'EXCEPTION,{self.prepare_log},EXCEPTION:{e}'
            self._logger.exception(msg=self.failed_log)
            raise zpal.exceptions.ZpalException(f'Error occurred during API request.') from e
    
    def get(self, endpoint: str, ep_params: dict = None, json: dict = None):
        '''
        Sends a GET request to the endpoint.
        '''
        return self.do(http_method = 'GET', endpoint = endpoint, ep_params = ep_params, json = json)
    
    def post(self, endpoint: str, ep_params: dict = None, json: dict = None):
        '''
        Sends a POST request to the endpoint.
        '''
        return self.do(http_method = 'POST', endpoint = endpoint, ep_params = ep_params, json = json)
    
    def put(self, endpoint: str, ep_params: dict = None, json: dict = None):
        '''
        Sends a PUT request to the endpoint.
        '''
        return self.do(http_method = 'PUT', endpoint = endpoint, ep_params = ep_params, json = json)
    
    def delete(self, endpoint: str, ep_params: dict = None, json: dict = None):
        '''
        Sends a DELETE request to the endpoint.
        '''
        return self.do(http_method = 'DELETE', endpoint = endpoint, ep_params = ep_params, json = json)
    
    def connect(self):
        '''
        Connects to ZPE. Don't use this function if you have an API token.
        '''
        #Grab session ticket from ZPE and update header with ticket. Verify response afterwards.
        self.id = self.post(endpoint = 'Session', json = self.auth)
        #Verify auth status.
        self.auth_failure(self.id)
        self.session.headers.update({"ticket": self.id['session']})
        return self.id
    
    def connect_change_password(self, new_password: str, current_password: str = None):
        '''
        Connects to ZPE and changes password. current_password will default to password passed to constructor.
        self.auth['password'] will be updated with new password after successfuly updating password.
        Useful for first time login.
        '''
        #Update current password if specified, then change password and update RequestsHandler password and ticket.
        if current_password: self.auth['password'] = current_password
        self.auth['new_password'] = new_password
        self.id = self.post(endpoint = 'ChangePasswordFirstLogin', json = self.auth)
        #Throw exceptions on authn/z failures.
        self.auth_failure(self.id)
        #Update headers and auth.
        self.session.headers.update({"ticket": self.id['session']})
        self.auth['password'] = new_password
        del self.auth['new_password']
        return self.id

    def auth_failure(self, status_code: int):
        '''
        Checks for 401/403 errors during the most important login processes.
        '''
        if status_code == 401:
            self._logger.critical(msg=f'AUTHENTICATION {self.failed_log}')
            raise zpal.exceptions.AuthenticationError(f'Failed to authenticate to device: {self.ip}. Please check login info.')
        elif status_code == 403:
            self._logger.critical(msg=f'AUTHORIZATION {self.failed_log}')
            raise zpal.exceptions.AuthorizationError(f'Failed to login to device: {self.ip} due to authorization issues.')
        return
        
    def disconnect(self):
        '''
        Destroys API session ticket.
        '''
        self.response = self.delete(endpoint = 'Session')
        return self.response

    def __enter__(self):
        #Don't request session ticket if using api_key
        if self.session.headers.get('api_key'): return
        return self.connect()
    
    def __exit__(self, exc_type, exc_value, traceback):
        self.disconnect()

    def get_access_table(self):
        '''
        Gets access table
        '''
        self.response = self.get('access/table')
        return self.response

    def get_access_device_fullinformation(self, device: str):
        '''
        Gets access {device} fullinformation
        '''
        self.response = self.get(f'access/{device}/fullinformation')
        return self.response

    def get_access_device_hostsysinformation(self, device: str):
        '''
        Gets access {device} hostsysinformation
        '''
        self.response = self.get(f'access/{device}/hostsysinformation')
        return self.response

    def post_ChangePasswordFirstLogin(self, data: dict):
        '''
        Posts ChangePasswordFirstLogin
        '''
        self.response = self.post('ChangePasswordFirstLogin', json = data)
        return self.response

    def get_auditing_destination_email(self):
        '''
        Gets auditing destination email
        '''
        self.response = self.get('auditing/destination/email')
        return self.response

    def put_auditing_destination_email(self, data: dict):
        '''
        Puts auditing destination email
        '''
        self.response = self.put('auditing/destination/email', json = data)
        return self.response

    def post_auditing_destination_email_testemail(self, data: dict):
        '''
        Posts auditing destination email testemail
        '''
        self.response = self.post('auditing/destination/email/testemail', json = data)
        return self.response

    def get_auditing_destination_file(self):
        '''
        Gets auditing destination file
        '''
        self.response = self.get('auditing/destination/file')
        return self.response

    def put_auditing_destination_file(self, data: dict):
        '''
        Puts auditing destination file
        '''
        self.response = self.put('auditing/destination/file', json = data)
        return self.response

    def get_auditing_destination_snmptrap(self):
        '''
        Gets auditing destination snmptrap
        '''
        self.response = self.get('auditing/destination/snmptrap')
        return self.response

    def put_auditing_destination_snmptrap(self, data: dict):
        '''
        Puts auditing destination snmptrap
        '''
        self.response = self.put('auditing/destination/snmptrap', json = data)
        return self.response

    def get_auditing_destination_syslog(self):
        '''
        Gets auditing destination syslog
        '''
        self.response = self.get('auditing/destination/syslog')
        return self.response

    def put_auditing_destination_syslog(self, data: dict):
        '''
        Puts auditing destination syslog
        '''
        self.response = self.put('auditing/destination/syslog', json = data)
        return self.response

    def get_auditing_events(self, event: str = None):
        '''
        Gets auditing events {event}
        '''
        if not event:
            self.response = self.get('auditing/events')
        else:
            self.response = self.get(f'auditing/events/{event}')
        return self.response

    def put_auditing_events(self, event: str, data: dict):
        '''
        Puts auditing events {event}
        '''
        self.response = self.put(f'auditing/events/{event}', json = data)
        return self.response

    def get_auditing_settings(self):
        '''
        Gets auditing settings
        '''
        self.response = self.get('auditing/settings')
        return self.response

    def put_auditing_settings(self, data: dict):
        '''
        Puts auditing settings
        '''
        self.response = self.put('auditing/settings', json = data)
        return self.response

    def get_auditing_event_list(self, event_number: str = None):
        '''
        Gets auditing event_list {event_number}
        '''
        if not event_number:
            self.response = self.get('auditing/event_list')
        else:
            self.response = self.get(f'auditing/event_list/{event_number}')
        return self.response

    def put_auditing_event_list_event(self, event_number: str, data: dict):
        '''
        Puts auditing event_list {event_number}
        '''
        self.response = self.put(f'auditing/event_list/{event_number}', json = data)
        return self.response

    def get_cluster_management(self):
        '''
        Gets cluster management
        '''
        self.response = self.get('cluster/management')
        return self.response

    def put_cluster_management_upgrade(self, data: dict):
        '''
        Puts cluster management upgrade
        '''
        self.response = self.put('cluster/management/upgrade', json = data)
        return self.response

    def get_cluster_peers(self):
        '''
        Gets cluster peers
        '''
        self.response = self.get('cluster/peers')
        return self.response

    def delete_cluster_peers(self, data: dict):
        '''
        Deletes cluster peers
        '''
        self.response = self.delete('cluster/peers', json = data)
        return self.response

    def get_cluster_clusters(self):
        '''
        Gets cluster clusters
        '''
        self.response = self.get('cluster/clusters')
        return self.response

    def post_cluster_clusters(self, data: dict):
        '''
        Posts cluster clusters
        '''
        self.response = self.post('cluster/clusters', json = data)
        return self.response

    def delete_cluster_clusters(self, data: dict):
        '''
        Deletes cluster clusters
        '''
        self.response = self.delete('cluster/clusters', json = data)
        return self.response

    def get_cluster_settings(self):
        '''
        Gets cluster settings
        '''
        self.response = self.get('cluster/settings')
        return self.response

    def put_cluster_settings(self, data: dict):
        '''
        Puts cluster settings
        '''
        self.response = self.put('cluster/settings', json = data)
        return self.response

    def get_cluster_settings_range(self):
        '''
        Gets cluster settings range
        '''
        self.response = self.get('cluster/settings/range')
        return self.response

    def post_cluster_settings_range(self, data: dict):
        '''
        Posts cluster settings range
        '''
        self.response = self.post('cluster/settings/range', json = data)
        return self.response

    def delete_cluster_settings_range(self, data: dict):
        '''
        Deletes cluster settings range
        '''
        self.response = self.delete('cluster/settings/range', json = data)
        return self.response

    def post_devices_discovery_hostname(self, data: dict):
        '''
        Posts devices discovery hostname
        '''
        self.response = self.post('devices/discovery/hostname', json = data)
        return self.response

    def delete_devices_discovery_hostname(self, data: dict):
        '''
        Deletes devices discovery hostname
        '''
        self.response = self.delete('devices/discovery/hostname', json = data)
        return self.response

    def get_devices_discovery_hostname(self, rule: str = None):
        '''
        Gets devices discovery hostname {rule}
        '''
        if not rule:
            self.response = self.get('devices/discovery/hostname')
        else:
            self.response = self.get(f'devices/discovery/hostname/{rule}')
        return self.response

    def put_devices_discovery_hostname(self, rule: str, data: dict):
        '''
        Puts devices discovery hostname {rule}
        '''
        self.response = self.put(f'devices/discovery/hostname/{rule}', json = data)
        return self.response

    def put_devices_discovery_hostname_rule_up(self, rule: str):
        '''
        Puts devices discovery hostname {rule} up
        '''
        self.response = self.put(f'devices/discovery/hostname/{rule}/up')
        return self.response

    def put_devices_discovery_hostname_rule_down(self, rule: str):
        '''
        Puts devices discovery hostname {rule} down
        '''
        self.response = self.put(f'devices/discovery/hostname/{rule}/down')
        return self.response

    def get_devices_discovery_hostname_globalsettings(self):
        '''
        Gets devices discovery hostname_globalsettings
        '''
        self.response = self.get('devices/discovery/hostname_globalsettings')
        return self.response

    def put_devices_discovery_hostname_globalsettings(self, data: dict):
        '''
        Puts devices discovery hostname_globalsettings
        '''
        self.response = self.put('devices/discovery/hostname_globalsettings', json = data)
        return self.response

    def get_devices_discovery_logs(self):
        '''
        Gets devices discovery logs
        '''
        self.response = self.get('devices/discovery/logs')
        return self.response

    def post_devices_discovery_logs_resetlogs(self):
        '''
        Posts devices discovery logs resetlogs
        '''
        self.response = self.post('devices/discovery/logs/resetlogs')
        return self.response

    def post_devices_discovery_network(self, data: dict):
        '''
        Posts devices discovery network
        '''
        self.response = self.post('devices/discovery/network', json = data)
        return self.response

    def delete_devices_discovery_network(self, data: dict):
        '''
        Deletes devices discovery network
        '''
        self.response = self.delete('devices/discovery/network', json = data)
        return self.response

    def get_devices_discovery_network(self, scan: str = None):
        '''
        Gets devices discovery network {scan}
        '''
        if not scan:
            self.response = self.get('devices/discovery/network')
        else:
            self.response = self.get(f'devices/discovery/network/{scan}')
        return self.response

    def put_devices_discovery_network(self, scan: str, data: dict):
        '''
        Puts devices discovery network {scan}
        '''
        self.response = self.put(f'devices/discovery/network/{scan}', json = data)
        return self.response

    def get_devices_discovery_now(self):
        '''
        Gets devices discovery now
        '''
        self.response = self.get('devices/discovery/now')
        return self.response

    def post_devices_discovery_now(self, data: dict):
        '''
        Posts devices discovery now
        '''
        self.response = self.post('devices/discovery/now', json = data)
        return self.response

    def post_devices_discovery_rules(self, data: dict):
        '''
        Posts devices discovery rules
        '''
        self.response = self.post('devices/discovery/rules', json = data)
        return self.response

    def delete_devices_discovery_rules(self, data: dict):
        '''
        Deletes devices discovery rules
        '''
        self.response = self.delete('devices/discovery/rules', json = data)
        return self.response

    def get_devices_discovery_rules(self, rule: str = None):
        '''
        Gets devices discovery rules {rule}
        '''
        if not rule:
            self.response = self.get('devices/discovery/rules')
        else:
            self.response = self.get(f'devices/discovery/rules/{rule}')
        return self.response

    def put_devices_discovery_rules(self, rule: str, data: dict):
        '''
        Puts devices discovery rules {rule}
        '''
        self.response = self.put(f'devices/discovery/rules/{rule}', json = data)
        return self.response

    def put_devices_discovery_rules_rule_up(self, rule: str):
        '''
        Puts devices discovery rules {rule} up
        '''
        self.response = self.put(f'devices/discovery/rules/{rule}/up')
        return self.response

    def put_devices_discovery_rules_rule_down(self, rule: str):
        '''
        Puts devices discovery rules {rule} down
        '''
        self.response = self.put(f'devices/discovery/rules/{rule}/down')
        return self.response

    def post_devices_discovery_vmmanager(self, data: dict):
        '''
        Posts devices discovery vmmanager
        '''
        self.response = self.post('devices/discovery/vmmanager', json = data)
        return self.response

    def delete_devices_discovery_vmmanager(self, data: dict):
        '''
        Deletes devices discovery vmmanager
        '''
        self.response = self.delete('devices/discovery/vmmanager', json = data)
        return self.response

    def get_devices_discovery_vmmanager(self, vm: str = None):
        '''
        Gets devices discovery vmmanager {vm}
        '''
        if not vm:
            self.response = self.get('devices/discovery/vmmanager')
        else:
            self.response = self.get(f'devices/discovery/vmmanager/{vm}')
        return self.response

    def put_devices_discovery_vmmanager(self, vm: str, data: dict):
        '''
        Puts devices discovery vmmanager {vm}
        '''
        self.response = self.put(f'devices/discovery/vmmanager/{vm}', json = data)
        return self.response

    def get_devices_preference_power(self):
        '''
        Gets devices preference power
        '''
        self.response = self.get('devices/preference/power')
        return self.response

    def put_devices_preference_power(self, data: dict):
        '''
        Puts devices preference power
        '''
        self.response = self.put('devices/preference/power', json = data)
        return self.response

    def get_devices_preference_session(self):
        '''
        Gets devices preference session
        '''
        self.response = self.get('devices/preference/session')
        return self.response

    def put_devices_preference_session(self, data: dict):
        '''
        Puts devices preference session
        '''
        self.response = self.put('devices/preference/session', json = data)
        return self.response

    def get_devices_preference_views(self):
        '''
        Gets devices preference views
        '''
        self.response = self.get('devices/preference/views')
        return self.response

    def put_devices_preference_views(self, data: dict):
        '''
        Puts devices preference views
        '''
        self.response = self.put('devices/preference/views', json = data)
        return self.response

    def post_devices_table(self, data: dict):
        '''
        Posts devices table
        '''
        self.response = self.post('devices/table', json = data)
        return self.response

    def delete_devices_table(self, data: dict):
        '''
        Deletes devices table
        '''
        self.response = self.delete('devices/table', json = data)
        return self.response

    def get_devices_table(self, device: str = None):
        '''
        Gets devices table {device}
        '''
        if not device:
            self.response = self.get('devices/table')
        else:
            self.response = self.get(f'devices/table/{device}')
        return self.response

    def put_devices_table(self, device: str, data: dict):
        '''
        Puts devices table {device}
        '''
        self.response = self.put(f'devices/table/{device}', json = data)
        return self.response

    def put_devices_table_device_bouncedtr(self, device: str):
        '''
        Puts devices table {device} bouncedtr
        '''
        self.response = self.put(f'devices/table/{device}/bouncedtr')
        return self.response

    def put_devices_table_device_clone(self, device: str, data: dict):
        '''
        Puts devices table {device} clone
        '''
        self.response = self.put(f'devices/table/{device}/clone', json = data)
        return self.response

    def get_devices_table_device_commands(self, device: str):
        '''
        Gets devices table {device} commands
        '''
        self.response = self.get(f'devices/table/{device}/commands')
        return self.response

    def post_devices_table_device_commands(self, device: str, data: dict):
        '''
        Posts devices table {device} commands
        '''
        self.response = self.post(f'devices/table/{device}/commands', json = data)
        return self.response

    def delete_devices_table_device_commands(self, device: str, data: dict):
        '''
        Deletes devices table {device} commands
        '''
        self.response = self.delete(f'devices/table/{device}/commands', json = data)
        return self.response

    def get_devices_table_device_commands_cmd(self, device: str, cmd: str):
        '''
        Gets devices table {device} commands {cmd}
        '''
        self.response = self.get(f'devices/table/{device}/commands/{cmd}')
        return self.response

    def put_devices_table_device_commands(self, device: str, cmd: str, data: dict):
        '''
        Puts devices table {device} commands {cmd}
        '''
        self.response = self.put(f'devices/table/{device}/commands/{cmd}', json = data)
        return self.response

    def get_devices_table_device_customcommand(self, device: str, customcommand: str):
        '''
        Gets devices table {device} customcommand([1-9]|10)
        '''
        self.response = self.get(f'devices/table/{device}/{customcommand}')
        return self.response

    def post_devices_table_device_customfields(self, device: str, data: dict):
        '''
        Posts devices table {device} customfields
        '''
        self.response = self.post(f'devices/table/{device}/customfields', json = data)
        return self.response

    def delete_devices_table_device_customfields(self, device: str):
        '''
        Deletes devices table {device} customfields
        '''
        self.response = self.delete(f'devices/table/{device}/customfields')
        return self.response

    def get_devices_table_device_customfields(self, device: str, field: str = None):
        '''
        Gets devices table {device} customfields {field}
        '''
        if not field:
            self.response = self.get(f'devices/table/{device}/customfields')
        else:
            self.response = self.get(f'devices/table/{device}/customfields/{field}')
        return self.response

    def put_devices_table_device_customfields(self, device: str, field: str, data: dict):
        '''
        Puts devices table {device} customfields {field}
        '''
        self.response = self.put(f'devices/table/{device}/customfields/{field}', json = data)
        return self.response

    def put_devices_table_device_default(self, device: str):
        '''
        Puts devices table {device} default
        '''
        self.response = self.put(f'devices/table/{device}/default')
        return self.response

    def put_devices_table_device_disable(self, device: str):
        '''
        Puts devices table {device} disable
        '''
        self.response = self.put(f'devices/table/{device}/disable')
        return self.response

    def put_devices_table_device_enable(self, device: str):
        '''
        Puts devices table {device} enable
        '''
        self.response = self.put(f'devices/table/{device}/enable')
        return self.response

    def get_devices_table_device_logging(self, device: str):
        '''
        Gets devices table {device} logging
        '''
        self.response = self.get(f'devices/table/{device}/logging')
        return self.response

    def put_devices_table_device_logging(self, device: str, data: dict):
        '''
        Puts devices table {device} logging
        '''
        self.response = self.put(f'devices/table/{device}/logging', json = data)
        return self.response

    def get_devices_table_device_management(self, device: str):
        '''
        Gets devices table {device} management
        '''
        self.response = self.get(f'devices/table/{device}/management')
        return self.response

    def put_devices_table_device_management(self, device: str, data: dict):
        '''
        Puts devices table {device} management
        '''
        self.response = self.put(f'devices/table/{device}/management', json = data)
        return self.response

    def put_devices_table_device_ondemand(self, device: str):
        '''
        Puts devices table {device} ondemand
        '''
        self.response = self.put(f'devices/table/{device}/ondemand')
        return self.response

    def get_devices_table_device_outlets(self, device: str):
        '''
        Gets devices table {device} outlets
        '''
        self.response = self.get(f'devices/table/{device}/outlets')
        return self.response

    def put_devices_table_device_outlets_cycle(self, device: str, data: dict):
        '''
        Puts devices table {device} outlets cycle
        '''
        self.response = self.put(f'devices/table/{device}/outlets/cycle', json = data)
        return self.response

    def get_devices_table_device_outlets_list(self, device: str):
        '''
        Gets devices table {device} outlets list
        '''
        self.response = self.get(f'devices/table/{device}/outlets/list')
        return self.response

    def put_devices_table_device_outlets_on(self, device: str, data: dict):
        '''
        Puts devices table {device} outlets on
        '''
        self.response = self.put(f'devices/table/{device}/outlets/on', json = data)
        return self.response

    def put_devices_table_device_outlets_off(self, device: str, data: dict):
        '''
        Puts devices table {device} outlets off
        '''
        self.response = self.put(f'devices/table/{device}/outlets/off', json = data)
        return self.response

    def get_devices_table_device_outlets_status(self, device: str):
        '''
        Gets devices table {device} outlets status
        '''
        self.response = self.get(f'devices/table/{device}/outlets/status')
        return self.response

    def get_devices_table_device_sshkeys(self, device: str):
        '''
        Gets devices table {device} sshkeys
        '''
        self.response = self.get(f'devices/table/{device}/sshkeys')
        return self.response

    def post_devices_table_device_sshkeys_generate(self, device: str, data: dict):
        '''
        Posts devices table {device} sshkeys generate
        '''
        self.response = self.post(f'devices/table/{device}/sshkeys/generate', json = data)
        return self.response

    def post_devices_table_device_sshkeys_send(self, device: str, data: dict):
        '''
        Posts devices table {device} sshkeys send
        '''
        self.response = self.post(f'devices/table/{device}/sshkeys/send', json = data)
        return self.response

    def put_devices_table_device_rename(self, device: str, data: dict):
        '''
        Puts devices table {device} rename
        '''
        self.response = self.put(f'devices/table/{device}/rename', json = data)
        return self.response

    def delete_devices_types(self, data: dict):
        '''
        Deletes devices types
        '''
        self.response = self.delete('devices/types', json = data)
        return self.response

    def get_devices_types(self, kind: str = None):
        '''
        Gets devices types {type}. {kind} used in place of standard Python variable {type}
        '''
        if not kind:
            self.response = self.get('devices/types')
        else:
            self.response = self.get(f'devices/types/{kind}')
        return self.response

    def put_devices_types(self, kind: str, data: dict):
        '''
        Puts devices types {type}
        '''
        self.response = self.put(f'devices/types/{kind}', json = data)
        return self.response

    def post_devices_types_type_clone(self, kind: str, data: dict):
        '''
        Posts devices types {type} clone
        '''
        self.response = self.post(f'devices/types/{kind}/clone', json = data)
        return self.response

    def post_network_connections(self, data: dict):
        '''
        Posts network connections
        '''
        self.response = self.post('network/connections', json = data)
        return self.response

    def delete_network_connections(self, data: dict):
        '''
        Deletes network connections
        '''
        self.response = self.delete('network/connections', json = data)
        return self.response

    def get_network_connections(self, connection: str = None):
        '''
        Gets network connections {connection}
        '''
        if not connection:
            self.response = self.get('network/connections')
        else:
            self.response = self.get(f'network/connections/{connection}')
        return self.response

    def put_network_connections(self, connection: str, data: dict):
        '''
        Puts network connections {connection}
        '''
        self.response = self.put(f'network/connections/{connection}', json = data)
        return self.response

    def put_network_connections_connection_down(self, connection: str):
        '''
        Puts network connections {connection} down
        '''
        self.response = self.put(f'network/connections/{connection}/down')
        return self.response

    def put_network_connections_connection_up(self, connection: str):
        '''
        Puts network connections {connection} up
        '''
        self.response = self.put(f'network/connections/{connection}/up')
        return self.response

    def post_network_dhcp(self, data: dict):
        '''
        Posts network dhcp
        '''
        self.response = self.post('network/dhcp', json = data)
        return self.response

    def delete_network_dhcp(self, data: dict):
        '''
        Deletes network dhcp
        '''
        self.response = self.delete('network/dhcp', json = data)
        return self.response

    def get_network_dhcp(self, dhcpdip: str = None):
        '''
        Gets network dhcp {dhcpdip}
        '''
        if not dhcpdip:
            self.response = self.get('network/dhcp')
        else:
            self.response = self.get(f'network/dhcp/{dhcpdip}')
        return self.response

    def put_network_dhcp(self, dhcpdip: str, data: dict):
        '''
        Puts network dhcp {dhcpdip}
        '''
        self.response = self.put(f'network/dhcp/{dhcpdip}', json = data)
        return self.response

    def get_network_dhcp_dhcpdip_networkrange(self, dhcpdip: str):
        '''
        Gets network dhcp {dhcpdip} networkrange
        '''
        self.response = self.get(f'network/dhcp/{dhcpdip}/networkrange')
        return self.response

    def post_network_dhcp_dhcpdip_networkrange(self, dhcpdip: str, data: dict):
        '''
        Posts network dhcp {dhcpdip} networkrange
        '''
        self.response = self.post(f'network/dhcp/{dhcpdip}/networkrange', json = data)
        return self.response

    def delete_network_dhcp_dhcpdip_networkrange(self, dhcpdip: str, data: dict):
        '''
        Deletes network dhcp {dhcpdip} networkrange
        '''
        self.response = self.delete(f'network/dhcp/{dhcpdip}/networkrange', json = data)
        return self.response

    def get_network_dhcp_dhcpdip_hosts(self, dhcpdip: str):
        '''
        Gets network dhcp {dhcpdip} hosts
        '''
        self.response = self.get(f'network/dhcp/{dhcpdip}/hosts')
        return self.response

    def post_network_dhcp_dhcpdip_hosts(self, dhcpdip: str, data: dict):
        '''
        Posts network dhcp {dhcpdip} hosts
        '''
        self.response = self.post(f'network/dhcp/{dhcpdip}/hosts', json = data)
        return self.response

    def delete_network_dhcp_dhcpdip_hosts(self, dhcpdip: str, data: dict):
        '''
        Deletes network dhcp {dhcpdip} hosts
        '''
        self.response = self.delete(f'network/dhcp/{dhcpdip}/hosts', json = data)
        return self.response

    def post_network_dhcp_relay(self, data: dict):
        '''
        Posts network dhcp_relay
        '''
        self.response = self.post('network/dhcp_relay', json = data)
        return self.response

    def delete_network_dhcp_relay(self, data: dict):
        '''
        Deletes network dhcp_relay
        '''
        self.response = self.delete('network/dhcp_relay', json = data)
        return self.response

    def get_network_dhcp_relay(self, relay_id: str = None):
        '''
        Gets network dhcp_relay {relay_id}
        '''
        if not relay_id:
            self.response = self.get('network/dhcp_relay')
        else:
            self.response = self.get(f'network/dhcp_relay/{relay_id}')
        return self.response

    def put_network_dhcp_relay_relay(self, relay_id: str, data: dict):
        '''
        Puts network dhcp_relay {relay_id}
        '''
        self.response = self.put(f'network/dhcp_relay/{relay_id}', json = data)
        return self.response

    def post_network_hosts(self, data: dict):
        '''
        Posts network hosts
        '''
        self.response = self.post('network/hosts', json = data)
        return self.response

    def delete_network_hosts(self, data: dict):
        '''
        Deletes network hosts
        '''
        self.response = self.delete('network/hosts', json = data)
        return self.response

    def get_network_hosts(self, host: str = None):
        '''
        Gets network hosts {host}
        '''
        if not host:
            self.response = self.get('network/hosts')
        else:
            self.response = self.get(f'network/hosts/{host}')
        return self.response

    def put_network_hosts(self, host: str, data: dict):
        '''
        Puts network hosts {host}
        '''
        self.response = self.put(f'network/hosts/{host}', json = data)
        return self.response

    def get_network_settings(self):
        '''
        Gets network settings
        '''
        self.response = self.get('network/settings')
        return self.response

    def put_network_settings(self, data: dict):
        '''
        Puts network settings
        '''
        self.response = self.put('network/settings', json = data)
        return self.response

    def post_network_snmp(self, data: dict):
        '''
        Posts network snmp
        '''
        self.response = self.post('network/snmp', json = data)
        return self.response

    def delete_network_snmp(self, data: dict):
        '''
        Deletes network snmp
        '''
        self.response = self.delete('network/snmp', json = data)
        return self.response

    def get_network_snmp(self, snmp: str = None):
        '''
        Gets network snmp {snmp}
        '''
        if not snmp:
            self.response = self.get('network/snmp')
        else:
            self.response = self.get(f'network/snmp/{snmp}')
        return self.response

    def put_network_snmp(self, snmp: str, data: dict):
        '''
        Puts network snmp {snmp}
        '''
        self.response = self.put(f'network/snmp/{snmp}', json = data)
        return self.response

    def get_network_snmp_system(self):
        '''
        Gets network snmp_system
        '''
        self.response = self.get('network/snmp_system')
        return self.response

    def put_network_snmp_system(self, data: dict):
        '''
        Puts network snmp_system
        '''
        self.response = self.put('network/snmp_system', json = data)
        return self.response

    def post_network_sslvpn_clients(self, data: dict):
        '''
        Posts network sslvpn clients
        '''
        self.response = self.post('network/sslvpn/clients', json = data)
        return self.response

    def delete_network_sslvpn_clients(self, data: dict):
        '''
        Deletes network sslvpn clients
        '''
        self.response = self.delete('network/sslvpn/clients', json = data)
        return self.response

    def get_network_sslvpn_clients(self, client: str = None):
        '''
        Gets network sslvpn clients {client}
        '''
        if not client:
            self.response = self.get('network/sslvpn/clients')
        else:
            self.response = self.get(f'network/sslvpn/clients/{client}')
        return self.response

    def put_network_sslvpn_clients(self, client: str, data: dict):
        '''
        Puts network sslvpn clients {client}
        '''
        self.response = self.put(f'network/sslvpn/clients/{client}', json = data)
        return self.response

    def put_network_sslvpn_clients_client_start(self, client: str):
        '''
        Puts network sslvpn clients {client} start
        '''
        self.response = self.put(f'network/sslvpn/clients/{client}/start')
        return self.response

    def put_network_sslvpn_clients_client_stop(self, client: str):
        '''
        Puts network sslvpn clients {client} stop
        '''
        self.response = self.put(f'network/sslvpn/clients/{client}/stop')
        return self.response

    def get_network_sslvpn_server(self):
        '''
        Gets network sslvpn server
        '''
        self.response = self.get('network/sslvpn/server')
        return self.response

    def put_network_sslvpn_server(self, data: dict):
        '''
        Puts network sslvpn server
        '''
        self.response = self.put('network/sslvpn/server', json = data)
        return self.response

    def get_network_sslvpn_serverstatus(self):
        '''
        Gets network sslvpn serverstatus
        '''
        self.response = self.get('network/sslvpn/serverstatus')
        return self.response

    def post_network_ipsec_tunnel(self, data: dict):
        '''
        Posts network ipsec tunnel
        '''
        self.response = self.post('network/ipsec/tunnel', json = data)
        return self.response

    def delete_network_ipsec_tunnel(self, data: dict):
        '''
        Deletes network ipsec tunnel
        '''
        self.response = self.delete('network/ipsec/tunnel', json = data)
        return self.response

    def get_network_ipsec_tunnel(self, tunnel: str = None):
        '''
        Gets network ipsec tunnel {tunnel}
        '''
        if not tunnel:
            self.response = self.get('network/ipsec/tunnel')
        else:
            self.response = self.get(f'network/ipsec/tunnel/{tunnel}')
        return self.response

    def put_network_ipsec_tunnel(self, tunnel: str, data: dict):
        '''
        Puts network ipsec tunnel {tunnel}
        '''
        self.response = self.put(f'network/ipsec/tunnel/{tunnel}', json = data)
        return self.response

    def put_network_ipsec_tunnel_tunnel_start(self, tunnel: str):
        '''
        Puts network ipsec tunnel {tunnel} start
        '''
        self.response = self.put(f'network/ipsec/tunnel/{tunnel}/start')
        return self.response

    def put_network_ipsec_tunnel_tunnel_stop(self, tunnel: str, data: dict):
        '''
        Puts network ipsec tunnel {tunnel} stop
        '''
        self.response = self.put(f'network/ipsec/tunnel/{tunnel}/stop', json = data)
        return self.response

    def post_network_ipsec_ike_profile(self, data: dict):
        '''
        Posts network ipsec ike_profile
        '''
        self.response = self.post('network/ipsec/ike_profile', json = data)
        return self.response

    def delete_network_ipsec_ike_profile(self, data: dict):
        '''
        Deletes network ipsec ike_profile
        '''
        self.response = self.delete('network/ipsec/ike_profile', json = data)
        return self.response

    def get_network_ipsec_ike_profile(self, ike_profile: str = None):
        '''
        Gets network ipsec ike_profile {ike_profile}
        '''
        if not ike_profile:
            self.response = self.get('network/ipsec/ike_profile')
        else:
            self.response = self.get(f'network/ipsec/ike_profile/{ike_profile}')
        return self.response

    def put_network_ipsec_ike_profile_ike(self, ike_profile: str, data: dict):
        '''
        Puts network ipsec ike_profile {ike_profile}
        '''
        self.response = self.put(f'network/ipsec/ike_profile/{ike_profile}', json = data)
        return self.response

    def get_network_ipsec_global(self):
        '''
        Gets network ipsec global
        '''
        self.response = self.get('network/ipsec/global')
        return self.response

    def put_network_ipsec_global(self, data: dict):
        '''
        Puts network ipsec global
        '''
        self.response = self.put('network/ipsec/global', json = data)
        return self.response

    def get_network_wireguard(self):
        '''
        Gets network wireguard
        '''
        self.response = self.get('network/wireguard')
        return self.response

    def post_network_wireguard(self, data: dict):
        '''
        Posts network wireguard
        '''
        self.response = self.post('network/wireguard', json = data)
        return self.response

    def delete_network_wireguard(self, data: dict):
        '''
        Deletes network wireguard
        '''
        self.response = self.delete('network/wireguard', json = data)
        return self.response

    def put_network_wireguard_interface_name_start(self, interface_name: str):
        '''
        Puts network wireguard {interface_name} start
        '''
        self.response = self.put(f'network/wireguard/{interface_name}/start')
        return self.response

    def put_network_wireguard_interface_name_stop(self, interface_name: str):
        '''
        Puts network wireguard {interface_name} stop
        '''
        self.response = self.put(f'network/wireguard/{interface_name}/stop')
        return self.response

    def get_network_wireguard_interface_name_interface(self, interface_name: str):    
        '''
        Gets network wireguard {interface_name} interface
        '''
        self.response = self.get(f'network/wireguard/{interface_name}/interface')
        return self.response

    def put_network_wireguard_interface_name_interface(self, interface_name: str, data: dict):
        '''
        Puts network wireguard {interface_name} interface
        '''
        self.response = self.put(f'network/wireguard/{interface_name}/interface', json = data)
        return self.response

    def post_network_wireguard_interface_name_peers(self, interface_name: str, data: dict):
        '''
        Posts network wireguard {interface_name} peers
        '''
        self.response = self.post(f'network/wireguard/{interface_name}/peers', json = data)
        return self.response

    def delete_network_wireguard_interface_name_peers(self, interface_name: str):     
        '''
        Deletes network wireguard {interface_name} peers
        '''
        self.response = self.delete(f'network/wireguard/{interface_name}/peers')
        return self.response

    def get_network_wireguard_interface_name_peers(self, interface_name: str, peer_name: str = None):
        '''
        Gets network wireguard {interface_name} peers {peer_name}
        '''
        if not peer_name:
            self.response = self.get(f'network/wireguard/{interface_name}/peers')
        else:
            self.response = self.get(f'network/wireguard/{interface_name}/peers/{peer_name}')
        return self.response

    def put_network_wireguard_interface_name_peers_peer(self, interface_name: str, peer_name: str, data: dict):
        '''
        Puts network wireguard {interface_name} peers {peer_name}
        '''
        self.response = self.put(f'network/wireguard/{interface_name}/peers/{peer_name}', json = data)
        return self.response

    def get_network_sdwan_settings(self):
        '''
        Gets network sdwan settings
        '''
        self.response = self.get('network/sdwan/settings')
        return self.response

    def put_network_sdwan_settings(self, data: dict):
        '''
        Puts network sdwan settings
        '''
        self.response = self.put('network/sdwan/settings', json = data)
        return self.response

    def get_network_sdwan_application(self):
        '''
        Gets network sdwan application
        '''
        self.response = self.get('network/sdwan/application')
        return self.response

    def post_network_sdwan_path_steering(self, data: dict):
        '''
        Posts network sdwan path_steering
        '''
        self.response = self.post('network/sdwan/path_steering', json = data)
        return self.response

    def delete_network_sdwan_path_steering(self, data: dict):
        '''
        Deletes network sdwan path_steering
        '''
        self.response = self.delete('network/sdwan/path_steering', json = data)
        return self.response

    def get_network_sdwan_path_steering(self, path_steering: str = None):
        '''
        Gets network sdwan path_steering {path_steering}
        '''
        if not path_steering:
            self.response = self.get('network/sdwan/path_steering')
        else:
            self.response = self.get(f'network/sdwan/path_steering/{path_steering}')
        return self.response

    def put_network_sdwan_path_steering_path(self, path_steering: str, data: dict):
        '''
        Puts network sdwan path_steering {path_steering}
        '''
        self.response = self.put(f'network/sdwan/path_steering/{path_steering}', json = data)
        return self.response

    def post_network_sdwan_link_profile(self, data: dict):
        '''
        Posts network sdwan link_profile
        '''
        self.response = self.post('network/sdwan/link_profile', json = data)
        return self.response

    def delete_network_sdwan_link_profile(self, data: dict):
        '''
        Deletes network sdwan link_profile
        '''
        self.response = self.delete('network/sdwan/link_profile', json = data)
        return self.response

    def get_network_sdwan_link_profile(self, link_profile: str = None):
        '''
        Gets network sdwan link_profile {link_profile}
        '''
        if not link_profile:
            self.response = self.get('network/sdwan/link_profile')
        else:
            self.response = self.get(f'network/sdwan/link_profile/{link_profile}')
        return self.response

    def put_network_sdwan_link_profile_link(self, link_profile: str, data: dict):
        '''
        Puts network sdwan link_profile {link_profile}
        '''
        self.response = self.put(f'network/sdwan/link_profile/{link_profile}', json = data)
        return self.response

    def post_network_sdwan_path_quality(self, data: dict):
        '''
        Posts network sdwan path_quality
        '''
        self.response = self.post('network/sdwan/path_quality', json = data)
        return self.response

    def delete_network_sdwan_path_quality(self, data: dict):
        '''
        Deletes network sdwan path_quality
        '''
        self.response = self.delete('network/sdwan/path_quality', json = data)
        return self.response

    def get_network_sdwan_path_quality(self, path_quality: str = None):
        '''
        Gets network sdwan path_quality {path_quality}
        '''
        if not path_quality:
            self.response = self.get('network/sdwan/path_quality')
        else:
            self.response = self.get(f'network/sdwan/path_quality/{path_quality}')
        return self.response

    def put_network_sdwan_path_quality_path(self, path_quality: str, data: dict):
        '''
        Puts network sdwan path_quality {path_quality}
        '''
        self.response = self.put(f'network/sdwan/path_quality/{path_quality}', json = data)
        return self.response

    def post_network_staticroutes(self, data: dict):
        '''
        Posts network staticroutes
        '''
        self.response = self.post('network/staticroutes', json = data)
        return self.response

    def delete_network_staticroutes(self, data: dict):
        '''
        Deletes network staticroutes
        '''
        self.response = self.delete('network/staticroutes', json = data)
        return self.response

    def get_network_staticroutes(self, route: str = None):
        '''
        Gets network staticroutes {route}
        '''
        if not route:
            self.response = self.get('network/staticroutes')
        else:
            self.response = self.get(f'network/staticroutes/{route}')
        return self.response

    def put_network_staticroutes(self, route: str, data: dict):
        '''
        Puts network staticroutes {route}
        '''
        self.response = self.put(f'network/staticroutes/{route}', json = data)
        return self.response

    def get_network_switch_backplane(self):
        '''
        Gets network switch backplane
        '''
        self.response = self.get('network/switch/backplane')
        return self.response

    def put_network_switch_backplane(self, data: dict):
        '''
        Puts network switch backplane
        '''
        self.response = self.put('network/switch/backplane', json = data)
        return self.response

    def get_network_switch_global(self):
        '''
        Gets network switch global
        '''
        self.response = self.get('network/switch/global')
        return self.response

    def put_network_switch_global(self, data: dict):
        '''
        Puts network switch global
        '''
        self.response = self.put('network/switch/global', json = data)
        return self.response

    def get_network_switch_interfaces(self, interface: str = None):
        '''
        Gets network switch interfaces {interface}
        '''
        if not interface:
            self.response = self.get('network/switch/interfaces')
        else:
            self.response = self.get(f'network/switch/interfaces/{interface}')
        return self.response

    def put_network_switch_interfaces(self, interface: str, data: dict):
        '''
        Puts network switch interfaces {interface}
        '''
        self.response = self.put(f'network/switch/interfaces/{interface}', json = data)
        return self.response

    def post_network_switch_lag(self, data: dict):
        '''
        Posts network switch lag
        '''
        self.response = self.post('network/switch/lag', json = data)
        return self.response

    def delete_network_switch_lag(self, data: dict):
        '''
        Deletes network switch lag
        '''
        self.response = self.delete('network/switch/lag', json = data)
        return self.response

    def get_network_switch_lag(self, lag: str = None):
        '''
        Gets network switch lag {lag}
        '''
        if not lag:
            self.response = self.get('network/switch/lag')
        else:
            self.response = self.get(f'network/switch/lag/{lag}')
        return self.response

    def put_network_switch_lag(self, lag: str, data: dict):
        '''
        Puts network switch lag {lag}
        '''
        self.response = self.put(f'network/switch/lag/{lag}', json = data)
        return self.response

    def get_network_switch_acl(self):
        '''
        Gets network switch acl
        '''
        self.response = self.get('network/switch/acl')
        return self.response
    
    def post_network_switch_acl(self, data: dict):
        '''
        Posts network switch acl
        '''
        self.response = self.post('network/switch/acl', json = data)
        return self.response

    def delete_network_switch_acl(self, data: dict):
        '''
        Deletes network switch acl
        '''
        self.response = self.delete('network/switch/acl', json = data)
        return self.response

    def put_network_switch_acl_acl_id_direction(self, acl_id: str, data: dict):
        '''
        Puts network switch acl {acl_id} direction
        '''
        self.response = self.put(f'network/switch/acl/{acl_id}/direction', json = data)
        return self.response

    def post_network_switch_acl_acl_id_rules(self, acl_id: str, data: dict):
        '''
        Posts network switch acl {acl_id} rules
        '''
        self.response = self.post(f'network/switch/acl/{acl_id}/rules', json = data)
        return self.response

    def delete_network_switch_acl_acl_id_rules(self, acl_id: str, data: dict):
        '''
        Deletes network switch acl {acl_id} rules
        '''
        self.response = self.delete(f'network/switch/acl/{acl_id}/rules', json = data)
        return self.response

    def get_network_switch_acl_acl_id_rules(self, acl_id: str, rule_id: str = None):
        '''
        Gets network switch acl {acl_id} rules {rule_id}
        '''
        if not rule_id:
            self.response = self.get(f'network/switch/acl/{acl_id}/rules')
        else:
            self.response = self.get(f'network/switch/acl/{acl_id}/rules/{rule_id}')
        return self.response

    def put_network_switch_acl_acl_id_rules_rule(self, acl_id: str, rule_id: str, data: dict):
        '''
        Puts network switch acl {acl_id} rules {rule_id}
        '''
        self.response = self.put(f'network/switch/acl/{acl_id}/rules/{rule_id}', json = data)
        return self.response

    def post_network_switch_mstp(self, data: dict):
        '''
        Posts network switch mstp
        '''
        self.response = self.post('network/switch/mstp', json = data)
        return self.response

    def delete_network_switch_mstp(self, data: dict):
        '''
        Deletes network switch mstp
        '''
        self.response = self.delete('network/switch/mstp', json = data)
        return self.response

    def put_network_switch_mstp_instance_vlan_priority(self, instance: str, data: dict):
        '''
        Puts network switch mstp {instance} vlan_priority
        '''
        self.response = self.put(f'network/switch/mstp/{instance}/vlan_priority', json = data)
        return self.response

    def get_network_switch_mstp_instance_interfaces(self, instance: str = None):
        '''
        Gets network switch mstp {instance} interfaces
        '''
        if not instance:
            self.response = self.get('network/switch/mstp')
        else:
            self.response = self.get(f'network/switch/mstp/{instance}/interfaces')
        return self.response

    def put_network_switch_mstp_instance_interfaces(self, instance: str, interface: str, data: dict):
        '''
        Puts network switch mstp {instance} interfaces {interface}
        '''
        self.response = self.put(f'network/switch/mstp/{instance}/interfaces/{interface}', json = data)
        return self.response

    def get_network_switch_poe(self, name: str = None):
        '''
        Gets network switch poe {name}
        '''
        if not name:
            self.response = self.get('network/switch/poe')
        else:
            self.response = self.get(f'network/switch/poe/{name}')
        return self.response

    def put_network_switch_poe(self, name: str, data: dict):
        '''
        Puts network switch poe {name}
        '''
        self.response = self.put(f'network/switch/poe/{name}', json = data)
        return self.response

    def post_network_switch_vlan(self, data: dict):
        '''
        Posts network switch vlan
        '''
        self.response = self.post('network/switch/vlan', json = data)
        return self.response

    def delete_network_switch_vlan(self, data: dict):
        '''
        Deletes network switch vlan
        '''
        self.response = self.delete('network/switch/vlan', json = data)
        return self.response

    def get_network_switch_vlan(self, vlan: str = None):
        '''
        Gets network switch vlan {vlan}
        '''
        if not vlan:
            self.response = self.get('network/switch/vlan')
        else:
            self.response = self.get(f'network/switch/vlan/{vlan}')
        return self.response

    def put_network_switch_vlan(self, vlan: str, data: dict):
        '''
        Puts network switch vlan {vlan}
        '''
        self.response = self.put(f'network/switch/vlan/{vlan}', json = data)
        return self.response

    def post_network_switch_portmirroring(self, data: dict):
        '''
        Posts network switch portmirroring
        '''
        self.response = self.post('network/switch/portmirroring', json = data)
        return self.response

    def delete_network_switch_portmirroring(self, data: dict):
        '''
        Deletes network switch portmirroring
        '''
        self.response = self.delete('network/switch/portmirroring', json = data)
        return self.response

    def get_network_switch_portmirroring(self, session_name: str = None):
        '''
        Gets network switch portmirroring {session_name}
        '''
        if not session_name:
            self.response = self.get('network/switch/portmirroring')
        else:
            self.response = self.get(f'network/switch/portmirroring/{session_name}')
        return self.response

    def put_network_switch_portmirroring_session(self, session_name: str, data: dict):
        '''
        Puts network switch portmirroring {session_name}
        '''
        self.response = self.put(f'network/switch/portmirroring/{session_name}', json = data)
        return self.response

    def put_network_switch_portmirroring_session_name_rename(self, session_name: str, data: dict):
        '''
        Puts network switch portmirroring {session_name} rename
        '''
        self.response = self.put(f'network/switch/portmirroring/{session_name}/rename', json = data)
        return self.response

    def put_network_switch_vlan_dhcpsnooping(self, data: dict):
        '''
        Puts network switch vlan dhcpsnooping
        '''
        self.response = self.put('network/switch/vlan/dhcpsnooping', json = data)
        return self.response

    def get_network_switch_vlan_dhcpsnooping(self, vlan: str = None):
        '''
        Gets network switch vlan dhcpsnooping {vlan}
        '''
        if not vlan:
            self.response = self.get('network/switch/vlan/dhcpsnooping')
        else:
            self.response = self.get(f'network/switch/vlan/dhcpsnooping/{vlan}')
        return self.response

    def get_network_wirelessmodem_global(self):
        '''
        Gets network wirelessmodem global
        '''
        self.response = self.get('network/wirelessmodem/global')
        return self.response

    def put_network_wirelessmodem_global_modem_reset(self, modem: str):
        '''
        Puts network wirelessmodem global {modem} reset
        '''
        self.response = self.put(f'network/wirelessmodem/global/{modem}/reset')
        return self.response

    def get_network_wirelessmodem_global_modem_firmware(self, modem: str):
        '''
        Gets network wirelessmodem global {modem} firmware
        '''
        self.response = self.get(f'network/wirelessmodem/global/{modem}/firmware')
        return self.response

    def put_network_wirelessmodem_global_modem_power_cycle(self, modem: str):
        '''
        Puts network wirelessmodem global {modem} power_cycle
        '''
        self.response = self.put(f'network/wirelessmodem/global/{modem}/power_cycle')
        return self.response

    def delete_network_wirelessmodem_global_modem_power_cycle(self, modem: str, data: dict):      
        '''
        Deletes network wirelessmodem global {modem} power_cycle
        '''
        self.response = self.delete(f'network/wirelessmodem/global/{modem}/power_cycle', json = data)
        return self.response

    def post_network_wirelessmodem_global_modem_firmware_upgrade(self, modem: str, data: dict):
        '''
        Posts network wirelessmodem global {modem} firmware upgrade
        '''
        self.response = self.post(f'network/wirelessmodem/global/{modem}/firmware/upgrade', json = data)
        return self.response

    def post_network_flow(self, data: dict):
        '''
        Posts network flow
        '''
        self.response = self.post('network/flow', json = data)
        return self.response

    def get_network_flow(self, flow_id: str = None):
        '''
        Gets network flow {flow_id}
        '''
        if not flow_id:
            self.response = self.get('network/flow')
        else:
            self.response = self.get(f'network/flow/{flow_id}')
        return self.response

    def put_network_flow_flow(self, flow_id: str, data: dict):
        '''
        Puts network flow {flow_id}
        '''
        self.response = self.put(f'network/flow/{flow_id}', json = data)
        return self.response

    def delete_network_flow_flow_id(self, flow_id: str):
        '''
        Deletes network flow {flow_id}
        '''
        self.response = self.delete(f'network/flow/{flow_id}')
        return self.response

    def post_network_qos_interfaces(self, data: dict):
        '''
        Posts network qos interfaces
        '''
        self.response = self.post('network/qos/interfaces', json = data)
        return self.response

    def get_network_qos_interfaces(self, interface_id: str = None):
        '''
        Gets network qos interfaces {interface_id}
        '''
        if not interface_id:
            self.response = self.get('network/qos/interfaces')
        else:
            self.response = self.get(f'network/qos/interfaces/{interface_id}')
        return self.response

    def put_network_qos_interfaces_interface(self, interface_id: str, data: dict):
        '''
        Puts network qos interfaces {interface_id}
        '''
        self.response = self.put(f'network/qos/interfaces/{interface_id}', json = data)
        return self.response

    def post_network_qos_classes(self, data: dict):
        '''
        Posts network qos classes
        '''
        self.response = self.post('network/qos/classes', json = data)
        return self.response

    def get_network_qos_classes(self, class_id: str = None):
        '''
        Gets network qos classes {class_id}
        '''
        if not class_id:
            self.response = self.get('network/qos/classes')
        else:
            self.response = self.get(f'network/qos/classes/{class_id}')
        return self.response

    def put_network_qos_classes_class(self, class_id: str, data: dict):
        '''
        Puts network qos classes {class_id}
        '''
        self.response = self.put(f'network/qos/classes/{class_id}', json = data)
        return self.response

    def post_network_qos_rules(self, data: dict):
        '''
        Posts network qos rules
        '''
        self.response = self.post('network/qos/rules', json = data)
        return self.response

    def get_network_qos_rules(self, rule_id: str = None):
        '''
        Gets network qos rules {rule_id}
        '''
        if not rule_id:
            self.response = self.get('network/qos/rules')
        else:
            self.response = self.get(f'network/qos/rules/{rule_id}')
        return self.response

    def put_network_qos_rules_rule(self, rule_id: str, data: dict):
        '''
        Puts network qos rules {rule_id}
        '''
        self.response = self.put(f'network/qos/rules/{rule_id}', json = data)
        return self.response

    def post_network_802_1x_profiles(self, data: dict):
        '''
        Posts network 802.1x profiles
        '''
        self.response = self.post('network/802.1x/profiles', json = data)
        return self.response

    def delete_network_802_1x_profiles(self, data: dict):
        '''
        Deletes network 802.1x profiles
        '''
        self.response = self.delete('network/802.1x/profiles', json = data)
        return self.response

    def get_network_802_1x_profiles(self, profile: str = None):
        '''
        Gets network 802.1x profiles {profile}
        '''
        if not profile:
            self.response = self.get('network/802.1x/profiles')
        else:
            self.response = self.get(f'network/802.1x/profiles/{profile}')
        return self.response

    def put_network_802_1x_profiles(self, profile: str, data: dict):
        '''
        Puts network 802.1x profiles {profile}
        '''
        self.response = self.put(f'network/802.1x/profiles/{profile}', json = data)
        return self.response

    def post_network_802_1x_credentials(self, data: dict):
        '''
        Posts network 802.1x credentials
        '''
        self.response = self.post('network/802.1x/credentials', json = data)
        return self.response

    def delete_network_802_1x_credentials(self, data: dict):
        '''
        Deletes network 802.1x credentials
        '''
        self.response = self.delete('network/802.1x/credentials', json = data)
        return self.response

    def get_network_802_1x_credentials(self, credential: str = None):
        '''
        Gets network 802.1x credentials {credential}
        '''
        if not credential:
            self.response = self.get('network/802.1x/credentials')
        else:
            self.response = self.get(f'network/802.1x/credentials/{credential}')
        return self.response

    def put_network_802_1x_credentials(self, credential: str, data: dict):
        '''
        Puts network 802.1x credentials {credential}
        '''
        self.response = self.put(f'network/802.1x/credentials/{credential}', json = data)
        return self.response

    def post_security_authentication(self, data: dict):
        '''
        Posts security authentication
        '''
        self.response = self.post('security/authentication', json = data)
        return self.response

    def delete_security_authentication(self, data: dict):
        '''
        Deletes security authentication
        '''
        self.response = self.delete('security/authentication', json = data)
        return self.response

    def get_security_authentication(self, method: str = None):
        '''
        Gets security authentication {method}
        '''
        if not method:
            self.response = self.get('security/authentication')
        else:
            self.response = self.get(f'security/authentication/{method}')
        return self.response

    def put_security_authentication(self, method: str, data: dict):
        '''
        Puts security authentication {method}
        '''
        self.response = self.put(f'security/authentication/{method}', json = data)
        return self.response

    def put_security_authentication_method_down(self, method: str):
        '''
        Puts security authentication {method} down
        '''
        self.response = self.put(f'security/authentication/{method}/down')
        return self.response

    def put_security_authentication_method_up(self, method: str):
        '''
        Puts security authentication {method} up
        '''
        self.response = self.put(f'security/authentication/{method}/up')
        return self.response

    def get_security_authentication_console(self):
        '''
        Gets security authentication_console
        '''
        self.response = self.get('security/authentication_console')
        return self.response

    def put_security_authentication_console(self, data: dict):
        '''
        Puts security authentication_console
        '''
        self.response = self.put('security/authentication_console', json = data)
        return self.response

    def get_security_authentication_defaultgroup(self):
        '''
        Gets security authentication_defaultgroup
        '''
        self.response = self.get('security/authentication_defaultgroup')
        return self.response

    def put_security_authentication_defaultgroup(self, data: dict):
        '''
        Puts security authentication_defaultgroup
        '''
        self.response = self.put('security/authentication_defaultgroup', json = data)
        return self.response

    def get_security_authentication_realms(self):
        '''
        Gets security authentication_realms
        '''
        self.response = self.get('security/authentication_realms')
        return self.response

    def put_security_authentication_realms(self, data: dict):
        '''
        Puts security authentication_realms
        '''
        self.response = self.put('security/authentication_realms', json = data)
        return self.response

    def post_security_authentication_sso(self, data: dict):
        '''
        Posts security authentication sso
        '''
        self.response = self.post('security/authentication/sso', json = data)
        return self.response

    def delete_security_authentication_sso(self, data: dict):
        '''
        Deletes security authentication sso
        '''
        self.response = self.delete('security/authentication/sso', json = data)
        return self.response

    def get_security_authentication_sso(self, method: str = None):
        '''
        Gets security authentication sso {method}
        '''
        if not method:
            self.response = self.get('security/authentication/sso')
        else:
            self.response = self.get(f'security/authentication/sso/{method}')
        return self.response

    def put_security_authentication_sso(self, method: str, data: dict):
        '''
        Puts security authentication sso {method}
        '''
        self.response = self.put(f'security/authentication/sso/{method}', json = data)
        return self.response

    def post_security_authentication_sso_method_certificate(self, method: str, data: dict):
        '''
        Posts security authentication sso {method} certificate
        '''
        self.response = self.post(f'security/authentication/sso/{method}/certificate', json = data)
        return self.response

    def post_security_authentication_sso_import_metadata(self, data: dict):
        '''
        Posts security authentication sso import_metadata
        '''
        self.response = self.post('security/authentication/sso/import_metadata', json = data)
        return self.response

    def get_security_authorization(self):
        '''
        Gets security authorization
        '''
        self.response = self.get('security/authorization')
        return self.response

    def post_security_authorization(self, data: dict):
        '''
        Posts security authorization
        '''
        self.response = self.post('security/authorization', json = data)
        return self.response

    def delete_security_authorization(self, data: dict):
        '''
        Deletes security authorization
        '''
        self.response = self.delete('security/authorization', json = data)
        return self.response

    def post_security_authorization_group_devices(self, group: str, data: dict):
        '''
        Posts security authorization {group} devices
        '''
        self.response = self.post(f'security/authorization/{group}/devices', json = data)
        return self.response

    def delete_security_authorization_group_devices(self, group: str, data: dict):
        '''
        Deletes security authorization {group} devices
        '''
        self.response = self.delete(f'security/authorization/{group}/devices', json = data)
        return self.response

    def get_security_authorization_group_devices(self, group: str, device: str = None):
        '''
        Gets security authorization {group} devices {device}
        '''
        if not device:
            self.response = self.get(f'security/authorization/{group}/devices')
        else:
            self.response = self.get(f'security/authorization/{group}/devices/{device}')
        return self.response

    def put_security_authorization_group_devices(self, group: str, device: str, data: dict):
        '''
        Puts security authorization {group} devices {device}
        '''
        self.response = self.put(f'security/authorization/{group}/devices/{device}', json = data)
        return self.response

    def get_security_authorization_group_members(self, group: str):
        '''
        Gets security authorization {group} members
        '''
        self.response = self.get(f'security/authorization/{group}/members')
        return self.response

    def post_security_authorization_group_members(self, group: str, data: dict):
        '''
        Posts security authorization {group} members
        '''
        self.response = self.post(f'security/authorization/{group}/members', json = data)
        return self.response

    def delete_security_authorization_group_members(self, group: str, data: dict):
        '''
        Deletes security authorization {group} members
        '''
        self.response = self.delete(f'security/authorization/{group}/members', json = data)
        return self.response

    def post_security_authorization_group_outlets(self, group: str, data: dict):
        '''
        Posts security authorization {group} outlets
        '''
        self.response = self.post(f'security/authorization/{group}/outlets', json = data)
        return self.response

    def delete_security_authorization_group_outlets(self, group: str, data: dict):
        '''
        Deletes security authorization {group} outlets
        '''
        self.response = self.delete(f'security/authorization/{group}/outlets', json = data)
        return self.response

    def get_security_authorization_group_outlets(self, group: str, outlet: str = None):
        '''
        Gets security authorization {group} outlets {outlet}
        '''
        if not outlet:
            self.response = self.get(f'security/authorization/{group}/outlets')
        else:
            self.response = self.get(f'security/authorization/{group}/outlets/{outlet}')
        return self.response

    def put_security_authorization_group_outlets(self, group: str, outlet: str, data: dict):
        '''
        Puts security authorization {group} outlets {outlet}
        '''
        self.response = self.put(f'security/authorization/{group}/outlets/{outlet}', json = data)
        return self.response

    def get_security_authorization_group_profile(self, group: str):
        '''
        Gets security authorization {group} profile
        '''
        self.response = self.get(f'security/authorization/{group}/profile')
        return self.response

    def put_security_authorization_group_profile(self, group: str, data: dict):
        '''
        Puts security authorization {group} profile
        '''
        self.response = self.put(f'security/authorization/{group}/profile', json = data)
        return self.response

    def get_security_authorization_group_remotegroups(self, group: str):
        '''
        Gets security authorization {group} remotegroups
        '''
        self.response = self.get(f'security/authorization/{group}/remotegroups')
        return self.response

    def put_security_authorization_group_remotegroups(self, group: str, data: dict):
        '''
        Puts security authorization {group} remotegroups
        '''
        self.response = self.put(f'security/authorization/{group}/remotegroups', json = data)
        return self.response

    def get_security_firewall(self):
        '''
        Gets security firewall
        '''
        self.response = self.get('security/firewall')
        return self.response

    def post_security_firewall(self, data: dict):
        '''
        Posts security firewall
        '''
        self.response = self.post('security/firewall', json = data)
        return self.response

    def delete_security_firewall(self, data: dict):
        '''
        Deletes security firewall
        '''
        self.response = self.delete('security/firewall', json = data)
        return self.response

    def post_security_firewall_chain_rules(self, chain: str, data: dict):
        '''
        Posts security firewall {chain} rules
        '''
        self.response = self.post(f'security/firewall/{chain}/rules', json = data)
        return self.response

    def delete_security_firewall_chain_rules(self, chain: str, data: dict):
        '''
        Deletes security firewall {chain} rules
        '''
        self.response = self.delete(f'security/firewall/{chain}/rules', json = data)
        return self.response

    def get_security_firewall_chain_rules(self, chain: str, rule: str = None):
        '''
        Gets security firewall {chain} rules {rule}
        '''
        if not rule:
            self.response = self.get(f'security/firewall/{chain}/rules')
        else:
            self.response = self.get(f'security/firewall/{chain}/rules/{rule}')
        return self.response

    def put_security_firewall_chain_rules(self, chain: str, rule: str, data: dict):
        '''
        Puts security firewall {chain} rules {rule}
        '''
        self.response = self.put(f'security/firewall/{chain}/rules/{rule}', json = data)
        return self.response

    def get_security_firewall_changepolicy(self, data: dict):
        '''
        Gets security firewall_changepolicy
        '''
        self.response = self.get('security/firewall_changepolicy', json = data)
        return self.response

    def put_security_firewall_changepolicy(self, data: dict):
        '''
        Puts security firewall_changepolicy
        '''
        self.response = self.put('security/firewall_changepolicy', json = data)
        return self.response

    def get_security_nat(self):
        '''
        Gets security nat
        '''
        self.response = self.get('security/nat')
        return self.response

    def post_security_nat(self, data: dict):
        '''
        Posts security nat
        '''
        self.response = self.post('security/nat', json = data)
        return self.response

    def delete_security_nat(self, data: dict):
        '''
        Deletes security nat
        '''
        self.response = self.delete('security/nat', json = data)
        return self.response

    def post_security_nat_chain_rules(self, chain: str, data: dict):
        '''
        Posts security nat {chain} rules
        '''
        self.response = self.post(f'security/nat/{chain}/rules', json = data)
        return self.response

    def delete_security_nat_chain_rules(self, chain: str, data: dict):
        '''
        Deletes security nat {chain} rules
        '''
        self.response = self.delete(f'security/nat/{chain}/rules', json = data)
        return self.response

    def get_security_nat_chain_rules(self, chain: str, rule: str = None):
        '''
        Gets security nat {chain} rules {rule}
        '''
        if not rule:
            self.response = self.get(f'security/nat/{chain}/rules')
        else:
            self.response = self.get(f'security/nat/{chain}/rules/{rule}')
        return self.response

    def put_security_nat_chain_rules(self, chain: str, rule: str, data: dict):
        '''
        Puts security nat {chain} rules {rule}
        '''
        self.response = self.put(f'security/nat/{chain}/rules/{rule}', json = data)
        return self.response

    def get_security_nat_changepolicy(self, data: dict):
        '''
        Gets security nat_changepolicy
        '''
        self.response = self.get('security/nat_changepolicy', json = data)
        return self.response

    def put_security_nat_changepolicy(self, data: dict):
        '''
        Puts security nat_changepolicy
        '''
        self.response = self.put('security/nat_changepolicy', json = data)
        return self.response

    def post_security_localaccounts(self, data: dict):
        '''
        Posts security localaccounts
        '''
        self.response = self.post('security/localaccounts', json = data)
        return self.response

    def delete_security_localaccounts(self, data: dict):
        '''
        Deletes security localaccounts
        '''
        self.response = self.delete('security/localaccounts', json = data)
        return self.response

    def get_security_localaccounts(self, account: str = None):
        '''
        Gets security localaccounts {account}
        '''
        if not account:
            self.response = self.get('security/localaccounts')
        else:
            self.response = self.get(f'security/localaccounts/{account}')
        return self.response

    def put_security_localaccounts(self, account: str, data: dict):
        '''
        Puts security localaccounts {account}
        '''
        self.response = self.put(f'security/localaccounts/{account}', json = data)
        return self.response

    def put_security_localaccounts_account_reset_api_key(self, account: str):
        '''
        Puts security localaccounts {account} reset_api_key
        '''
        self.response = self.put(f'security/localaccounts/{account}/reset_api_key')
        return self.response

    def put_security_localaccounts_account_lock(self, account: str):
        '''
        Puts security localaccounts {account} lock
        '''
        self.response = self.put(f'security/localaccounts/{account}/lock')
        return self.response

    def put_security_localaccounts_account_unlock(self, account: str):
        '''
        Puts security localaccounts {account} unlock
        '''
        self.response = self.put(f'security/localaccounts/{account}/unlock')
        return self.response

    def get_security_passwordrules(self):
        '''
        Gets security passwordrules
        '''
        self.response = self.get('security/passwordrules')
        return self.response

    def put_security_passwordrules(self, data: dict):
        '''
        Puts security passwordrules
        '''
        self.response = self.put('security/passwordrules', json = data)
        return self.response

    def get_security_services(self):
        '''
        Gets security services
        '''
        self.response = self.get('security/services')
        return self.response

    def put_security_services(self, data: dict):
        '''
        Puts security services
        '''
        self.response = self.put('security/services', json = data)
        return self.response

    def get_security_zpecloud(self):
        '''
        Gets security zpecloud
        '''
        self.response = self.get('security/zpecloud')
        return self.response

    def put_security_zpecloud(self, data: dict):
        '''
        Puts security zpecloud
        '''
        self.response = self.put('security/zpecloud', json = data)
        return self.response

    def get_security_fips(self):
        '''
        Gets security fips
        '''
        self.response = self.get('security/fips')
        return self.response

    def put_security_fips(self, data: dict):
        '''
        Puts security fips
        '''
        self.response = self.put('security/fips', json = data)
        return self.response

    def get_security_geo_fence(self):
        '''
        Gets security geo_fence
        '''
        self.response = self.get('security/geo_fence')
        return self.response

    def put_security_geo_fence(self, data: dict):
        '''
        Puts security geo_fence
        '''
        self.response = self.put('security/geo_fence', json = data)
        return self.response

    def get_system_about(self):
        '''
        Gets system about
        '''
        self.response = self.get('system/about')
        return self.response

    def get_system_fips_status(self):
        '''
        Gets system fips status
        '''
        self.response = self.get('system/fips/status')
        return self.response

    def get_system_fips_services(self):
        '''
        Gets system fips services
        '''
        self.response = self.get('system/fips/services')
        return self.response

    def post_system_customfields(self, data: dict):
        '''
        Posts system customfields
        '''
        self.response = self.post('system/customfields', json = data)
        return self.response

    def delete_system_customfields(self, data: dict):
        '''
        Deletes system customfields
        '''
        self.response = self.delete('system/customfields', json = data)
        return self.response

    def get_system_customfields(self, field: str = None):
        '''
        Gets system customfields {field}
        '''
        if not field:
            self.response = self.get('system/customfields')
        else:
            self.response = self.get(f'system/customfields/{field}')
        return self.response

    def put_system_customfields(self, field: str, data: dict):
        '''
        Puts system customfields {field}
        '''
        self.response = self.put(f'system/customfields/{field}', json = data)
        return self.response

    def get_system_datetime(self):
        '''
        Gets system datetime
        '''
        self.response = self.get('system/datetime')
        return self.response

    def put_system_datetime(self, data: dict):
        '''
        Puts system datetime
        '''
        self.response = self.put('system/datetime', json = data)
        return self.response

    def get_system_datetime_ntpserver(self):
        '''
        Gets system datetime ntpserver
        '''
        self.response = self.get('system/datetime/ntpserver')
        return self.response

    def put_system_datetime_ntpserver(self, data: dict):
        '''
        Puts system datetime ntpserver
        '''
        self.response = self.put('system/datetime/ntpserver', json = data)
        return self.response

    def post_system_datetime_ntp(self, data: dict):
        '''
        Posts system datetime ntp
        '''
        self.response = self.post('system/datetime/ntp', json = data)
        return self.response

    def delete_system_datetime_ntp(self, data: dict):
        '''
        Deletes system datetime ntp
        '''
        self.response = self.delete('system/datetime/ntp', json = data)
        return self.response

    def get_system_datetime_ntp(self, key_number: str = None):
        '''
        Gets system datetime ntp {key_number}
        '''
        if not key_number:
            self.response = self.get('system/datetime/ntp')
        else:
            self.response = self.get(f'system/datetime/ntp/{key_number}')
        return self.response

    def put_system_datetime_ntp_key(self, key_number: str, data: dict):
        '''
        Puts system datetime ntp {key_number}
        '''
        self.response = self.put(f'system/datetime/ntp/{key_number}', json = data)
        return self.response

    def get_system_dialup(self):
        '''
        Gets system dialup
        '''
        self.response = self.get('system/dialup')
        return self.response

    def put_system_dialup(self, data: dict):
        '''
        Puts system dialup
        '''
        self.response = self.put('system/dialup', json = data)
        return self.response

    def post_system_dialup_callbackusers(self, data: dict):
        '''
        Posts system dialup callbackusers
        '''
        self.response = self.post('system/dialup/callbackusers', json = data)
        return self.response

    def delete_system_dialup_callbackusers(self, data: dict):
        '''
        Deletes system dialup callbackusers
        '''
        self.response = self.delete('system/dialup/callbackusers', json = data)
        return self.response

    def get_system_dialup_callbackusers(self, user: str = None):
        '''
        Gets system dialup callbackusers {user}
        '''
        if not user:
            self.response = self.get('system/dialup/callbackusers')
        else:
            self.response = self.get(f'system/dialup/callbackusers/{user}')
        return self.response

    def put_system_dialup_callbackusers(self, user: str, data: dict):
        '''
        Puts system dialup callbackusers {user}
        '''
        self.response = self.put(f'system/dialup/callbackusers/{user}', json = data)
        return self.response

    def get_system_licenses(self):
        '''
        Gets system licenses
        '''
        self.response = self.get('system/licenses')
        return self.response

    def post_system_licenses(self, data: dict):
        '''
        Posts system licenses
        '''
        self.response = self.post('system/licenses', json = data)
        return self.response

    def delete_system_licenses(self, data: dict):
        '''
        Deletes system licenses
        '''
        self.response = self.delete('system/licenses', json = data)
        return self.response

    def get_system_logging(self):
        '''
        Gets system logging
        '''
        self.response = self.get('system/logging')
        return self.response

    def put_system_logging(self, data: dict):
        '''
        Puts system logging
        '''
        self.response = self.put('system/logging', json = data)
        return self.response

    def get_system_preferences(self):
        '''
        Gets system preferences
        '''
        self.response = self.get('system/preferences')
        return self.response

    def put_system_preferences(self, data: dict):
        '''
        Puts system preferences
        '''
        self.response = self.put('system/preferences', json = data)
        return self.response

    def post_system_preferences_alarmstate(self):
        '''
        Posts system preferences alarmstate
        '''
        self.response = self.post('system/preferences/alarmstate')
        return self.response

    def post_system_schedule(self, data: dict):
        '''
        Posts system schedule
        '''
        self.response = self.post('system/schedule', json = data)
        return self.response

    def delete_system_schedule(self, data: dict):
        '''
        Deletes system schedule
        '''
        self.response = self.delete('system/schedule', json = data)
        return self.response

    def get_system_schedule(self, task: str = None):
        '''
        Gets system schedule {task}
        '''
        if not task:
            self.response = self.get('system/schedule')
        else:
            self.response = self.get(f'system/schedule/{task}')
        return self.response

    def put_system_schedule(self, task: str, data: dict):
        '''
        Puts system schedule {task}
        '''
        self.response = self.put(f'system/schedule/{task}', json = data)
        return self.response

    def post_system_schedule_task_clone(self, task: str, data: dict):
        '''
        Posts system schedule {task} clone
        '''
        self.response = self.post(f'system/schedule/{task}/clone', json = data)
        return self.response

    def post_system_schedule_enable(self, data: dict):
        '''
        Posts system schedule enable
        '''
        self.response = self.post('system/schedule/enable', json = data)
        return self.response

    def post_system_schedule_disable(self, data: dict):
        '''
        Posts system schedule disable
        '''
        self.response = self.post('system/schedule/disable', json = data)
        return self.response

    def get_system_slots(self, slot: str = None):
        '''
        Gets system slots {slot}
        '''
        if not slot:
            self.response = self.get('system/slots')
        else:
            self.response = self.get(f'system/slots/{slot}')
        return self.response

    def get_system_sms(self):
        '''
        Gets system sms
        '''
        self.response = self.get('system/sms')
        return self.response

    def put_system_sms(self, data: dict):
        '''
        Puts system sms
        '''
        self.response = self.put('system/sms', json = data)
        return self.response

    def post_system_sms_whitelist(self, data: dict):
        '''
        Posts system sms whitelist
        '''
        self.response = self.post('system/sms/whitelist', json = data)
        return self.response

    def delete_system_sms_whitelist(self, data: dict):
        '''
        Deletes system sms whitelist
        '''
        self.response = self.delete('system/sms/whitelist', json = data)
        return self.response

    def get_system_sms_whitelist(self, name: str = None):
        '''
        Gets system sms whitelist {name}
        '''
        if not name:
            self.response = self.get('system/sms/whitelist')
        else:
            self.response = self.get(f'system/sms/whitelist/{name}')
        return self.response

    def put_system_sms_whitelist(self, name: str, data: dict):
        '''
        Puts system sms whitelist {name}
        '''
        self.response = self.put(f'system/sms/whitelist/{name}', json = data)
        return self.response

    def post_system_remote_file_system(self, data: dict):
        '''
        Posts system remote_file_system
        '''
        self.response = self.post('system/remote_file_system', json = data)
        return self.response

    def delete_system_remote_file_system(self, data: dict):
        '''
        Deletes system remote_file_system
        '''
        self.response = self.delete('system/remote_file_system', json = data)
        return self.response

    def get_system_remote_file_system(self, mountpoint: str = None):
        '''
        Gets system remote_file_system {mountpoint}
        '''
        if not mountpoint:
            self.response = self.get('system/remote_file_system')
        else:
            self.response = self.get(f'system/remote_file_system/{mountpoint}')
        return self.response

    def put_system_remote_file_system(self, mountpoint: str, data: dict):
        '''
        Puts system remote_file_system {mountpoint}
        '''
        self.response = self.put(f'system/remote_file_system/{mountpoint}', json = data)
        return self.response

    def get_system_ioports(self):
        '''
        Gets system ioports
        '''
        self.response = self.get('system/ioports')
        return self.response

    def put_system_ioports(self, data: dict):
        '''
        Puts system ioports
        '''
        self.response = self.put('system/ioports', json = data)
        return self.response

    def post_system_toolkit_applysettings(self, data: dict):
        '''
        Posts system toolkit applysettings
        '''
        self.response = self.post('system/toolkit/applysettings', json = data)
        return self.response

    def post_system_toolkit_certificate(self, data: dict):
        '''
        Posts system toolkit certificate
        '''
        self.response = self.post('system/toolkit/certificate', json = data)
        return self.response

    def get_system_toolkit_checksum(self):
        '''
        Gets system toolkit checksum
        '''
        self.response = self.get('system/toolkit/checksum')
        return self.response

    def post_system_toolkit_checksum(self, data: dict):
        '''
        Posts system toolkit checksum
        '''
        self.response = self.post('system/toolkit/checksum', json = data)
        return self.response

    def get_system_toolkit_cloudenrollment(self):
        '''
        Gets system toolkit cloudenrollment
        '''
        self.response = self.get('system/toolkit/cloudenrollment')
        return self.response

    def post_system_toolkit_cloudenrollment(self, data: dict):
        '''
        Posts system toolkit cloudenrollment
        '''
        self.response = self.post('system/toolkit/cloudenrollment', json = data)
        return self.response

    def post_system_toolkit_cloudenrollment_stopenrollment(self):
        '''
        Posts system toolkit cloudenrollment stopenrollment
        '''
        self.response = self.post('system/toolkit/cloudenrollment/stopenrollment')
        return self.response

    def post_system_toolkit_create_csr(self, data: dict):
        '''
        Posts system toolkit create_csr
        '''
        self.response = self.post('system/toolkit/create_csr', json = data)
        return self.response

    def post_system_toolkit_detectmtu(self, data: dict):
        '''
        Posts system toolkit detectmtu
        '''
        self.response = self.post('system/toolkit/detectmtu', json = data)
        return self.response

    def post_system_toolkit_diagnosticdata(self):
        '''
        Posts system toolkit diagnosticdata
        '''
        self.response = self.post('system/toolkit/diagnosticdata')
        return self.response

    def post_system_toolkit_dnslookup(self, data: dict):
        '''
        Posts system toolkit dnslookup
        '''
        self.response = self.post('system/toolkit/dnslookup', json = data)
        return self.response

    def post_system_toolkit_checkmobileconnection(self, data: dict):
        '''
        Posts system toolkit checkmobileconnection
        '''
        self.response = self.post('system/toolkit/checkmobileconnection', json = data)
        return self.response

    def post_system_toolkit_factory(self, data: dict):
        '''
        Posts system toolkit factory
        '''
        self.response = self.post('system/toolkit/factory', json = data)
        return self.response

    def post_system_toolkit_files_download(self, data: dict):
        '''
        Posts system toolkit files download
        '''
        self.response = self.post('system/toolkit/files/download', json = data)
        return self.response

    def post_system_toolkit_files_execute(self, data: dict):
        '''
        Posts system toolkit files execute
        '''
        self.response = self.post('system/toolkit/files/execute', json = data)
        return self.response

    def post_system_toolkit_files_list(self, data: dict):
        '''
        Posts system toolkit files list
        '''
        self.response = self.post('system/toolkit/files/list', json = data)
        return self.response

    def delete_system_toolkit_files_remove(self, data: dict):
        '''
        Deletes system toolkit files remove
        '''
        self.response = self.delete('system/toolkit/files/remove', json = data)
        return self.response

    def post_system_toolkit_files_upload(self, data: dict):
        '''
        Posts system toolkit files upload
        '''
        self.response = self.post('system/toolkit/files/upload', json = data)
        return self.response

    def post_system_toolkit_ping(self, data: dict):
        '''
        Posts system toolkit ping
        '''
        self.response = self.post('system/toolkit/ping', json = data)
        return self.response

    def post_system_toolkit_reboot(self):
        '''
        Posts system toolkit reboot
        '''
        self.response = self.post('system/toolkit/reboot')
        return self.response

    def post_system_toolkit_savesettings(self, data: dict):
        '''
        Posts system toolkit savesettings
        '''
        self.response = self.post('system/toolkit/savesettings', json = data)
        return self.response

    def post_system_toolkit_shutdown(self):
        '''
        Posts system toolkit shutdown
        '''
        self.response = self.post('system/toolkit/shutdown')
        return self.response

    def post_system_toolkit_traceroute(self, data: dict):
        '''
        Posts system toolkit traceroute
        '''
        self.response = self.post('system/toolkit/traceroute', json = data)
        return self.response

    def post_system_toolkit_upgrade(self, data: dict):
        '''
        Posts system toolkit upgrade
        '''
        self.response = self.post('system/toolkit/upgrade', json = data)
        return self.response

    def get_system_toolkit_upgrade_savedconfigs(self):
        '''
        Gets system toolkit upgrade savedconfigs
        '''
        self.response = self.get('system/toolkit/upgrade/savedconfigs')
        return self.response

    def get_system_central_mgmt_inventory(self):
        '''
        Gets system central_mgmt inventory
        '''
        self.response = self.get('system/central_mgmt/inventory')
        return self.response

    def post_system_central_mgmt_inventory_run(self, data: dict):
        '''
        Posts system central_mgmt inventory run
        '''
        self.response = self.post('system/central_mgmt/inventory/run', json = data)
        return self.response

    def get_system_central_mgmt_playbooks(self):
        '''
        Gets system central_mgmt playbooks
        '''
        self.response = self.get('system/central_mgmt/playbooks')
        return self.response

    def delete_system_central_mgmt_playbooks(self, data: dict):
        '''
        Deletes system central_mgmt playbooks
        '''
        self.response = self.delete('system/central_mgmt/playbooks', json = data)
        return self.response

    def post_system_central_mgmt_playbooks_upload(self, data: dict):
        '''
        Posts system central_mgmt playbooks upload
        '''
        self.response = self.post('system/central_mgmt/playbooks/upload', json = data)
        return self.response

    def get_system_central_mgmt_variables(self):
        '''
        Gets system central_mgmt variables
        '''
        self.response = self.get('system/central_mgmt/variables')
        return self.response

    def put_system_central_mgmt_variables(self, data: dict):
        '''
        Puts system central_mgmt variables
        '''
        self.response = self.put('system/central_mgmt/variables', json = data)
        return self.response

    def post_system_central_mgmt_variables(self, data: dict):
        '''
        Posts system central_mgmt variables
        '''
        self.response = self.post('system/central_mgmt/variables', json = data)
        return self.response

    def delete_system_central_mgmt_variables(self, data: dict):
        '''
        Deletes system central_mgmt variables
        '''
        self.response = self.delete('system/central_mgmt/variables', json = data)
        return self.response

    def post_system_central_mgmt_variables_upload(self, data: dict):
        '''
        Posts system central_mgmt variables upload
        '''
        self.response = self.post('system/central_mgmt/variables/upload', json = data)
        return self.response

    def get_system_central_mgmt_logs(self):
        '''
        Gets system central_mgmt logs
        '''
        self.response = self.get('system/central_mgmt/logs')
        return self.response

    def post_system_central_mgmt_logs(self, data: dict):
        '''
        Posts system central_mgmt logs
        '''
        self.response = self.post('system/central_mgmt/logs', json = data)
        return self.response

    def get_tracking_devices_serialstats(self):
        '''
        Gets tracking devices serialstats
        '''
        self.response = self.get('tracking/devices/serialstats')
        return self.response

    def post_tracking_devices_serialstats_resetstats(self, data: dict):
        '''
        Posts tracking devices serialstats resetstats
        '''
        self.response = self.post('tracking/devices/serialstats/resetstats', json = data)
        return self.response

    def get_tracking_devices_usbdevices(self, usb_path: str = None):
        '''
        Gets tracking devices usbdevices {usb_path}
        '''
        if not usb_path:
            self.response = self.get('tracking/devices/usbdevices')
        else:
            self.response = self.get(f'tracking/devices/usbdevices/{usb_path}')
        return self.response

    def get_tracking_devices_gps(self):
        '''
        Gets tracking devices gps
        '''
        self.response = self.get('tracking/devices/gps')
        return self.response

    def get_tracking_devices_geo_fence(self):
        '''
        Gets tracking devices geo_fence
        '''
        self.response = self.get('tracking/devices/geo_fence')
        return self.response

    def get_tracking_devicessessions(self):
        '''
        Gets tracking devicessessions
        '''
        self.response = self.get('tracking/devicessessions')
        return self.response

    def post_tracking_devicessessions_terminate(self, data: dict):
        '''
        Posts tracking devicessessions terminate
        '''
        self.response = self.post('tracking/devicessessions/terminate', json = data)
        return self.response

    def get_tracking_discoverylogs(self):
        '''
        Gets tracking discoverylogs
        '''
        self.response = self.get('tracking/discoverylogs')
        return self.response

    def post_tracking_discoverylogs_resetlogs(self):
        '''
        Posts tracking discoverylogs resetlogs
        '''
        self.response = self.post('tracking/discoverylogs/resetlogs')
        return self.response

    def get_tracking_eventlist_events(self):
        '''
        Gets tracking eventlist events
        '''
        self.response = self.get('tracking/eventlist/events')
        return self.response

    def post_tracking_eventlist_events(self, data: dict):
        '''
        Posts tracking eventlist events
        '''
        self.response = self.post('tracking/eventlist/events', json = data)
        return self.response

    def get_tracking_eventlist_statistics(self):
        '''
        Gets tracking eventlist statistics
        '''
        self.response = self.get('tracking/eventlist/statistics')
        return self.response

    def get_tracking_events(self):
        '''
        Gets tracking events
        '''
        self.response = self.get('tracking/events')
        return self.response

    def post_tracking_events_resetcounters(self, data: dict):
        '''
        Posts tracking events resetcounters
        '''
        self.response = self.post('tracking/events/resetcounters', json = data)
        return self.response

    def get_tracking_network_interfaces(self, interface: str = None):
        '''
        Gets tracking network interfaces {interface}
        '''
        if not interface:
            self.response = self.get('tracking/network/interfaces')
        else:
            self.response = self.get(f'tracking/network/interfaces/{interface}')
        return self.response

    def get_tracking_network_lldp(self):
        '''
        Gets tracking network lldp
        '''
        self.response = self.get('tracking/network/lldp')
        return self.response

    def get_tracking_network_switch(self, interface: str = None):
        '''
        Gets tracking network switch {interface}
        '''
        if not interface:
            self.response = self.get('tracking/network/switch')
        else:
            self.response = self.get(f'tracking/network/switch/{interface}')
        return self.response

    def get_tracking_network_mstp(self, instance: str = None, interface: str = None):
        '''
        Gets tracking network mstp {instance}
        '''
        if not instance:
            self.response = self.get('tracking/network/mstp')
        elif instance and not interface:
            self.response = self.get(f'tracking/network/mstp/{instance}')
        elif instance and interface:
            self.response = self.get(f'tracking/network/mstp/{instance}/{interface}')
        return self.response

    def get_tracking_network_routingtable(self):
        '''
        Gets tracking network routingtable
        '''
        self.response = self.get('tracking/network/routingtable')
        return self.response

    def get_tracking_network_mactable(self):
        '''
        Gets tracking network mactable
        '''
        self.response = self.get('tracking/network/mactable')
        return self.response

    def post_tracking_network_mactable(self, data: dict):
        '''
        Posts tracking network mactable
        '''
        self.response = self.post('tracking/network/mactable', json = data)
        return self.response

    def post_tracking_network_mactable_refresh(self):
        '''
        Posts tracking network mactable refresh
        '''
        self.response = self.post('tracking/network/mactable/refresh')
        return self.response

    def get_tracking_network_ipsec(self):
        '''
        Gets tracking network ipsec
        '''
        self.response = self.get('tracking/network/ipsec')
        return self.response

    def get_tracking_network_wireguard(self, interface: str = None):
        '''
        Gets tracking network wireguard {interface}
        '''
        if not interface:
            self.response = self.get('tracking/network/wireguard')
        else:
            self.response = self.get(f'tracking/network/wireguard/{interface}')
        return self.response

    def get_tracking_network_hotspot(self):
        '''
        Gets tracking network hotspot
        '''
        self.response = self.get('tracking/network/hotspot')
        return self.response

    def get_tracking_network_qos(self):
        '''
        Gets tracking network qos
        '''
        self.response = self.get('tracking/network/qos')
        return self.response

    def get_tracking_network_dhcp(self):
        '''
        Gets tracking network dhcp
        '''
        self.response = self.get('tracking/network/dhcp')
        return self.response

    def get_tracking_network_flowexporter(self):
        '''
        Gets tracking network flowexporter
        '''
        self.response = self.get('tracking/network/flowexporter')
        return self.response

    def get_tracking_opensessions(self):
        '''
        Gets tracking opensessions
        '''
        self.response = self.get('tracking/opensessions')
        return self.response

    def post_tracking_opensessions_terminate(self, data: dict):
        '''
        Posts tracking opensessions terminate
        '''
        self.response = self.post('tracking/opensessions/terminate', json = data)
        return self.response

    def get_tracking_schedule(self):
        '''
        Gets tracking schedule
        '''
        self.response = self.get('tracking/schedule')
        return self.response

    def post_tracking_schedule(self, data: dict):
        '''
        Posts tracking schedule
        '''
        self.response = self.post('tracking/schedule', json = data)
        return self.response

    def post_tracking_schedule_resetlogs(self):
        '''
        Posts tracking schedule resetlogs
        '''
        self.response = self.post('tracking/schedule/resetlogs')
        return self.response

    def get_tracking_system_cpu(self):
        '''
        Gets tracking system cpu
        '''
        self.response = self.get('tracking/system/cpu')
        return self.response

    def get_tracking_system_disk(self):
        '''
        Gets tracking system disk
        '''
        self.response = self.get('tracking/system/disk')
        return self.response

    def get_tracking_system_memory(self):
        '''
        Gets tracking system memory
        '''
        self.response = self.get('tracking/system/memory')
        return self.response

    def get_tracking_hwmonitor_thermal(self):
        '''
        Gets tracking hwmonitor thermal
        '''
        self.response = self.get('tracking/hwmonitor/thermal')
        return self.response

    def get_tracking_hwmonitor_power(self):
        '''
        Gets tracking hwmonitor power
        '''
        self.response = self.get('tracking/hwmonitor/power')
        return self.response

    def get_tracking_hwmonitor_usbsensors(self):
        '''
        Gets tracking hwmonitor usbsensors
        '''
        self.response = self.get('tracking/hwmonitor/usbsensors')
        return self.response

    def get_tracking_devices_wirelessmodem(self, id: str = None):
        '''
        Gets tracking devices wirelessmodem {id}
        '''
        if not id:
            self.response = self.get('tracking/devices/wirelessmodem')
        else:
            self.response = self.get(f'tracking/devices/wirelessmodem/{id}')
        return self.response
