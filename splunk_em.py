import json
import os
from datetime import datetime

from dotenv import load_dotenv

import input_module_intersight

load_dotenv('example.env')

# This code allows us to execute the input for testing without needing additional code from splunk
# by providing a minimal sub-out of the two classes that splunk passes to the input

class SplunkEmHelper:
    # this function provides all of the input-specific configuration data
    def get_arg(self, arg_name):
        if arg_name == 'intersight_hostname':
            return "www.intersight.com"
        if arg_name == 'api_key_id':
            return os.environ.get('IntersightKeyId')
        if arg_name == 'api_secret_key':
            return os.environ.get('IntersightSecretKey')
        if arg_name == 'validate_ssl':
            return True
        if arg_name == 'enable_aaa_audit_records':
            return True
        if arg_name == 'enable_alarms':
            return True
        if arg_name == 'inventory_interval':
            return 300
        if arg_name == 'inventory':
            all = {'advisories', 'compute', 'contract',
                   'network', 'hyperflex', 'target'}
            none = {}
            return all

    # this function provides the input name
    def get_input_stanza(self):
        return {'SPLUNK_EM': {}}

    # this function provides the proxy configuration
    def get_proxy(self):
        noproxy = {}
        proxy = {
            "proxy_url": "host",
            "proxy_port": "999",
            "proxy_username": "username",
            "proxy_password": "password",
            "proxy_type": "http",  # other values are "socks4" and "socks5"
            "proxy_rdns": False
        }
        return noproxy

    # this function provides the index name (which we don't really care about right now)
    def get_output_index(self):
        return "main"

    # these functions catch and print the logging messages from the input
    def log_debug(self, message):
        print(datetime.now().strftime("%H:%M:%S") + " DEBUG: " + message)

    def log_info(self, message):
        print(datetime.now().strftime("%H:%M:%S") + " INFO: " + message)

    def log_critical(self, message):
        print(datetime.now().strftime("%H:%M:%S") + " CRITICAL: " + message)

    def log_warning(self, message):
        print(datetime.now().strftime("%H:%M:%S") + " WARNING: " + message)

    # these two functions print the checkpoint save/delete operations
    # this class doesn't attempt to persist checkpoints
    def save_check_point(self, name, state):
        print(datetime.now().strftime("%H:%M:%S") +
              " CHECKPOINT SAVE: " + str(name) + " = " + str(state))

    def delete_check_point(self, name):
        print(datetime.now().strftime("%H:%M:%S") +
              " CHECKPOINT DELETE: " + str(name))

    # this function catches the event value and returns only the data
    def new_event(self, source, index, sourcetype, data):
        return data


helper = SplunkEmHelper()

class SplunkEmEventWriter:
    def write_event(self, event):
        event = json.loads(event)
        # print(json.dumps(event, indent=3))
        pass

ew = SplunkEmEventWriter()

input_module_intersight.collect_events(helper, ew)
