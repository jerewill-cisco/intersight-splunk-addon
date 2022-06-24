
# encoding = utf-8

import datetime
import json
import re
import sys
from types import SimpleNamespace

import requests
from intersight_auth import IntersightAuth, repair_pem


def validate_input(helper, definition):
    intersight_hostname = definition.parameters.get(
        'intersight_hostname', None)
    api_key_id = definition.parameters.get('api_key_id', None)
    api_secret_key = definition.parameters.get('api_secret_key', None)
    validate_ssl = definition.parameters.get('validate_ssl', None)
    pass


def collect_events(helper, ew):
    # User helper functions to retrieve the configuration
    stanza_name = next(iter(helper.get_input_stanza()))
    helper.log_info(stanza_name + ' | ' +
                    'Starting input named ' + stanza_name)
    opt_intersight_hostname = helper.get_arg('intersight_hostname')
    helper.log_debug(stanza_name + ' | ' +
                     "Intersight is at "+opt_intersight_hostname)
    opt_api_key_id = helper.get_arg('api_key_id')
    opt_api_secret_key = helper.get_arg('api_secret_key')
    opt_validate_ssl = helper.get_arg('validate_ssl')
    opt_enable_aaa_audit_records = helper.get_arg('enable_aaa_audit_records')
    opt_enable_alarms = helper.get_arg('enable_alarms')
    opt_inventory_interval = helper.get_arg('inventory_interval')
    opt_inventory = helper.get_arg('inventory')

    # get proxy setting configuration
    proxy = SimpleNamespace(**helper.get_proxy())

    if len(proxy.__dict__) == 0:
        # if `Enable proxy` is not checked, the dict will be empty
        r_proxy = {'https': None}
        helper.log_debug(stanza_name + ' | ' + "Proxy is not configured")
    else:
        if proxy.proxy_type != 'http':
            raise Exception("Only HTTP proxy type is implemented")
        if proxy.proxy_username and proxy.proxy_password:
            r_proxy = {"https": "http://"+proxy.proxy_username+":" +
                       proxy.proxy_password+"@"+proxy.proxy_url+":"+proxy.proxy_port}
            helper.log_debug(stanza_name + ' | ' + "Proxy is " +
                             proxy.proxy_url+":"+proxy.proxy_port + " with authentication")
        else:
            r_proxy = {"https": "http://"+proxy.proxy_url+":"+proxy.proxy_port}
            helper.log_debug(stanza_name + ' | ' + "Proxy is " +
                             proxy.proxy_url+":"+proxy.proxy_port)

    # get the configured index
    index = helper.get_output_index()
    helper.log_debug(stanza_name + ' | ' + "Configured index is " + index)

    # Fix the private key after if passes through Splunk's UI
    repaired_pem = repair_pem(opt_api_secret_key)

    # Build the AUTH object to sign API calls
    AUTH = IntersightAuth(
        secret_key_string=repaired_pem,
        api_key_id=opt_api_key_id
    )

    ##
    # Get the value for source and figure out our hostname situation
    ##

    saas = re.compile(r"\S*\.?intersight\.com\.?$")
    fqdn = re.compile(
        r"^(?!:\/\/)(?=.{1,255}$)((.{1,63}\.){1,127}(?![0-9]*$)[a-z0-9-]+\.?)$")

    if bool(saas.match(opt_intersight_hostname)):
        try:
            RESPONSE = requests.request(
                method='GET',
                url='https://'+opt_intersight_hostname+'/api/v1/iam/Accounts?$select=Name',
                auth=AUTH,
                verify=opt_validate_ssl,
                proxies=r_proxy
            )
            account_name = RESPONSE.json()['Results'][0]['Name']
            helper.log_info(
                stanza_name + ' | ' + "Connected to Intersight SaaS account named " + account_name)
        except:
            helper.log_critical(stanza_name + ' | ' +
                                "Unable to connect to Intersight SaaS")
            sys.exit("FAILED CONNECTION TO INTERSIGHT SAAS")

    else:
        if bool(fqdn.match(opt_intersight_hostname)):
            try:
                RESPONSE = requests.request(
                    method='GET',
                    url='https://'+opt_intersight_hostname+'/api/v1/iam/UserPreferences',
                    auth=AUTH,
                    verify=opt_validate_ssl,
                    proxies=r_proxy
                )
                account_name = opt_intersight_hostname
                helper.log_info(
                    stanza_name + ' | ' + "Connected to Intersight On Prem server named " + opt_intersight_hostname)
            except:
                helper.log_critical(
                    stanza_name + ' | ' + "Unable to connect to Intersight server at "+opt_intersight_hostname)
                sys.exit("FAILED CONNECTION TO INTERSIGHT ON PREM")

        else:
            helper.log_critical(
                stanza_name + ' | ' + "INVALID HOSTNAME... configured value is " + opt_intersight_hostname)
            sys.exit("BAD HOSTNAME")

    ##
    # Audit records
    ##

    if opt_enable_aaa_audit_records:
        helper.log_info(stanza_name + ' | ' + "Retrieving Audit Records...")

        # Let's go retrieve our state
        try:
            state = helper.get_check_point(account_name+'_last_audit_record')
            helper.log_debug(stanza_name + ' | ' +
                             "Checkpoint key for audit records is " + state)
        except:
            # set the state if it's not set
            state = (datetime.datetime.now() - datetime.timedelta(days=2)
                     ).isoformat()[:-6].rstrip('0')+'0Z'
            helper.log_debug(
                stanza_name + ' | ' + "Checkpoint key for audit records was not set but is now " + state)
            helper.save_check_point(account_name+'_last_audit_record', state)

        # Let's get the audit records
        RESPONSE = requests.request(
            method='GET',
            url='https://'+opt_intersight_hostname +
                '/api/v1/aaa/AuditRecords?$orderby=ModTime%20asc&$filter=ModTime%20gt%20'+state,
            auth=AUTH,
            verify=opt_validate_ssl,
            proxies=r_proxy
        )

        # Process the audit records
        for data in RESPONSE.json()['Results']:
            # remove things that just aren't helpful in splunk
            for thepop in ['Account', 'Ancestors', 'PermissionResources', 'Owners', 'User']:
                data.pop(thepop)
            # Splunk default doesn't allow events over 10k characters by default
            if len(json.dumps(data)) > 9999:
                # we're truncating the Request if it's larger than that
                data['Request'] = "TRUNCATED"
                helper.log_debug(stanza_name + ' | ' +
                                 "Truncating "+data['Moid'])
            event = helper.new_event(source=account_name, index=index,
                                     sourcetype='cisco:intersight:aaaAuditRecords', data=json.dumps(data))
            ew.write_event(event)
            helper.log_debug(stanza_name + ' | ' +
                             "Creating event for Moid "+data['Moid'])
            # Here we check to see if the latest event is newer than our checkpoint, if so we update it.
            if datetime.datetime.strptime(state, "%Y-%m-%dT%H:%M:%S.%f%z") < datetime.datetime.strptime(data['ModTime'], "%Y-%m-%dT%H:%M:%S.%f%z"):
                state = data['ModTime']
                helper.log_debug(
                    stanza_name + ' | ' + "Checkpoint key for audit records was updated to " + state)
        # Persist our checkpoint at the end of the audit records
        helper.save_check_point(account_name+'_last_audit_record', state)

    else:
        helper.log_debug(stanza_name + ' | ' + "Skipping audit Records.")
        helper.delete_check_point(account_name+'_last_audit_record')

    ##
    # Alarms
    ##

    if opt_enable_alarms:
        helper.log_info(stanza_name + ' | ' + "Retrieving Alarms...")

        # Let's go retrieve our state
        try:
            state = helper.get_check_point(account_name+'_last_alarm_record')
            helper.log_debug(
                "stanza_name + ' | ' + Checkpoint key for alarms records is " + state)
        except:
            # set the state if it's not set
            state = (datetime.datetime.now() - datetime.timedelta(days=2)
                     ).isoformat()[:-6].rstrip('0')+'0Z'
            helper.log_debug(
                "stanza_name + ' | ' + Checkpoint key for alarm records was not set but is now " + state)
            helper.save_check_point(account_name+'_last_alarm_record', state)

        # Let's get the alarm records
        RESPONSE = requests.request(
            method='GET',
            url='https://'+opt_intersight_hostname +
                '/api/v1/cond/Alarms?$orderby=ModTime%20asc&$filter=ModTime%20gt%20'+state,
            auth=AUTH,
            verify=opt_validate_ssl,
            proxies=r_proxy
        )

        # Process the alarm records
        for data in RESPONSE.json()['Results']:
            # remove things that just aren't helpful in splunk
            for thepop in ['AffectedMo', 'Ancestors', 'Owners', 'PermissionResources', 'RegisteredDevice']:
                data.pop(thepop)
            event = helper.new_event(source=account_name, index=index,
                                     sourcetype='cisco:intersight:condAlarms', data=json.dumps(data))
            ew.write_event(event)
            helper.log_debug(stanza_name + ' | ' +
                             "Creating event for Moid "+data['Moid'])
            # Here we check to see if the latest event is newer than our checkpoint, if so we update it.
            if datetime.datetime.strptime(state, "%Y-%m-%dT%H:%M:%S.%f%z") < datetime.datetime.strptime(data['ModTime'], "%Y-%m-%dT%H:%M:%S.%f%z"):
                state = data['ModTime']
                helper.log_debug(
                    stanza_name + ' | ' + "Checkpoint key for alarm records was updated to " + state)
        # Persist our checkpoint at the end of the audit records
        helper.save_check_point(account_name+'_last_alarm_record', state)

    else:
        helper.log_debug("stanza_name + ' | ' + Skipping Alarms...")
        helper.delete_check_point(account_name+'_last_alarm_record')

    ###
    # Inventory checkpointing
    ###

    try:
        inventory_checkpoint = helper.get_check_point(
            account_name+'_inventory_interval')
        # increment the inventory checkpoint
        inventory_checkpoint += 1
        # If this isn't the right interval to run inventory, just save the checkpoint
        if inventory_checkpoint < int(opt_inventory_interval):
            doInventory = False
            helper.log_info(stanza_name + ' | ' +
                            "Skipping Advisories and Inventories this inverval.")
            helper.log_debug(stanza_name + ' | ' + "Inventory checkpoint is less than " + str(opt_inventory_interval) +
                             "... now " + str(inventory_checkpoint) + "... so we're skipping Advisories and all Inventory types.")
            helper.save_check_point(
                account_name+'_inventory_interval', inventory_checkpoint)
        else:
            # If this is the right interval to run inventory... run inventory and reset the checkpoint
            doInventory = True
            inventory_checkpoint = 0
            helper.log_debug(
                stanza_name + ' | ' + "Inventory is running this interval, checkpoint is now " + str(inventory_checkpoint))
            helper.save_check_point(
                account_name+'_inventory_interval', inventory_checkpoint)

    except:
        # If the checkpoint isn't set, run inventory this interval and set the checkpoint
        doInventory = True
        inventory_checkpoint = 0
        helper.log_debug(
            stanza_name + ' | ' + "First run, so inventory checkpoint is now " + str(inventory_checkpoint))
        helper.save_check_point(
            account_name+'_inventory_interval', inventory_checkpoint)

    ##
    # Advisories
    ##

    if 'advisories' in opt_inventory and doInventory:
        helper.log_info(stanza_name + ' | ' + "Retrieving Advisories...")
        RESPONSE = requests.request(
            method='GET',
            url='https://'+opt_intersight_hostname +
                '/api/v1/tam/AdvisoryInstances?$count=True',
            auth=AUTH,
            verify=opt_validate_ssl,
            proxies=r_proxy
        )
        count = RESPONSE.json()['Count']
        helper.log_debug(stanza_name + ' | ' + "Found " +
                         str(count) + " advisory records to retrieve...")
        results_per_page = 10  # adjust the number of results we pull per API call
        for i in range(0, count, results_per_page):
            RESPONSE = requests.request(
                method='GET',
                url='https://'+opt_intersight_hostname +
                    '/api/v1/tam/AdvisoryInstances?$expand=Advisory&$top=' +
                str(results_per_page)+'&$skip='+str(i),
                auth=AUTH,
                verify=opt_validate_ssl,
                proxies=r_proxy
            )

            for data in RESPONSE.json()['Results']:
                # remove things that just aren't helpful in splunk
                for thepop in ['Ancestors', 'AffectedObject', 'PermissionResources', 'Owners', 'DeviceRegistration']:
                    data.pop(thepop)
                for thepop in ['Ancestors', 'Actions', 'ApiDataSources', 'Organization', 'Owners', 'PermissionResources', 'Recommendation']:
                    data['Advisory'].pop(thepop)
                event = helper.new_event(source=account_name, index=index,
                                         sourcetype='cisco:intersight:tamAdvisoryInstances', data=json.dumps(data))
                ew.write_event(event)
                helper.log_debug(stanza_name + ' | ' +
                                 "Creating event for Moid "+data['Moid'])

    else:
        helper.log_debug(stanza_name + ' | ' + "Skipping Advisories.")

    ###
    # Compute Inventory
    ###

    if 'compute' in opt_inventory and doInventory:
        helper.log_info(stanza_name + ' | ' +
                        "Retrieving compute inventory...")
        RESPONSE = requests.request(
            method='GET',
            url='https://'+opt_intersight_hostname +
                '/api/v1/compute/PhysicalSummaries?$count=True',
            auth=AUTH,
            verify=opt_validate_ssl,
            proxies=r_proxy
        )
        count = RESPONSE.json()['Count']
        helper.log_debug(stanza_name + ' | ' + "Found " +
                         str(count) + " inventory records to retrieve...")
        results_per_page = 10  # adjust the number of results we pull per API call
        for i in range(0, count, results_per_page):
            RESPONSE = requests.request(
                method='GET',
                url='https://'+opt_intersight_hostname +
                    '/api/v1/compute/PhysicalSummaries?$top=' +
                str(results_per_page)+'&$skip='+str(i),
                auth=AUTH,
                verify=opt_validate_ssl,
                proxies=r_proxy
            )

            for data in RESPONSE.json()['Results']:
                # remove things that just aren't helpful in splunk
                for thepop in ['Ancestors', 'PermissionResources', 'Owners', 'RegisteredDevice']:
                    data.pop(thepop)
                event = helper.new_event(
                    source=account_name, index=index, sourcetype='cisco:intersight:computePhysicalSummaries', data=json.dumps(data))
                ew.write_event(event)
                helper.log_debug(stanza_name + ' | ' +
                                 "Creating inventory for Moid "+data['Moid'])

    else:
        helper.log_debug(stanza_name + ' | ' + "Skipping compute inventory.")

    ###
    # Compute HCL Status
    ###

    if 'compute' in opt_inventory and doInventory:
        helper.log_info(stanza_name + ' | ' +
                        "Retrieving compute HCL status...")
        RESPONSE = requests.request(
            method='GET',
            url='https://'+opt_intersight_hostname +
                '/api/v1/cond/HclStatuses?$count=True',
            auth=AUTH,
            verify=opt_validate_ssl,
            proxies=r_proxy
        )
        count = RESPONSE.json()['Count']
        helper.log_debug(stanza_name + ' | ' + "Found " +
                         str(count) + " inventory records to retrieve...")
        results_per_page = 10  # adjust the number of results we pull per API call
        for i in range(0, count, results_per_page):
            RESPONSE = requests.request(
                method='GET',
                url='https://'+opt_intersight_hostname +
                    '/api/v1/cond/HclStatuses?$top=' +
                str(results_per_page)+'&$skip='+str(i),
                auth=AUTH,
                verify=opt_validate_ssl,
                proxies=r_proxy
            )

            for data in RESPONSE.json()['Results']:
                # remove things that just aren't helpful in splunk
                for thepop in ['Ancestors', 'Details', 'Owners', 'PermissionResources', 'RegisteredDevice']:
                    data.pop(thepop)
                for thepop in ['ClassId', 'link']:
                    data['ManagedObject'].pop(thepop)
                event = helper.new_event(
                    source=account_name, index=index, sourcetype='cisco:intersight:condHclStatuses', data=json.dumps(data))
                ew.write_event(event)
                helper.log_debug(stanza_name + ' | ' +
                                 "Creating inventory for Moid "+data['Moid'])

    else:
        helper.log_debug(stanza_name + ' | ' + "Skipping compute HCL status.")

    ###
    # Contract Status
    ###

    if 'contract' in opt_inventory and doInventory:
        helper.log_info(stanza_name + ' | ' +
                        "Retrieving contract status items...")
        RESPONSE = requests.request(
            method='GET',
            url='https://'+opt_intersight_hostname +
                '/api/v1/asset/DeviceContractInformations?$count=True',
            auth=AUTH,
            verify=opt_validate_ssl,
            proxies=r_proxy
        )
        count = RESPONSE.json()['Count']
        helper.log_debug(stanza_name + ' | ' + "Found " +
                         str(count) + " inventory records to retrieve...")
        results_per_page = 10  # adjust the number of results we pull per API call
        for i in range(0, count, results_per_page):
            RESPONSE = requests.request(
                method='GET',
                url='https://'+opt_intersight_hostname +
                    '/api/v1/asset/DeviceContractInformations?$top=' +
                str(results_per_page)+'&$skip='+str(i),
                auth=AUTH,
                verify=opt_validate_ssl,
                proxies=r_proxy
            )

            for data in RESPONSE.json()['Results']:
                # remove things that just aren't helpful in splunk
                for thepop in ['Ancestors', 'Contract', 'EndCustomer', 'EndUserGlobalUltimate', 'Owners', 'PermissionResources', 'Product', 'RegisteredDevice', 'ResellerGlobalUltimate']:
                    data.pop(thepop)
                for thepop in ['ClassId', 'link']:
                    data['Source'].pop(thepop)
                event = helper.new_event(
                    source=account_name, index=index, sourcetype='cisco:intersight:assetDeviceContractInformations', data=json.dumps(data))
                ew.write_event(event)
                helper.log_debug(stanza_name + ' | ' +
                                 "Creating inventory for Moid "+data['Moid'])

    else:
        helper.log_debug(stanza_name + ' | ' +
                         "Skipping compute contract status.")

    ###
    # Network Inventory
    ###

    if 'network' in opt_inventory and doInventory:
        helper.log_info(stanza_name + ' | ' +
                        "Retrieving network inventory...")

        RESPONSE = requests.request(
            method='GET',
            url='https://'+opt_intersight_hostname +
                '/api/v1/network/ElementSummaries?$count=True',
            auth=AUTH,
            verify=opt_validate_ssl,
            proxies=r_proxy
        )
        count = RESPONSE.json()['Count']
        helper.log_debug(stanza_name + ' | ' + "Found " +
                         str(count)+" inventory records to retrieve...")
        results_per_page = 10  # adjust the number of results we pull per API call
        for i in range(0, count, results_per_page):
            RESPONSE = requests.request(
                method='GET',
                url='https://'+opt_intersight_hostname +
                    '/api/v1/network/ElementSummaries?$top=' +
                str(results_per_page)+'&$skip='+str(i),
                auth=AUTH,
                verify=opt_validate_ssl,
                proxies=r_proxy
            )

            for data in RESPONSE.json()['Results']:
                for thepop in ['Ancestors', 'PermissionResources', 'Owners', 'RegisteredDevice']:
                    data.pop(thepop)
                event = helper.new_event(
                    source=account_name, index=index, sourcetype='cisco:intersight:networkElementSummaries', data=json.dumps(data))
                ew.write_event(event)
                helper.log_debug(stanza_name + ' | ' +
                                 "Creating inventory for Moid "+data['Moid'])

    else:
        helper.log_debug(stanza_name + ' | ' + "Skipping network inventory.")

    ###
    # Target Inventory
    ###

    if 'target' in opt_inventory and doInventory:
        helper.log_info(stanza_name + ' | ' + "Retrieving target inventory...")

        RESPONSE = requests.request(
            method='GET',
            url='https://'+opt_intersight_hostname+'/api/v1/asset/Targets?$count=True',
            auth=AUTH,
            verify=opt_validate_ssl,
            proxies=r_proxy
        )
        count = RESPONSE.json()['Count']
        helper.log_debug(stanza_name + ' | ' + "Found " +
                         str(count)+" inventory records to retrieve...")
        results_per_page = 10  # adjust the number of results we pull per API call
        for i in range(0, count, results_per_page):
            RESPONSE = requests.request(
                method='GET',
                url='https://'+opt_intersight_hostname+'/api/v1/asset/Targets?$top=' +
                    str(results_per_page)+'&$skip='+str(i),
                auth=AUTH,
                verify=opt_validate_ssl,
                proxies=r_proxy
            )

            for data in RESPONSE.json()['Results']:
                for thepop in ['Account', 'Ancestors', 'Connections', 'PermissionResources', 'Owners', 'RegisteredDevice']:
                    data.pop(thepop)
                event = helper.new_event(
                    source=account_name, index=index, sourcetype='cisco:intersight:assetTargets', data=json.dumps(data))
                ew.write_event(event)
                helper.log_debug(stanza_name + ' | ' +
                                 "Creating inventory for Moid "+data['Moid'])
    else:
        helper.log_debug(stanza_name + ' | ' + "Skipping target inventory.")

    ###
    # Hyperflex Cluster Inventory
    ###

    if 'hyperflex' in opt_inventory and doInventory:
        helper.log_info(stanza_name + ' | ' +
                        "Retrieving Hyperflex cluster inventory...")

        RESPONSE = requests.request(
            method='GET',
            url='https://'+opt_intersight_hostname+'/api/v1/hyperflex/Clusters?$count=True',
            auth=AUTH,
            verify=opt_validate_ssl,
            proxies=r_proxy
        )
        count = RESPONSE.json()['Count']
        helper.log_debug(stanza_name + ' | ' + "Found " +
                         str(count)+" inventory records to retrieve...")
        results_per_page = 10  # adjust the number of results we pull per API call
        for i in range(0, count, results_per_page):
            RESPONSE = requests.request(
                method='GET',
                url='https://'+opt_intersight_hostname +
                    '/api/v1/hyperflex/Clusters?$expand=License&$top=' +
                str(results_per_page)+'&$skip='+str(i),
                auth=AUTH,
                verify=opt_validate_ssl,
                proxies=r_proxy
            )

            for data in RESPONSE.json()['Results']:
                for thepop in ['Alarm', 'Ancestors', 'ChildClusters', 'Owners', 'PermissionResources', 'RegisteredDevice', 'StorageContainers', 'Nodes', 'Health', 'ParentCluster']:
                    data.pop(thepop)
                for thepop in ['Ancestors', 'Cluster', 'Owners', 'PermissionResources', 'RegisteredDevice']:
                    data['License'].pop(thepop)
                event = helper.new_event(
                    source=account_name, index=index, sourcetype='cisco:intersight:hyperflexClusters', data=json.dumps(data))
                ew.write_event(event)
                helper.log_debug(stanza_name + ' | ' +
                                 "Creating inventory for Moid "+data['Moid'])
    else:
        helper.log_debug(stanza_name + ' | ' +
                         "Skipping Hyperflex cluster inventory.")

    ###
    # Hyperflex Node Inventory
    ###

    if 'hyperflex' in opt_inventory and doInventory:
        helper.log_info(stanza_name + ' | ' +
                        "Retrieving Hyperflex node inventory...")

        RESPONSE = requests.request(
            method='GET',
            url='https://'+opt_intersight_hostname+'/api/v1/hyperflex/Nodes?$count=True',
            auth=AUTH,
            verify=opt_validate_ssl,
            proxies=r_proxy
        )
        count = RESPONSE.json()['Count']
        helper.log_debug(stanza_name + ' | ' + "Found " +
                         str(count)+" inventory records to retrieve...")
        results_per_page = 10  # adjust the number of results we pull per API call
        for i in range(0, count, results_per_page):
            RESPONSE = requests.request(
                method='GET',
                url='https://'+opt_intersight_hostname +
                    '/api/v1/hyperflex/Nodes?$expand=Drives&$top=' +
                str(results_per_page)+'&$skip='+str(i),
                auth=AUTH,
                verify=opt_validate_ssl,
                proxies=r_proxy
            )

            for data in RESPONSE.json()['Results']:
                for thepop in ['Ancestors', 'ClusterMember', 'Identity', 'Owners', 'Parent', 'PermissionResources']:
                    data.pop(thepop)
                for thepop in ['ClassId', 'link']:
                    data['Cluster'].pop(thepop)
                for thepop in ['ClassId', 'link']:
                    data['PhysicalServer'].pop(thepop)
                for i in range(0, len(data['Drives'])):
                    for thepop in ['Ancestors', 'LocatorLed', 'Node', 'Owners', 'Parent', 'PermissionResources']:
                        data['Drives'][i].pop(thepop)
                event = helper.new_event(
                    source=account_name, index=index, sourcetype='cisco:intersight:hyperflexNodes', data=json.dumps(data))
                ew.write_event(event)
                helper.log_debug(stanza_name + ' | ' +
                                 "Creating inventory for Moid "+data['Moid'])
    else:
        helper.log_debug(stanza_name + ' | ' +
                         "Skipping Hyperflex node inventory.")

    helper.log_info(stanza_name + ' | ' + "FINISHED")
