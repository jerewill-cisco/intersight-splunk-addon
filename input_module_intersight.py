
# encoding = utf-8

import datetime
import json
import re
import sys
from datetime import datetime, timedelta
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
    start = datetime.now()
    ##
    # local functions
    ##

    # function to call Intersight with all the right options
    def r_intersight(method):
        RESPONSE = requests.request(
            method='GET',
            url=f"https://{opt_intersight_hostname}/api/v1/{method}",
            auth=AUTH,
            verify=opt_validate_ssl,
            proxies=r_proxy
        )
        return RESPONSE

    # function to access check the endpoint
    def check_intersight(method):
        RESPONSE = r_intersight(f'{method}?$top=1')
        if RESPONSE.status_code != 200:
            try:
                code = RESPONSE.json()['code']
                helper.log_warning(
                    f"{s} | {method} error code is {code}")
                return False
            except:
                RESPONSE.raise_for_status
        else:
            helper.log_debug(f"{s} | Connected to {method}")
            return True

    # function to retrieve the checkpoint
    def get_checkpoint(type):
        try:
            state = helper.get_check_point(
                f"{account_name}_last_{type}_record")
            helper.log_debug(
                f"{s} | Checkpoint value for {type} records is {state}")
            return state
        except:
            # set the state if it's not set
            state = f"{(datetime.now() - timedelta(days=2)).isoformat()[:-6].rstrip('0')}0Z"
            helper.log_debug(
                f"{s} | Checkpoint value for {type} records was not set but is now {state}")
            helper.save_check_point(
                f"{account_name}_last_{type}_record", state)
            return state

    # function to compare times from Intersight and return the higher of the two
    def larger_datetime(new, state):
        # function to convert Intersight datetimes into usable Python datetimes
        # in some misguided attempt not to add dateutil to this code
        # for reasons that are vague now even for me
        def strptime(i_time):
            try:
                # Times with a fraction of a second, like 2022-07-07T20:01:38.747Z
                # i.e. most times
                p_time = datetime.strptime(i_time, "%Y-%m-%dT%H:%M:%S.%f%z")
                return p_time
            except (ValueError):
                # Times without a fraction of a second, like 2022-07-08T20:07:23Z
                p_time = datetime.strptime(i_time, "%Y-%m-%dT%H:%M:%S%z")
                return p_time

        # Here we check to see if the latest event is newer than our state checkpoint, if so we update it.
        try:
            if strptime(state) < strptime(new):
                helper.log_debug(
                    f"{s} | Checkpoint value was updated to {state}")
                return new
            else:
                return state
        except (ValueError):
            helper.log_warning(
                f"{s} | Checkpoint value was unable to be updated with {new}")
            return state

    def pop(pop, data):
        try:
            for thepop in pop:
                try:
                    data.pop(thepop)
                except:
                    helper.log_debug(
                        f"{s} | Failed to pop {thepop}")
            return data
        except:
            return data

    def write_splunk(index, source, sourcetype, data):
        length = len(json.dumps(data))
        if length > 9999:
            helper.log_warning(
                f"{s} | Record for {sourcetype} exceeds 10k limit! Length={length}  Moid={data['Moid']}")
        event = helper.new_event(
            source=source, index=index, sourcetype=sourcetype, data=json.dumps(data))
        ew.write_event(event)
        helper.log_debug(
            f"{s} | Creating {sourcetype} event for Moid {data['Moid']}")

    ##
    # Configuration
    ##
    # User helper functions to retrieve the configuration
    s = next(iter(helper.get_input_stanza()))
    helper.log_info(f"{s} | Starting input named {s}")
    opt_intersight_hostname = helper.get_arg('intersight_hostname')
    helper.log_debug(
        f"{s} | Intersight is at {opt_intersight_hostname}")
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
        helper.log_debug(f"{s} | Proxy is not configured")
    else:
        if proxy.proxy_type != 'http':
            helper.log_critical(
                f"{s} | Proxy type was {proxy.proxy_type} and not supported")
            raise Exception("Only HTTP proxy type is implemented")
        if proxy.proxy_username and proxy.proxy_password:
            r_proxy = {
                "https": f"http://{proxy.proxy_username}:{proxy.proxy_password}@{proxy.proxy_url}:{proxy.proxy_port}"}
            masked = re.sub('\:[^:]+@', '@', r_proxy['https'])
            helper.log_debug(
                f"{s} | Proxy is {masked} (password has been removed in this log)")
        else:
            r_proxy = {"https": f"http://{proxy.proxy_url}:{proxy.proxy_port}"}
            helper.log_debug(f"{s} | Proxy is {r_proxy['https']}")

    # get the configured index
    index = helper.get_output_index()
    helper.log_debug(f"{s} | Configured index is {index}")

    # Build the AUTH object to sign API calls
    AUTH = IntersightAuth(
        secret_key_string=repair_pem(opt_api_secret_key),
        api_key_id=opt_api_key_id
    )

    # Hostname and source
    saas = re.compile(r"\S*\.?intersight\.com\.?$")
    fqdn = re.compile(
        r"^(?!:\/\/)(?=.{1,255}$)((.{1,63}\.){1,127}(?![0-9]*$)[a-z0-9-]+\.?)$")

    if bool(saas.match(opt_intersight_hostname)):
        try:
            RESPONSE = r_intersight(f"iam/Accounts?$select=Name")
            account_name = RESPONSE.json()['Results'][0]['Name']
            helper.log_info(
                f"{s} | Connected to Intersight SaaS account named {account_name}")
        except:
            helper.log_critical(
                f"{s} | Unable to connect to Intersight SaaS")
            sys.exit("FAILED CONNECTION TO INTERSIGHT SAAS")
    else:
        if bool(fqdn.match(opt_intersight_hostname)):
            try:
                RESPONSE = r_intersight(f"iam/UserPreferences")
                account_name = opt_intersight_hostname
                helper.log_info(
                    f"{s} | Connected to Intersight On Prem server named {opt_intersight_hostname}")
            except:
                helper.log_critical(
                    f"{s} | Failed to connect to Intersight On Prem server named {opt_intersight_hostname}")
                sys.exit("FAILED CONNECTION TO INTERSIGHT ON PREM")
        else:
            helper.log_critical(
                f"{s} | INVALID HOSTNAME: configured value is {opt_intersight_hostname}")
            sys.exit("BAD HOSTNAME")

    ##
    # Audit records
    ##
    endpoint = "aaa/AuditRecords"
    checkpoint = f"{account_name}_last_audit_record"
    if opt_enable_aaa_audit_records:
        helper.log_info(f"{s} | Retrieving Audit Records")
        doAuditRecords = check_intersight(endpoint)

    if opt_enable_aaa_audit_records and doAuditRecords:
        state = get_checkpoint('audit')
        # get the audit records
        RESPONSE = r_intersight(
            f"{endpoint}?$orderby=ModTime%20asc&$filter=ModTime%20gt%20{state}")
        # process the audit records
        for data in RESPONSE.json()['Results']:
            # pop things we don't need
            data = pop(['Account', 'Ancestors',
                       'PermissionResources', 'Owners', 'User', 'ClassId', 'DomainGroupMoid', 'ObjectType', 'Sessions', 'SharedScope'], data)
            # Splunk default doesn't allow events over 10k characters by default
            if len(json.dumps(data)) > 9999:
                # we're truncating the Request value if it's larger than that
                data['Request'] = "TRUNCATED"
                helper.log_debug(
                    f"{s} | Truncating Audit Record {data['Moid']}")
            write_splunk(index, account_name,
                         'cisco:intersight:aaaAuditRecords', data)
            state = larger_datetime(data['ModTime'], state)

        # Persist our checkpoint at the end of the audit records
        helper.save_check_point(checkpoint, state)

    if not opt_enable_aaa_audit_records:
        helper.log_debug(
            f"{s} | Audit records were not enabled in the configuration")
        helper.delete_check_point(checkpoint)

    ##
    # Alarms
    ##
    endpoint = "cond/Alarms"
    checkpoint = f"{account_name}_last_alarm_record"
    if opt_enable_alarms:
        helper.log_info(f"{s} | Retrieving Alarm Records")
        doAlarms = check_intersight(endpoint)

    if opt_enable_alarms and doAlarms:
        state = get_checkpoint('alarm')
        # Let's get the alarm records
        RESPONSE = r_intersight(
            f"{endpoint}?$orderby=ModTime%20asc&$filter=ModTime%20gt%20{state}")

        # Process the alarm records
        for data in RESPONSE.json()['Results']:
            data = pop(['AffectedMo', 'Ancestors', 'Owners', 'PermissionResources',
                       'RegisteredDevice', 'ClassId', 'DomainGroupMoid', 'ObjectType', 'SharedScope'], data)
            write_splunk(index, account_name,
                         'cisco:intersight:condAlarms', data)
            state = larger_datetime(data['ModTime'], state)

        # Persist our checkpoint at the end of the audit records
        helper.save_check_point(checkpoint, state)

    if not opt_enable_alarms:
        helper.log_debug(
            f"{s} | Alarm records were not enabled in the configuration")
        helper.delete_check_point(checkpoint)

    ###
    # Inventory checkpointing
    ###
    checkpoint = f"{account_name}_inventory_interval"
    try:
        inventory_checkpoint = helper.get_check_point(checkpoint)
        # increment the inventory checkpoint
        inventory_checkpoint += 1
        # If this isn't the right interval to run inventory, just save the checkpoint
        if inventory_checkpoint < int(opt_inventory_interval):
            doInventory = False
            helper.log_info(
                f"{s} | Skipping Inventory records this inverval, checkpoint is now {inventory_checkpoint} of {opt_inventory_interval}")
            helper.save_check_point(checkpoint, inventory_checkpoint)
        else:
            # If this is the right interval to run inventory then run inventory and reset the checkpoint
            doInventory = True
            inventory_checkpoint = 0
            helper.log_info(
                f"{s} | Inventory is running this interval, checkpoint is now {inventory_checkpoint} of {opt_inventory_interval}")
            helper.save_check_point(checkpoint, inventory_checkpoint)
    except:
        # If the checkpoint isn't set, run inventory this interval and set the checkpoint
        doInventory = True
        inventory_checkpoint = 0
        helper.log_info(
            f"{s} | Inventory is running for the first time, checkpoint is now {inventory_checkpoint} of {opt_inventory_interval}")
        helper.save_check_point(checkpoint, inventory_checkpoint)

    ##
    # Advisories
    ##
    endpoint = "tam/AdvisoryInstances"
    if 'advisories' in opt_inventory and doInventory:
        helper.log_debug(f"{s} | Retrieving Advisory Inventory Records")
        doAdvisories = check_intersight(endpoint)

    if 'advisories' in opt_inventory and doInventory and doAdvisories:
        RESPONSE = r_intersight(f"{endpoint}?$count=True")
        count = RESPONSE.json()['Count']
        helper.log_info(
            f"{s} | Found {str(count)} advisory records to retrieve")
        results_per_page = 10  # adjust the number of results we pull per API call
        for i in range(0, count, results_per_page):
            RESPONSE = r_intersight(
                f"{endpoint}?$expand=Advisory&$top={results_per_page}&$skip={str(i)}")
            for data in RESPONSE.json()['Results']:
                data = pop(['Ancestors', 'AffectedObject',
                            'PermissionResources', 'Owners', 'DeviceRegistration', 'ClassId', 'DomainGroupMoid', 'ObjectType', 'SharedScope'], data)
                data['Advisory'] = pop(['AccountMoid', 'Ancestors', 'Actions', 'ApiDataSources', 'Organization',
                                        'Owners', 'PermissionResources', 'Recommendation', 'DomainGroupMoid', 'ObjectType', 'SharedScope'], data['Advisory'])
                write_splunk(index, account_name,
                             'cisco:intersight:tamAdvisoryInstances', data)

    if not 'advisories' in opt_inventory:
        helper.log_debug(
            f"{s} | Advisories were not selected in the Inventory configuration")

    ###
    # Compute Inventory
    ###
    endpoint = "compute/PhysicalSummaries"
    if 'compute' in opt_inventory and doInventory:
        helper.log_debug(f"{s} | Retrieving Compute Inventory Records")
        doCompute = check_intersight(endpoint)

    if 'compute' in opt_inventory and doInventory and doCompute:
        RESPONSE = r_intersight(f"{endpoint}?$count=True")
        count = RESPONSE.json()['Count']
        helper.log_info(
            f"{s} | Found {str(count)} compute inventory records to retrieve")
        results_per_page = 10  # adjust the number of results we pull per API call
        for i in range(0, count, results_per_page):
            RESPONSE = r_intersight(
                f"{endpoint}?$expand=RegisteredDevice($select=ClaimedByUserName,ClaimedTime,ConnectionStatusLastChangeTime,ConnectionStatus,CreateTime,ReadOnly)&$top={results_per_page}&$skip={str(i)}")
            for data in RESPONSE.json()['Results']:
                data = pop(
                    ['Ancestors', 'PermissionResources', 'Owners', 'DomainGroupMoid', 'ClassId', 'FaultSummary', 'EquipmentChassis', 'InventoryDeviceInfo', 'KvmVendor', 'ObjectType', 'ScaledMode', 'Rn', 'SharedScope'], data)
                data['RegisteredDevice'] = pop(
                    ['ClassId', 'ObjectType'], data['RegisteredDevice'])
                data['AlarmSummary'] = pop(
                    ['ClassId', 'ObjectType'], data['AlarmSummary'])
                write_splunk(index, account_name,
                             'cisco:intersight:computePhysicalSummaries', data)
                # try to get HCL data also
                try:
                    hclRESPONSE = r_intersight(
                        f"cond/HclStatuses?$filter=ManagedObject.Moid%20eq%20%27{data['Moid']}%27")
                    hcldata = hclRESPONSE.json()['Results'][0]
                    hcldata = pop(['Ancestors', 'Details', 'Owners',
                                  'PermissionResources', 'RegisteredDevice'], hcldata)
                    hcldata['ManagedObject'] = pop(
                        ['ClassId', 'link'], hcldata['ManagedObject'])
                    write_splunk(index, account_name,
                                 'cisco:intersight:condHclStatuses', hcldata)
                except:
                    if hclRESPONSE.status_code != 200:
                        helper.log_debug(
                            f"{s} | Unable to retrieve HCL for {data['Moid']} with code {hclRESPONSE.json()['code']}")
                    else:
                        helper.log_debug(
                            f"{s} | HCL for {data['Moid']} not found")

    if not 'compute' in opt_inventory:
        helper.log_debug(
            f"{s} | Compute was not selected in the Inventory configuration")

    ###
    # Contract Status
    ###
    endpoint = "asset/DeviceContractInformations"
    if 'contract' in opt_inventory and doInventory:
        helper.log_debug(f"{s} | Retrieving Contract Inventory Records")
        doContracts = check_intersight(endpoint)

    if 'contract' in opt_inventory and doInventory and doContracts:
        RESPONSE = r_intersight(f"{endpoint}?$count=True")
        count = RESPONSE.json()['Count']
        helper.log_info(
            f"{s} | Found {str(count)} contract inventory records to retrieve")
        results_per_page = 10  # adjust the number of results we pull per API call
        for i in range(0, count, results_per_page):
            RESPONSE = r_intersight(
                f"{endpoint}?$top={results_per_page}&$skip={str(i)}")
            for data in RESPONSE.json()['Results']:
                data = pop(['Ancestors', 'Contract', 'EndCustomer', 'EndUserGlobalUltimate', 'Owners',
                           'PermissionResources', 'Product', 'RegisteredDevice', 'ResellerGlobalUltimate', 'ClassId', 'ObjectType', 'SharedScope'], data)
                data['Source'] = pop(['ClassId', 'link'], data['Source'])
                write_splunk(
                    index, account_name, 'cisco:intersight:assetDeviceContractInformations', data)

    if not 'contract' in opt_inventory:
        helper.log_debug(
            f"{s} | Contract was not selected in the Inventory configuration")

    ###
    # Network Inventory
    ###
    endpoint = "network/ElementSummaries"
    if 'network' in opt_inventory and doInventory:
        helper.log_debug(f"{s} | Retrieving Network Inventory Records")
        doNetwork = check_intersight(endpoint)

    if 'network' in opt_inventory and doInventory and doNetwork:
        RESPONSE = r_intersight(f"{endpoint}?$count=True")
        count = RESPONSE.json()['Count']
        helper.log_info(
            f"{s} | Found {str(count)} network inventory records to retrieve")
        results_per_page = 10  # adjust the number of results we pull per API call
        for i in range(0, count, results_per_page):
            RESPONSE = r_intersight(
                f"{endpoint}?$expand=RegisteredDevice($select=ClaimedByUserName,ClaimedTime,ConnectionStatusLastChangeTime,ConnectionStatus,CreateTime,ReadOnly)&$top={results_per_page}&$skip={str(i)}")
            for data in RESPONSE.json()['Results']:
                data = pop(['Ancestors', 'PermissionResources',
                           'Owners', 'FaultSummary', 'ClassId', 'ObjectType', 'SharedScope'], data)
                data['RegisteredDevice'] = pop(
                    ['ClassId', 'ObjectType'], data['RegisteredDevice'])
                data['AlarmSummary'] = pop(
                    ['ClassId', 'ObjectType'], data['AlarmSummary'])
                write_splunk(
                    index, account_name, 'cisco:intersight:networkElementSummaries', data=data)

    if not 'network' in opt_inventory:
        helper.log_debug(
            f"{s} | Network was not selected in the Inventory configuration")

    ###
    # Target Inventory
    ###
    endpoint = "asset/Targets"
    if 'target' in opt_inventory and doInventory:
        helper.log_debug(f"{s} | Retrieving Target Inventory Records")
        doTarget = check_intersight(endpoint)

    if 'target' in opt_inventory and doInventory and doTarget:
        RESPONSE = r_intersight(f"{endpoint}?$count=True")
        count = RESPONSE.json()['Count']
        helper.log_info(
            f"{s} | Found {str(count)} target inventory records to retrieve")
        results_per_page = 10  # adjust the number of results we pull per API call
        for i in range(0, count, results_per_page):
            RESPONSE = r_intersight(
                f"{endpoint}?$top={results_per_page}&$skip={str(i)}")
            for data in RESPONSE.json()['Results']:
                data = pop(['Account', 'Ancestors', 'Connections', 'Parent', 'DomainGroupMoid',
                           'PermissionResources', 'Owners', 'RegisteredDevice', 'SharedScope', 'ClassId', 'ObjectType'], data)
                write_splunk(
                    index, account_name, 'cisco:intersight:assetTargets', data=data)

    if not 'target' in opt_inventory:
        helper.log_debug(
            f"{s} | Target was not selected in the Inventory configuration")

    ##
    # Hyperflex Inventory
    ##

    # Clusters
    endpoint = "hyperflex/Clusters"
    if 'hyperflex' in opt_inventory and doInventory:
        helper.log_debug(f"{s} | Retrieving HX Cluster Inventory Records")
        doHxClusters = check_intersight(endpoint)

    if 'hyperflex' in opt_inventory and doInventory and doHxClusters:
        RESPONSE = r_intersight(f"{endpoint}?$count=True")
        count = RESPONSE.json()['Count']
        helper.log_info(
            f"{s} | Found {str(count)} Hyperflex cluster records to retrieve")
        results_per_page = 10  # adjust the number of results we pull per API call
        for i in range(0, count, results_per_page):
            RESPONSE = r_intersight(
                f"{endpoint}?$expand=Encryption($select=State),License,RegisteredDevice($select=ClaimedByUserName,ClaimedTime,ConnectionStatusLastChangeTime,ConnectionStatus,CreateTime,ReadOnly)&$top={results_per_page}&$skip={str(i)}")
            for data in RESPONSE.json()['Results']:
                data = pop(['Alarm', 'Ancestors', 'ChildClusters', 'DomainGroupMoid', 'ClassId', 'Owners', 'ObjectType', 'PermissionResources',
                           'StorageContainers', 'SharedScope', 'Nodes', 'Health', 'ParentCluster', 'Volumes'], data)
                data['License'] = pop(
                    ['Ancestors', 'Cluster', 'Owners', 'DomainGroupMoid', 'PermissionResources', 'RegisteredDevice'], data['License'])
                data['RegisteredDevice'] = pop(
                    ['ClassId', 'ObjectType'], data['RegisteredDevice'])
                if data['Encryption'] != None:
                    data['Encryption'] = pop(
                        ['ClassId', 'ObjectType', 'Moid'], data['Encryption'])
                data['AlarmSummary'] = pop(
                    ['ClassId', 'ObjectType'], data['AlarmSummary'])
                write_splunk(index, account_name,
                             'cisco:intersight:hyperflexClusters', data)

    # Nodes
    endpoint = "hyperflex/Nodes"
    if 'hyperflex' in opt_inventory and doInventory:
        helper.log_debug(f"{s} | Retrieving HX Node Inventory Records")
        doHxNodes = check_intersight(endpoint)

    if 'hyperflex' in opt_inventory and doInventory and doHxNodes:
        RESPONSE = r_intersight(f"{endpoint}?$count=True")
        count = RESPONSE.json()['Count']
        helper.log_info(
            f"{s} | Found {str(count)} Hyperflex node records to retrieve")
        results_per_page = 10  # adjust the number of results we pull per API call
        for i in range(0, count, results_per_page):
            RESPONSE = r_intersight(
                f"{endpoint}?$expand=Drives&$top={results_per_page}&$skip={str(i)}")
            for data in RESPONSE.json()['Results']:
                data = pop(['Ancestors', 'ClusterMember', 'Identity', 'Owners',
                           'Parent', 'PermissionResources', 'SharedScope', 'DomainGroupMoid', 'ClassId', 'ObjectType', 'NodeUuid'], data)
                data['Cluster'] = pop(['ClassId', 'link'], data['Cluster'])
                data['PhysicalServer'] = pop(
                    ['ClassId', 'link'], data['PhysicalServer'])
                if data['Drives'] == None:
                    helper.log_warning(
                        f"{s} | Hyperflex host {data['Moid']} has no list of drives")
                else:
                    for i in range(0, len(data['Drives'])):
                        data['Drives'][i] = pop(
                            ['AccountMoid', 'Ancestors', 'ClassId', 'NodeUuid', 'Uuid', 'SharedScope',
                             'ObjectType', 'Moid', 'HostName', 'Tags', 'DomainGroupMoid', 'LocatorLed',
                             'Node', 'Owners', 'Parent', 'PermissionResources', 'HostUuid'], data['Drives'][i])
                write_splunk(index, account_name,
                             'cisco:intersight:hyperflexNodes', data)

    # StorageContainers
    endpoint = "hyperflex/StorageContainers"
    if 'hyperflex' in opt_inventory and doInventory:
        helper.log_debug(
            f"{s} | Retrieving HX Storage Container Inventory Records")
        doHxStorageContainers = check_intersight(endpoint)

    if 'hyperflex' in opt_inventory and doInventory and doHxStorageContainers:
        RESPONSE = r_intersight(f"{endpoint}?$count=True")
        count = RESPONSE.json()['Count']
        helper.log_info(
            f"{s} | Found {str(count)} Hyperflex storage container records to retrieve")
        results_per_page = 10  # adjust the number of results we pull per API call
        for i in range(0, count, results_per_page):
            RESPONSE = r_intersight(
                f"{endpoint}?$top={results_per_page}&$skip={str(i)}")
            for data in RESPONSE.json()['Results']:
                data = pop(['Ancestors', 'Owners', 'PermissionResources', 'SharedScope',
                           'DomainGroupMoid', 'ClassId', 'ObjectType', 'Uuid', 'Volumes'], data)
                data['Cluster'] = pop(
                    ['ClassId', 'link', 'ObjectType'], data['Cluster'])
                data['StorageUtilization'] = pop(
                    ['ClassId', 'ObjectType'], data['StorageUtilization'])
                if data['HostMountStatus'] != None:
                    for i in range(0, len(data['HostMountStatus'])):
                        data['HostMountStatus'][i] = pop(
                            ['ClassId', 'ObjectType'], data['HostMountStatus'][i])
                write_splunk(index, account_name,
                             'cisco:intersight:hyperflexStorageContainers', data)

    # Licenses
    endpoint = "hyperflex/Licenses"
    if 'hyperflex' in opt_inventory and doInventory:
        helper.log_debug(
            f"{s} | Retrieving HX License Inventory Records")
        doHxLicenses = check_intersight(endpoint)

    if 'hyperflex' in opt_inventory and doInventory and doHxLicenses:
        RESPONSE = r_intersight(f"{endpoint}?$count=True")
        count = RESPONSE.json()['Count']
        helper.log_info(
            f"{s} | Found {str(count)} Hyperflex license records to retrieve")
        results_per_page = 10  # adjust the number of results we pull per API call
        for i in range(0, count, results_per_page):
            RESPONSE = r_intersight(
                f"{endpoint}?$top={results_per_page}&$skip={str(i)}")
            for data in RESPONSE.json()['Results']:
                data = pop(['Ancestors', 'Owners', 'PermissionResources', 'SharedScope',
                           'DomainGroupMoid', 'ClassId', 'ObjectType', 'RegisteredDevice'], data)
                for x in ['LicenseRegistration', 'LicenseAuthorization', 'Cluster']:
                    data[x] = pop(['ClassId', 'ObjectType'], data[x])
                data['Cluster'] = pop(['link'], data['Cluster'])
                write_splunk(index, account_name,
                             'cisco:intersight:hyperflexLicenses', data)

    if not 'hyperflex' in opt_inventory:
        helper.log_debug(
            f"{s} | Hyperflex was not selected in the Inventory configuration")

    ##
    # Netapp Inventory
    ##

    # NetApp Clusters
    endpoint = "storage/NetAppClusters"
    if 'netapp' in opt_inventory and doInventory:
        helper.log_debug(f"{s} | Retrieving NetApp Cluster Inventory Records")
        doNetAppClusters = check_intersight(endpoint)

    if 'netapp' in opt_inventory and doInventory and doNetAppClusters:
        RESPONSE = r_intersight(f"{endpoint}?$count=True")
        count = RESPONSE.json()['Count']
        helper.log_info(
            f"{s} | Found {str(count)} NetApp cluster records to retrieve")
        results_per_page = 10  # adjust the number of results we pull per API call
        for i in range(0, count, results_per_page):
            RESPONSE = r_intersight(
                f"{endpoint}?$expand=RegisteredDevice($select=ClaimedByUserName,ClaimedTime,ConnectionStatusLastChangeTime,ConnectionStatus,CreateTime,ReadOnly)&$top={results_per_page}&$skip={str(i)}")
            for data in RESPONSE.json()['Results']:
                data = pop(['Ancestors', 'DomainGroupMoid', 'ClassId', 'DeviceMoId', 'Events', 'Key',
                           'Owners', 'ObjectType', 'PermissionResources', 'SharedScope', 'Uuid'], data)
                for x in ['AutoSupport', 'AvgPerformanceMetrics', 'ClusterEfficiency', 'RegisteredDevice', 'StorageUtilization']:
                    data[x] = pop(['ClassId', 'ObjectType'], data[x])
                write_splunk(index, account_name,
                             'cisco:intersight:storageNetAppClusters', data)

    # NetApp Nodes
    endpoint = "storage/NetAppNodes"
    if 'netapp' in opt_inventory and doInventory:
        helper.log_debug(f"{s} | Retrieving NetApp Node Inventory Records")
        doNetAppNodes = check_intersight(endpoint)

    if 'netapp' in opt_inventory and doInventory and doNetAppNodes:
        RESPONSE = r_intersight(f"{endpoint}?$count=True")
        count = RESPONSE.json()['Count']
        helper.log_info(
            f"{s} | Found {str(count)} NetApp node records to retrieve")
        results_per_page = 10  # adjust the number of results we pull per API call
        for i in range(0, count, results_per_page):
            RESPONSE = r_intersight(
                f"{endpoint}?$top={results_per_page}&$skip={str(i)}")
            for data in RESPONSE.json()['Results']:
                data = pop(['Ancestors', 'DomainGroupMoid', 'ClassId', 'DeviceMoId', 'Events', 'Key',
                           'Owners', 'Parent', 'ObjectType', 'PermissionResources', 'SharedScope', 'Uuid'], data)
                for x in ['Array', 'AvgPerformanceMetrics', 'HighAvailability']:
                    data[x] = pop(['ClassId', 'ObjectType'], data[x])
                data['Array'] = pop(['link'], data['Array'])
                write_splunk(index, account_name,
                             'cisco:intersight:storageNetAppNodes', data)

    # NetApp Volumes
    endpoint = "storage/NetAppVolumes"
    if 'netapp' in opt_inventory and doInventory:
        helper.log_debug(f"{s} | Retrieving NetApp Volume Inventory Records")
        doNetAppVolumes = check_intersight(endpoint)

    if 'netapp' in opt_inventory and doInventory and doNetAppVolumes:
        RESPONSE = r_intersight(f"{endpoint}?$count=True")
        count = RESPONSE.json()['Count']
        helper.log_info(
            f"{s} | Found {str(count)} NetApp volume records to retrieve")
        results_per_page = 10  # adjust the number of results we pull per API call
        for i in range(0, count, results_per_page):
            RESPONSE = r_intersight(
                f"{endpoint}?$top={results_per_page}&$skip={str(i)}")
            for data in RESPONSE.json()['Results']:
                data = pop(['Ancestors', 'DomainGroupMoid', 'DiskPool', 'ClassId', 'Events', 'Key',
                           'Owners', 'Parent', 'ObjectType', 'PermissionResources', 'SharedScope', 'SnapshotPolicyUuid', 'Uuid'], data)
                for x in ['AvgPerformanceMetrics', 'StorageUtilization']:
                    data[x] = pop(['ClassId', 'ObjectType'], data[x])
                for x in ['Array', 'Tenant']:
                    data[x] = pop(['ClassId', 'ObjectType', 'link'], data[x])
                write_splunk(index, account_name,
                             'cisco:intersight:storageNetAppVolumes', data)

    # NetApp Storage VMs
    endpoint = "storage/NetAppStorageVms"
    if 'netapp' in opt_inventory and doInventory:
        helper.log_debug(f"{s} | Retrieving NetApp Storage VM Inventory Records")
        doNetAppStorageVms = check_intersight(endpoint)

    if 'netapp' in opt_inventory and doInventory and doNetAppStorageVms:
        RESPONSE = r_intersight(f"{endpoint}?$count=True")
        count = RESPONSE.json()['Count']
        helper.log_info(
            f"{s} | Found {str(count)} NetApp storage vm records to retrieve")
        results_per_page = 10  # adjust the number of results we pull per API call
        for i in range(0, count, results_per_page):
            RESPONSE = r_intersight(
                f"{endpoint}?$top={results_per_page}&$skip={str(i)}")
            for data in RESPONSE.json()['Results']:
                data = pop(['Ancestors', 'DomainGroupMoid', 'ClassId', 'Events', 'Key', 'DiskPool',
                           'Owners', 'Parent', 'ObjectType', 'PermissionResources', 'SharedScope', 'Uuid'], data)
                for x in ['Array', 'AvgPerformanceMetrics']:
                    data[x] = pop(['ClassId', 'ObjectType'], data[x])
                data['Array'] = pop(['link'], data['Array'])
                write_splunk(index, account_name,
                             'cisco:intersight:storageNetAppStorageVms', data)

    # Converged Infra Pods
    endpoint = "convergedinfra/Pods"
    if 'netapp' in opt_inventory and doInventory:
        helper.log_debug(f"{s} | Retrieving NetApp CI Pod Inventory Records")
        doNetAppPods = check_intersight(endpoint)

    if 'netapp' in opt_inventory and doInventory and doNetAppPods:
        RESPONSE = r_intersight(
            f"{endpoint}?$count=True&$filter=Type%20eq%20%27FlexPod%27")
        count = RESPONSE.json()['Count']
        helper.log_info(
            f"{s} | Found {str(count)} NetApp CI pod records to retrieve")
        results_per_page = 10  # adjust the number of results we pull per API call
        for i in range(0, count, results_per_page):
            RESPONSE = r_intersight(
                f"{endpoint}?$filter=Type%20eq%20%27FlexPod%27&$top={results_per_page}&$skip={str(i)}")
            for data in RESPONSE.json()['Results']:
                data = pop(['Ancestors', 'DomainGroupMoid', 'DeploymentType', 'ClassId', 'Organization',
                           'Owners', 'ObjectType', 'PermissionResources', 'SharedScope', 'PodResourceGroup'], data)
                for x in ['ServiceItemInstance', 'Summary']:
                    data[x] = pop(['ClassId', 'ObjectType'], data[x])
                for x in ['AlarmSummary', 'ComplianceSummary']:
                    data['Summary'][x] = pop(
                        ['ClassId', 'ObjectType'], data['Summary'][x])
                data['ServiceItemInstance'] = pop(
                    ['link'], data['ServiceItemInstance'])
                write_splunk(index, account_name,
                             'cisco:intersight:convergedinfraPods', data)

    if not 'netapp' in opt_inventory:
        helper.log_debug(
            f"{s} | NetApp was not selected in the Inventory configuration")

    ##
    # Pure Inventory
    ##

    # Pure Arrays
    endpoint = "storage/PureArrays"
    if 'pure' in opt_inventory and doInventory:
        helper.log_debug(f"{s} | Retrieving Pure Array Inventory Records")
        doPureArrays = check_intersight(endpoint)

    if 'pure' in opt_inventory and doInventory and doPureArrays:
        RESPONSE = r_intersight(f"{endpoint}?$count=True")
        count = RESPONSE.json()['Count']
        helper.log_info(
            f"{s} | Found {str(count)} Pure Array records to retrieve")
        results_per_page = 10  # adjust the number of results we pull per API call
        for i in range(0, count, results_per_page):
            RESPONSE = r_intersight(
                f"{endpoint}?$expand=RegisteredDevice($select=ClaimedByUserName,ClaimedTime,ConnectionStatusLastChangeTime,ConnectionStatus,CreateTime,ReadOnly)&$top={results_per_page}&$skip={str(i)}")
            for data in RESPONSE.json()['Results']:
                data = pop(['Ancestors', 'DomainGroupMoid', 'ClassId', 'DeviceMoId', 'Owners',
                           'ObjectType', 'PermissionResources', 'SharedScope', 'Uuid'], data)
                for x in ['RegisteredDevice', 'StorageUtilization']:
                    data[x] = pop(['ClassId', 'ObjectType'], data[x])
                write_splunk(index, account_name,
                             'cisco:intersight:storagePureArrays', data)

    # Pure Controllers
    endpoint = "storage/PureControllers"
    if 'pure' in opt_inventory and doInventory:
        helper.log_debug(f"{s} | Retrieving Pure Controller Inventory Records")
        doPureControllers = check_intersight(endpoint)

    if 'pure' in opt_inventory and doInventory and doPureControllers:
        RESPONSE = r_intersight(f"{endpoint}?$count=True")
        count = RESPONSE.json()['Count']
        helper.log_info(
            f"{s} | Found {str(count)} Pure controller records to retrieve")
        results_per_page = 10  # adjust the number of results we pull per API call
        for i in range(0, count, results_per_page):
            RESPONSE = r_intersight(
                f"{endpoint}?$expand=RegisteredDevice($select=ClaimedByUserName,ClaimedTime,ConnectionStatusLastChangeTime,ConnectionStatus,CreateTime,ReadOnly)&$top={results_per_page}&$skip={str(i)}")
            for data in RESPONSE.json()['Results']:
                data = pop(['Ancestors', 'DomainGroupMoid', 'ClassId', 'DeviceMoId', 'Owners',
                           'Parent', 'ObjectType', 'PermissionResources', 'SharedScope'], data)
                for x in ['RegisteredDevice', 'Array']:
                    data[x] = pop(['ClassId', 'ObjectType'], data[x])
                data['Array'] = pop(['link'], data['Array'])
                write_splunk(index, account_name,
                             'cisco:intersight:storagePureControllers', data)

    # Pure Volumes
    endpoint = "storage/PureVolumes"
    if 'pure' in opt_inventory and doInventory:
        helper.log_debug(f"{s} | Retrieving Pure Controller Inventory Records")
        doPureVolumes = check_intersight(endpoint)

    if 'pure' in opt_inventory and doInventory and doPureVolumes:
        RESPONSE = r_intersight(f"{endpoint}?$count=True")
        count = RESPONSE.json()['Count']
        helper.log_info(
            f"{s} | Found {str(count)} Pure volume records to retrieve")
        results_per_page = 10  # adjust the number of results we pull per API call
        for i in range(0, count, results_per_page):
            RESPONSE = r_intersight(
                f"{endpoint}?$top={results_per_page}&$skip={str(i)}")
            for data in RESPONSE.json()['Results']:
                data = pop(['Ancestors', 'DomainGroupMoid', 'ClassId', 'Owners', 'Parent', 'ObjectType',
                           'PermissionResources', 'SharedScope', 'NaaId', 'RegisteredDevice'], data)
                for x in ['Array', 'StorageUtilization']:
                    data[x] = pop(['ClassId', 'ObjectType'], data[x])
                data['Array'] = pop(['link'], data['Array'])
                write_splunk(index, account_name,
                             'cisco:intersight:storagePureVolumes', data)

    if not 'pure' in opt_inventory:
        helper.log_debug(
            f"{s} | Pure was not selected in the Inventory configuration")

    ##
    # Hitachi Inventory
    ##

    # Hitachi Arrays
    endpoint = "storage/HitachiArrays"
    if 'hitachi' in opt_inventory and doInventory:
        helper.log_debug(f"{s} | Retrieving Hitachi Array Inventory Records")
        doHitachiArrays = check_intersight(endpoint)

    if 'hitachi' in opt_inventory and doInventory and doHitachiArrays:
        RESPONSE = r_intersight(f"{endpoint}?$count=True")
        count = RESPONSE.json()['Count']
        helper.log_info(
            f"{s} | Found {str(count)} Hitachi Array records to retrieve")
        results_per_page = 10  # adjust the number of results we pull per API call
        for i in range(0, count, results_per_page):
            RESPONSE = r_intersight(
                f"{endpoint}?$expand=RegisteredDevice($select=ClaimedByUserName,ClaimedTime,ConnectionStatusLastChangeTime,ConnectionStatus,CreateTime,ReadOnly)&$top={results_per_page}&$skip={str(i)}")
            for data in RESPONSE.json()['Results']:
                data = pop(['Ancestors', 'DomainGroupMoid', 'ClassId', 'DeviceMoId', 'Owners',
                           'ObjectType', 'PermissionResources', 'SharedScope', 'Uuid'], data)
                for x in ['RegisteredDevice', 'StorageUtilization']:
                    data[x] = pop(['ClassId', 'ObjectType'], data[x])
                write_splunk(index, account_name,
                             'cisco:intersight:storageHitachiArrays', data)

    # Hitachi Controllers
    endpoint = "storage/HitachiControllers"
    if 'hitachi' in opt_inventory and doInventory:
        helper.log_debug(
            f"{s} | Retrieving Hitachi Controller Inventory Records")
        doHitachiControllers = check_intersight(endpoint)

    if 'hitachi' in opt_inventory and doInventory and doHitachiControllers:
        RESPONSE = r_intersight(f"{endpoint}?$count=True")
        count = RESPONSE.json()['Count']
        helper.log_info(
            f"{s} | Found {str(count)} Hitachi controller records to retrieve")
        results_per_page = 10  # adjust the number of results we pull per API call
        for i in range(0, count, results_per_page):
            RESPONSE = r_intersight(
                f"{endpoint}?$top={results_per_page}&$skip={str(i)}")
            for data in RESPONSE.json()['Results']:
                data = pop(['Ancestors', 'DomainGroupMoid', 'ClassId', 'DeviceMoId', 'Owners',
                           'Parent', 'ObjectType', 'PermissionResources', 'SharedScope', 'RegisteredDevice'], data)
                data['Array'] = pop(
                    ['ClassId', 'ObjectType', 'link'], data['Array'])
                write_splunk(index, account_name,
                             'cisco:intersight:storageHitachiControllers', data)

    # Hitachi Volumes
    endpoint = "storage/HitachiVolumes"
    if 'hitachi' in opt_inventory and doInventory:
        helper.log_debug(
            f"{s} | Retrieving Hitachi Controller Inventory Records")
        doHitachiVolumes = check_intersight(endpoint)

    if 'hitachi' in opt_inventory and doInventory and doHitachiVolumes:
        RESPONSE = r_intersight(f"{endpoint}?$count=True")
        count = RESPONSE.json()['Count']
        helper.log_info(
            f"{s} | Found {str(count)} Hitachi volume records to retrieve")
        results_per_page = 10  # adjust the number of results we pull per API call
        for i in range(0, count, results_per_page):
            RESPONSE = r_intersight(
                f"{endpoint}?$top={results_per_page}&$skip={str(i)}")
            for data in RESPONSE.json()['Results']:
                data = pop(['Ancestors', 'DomainGroupMoid', 'ClassId', 'Owners', 'Parent', 'ObjectType',
                           'PermissionResources', 'SharedScope', 'RegisteredDevice', 'Pool', 'ParityGroups', 'ParityGroupIds'], data)
                for x in ['Array', 'StorageUtilization']:
                    data[x] = pop(['ClassId', 'ObjectType'], data[x])
                data['Array'] = pop(['link'], data['Array'])
                write_splunk(index, account_name,
                             'cisco:intersight:storageHitachiVolumes', data)

    if not 'hitachi' in opt_inventory:
        helper.log_debug(
            f"{s} | Hitachi was not selected in the Inventory configuration")

    ###
    # License Inventory
    ###
    endpoint = "license/AccountLicenseData"
    if 'license' in opt_inventory and doInventory:
        helper.log_debug(f"{s} | Retrieving License Records")
        doLicense = check_intersight(endpoint)

    if 'license' in opt_inventory and doInventory and doLicense:
        RESPONSE = r_intersight(f"{endpoint}?$count=True")
        count = RESPONSE.json()['Count']
        helper.log_info(
            f"{s} | Found {str(count)} license account records to retrieve")
        results_per_page = 10  # adjust the number of results we pull per API call
        for i in range(0, count, results_per_page):
            RESPONSE = r_intersight(
                f"{endpoint}?$top={results_per_page}&$skip={str(i)}")
            for data in RESPONSE.json()['Results']:
                data = pop(['Account', 'AgentData', 'Ancestors', 'DomainGroupMoid',
                           'PermissionResources', 'Owners', 'SharedScope', 'ClassId', 'ObjectType'], data)
                write_splunk(
                    index, account_name, 'cisco:intersight:licenseAccountLicenseData', data=data)

    endpoint = "license/LicenseInfos"
    if 'license' in opt_inventory and doInventory and doLicense:
        RESPONSE = r_intersight(f"{endpoint}?$count=True")
        count = RESPONSE.json()['Count']
        helper.log_info(
            f"{s} | Found {str(count)} license info records to retrieve")
        results_per_page = 10  # adjust the number of results we pull per API call
        for i in range(0, count, results_per_page):
            RESPONSE = r_intersight(
                f"{endpoint}?$top={results_per_page}&$skip={str(i)}")
            for data in RESPONSE.json()['Results']:
                data = pop(['Ancestors', 'DomainGroupMoid', 'Parent',
                           'PermissionResources', 'Owners', 'SharedScope', 'ClassId', 'ObjectType'], data)
                write_splunk(
                    index, account_name, 'cisco:intersight:licenseLicenseInfos', data=data)

    if not 'license' in opt_inventory:
        helper.log_debug(
            f"{s} | License was not selected in the Inventory configuration")

    # Epilogue
    end = datetime.now()
    elapsed = end - start
    helper.log_info(f"{s} | FINISHED -- runtime was {elapsed}")
