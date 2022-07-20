# Cisco Intersight Add-on for Splunk

This project came about to fill a gap that I saw in the [Cisco Intersight](https://intersight.com/help/saas) ecosystem. How can you get useful data from Intersight into Splunk? Since Intersight uses a unique API authentication scheme, simple REST API inputs could not be used.

This Splunk [Add-On](https://docs.splunk.com/Splexicon:Addon) begins to solve this problem by providing inputs for a number of Intersight data types.

This Add-on is not supported by Cisco Systems or the Cisco Technical Assistance Center (TAC). It was developed by me, as a member of the community.

## Development

I used the [Splunk Add-on Builder](https://splunkbase.splunk.com/app/2962/) to create this Add-on. This approach provides a solid framework to build a python-based [scripted input](https://docs.splunk.com/Splexicon:Scriptedinput).

Intersight uses API keys to cryptographically sign API requests. To sign requests to Intersight, I am using the [intersight-auth](https://github.com/cgascoig/intersight-auth) library. I also had to bundle in some of it's dependencies, including... cffi, cryptography, pycparser, cffi.libs and _cffi_backend. I added these libraries to Splunk Add-on Builder (for me, /opt/splunk/etc/apps/splunk_app_addon-builder/bin/ta_generator/resources_lib/aob_py3) manually to have it bundle them in the distributable package for me.

From here, the bulk of the work is contained in [input_module_intersight.py](input_module_intersight.py) and the connectivity is done with relatively straightforward usage of the Python Requests library.

To execute the Intersight-facing input code without Splunk, see [splunk_em.py](splunk_em.py).  It provides a really minimal set of code that will allow it to call [input_module_intersight.py](input_module_intersight.py) and output some logging without an actual Splunk server.  It does not persist any of the checkpoints so functionally it's like a first-run every time.  This is really helpful for debugging and testing.  It picks up the Intersight api key and secret key from a .env file.

## Distribution

This Add-on is available [from Splunkbase](https://splunkbase.splunk.com/app/6482/).

Please review [the release notes](splunkbase/releasenotes.md).

## Deployment

Typically, this Add-on would be installed on an indexer in your Splunk architecture.

The Add-on will need an API key from Intersight. You may use either v2 schema or v3 schema keys. Currently, there is no functional difference between the two as far as Intersight is concerned. They simply use different underlying cryptography. Remember that when you create an API key, it will provide access as the currently logged-in user in the current role. You probably don't want to give Splunk an Account Administrator role API key.

![Generate an API Key](images/generate_api_key.png)

Most of the functionality will work with an API key having the system defined Read-Only role. But to get the Audit Logs while maintaining a least privilege access model, I would suggest that you create a custom role that includes the Read-Only and Audit Log Viewer privileges. Login to Intersight using this role to create the API key.

![Least-Privilige Role](images/role.png)

Simply install the app and click on the Inputs tab. Click the 'Create New Input' button to add an input for each Intersight account or appliance you wish to use with Splunk. If you have multiple appliances or SaaS accounts (or a mix of both), you can add each of them as a separate Input on this page. SaaS inputs will retrieve the account name from Intersight as the source field, while appliances will use the value from Intersight Hostname as the source field.

![Add Intersight Input](images/add_intersight.png)

## Configuration

- Name : This name is the name of the input. It isn't used anywhere except the Add-on logs (see [Troubleshooting](#troubleshooting)) and can be a friendly name for the Intersight account.
- Interval : This interval (in seconds) controls how often the input will retrieve data from Intersight. I think `60` seconds is probably ideal, but anything between `30` seconds and `300` seconds is probably reasonable.
- Index : The name of the Splunk index (which needs to already exist!) where the data should be stored.
- Intersight Hostname : This field should keep the default of 'www.intersight.com' for SaaS instances of Intersight. For On-Premise Intersight Appliances (sometimes known as Connected Virtual Appliance or Private Virtual Appliance), set this field to the FQDN of the appliance.
- Validate SSL Certificate : This box should remain checked for SaaS instances of Intersight. Sometimes an on-premise appliance will use a self-signed certificate that this Add-on will not know to trust or perhaps your network will have an inline security appliance that does SSL interception. In any case, this setting allows us to ignore the validity of the SSL certificate. See [Troubleshooting](#troubleshooting) for more details on how to see that this is happening.
- API Key Id : This will be the public half of the API key from Intersight.
- API Secret Key : This will be the secret half of the API key from Intersight. It will be [PEM formatted binary data](https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail) and you can paste the entire key including the header and footer into this field.
- Enable AAA Audit Records : This checkbox enables the input for activity audit logs from Intersight. The Read-Only role does not have access to these. See Least-Privilege Role above. Also, be aware that this input will not go back to the beginning of time and import all Audit records.  The input has a static configuration to import records that have a ModTime in the last two days at the initial run.
- Enable Alarms : This checkbox enables the input for alarms from Intersight. Be aware that this input will not go back to the beginning of time and import all Alarms. The input has a static configuration to import Alarms that have a ModTime in the last two days at the initial run.
- Enable Inventory : This multi-select enables the various inventory import options. All, some, or none of these items may be selected. [See below for more details](#the-data-from-intersight-in-splunk) on what is included in the various options.
- Inventory Interval : Inventory records don't need to be imported from Intersight at every interval in a typical environment. This value selects how many intervals should occur between imports of these items. A selection of `1` here will import them on every interval. Perhaps if the Interval above is `60` seconds, then an Inventory Interval here of `300` will cause inventory and advisories to be imported a few times a day on every 300th run of this input. This is a sensible way to reduce the repetitive input of data that doesn't change that often. I would suggest a configuration that imports inventory at least once every 24 hours.

## Proxy

An HTTP proxy server may be configured for the Add-on by clicking on Configuration at the top of the page. Basic authentication should work, but hasn't been tested. Username and Password must BOTH be populated to send Basic Authentication to the proxy server. If either field is empty, the Add-on will attempt to use the proxy server without authentication.

![Proxy Configuration](images/proxy.png)

- Enable : This checkbox enables the proxy configuration.
- Proxy Type : Only `http` type is supported. Selecting `socks4` or `socks5` will cause all of the Inputs to fail.
- Host : FQDN or IP address of the HTTP proxy server.
- Port : TCP port number of the proxy service.
- Username : Username for proxy servers that require Basic Authenitcation.
- Password : Password for proxy servers that require Basic Authentication.
- Remote DNS resolution : This option is not used and it's state doesn't matter.

These fields are assembled into a proxy URL such as `http://username:password@hostname.domain.com:3128`.

## Data

Each API endpoint in Intersight becomes a different sourcetype in Splunk as shown below. Some of the Inventory types pull data from multiple API endpoints in Intersight to get a complete data set.

| Checkbox | Intersight API | Splunk sourcetype |
| --- | --- | --- |
| Enable AAA Audit Records | [aaa/AuditRecords][1] | cisco:intersight:aaaAuditRecords |
| Enable Alarms | [cond/Alarms][2] | cisco:intersight:condAlarms |

These inventory options are enabled via the multi-select in the input configuration.

| Enable Inventory Options | Intersight API | Splunk sourcetype |
| --- | --- | --- |
| Advisories | [tam/AdvisoryInstances][3] | cisco:intersight:tamAdvisoryInstances |
| Compute | [compute/PhysicalSummaries][4] | cisco:intersight:computePhysicalSummaries |
| Compute | [cond/HclStatuses][9] | cisco:intersight:condHclStatuses |
| Hyperflex | [hyperflex/Clusters][5] | cisco:intersight:hyperflexClusters |
| Hyperflex | [hyperflex/Nodes][8] |cisco:intersight:hyperflexNodes |
| Network | [network/ElementSummaries][6] | cisco:intersight:networkElementSummaries |
| Target | [asset/Targets][7] | cisco:intersight:assetTargets |
| Contract | [asset/DeviceContractStatusInformations][10] | cisco:intersight:assetDeviceContractInformations |

All of the data from this Add-on can be queried in Splunk using the following [SPL](https://docs.splunk.com/Splexicon:SPL):

`index=* sourcetype=cisco:intersight:*`

In many cases, this will retrieve duplicate records as alarms are updated or inventory is regularly re-imported. The [dedup command](https://docs.splunk.com/Documentation/Splunk/8.2.6/SearchReference/Dedup) can be easily used to retrieve data without unwanted duplication.

`index=* sourcetype="cisco:intersight:computePhysicalSummaries" | dedup Moid`

The technique of using `| dedup Moid` is applicable to all sourcetypes except cisco:intersight:aaaAuditRecords and should be used in most circumstances.

You may also notice, if you are very familiar with the Intersight API, that there are a few nodes of JSON that are missing in Splunk that are present elsewhere. This is due to some editorial pruning that is occurring in the Add-on. There are some object references in the API results that simply don't serve any purpose in Splunk. The Add-on is pruning these to improve the overall experience and optimize the amount of data that gets pushed to Splunk.

## Examples

One for each sourcetype...

| Splunk sourcetype | Example Search |
| --- | --- |
| cisco:intersight:aaaAuditRecords | `index=* sourcetype=cisco:intersight:aaaAuditRecords MoType!=iam.UserPreference \| rename MoType as Type \| rename MoDisplayNames.Name{} as Object \| eval Request=json_extract(_raw,"Request") \| table source, Email, Event, Type, Object, Request` |
| cisco:intersight:condAlarms | `index=* sourcetype=cisco:intersight:condAlarms \| dedup Moid \| search Severity != Cleared \| rename AffectedMoDisplayName as AffectedDevice \| table source, Name, AffectedDevice, Severity, Description` |
| cisco:intersight:tamAdvisoryInstances | `index=* sourcetype=cisco:intersight:tamAdvisoryInstances \| dedup Advisory.Moid \| rename Advisory.BaseScore as CVSSBaseScore \| rename Advisory.AdvisoryId as Id \| rename Advisory.ObjectType as Type \| rename Advisory.Name as Name \| rename Advisory.Severity.Level as Severity \| rename Advisory.CveIds{} as Attached_CVEs \| table source, Name, Id, Type, CVSSBaseScore, Severity, Attached_CVEs` |
| cisco:intersight:computePhysicalSummaries | `index=* sourcetype=cisco:intersight:computePhysicalSummaries RegisteredDevice.ConnectionStatus!=Unclaimed \| dedup Moid \| rename NumCpuCoresEnabled as Cores \| rename TotalMemory as RAM \| eval RAM=RAM/1024 \| rename OperPowerState as Power \| rename AlarmSummary.Critical as Criticals \| rename AlarmSummary.Warning as Warnings \| rename RegisteredDevice.ConnectionStatus as Status \| eval Health=case(Criticals >= 1,"Critical", Warnings >= 1,"Warning", 1=1, "Healthy") \| table source, Power, Status, Health, Name, Model,Serial, Firmware, Cores, RAM`
| cisco:intersight:condHclStatuses | `index=* sourcetype=cisco:intersight:condHclStatuses \| Table source, ManagedObject.Moid, Status, Reason, HardwareStatus, SoftwareStatus, ComponentStatus`
| cisco:intersight:hyperflexClusters | `index=* sourcetype=cisco:intersight:hyperflexClusters \| dedup Moid \| rename Summary.ResiliencyInfo.State as State \| rename RegisteredDevice.ConnectionStatus as ConnectionStatus \| rename Encryption.State as SoftwareEncryption \|  eval SoftwareEncryption=case(isnull(SoftwareEncryption), "NONE", 1=1, replace(SoftwareEncryption, "_", " ")) \| Table source, Name, ConnectionStatus, State, HypervisorType, DeploymentType, DriveType, HxVersion, SoftwareEncryption, UtilizationPercentage`
| cisco:intersight:hyperflexNodes | `index=* sourcetype=cisco:intersight:hyperflexNodes \| dedup Moid \| rename "Drives{}.Usage" as DriveUsage \| rename "EmptySlotsList{}" as EmptySlots \| eval PersistenceDiskCount=mvcount(mvfilter(match(DriveUsage, "PERSISTENCE"))) \| eval OpenDiskSlots=mvcount(EmptySlots) \| table source, HostName, ModelNumber, SerialNumber, Role, Hypervisor, Status, PersistenceDiskCount, OpenDiskSlots`
| cisco:intersight:networkElementSummaries | `index=* sourcetype=cisco:intersight:networkElementSummaries \| dedup Moid \| rename AlarmSummary.Critical as Criticals \| rename AlarmSummary.Warning as Warnings \| table source, Name, Model, Serial, Version, ManagementMode, Criticals, Warnings`
| cisco:intersight:assetTargets | `index=* sourcetype=cisco:intersight:assetTargets \| dedup Moid \| table source, Name, Status, TargetType, ManagementLocation, ConnectorVersion`
| cisco:intersight:assetDeviceContractInformations | `index=* sourcetype=cisco:intersight:assetDeviceContractInformations StateContract=OK \| dedup Moid \| table source, DeviceType, PlatformType, DeviceId, ContractStatus, ServiceLevel, ServiceEndDate, WarrantyEndDate`

And just a few more for fun...

Here's an example where we summarize our compute inventory and demonstrate how we might extract information from the Model field of UCS Servers...

`index=* sourcetype=cisco:intersight:computePhysicalSummaries | dedup Moid | chart count by Model | rex field=Model "^(?<series>.*?)[-\d]" | rex field=Model "(?<model>\w{0,4}\d{3,4}\w?)" | rex field=Model "(?<generation>M\d)" | rex field=Model "M\d(?<variant>\w+)" | rex field=Model "(?<gen_variant>M\d\w*)" | table Model count series model generation variant gen_variant`

Here's an example where we join the computePhysicalSummaries and the networkElementSummaries into a combined table...

`index=* sourcetype=cisco:intersight:*Summaries | dedup Moid | eval version=coalesce(Version,Firmware) | rex field=SourceObjectType "compute\.(?<ComputeType>.*)" | eval Type=coalesce(ComputeType,SwitchType)| rename AlarmSummary.Critical as Criticals | rename AlarmSummary.Warning as Warnings | eval Health=case(Criticals >= 1,"Critical", Warnings >= 1,"Warning", 1=1, "Healthy") | rename RegisteredDevice.ConnectionStatus as Status | table source, Status, Health, Type, Name, Model, Serial, version`

Here's an example where we join the Advisory instances to our other inventory types to provide a detailed view...

`index=* sourcetype=cisco:intersight:tamAdvisoryInstances | dedup Moid | rename AffectedObjectType as type | rename Advisory.AdvisoryId as Id | rename Advisory.Severity.Level as Severity | join type=outer AffectedObjectMoid [search index=* (sourcetype="cisco:intersight:*Summaries" OR sourcetype=cisco:intersight:hyperflexClusters) | dedup Moid | rename Moid as AffectedObjectMoid | eval version=coalesce(Version,Firmware,HxVersion) | eval Model=coalesce(Model,DeploymentType+" "+DriveType)] | sort Severity | table source, Id, Severity, Name, type, Model, Serial, version`

Here's an example where we join the hyperflexCluster and hyperflexNodes to get an overview of the cluster that is slightly different than the one above, but it now includes counts of the converged nodes and compute-only nodes in the cluster...

`index=* sourcetype=cisco:intersight:hyperflexNodes | dedup Moid | chart count by Cluster.Moid, Role | join Cluster.Moid [search index=* sourcetype=cisco:intersight:hyperflexClusters | dedup Moid | rename Moid as Cluster.Moid ] | rename STORAGE as ConvergedNodes | rename COMPUTE as ComputeOnlyNodes | rename Summary.DataReplicationFactor as RF | eval StorageCapacity.TB=round(StorageCapacity/1024/1024/1024/1024, 1) | rename UtilizationPercentage as Used | eval Used=round(Used, 0)."%" | rename Summary.ResiliencyInfo.NodeFailuresTolerable as FTT | rename HypervisorType as Hypervisor | fields source, ClusterName, DeploymentType, DriveType, Hypervisor, RF, FTT, ConvergedNodes, ComputeOnlyNodes, StorageCapacity.TB, Used`

Here's an example where we join the computePhysicalSummaries with the condHclStatuses to see a more useful HCL compliance view...

`index=* sourcetype=cisco:intersight:computePhysicalSummaries | dedup Moid | rename OperPowerState as Power | join type=outer Moid [search index=* sourcetype=cisco:intersight:condHclStatuses | dedup Moid | Table ManagedObject.Moid, Status, Reason, HardwareStatus, SoftwareStatus, ComponentStatus | rename ManagedObject.Moid as Moid] | Table source, Power, Name, Model, Serial, Status, Reason, HardwareStatus, SoftwareStatus, ComponentStatus`

## Tags

Tags from Intersight are actually quite challenging in Splunk.  The default Splunk [spath](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Spath) decode of the JSON from Intersight will naturally create two multivalue fields... a `Tags{}.Key` field will have all of the keys and a `Tags{}.Value` field will have all of the values.  For example...

``` JSON
"Tags": [{"Key": "Intersight.LicenseTier", "Value": "Premier"}]
```

Becomes...

![Default Tag Decoding Example](images/default_spath.png)

So it seems very easy to search for Tags{}.Value=Premier if you wanted to find all of the things with a Premier Intersight.LicenseTier tag, but this is not safe.  The problem is that if there is also a tag named, for example, SLA that also has a value of Premier you'd match it.  In this default model, the Key and the Value have no relationship so using these fields is desceptively dangerous from a data integrity standpoint.

The solution that I've come up with using only native Splunk SPL is pretty complex but appears to be safe to use.  Here is an example...

`index=* sourcetype="cisco:intersight:*" | dedup Moid | rename Tags{}.Key as Key, Tags{}.Value as Value | eval zip=mvzip(Key,Value, ":") | mvexpand zip |rex field=zip mode=sed "s/$/\"}/g" |rex field=zip mode=sed "s/^/{\"Tags./g"| rex field=zip mode=sed "s/:/\": \"/g" | spath input=zip | transaction Moid | search Tags.Intersight.LicenseTier=Premier`

This approach returns all of the available tags as separate fields named `Tags.<Key>`.  This certainly seems much more convenient to use as we can now search the value of specific tags.

![Improved Tag Decoding Example](images/improved_tag.png)

An alternate (and perhaps better) approach is using the [array2object](https://splunkbase.splunk.com/app/6161/) application that is available from Splunkbase.

`index=* sourcetype="cisco:intersight:*" | dedup Moid | array2object path="Tags" key=Key value=Value | search Tags.Intersight.LicenseTier=Premier`

This approach provides the same end result to the search above with a much cleaner query syntax.

Read more about [array2object at SplunkBase](https://splunkbase.splunk.com/app/6161/).

## aaaAuditRecords

The default maximum size for an event in splunk is 10KB. It is possible (even likely) that you will have aaaAuditRecords that exceed this size. While it is possible to increase this value so that Splunk can ingest these very large events, a look at the data indicates that the contents of the Results field was always the culprit and often not particularly useful in these large records. If the event is less than 10KB in size, it passes through to Splunk with the Results JSON structure intact. If the event would have exceeded 10k, the Results field is replaced with the value `TRUNCATED` so that the base audit log data is still available in Splunk and able to be extracted properly. Such truncated records can be found using the following search.

`index=* sourcetype=cisco:intersight:aaaAuditRecords Request=TRUNCATED`

A further look at the data will indicate that most of these are actually related to routine processing of user preferences and filtering those out gives a much more valuable list of audit logs with truncated Results values.

`index=* sourcetype=cisco:intersight:aaaAuditRecords Request=TRUNCATED MoType!=iam.UserPreference | rename MoDisplayNames.Name{} as name |table source, Email, Event, MoType, name`

Everything else has been pruned of unhelpful data to the point that it shouldn't exceed the 10KB limit.  If anything does exceeed that 10KB, it will be logged...

`2022-07-15 12:45:20,726 INFO pid=12445 tid=MainThread file=base_modinput.py:log_warning:302 | EXAMPLE | Record exceeds 10k limit!  Moid=62b22eeb656c6c2d32394990 Type=hyperflex.Node`

## Troubleshooting

The most useful thing will be the log file from the Add-on. This will be called `ta_intersight_addon_intersight.log`. I suggest tailing this log if you're trying to figure out what is happening. Adjust the path to get to your Splunk directory as necessary...

`tail -f /opt/splunk/var/log/splunk/ta_intersight_addon_intersight.log`

It should also be available via the following search...

`index=_* sourcetype=taintersightaddon:log | rex field=_raw "\d+ (?<loglevel>\w+) pid.* \| (?<intersightinput>\w+) \| (?<logmessage>.*)" | search intersightinput=* | table _time, intersightinput, loglevel, logmessage`

Note that if you have multiple inputs (i.e. different Intersight accounts/appliances) configured in the Add-on, the log messages for all of the configured inputs will be interspersed. The Name from the 'Add Input' dialog above is used in the log to differentiate. In these logs, the name EXAMPLE was used.

A normal run without inventory might look like this...

``` LOG
2022-07-10 17:55:20,256 INFO pid=16028 tid=MainThread file=base_modinput.py:log_info:295 | EXAMPLE | Connected to Intersight SaaS account named EXAMPLE-LAB
2022-07-10 17:55:20,256 INFO pid=16028 tid=MainThread file=base_modinput.py:log_info:295 | EXAMPLE | Retrieving Audit Records
2022-07-10 17:55:20,345 INFO pid=16028 tid=MainThread file=splunk_rest_client.py:_request_handler:99 | Use HTTP connection pooling
2022-07-10 17:55:20,521 INFO pid=16028 tid=MainThread file=base_modinput.py:log_info:295 | EXAMPLE | Retrieving Alarm Records
2022-07-10 17:55:20,706 INFO pid=16028 tid=MainThread file=base_modinput.py:log_info:295 | EXAMPLE | Skipping Inventory records this inverval, checkpoint is now 4 of 10
2022-07-10 17:55:20,726 INFO pid=16028 tid=MainThread file=base_modinput.py:log_info:295 | EXAMPLE | FINISHED -- runtime was 0:00:00.593535
```

A normal run with inventory might look like this...

``` LOG
2022-07-10 17:54:20,479 INFO pid=15980 tid=MainThread file=base_modinput.py:log_info:295 | EXAMPLE | Starting input named EXAMPLE
2022-07-10 17:54:20,479 INFO pid=15980 tid=MainThread file=setup_util.py:log_info:117 | Proxy is not enabled!
2022-07-10 17:54:20,636 INFO pid=15980 tid=MainThread file=base_modinput.py:log_info:295 | EXAMPLE | Connected to Intersight SaaS account named EXAMPLE-LAB
2022-07-10 17:54:20,636 INFO pid=15980 tid=MainThread file=base_modinput.py:log_info:295 | EXAMPLE | Retrieving Audit Records
2022-07-10 17:54:20,708 INFO pid=15980 tid=MainThread file=splunk_rest_client.py:_request_handler:99 | Use HTTP connection pooling
2022-07-10 17:54:20,860 INFO pid=15980 tid=MainThread file=base_modinput.py:log_info:295 | EXAMPLE | Retrieving Alarm Records
2022-07-10 17:54:21,034 INFO pid=15980 tid=MainThread file=base_modinput.py:log_info:295 | EXAMPLE | Inventory is running this interval, checkpoint is now 0 of 10
2022-07-10 17:54:21,333 INFO pid=15980 tid=MainThread file=base_modinput.py:log_info:295 | EXAMPLE | Found 1 advisory records to retrieve
2022-07-10 17:54:21,484 INFO pid=15980 tid=MainThread file=base_modinput.py:log_info:295 | EXAMPLE | Found 1 compute inventory records to retrieve
2022-07-10 17:54:22,066 INFO pid=15980 tid=MainThread file=base_modinput.py:log_info:295 | EXAMPLE | Found 1 contract inventory records to retrieve
2022-07-10 17:54:22,288 INFO pid=15980 tid=MainThread file=base_modinput.py:log_info:295 | EXAMPLE | Found 0 network inventory records to retrieve
2022-07-10 17:54:22,404 INFO pid=15980 tid=MainThread file=base_modinput.py:log_info:295 | EXAMPLE | Found 2 target inventory records to retrieve
2022-07-10 17:54:22,623 INFO pid=15980 tid=MainThread file=base_modinput.py:log_info:295 | EXAMPLE | Found 1 Hyperflex cluster records to retrieve
2022-07-10 17:54:22,843 INFO pid=15980 tid=MainThread file=base_modinput.py:log_info:295 | EXAMPLE | Found 2 Hyperflex node records to retrieve
2022-07-10 17:54:22,923 INFO pid=15980 tid=MainThread file=base_modinput.py:log_info:295 | EXAMPLE | FINISHED -- runtime was 0:00:02.443714
```

A log message like this would indicate that Splunk can't connect to an Intersight on-premise appliance. Verify connectivity, DNS resolution, and if all else fails try un-checking the 'Validate SSL Certificate' checkbox on the Input.

``` log
2022-06-16 15:08:00,137 CRITICAL pid=12061 tid=MainThread file=base_modinput.py:log_critical:316 | EXAMPLE | Unable to connect to Intersight server at intersight.example.local
```

A log message like this indicates that you put something other than an FQDN as the Intersight Hostname value. The Add-on isn't asking for a URL in that field. Please provide just the fully-qualified domain name.

``` log
2022-06-16 15:07:53,922 CRITICAL pid=12052 tid=MainThread file=base_modinput.py:log_critical:316 | EXAMPLE | INVALID HOSTNAME... configured value is https://intersight.example.local/
```

A log message like this indicates that Splunk can't connect to the Intersight SaaS platform. Verify connectivity and DNS resolution.

``` log
2022-06-16 15:01:22,013 CRITICAL pid=12044 tid=MainThread file=base_modinput.py:log_critical:316 | EXAMPLE | Unable to connect to Intersight SaaS
```

The default logging level here will be `info` but additional detail can be enabled by changing the logging level on the configuration tab of the Add-on as seen below.

![Logging](images/logging.png)

## Known Issues

[See Issues on Github](https://github.com/jerewill-cisco/intersight-splunk-addon/issues/)

[1]: https://intersight.com/apidocs/apirefs/api/v1/aaa/AuditRecords/model/
[2]: https://intersight.com/apidocs/apirefs/api/v1/cond/Alarms/model/
[3]: https://intersight.com/apidocs/apirefs/api/v1/tam/AdvisoryInstances/model/
[4]: https://intersight.com/apidocs/apirefs/api/v1/compute/PhysicalSummaries/model/
[5]: https://intersight.com/apidocs/apirefs/api/v1/hyperflex/Clusters/model/
[6]: https://intersight.com/apidocs/apirefs/api/v1/network/ElementSummaries/model/
[7]: https://intersight.com/apidocs/apirefs/api/v1/asset/Targets/model/
[8]: https://intersight.com/apidocs/apirefs/api/v1/hyperflex/Nodes/model/
[9]: https://intersight.com/apidocs/apirefs/api/v1/cond/HclStatuses/model/
[10]: https://intersight.com/apidocs/apirefs/api/v1/asset/DeviceContractInformations/model/
