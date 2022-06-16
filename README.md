# Intersight Add-on for Splunk

This project came about to fill a gap that I saw in the [Intersight](https://intersight.com/help/saas) ecosystem.  How can you get useful data from Intersight into Splunk?  Since Intersight uses a unique API authentication scheme, simple REST API inputs could not be used.

This Splunk [Add-On](https://docs.splunk.com/Splexicon:Addon) begins to solve this problem by providing inputs for a number of Intersight data types.

## Development Overview

I used the [Splunk Add-on Builder](https://splunkbase.splunk.com/app/2962/) to create this Add-on.  This approach provides a solid framework to build a python-based input.

To authenticate to Intersight, I integrated code from the [intersight-auth](https://github.com/cgascoig/intersight-auth) library while making some modifications for this use case.  I also had to bundle in some of it's dependencies, including... cffi, cryptography, pycparser, cffi.libs and _cffi_backend.  I added these libraries to Splunk Add-on Builder (for me, /opt/splunk/etc/apps/splunk_app_addon-builder/bin/ta_generator/resources_lib/aob_py3) manually to have it bundle them in the distibutable package for me.

From here, the bulk of the work is contained in [input_module_intersight.py](input_module_intersight.py) and the connectivity is done with simple usage of the Python Requests library.

## Distribution

This add-on is available from Splunkbase at [future URL].

## Deployment

First, you will need an API key from Intersight.  For now, only v2 API keys will work.  Hopefully an update to intersight-auth will allow me to enable v3 keys in the future.  Remember that when you create an API key, it will provide access as the currently logged-in user in the current role.  You probably don't want to give Splunk an Account Administrator role API key.

![Generate an API Key](images/generate_api_key.png)

Most of the functionality will work with an API key having the system defined Read-Only role.  But to get the Audit Logs while maintainig a least privilige access model, I would suggest that you create a custom role that includes the Read-Only and Audit Log Viewer privleges.  Login to Intersight using this role to create the API key.

![Least-Privilige Role](images/role.png)

Simply install the app and click on the Inputs tab.  Click the 'Create New Input' button to add an input for each Intersight account or appliance you wish use with Splunk.  Don't forget to scroll down!  If you have multiple appliances or SaaS accounts (or a mix of both), you can add each of them as a separate Intput on this page.  SaaS inputs will retrieve the account name from Intersight as the source field, while appliances will use the value from Intersight Hostname as the source field.

![Add Intersight Input](images/add_intersight.png)

## Fields on the Add Intersight dialog

- Name : This name is the name of the input.  It isn't used elsewhere and can be a friendly name for the Intersight account.
- Interval : This interval (in seconds) controls how often the input will retrieve data from Intersight.
- Index : The name of the Splunk index (which needs to already exist!) where the data should be stored.
- Intersight Hostname : This field should keep the default of 'www.intersight.com' for SaaS instances of Intersight.  For On-Premise Intersight Appliances (sometimes known as Connected Virtual Appliance or Private Virtual Appliance), set this field to the FQDN of the appliance.
- Validate SSL Certificate : This box should remain checked for SaaS instances of Intersight.  Sometimes an on-premise appliance will use a self-signed certificate that this Add-on will not know to trust or perhaps your network will have an inline security appliance that does SSL interception.  In any case, this setting allows us to ignore the validity of the SSL certificate.  See [troubleshooting] for more details on how to see that this is happening.
- API Key Id : This will be the public half of the API key from Intersight.
- API Secret Key : This will be the secret half of the API key from Intersight.  It will be in [PEM formatted binary data](https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail) and you can paste the entire key including the header and footer into this field.
- Enable AAA Audit Records : This checkbox enables the input for activity audit logs from Intersight.  The Read-Only role does not have access to these.  See Least-Privilige Role above.  Also, be aware that this input will not go back to the beginning of time and import all Audit records.    The input has a static configuration to import records that have a ModTime in the last two days at the initial run.
- Enable Alarms : This checkbox enables the input for alarms from Intersight.  Be aware that this input will not go back to the beginning of time and import all Alarms.  The input has a static configuration to import Alarms that have a ModTime in the last two days at the initial run.
- Inventory Interval : All of the 'Enable' checkboxes below this point don't need to be imported from Intersight at every interval in a typical environment.  This value selects how many intervals should occur between inports of these items.  A selection of `1` here will import them on every interval.  Perhaps if the Interval above is `60` seconds, then an Inventory Interval here of `300` will cause inventory and advisories to be imported a few times a day on every 300th run of this input.  This is a sensible way to reduce the repetitive input of data that doesn't chagne that often.
- Enable Advisories : This checkbox enables the retrieval of Advisories.
- Enable Compute Inventory : This checkbox enables the retrieval of compute (i.e. server) inventory.
- Enable HX Cluster Inventory : This checkbox enables the retrieval of Hyperflex Cluster inventory.
- Enable Network Inventory : This checkbox enables the retrieval of Network (i.e. Fabric Interconnects, Nexus Switches, and MDS switches) inventory
- Enable Target Inventory : This checkbox enables the retrieval of the target inventory.  This could include hardware, software, or cloud targets.

## The data from Intersight in Splunk

Each of the selectable options above maps to APIs in Intersight with unique sourcetypes in Splunk.

| Checkbox | Intersight API | Splunk sourcetype |
| --- | --- | --- |
| Enable AAA Audit Records | [aaa/AuditRecords][1] | cisco:intersight:aaaAuditRecords |
| Enable Alarms | [cond/Alarms][2] | cisco:intersight:condAlarms |
| Enable Advisories | [tam/AdvisoryInstances][3] | cisco:intersight:tamAdvisoryInstances |
| Enable Compute Inventory | [compute/PhysicalSummaries][4] | cisco:intersight:computePhysicalSummaries |
| Enable HX Cluster Inventory | [hyperflex/Clusters][5] | cisco:intersight:hyperflexClusters |
| Enable HX Cluster Inventory | [hyperflex/Nodes][8] | cisco:intersight:hyperflexNodes |
| Enable Network Inventory | [network/ElementSummaries][6] | cisco:intersight:networkElementSummaries |
| Enable Target Inventory | [asset/Targets][7] | cisco:intersight:assetTargets |

All of the data from this Add-on can be queried in Splunk using the following [SPL](https://docs.splunk.com/Splexicon:SPL):

`index=* sourcetype=cisco:intersight:*`

In many cases, this will retrieve duplicate records as alarms are updated or inventory is regularly re-imported.  The [dedup command](https://docs.splunk.com/Documentation/Splunk/8.2.6/SearchReference/Dedup) can be easily used to retrieve data without unwanted duplication.

`index=* sourcetype="cisco:intersight:computePhysicalSummaries" | dedup Moid`

The technique of using `| dedup Moid` is applicable to all sourcetypes except cisco:intersight:aaaAuditRecords and should be used in most circumstances.

You may also notice, if you are very famililar with the Intersight API, that there are a few nodes of JSON that are missing in Splunk that are present elsewhere.  This is due to some editorial pruning that is occuring in the Add-on.  There are some object references in the API results that simply don't serve any purpose in Splunk.  The Add-on is pruning these to improve the overall experience and optimize the amount of data that gets pushed to Splunk.

## More examples

One for each sourcetype...

| Splunk sourcetype | Example Search |
| --- | --- |
| cisco:intersight:aaaAuditRecords | `index=* sourcetype=cisco:intersight:aaaAuditRecords MoType!=iam.UserPreference \| rename MoType as Type \| rename MoDisplayNames.Name{} as Object \| eval Request=json_extract(_raw,"Request") \| table source, Email, Event, Type, Object, Request` |
| cisco:intersight:condAlarms | `index=* sourcetype=cisco:intersight:condAlarms \| dedup Moid \| search Severity != Cleared \| rename AffectedMoDisplayName as AffectedDevice \| table source, Name, AffectedDevice, Severity, Description` |
| cisco:intersight:tamAdvisoryInstances | `index=* sourcetype=cisco:intersight:tamAdvisoryInstances \| dedup Advisory.Moid \| rename Advisory.BaseScore as CVSSBaseScore \| rename Advisory.AdvisoryId as Id \| rename Advisory.ObjectType as Type \| rename Advisory.Name as Name \| rename Advisory.Severity.Level as Severity \| rename Advisory.CveIds{} as Attached_CVEs \| table source, Name, Id, Type, CVSSBaseScore, Severity, Attached_CVEs` |
| cisco:intersight:computePhysicalSummaries | `index=* sourcetype=cisco:intersight:computePhysicalSummaries \| dedup Moid \| rename NumCpuCoresEnabled as Cores \| rename TotalMemory as RAM \| eval RAM=RAM/1024 \| rename OperPowerState as Power \| rename AlarmSummary.Critical as Criticals \| rename AlarmSummary.Warning as Warnings \| table source, Power, Name, Model,Serial, Firmware, Cores, RAM, Criticals, Warnings`
| cisco:intersight:hyperflexClusters | `index=* sourcetype=cisco:intersight:hyperflexClusters \| dedup Moid \| rename Summary.ResiliencyInfo.State as State \| Table source,Name, State, HypervisorType,DeploymentType,DriveType,HxVersion,UtilizationPercentage`
| cisco:intersight:hyperflexNodes | `index=* sourcetype=cisco:intersight:hyperflexNodes \| dedup Moid \| rename "Drives{}.Usage" as DriveUsage \| rename "EmptySlotsList{}" as EmptySlots \| eval PersistenceDiskCount=mvcount(mvfilter(match(DriveUsage, "PERSISTENCE"))) \| eval OpenDiskSlots=mvcount(EmptySlots) \| table source, HostName, ModelNumber, SerialNumber, Role, Hypervisor, Status, PersistenceDiskCount, OpenDiskSlots`
| cisco:intersight:networkElementSummaries | `index=* sourcetype=cisco:intersight:networkElementSummaries \| dedup Moid \| rename AlarmSummary.Critical as Criticals \| rename AlarmSummary.Warning as Warnings \| table source, Name, Model, Serial, Version, ManagementMode, Criticals, Warnings`
| cisco:intersight:assetTargets | `index=* sourcetype=cisco:intersight:assetTargets \ dedup Moid \| table source, Name, Status, TargetType, ManagementLocation, ConnectorVersion`

And just a few more for fun...

Here's an example where we join the computePhyiscalSummaries and the networkElementSummaries into a combined table...

`index=* sourcetype="cisco:intersight:*Summaries" | dedup Moid | eval version=coalesce(Version,Firmware) | table source, Name, Model, Serial, version`

Here's an example where we join the Advisory instances to our other inventory types to provide a detailed view...

`index=* sourcetype=cisco:intersight:tamAdvisoryInstances | dedup Moid | rename AffectedObjectType as type | rename Advisory.AdvisoryId as Id | rename Advisory.Severity.Level as Severity | join type=outer AffectedObjectMoid [search index=* (sourcetype="cisco:intersight:*Summaries" OR sourcetype=cisco:intersight:hyperflexClusters) | dedup Moid | rename Moid as AffectedObjectMoid | eval version=coalesce(Version,Firmware,HxVersion)] | sort Severity | table source, Id, Severity, Name, type, Model, Serial, version`

Here's an example where we join the hyperflexCluster and hyperflexNodes to get an overview of the cluster that is slightly different than the one above, but it now includes counts of the converged nodes and compute-only nodes in the cluster...

`index=* sourcetype=cisco:intersight:hyperflexNodes | dedup Moid | chart count by Cluster.Moid, Role | join Cluster.Moid [search index=* sourcetype=cisco:intersight:hyperflexClusters | dedup Moid | rename Moid as Cluster.Moid ] | rename STORAGE as ConvergedNodes | rename COMPUTE as ComputeOnlyNodes | rename Summary.DataReplicationFactor as RF | eval StorageCapacity.TB=round(StorageCapacity/1024/1024/1024/1024, 1) | rename UtilizationPercentage as Used | eval Used=round(Used, 0)."%" | rename Summary.ResiliencyInfo.NodeFailuresTolerable as FTT | rename HypervisorType as Hypervisor | fields source, ClusterName, DeploymentType, DriveType, Hypervisor, RF, FTT, ConvergedNodes, ComputeOnlyNodes, StorageCapacity.TB, Used`

## A note about aaaAuditRecords

The default maximum size for an event in splunk is 10KB.  It is possible (even likley) that you will have aaaAuditRecords that exceed this size.  While it is possible to increase this value so that Splunk can ingest these very large events, a look at the data indicates that the contents of the Results field was always the culprit and often not particularly useful in these large records.  If the event is less than 10KB in size, it passes through to Splunk with the Results JSON structure intact.  If the event would have exceeded 10k, the Results field is replaced with the value `TRUNCATED` so that the base audit log data is still available in Splunk and able to be extracted properly.  Such truncated records can be found using the following search.

`index=* sourcetype=cisco:intersight:aaaAuditRecords Request=TRUNCATED`

A further look at the data will indicate that most of these are actually related to routine processing of user preferences and filtering those out gives a much more valuable list of audit logs with truncated Results values.

`index=* sourcetype=cisco:intersight:aaaAuditRecords Request=TRUNCATED MoType!=iam.UserPreference | rename MoDisplayNames.Name{} as name |table source, Email, Event, MoType, name`

[1]: https://intersight.com/apidocs/apirefs/api/v1/aaa/AuditRecords/get/
[2]: https://intersight.com/apidocs/apirefs/api/v1/cond/Alarms/get/
[3]: https://intersight.com/apidocs/apirefs/api/v1/tam/AdvisoryInstances/get/
[4]: https://intersight.com/apidocs/apirefs/api/v1/compute/PhysicalSummaries/get/
[5]: https://intersight.com/apidocs/apirefs/api/v1/hyperflex/Clusters/get/
[6]: https://intersight.com/apidocs/apirefs/api/v1/network/ElementSummaries/get/
[7]: https://intersight.com/apidocs/apirefs/api/v1/asset/Targets/get/
[8]: https://intersight.com/apidocs/apirefs/api/v1/hyperflex/Nodes/get/
