# Cisco Intersight Add-on for Splunk

The Cisco Intersight Add-on for Splunk (TA-intersight-addon) provides a python-based scripted input to retrieve data from Cisco Intersight. SaaS, Connected Virtual Appliance, and Private Virtual Appliance deployments of Intersight are all supported.

The Add-on leverages the [Cisco Intersight RESTful API](https://intersight.com/apidocs/introduction/overview/) to retrieve various kinds of data. Multiple inputs for different Intersight accounts/appliances are configurable and each account/appliance can optionally retrieve the following data types. Events are in JSON format.

| Options | Intersight API | Splunk sourcetype |
| --- | --- | --- |
| AAA Audit Records | [aaa/AuditRecords][1] | cisco:intersight:aaaAuditRecords |
| Alarms | [cond/Alarms][2] | cisco:intersight:condAlarms |
| Advisories | [tam/AdvisoryInstances][3] | cisco:intersight:tamAdvisoryInstances |
| Compute Inventory | [compute/PhysicalSummaries][4] | cisco:intersight:computePhysicalSummaries |
| HX Cluster Inventory | [hyperflex/Clusters][5] | cisco:intersight:hyperflexClusters |
| HX Cluster Inventory | [hyperflex/Nodes][8] | cisco:intersight:hyperflexNodes |
| Network Inventory | [network/ElementSummaries][6] | cisco:intersight:networkElementSummaries |
| Target Inventory | [asset/Targets][7] | cisco:intersight:assetTargets |

[1]: https://intersight.com/apidocs/apirefs/api/v1/aaa/AuditRecords/model/
[2]: https://intersight.com/apidocs/apirefs/api/v1/cond/Alarms/model/
[3]: https://intersight.com/apidocs/apirefs/api/v1/tam/AdvisoryInstances/model/
[4]: https://intersight.com/apidocs/apirefs/api/v1/compute/PhysicalSummaries/model/
[5]: https://intersight.com/apidocs/apirefs/api/v1/hyperflex/Clusters/model/
[6]: https://intersight.com/apidocs/apirefs/api/v1/network/ElementSummaries/model/
[7]: https://intersight.com/apidocs/apirefs/api/v1/asset/Targets/model/
[8]: https://intersight.com/apidocs/apirefs/api/v1/hyperflex/Nodes/model/

Further documentation, sample searches, and known issues are all available at [the Github repository](https://github.com/jerewill-cisco/intersight-splunk-addon).

---
This Add-on is community developed and is not supported by Cisco Systems or the Cisco Technical Assistance Center (TAC).
