# Details

The Add-on leverages the [Cisco Intersight RESTful API](https://intersight.com/apidocs/introduction/overview/) to retrieve various kinds of data. Multiple inputs for different Intersight accounts/appliances are configurable and each account/appliance can optionally retrieve the following data types. Events are in JSON format.

| Options | Intersight API | Splunk sourcetype |
| --- | --- | --- |
| Advisories | [tam/AdvisoryInstances][3] | cisco:intersight:tamAdvisoryInstances |
| Compute | [compute/PhysicalSummaries][4] | cisco:intersight:computePhysicalSummaries |
| Compute | [cond/HclStatuses][9] | cisco:intersight:condHclStatuses |
| Contract | [asset/DeviceContractStatusInformations][10] | cisco:intersight:assetDeviceContractInformations |
| Hyperflex | [hyperflex/Clusters][5] | cisco:intersight:hyperflexClusters |
| Hyperflex | [hyperflex/Nodes][8] | cisco:intersight:hyperflexNodes |
| Hyperflex | [hyperflex/StorageContainers][16] | cisco:intersight:hyperflexStorageContainers |
| NetApp | [storage/NetAppClusters][11] | cisco:intersight:storageNetAppClusters |
| NetApp | [storage/NetAppNodes][12] | cisco:intersight:storageNetAppNodes |
| NetApp | [storage/NetAppVolumes][17] | cisco:intersight:storageNetAppVolumes |
| NetApp | [convergedinfra/Pods][13] | cisco:intersight:convergedinfraPods |
| Network | [network/ElementSummaries][6] | cisco:intersight:networkElementSummaries |
| Pure | [storage/PureArrays][14] | cisco:intersight:storagePureArrays |
| Pure | [storage/PureControllers][15] | cisco:intersight:storagePureControllers |
| Pure | [storage/PureVolumes][18] | cisco:intersight:storagePureVolumes |
| Target | [asset/Targets][7] | cisco:intersight:assetTargets |

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
[11]: https://intersight.com/apidocs/apirefs/api/v1/storage/NetAppClusters/model
[12]: https://intersight.com/apidocs/apirefs/api/v1/storage/NetAppNodes/model
[13]: https://intersight.com/apidocs/apirefs/api/v1/convergedinfra/Pods/model
[14]: https://intersight.com/apidocs/apirefs/api/v1/storage/PureArrays/model/
[15]: https://intersight.com/apidocs/apirefs/api/v1/storage/PureControllers/model/
[16]: https://intersight.com/apidocs/apirefs/api/v1/hyperflex/StorageContainers/model/
[17]: https://intersight.com/apidocs/apirefs/api/v1/storage/NetAppVolumes/model/
[18]: https://intersight.com/apidocs/apirefs/api/v1/storage/PureVolumes/model/

Further documentation, sample searches, and known issues are all available at [the Github repository](https://github.com/jerewill-cisco/intersight-splunk-addon).

---

This Add-on is community developed and is not supported by Cisco Systems or the Cisco Technical Assistance Center (TAC).
