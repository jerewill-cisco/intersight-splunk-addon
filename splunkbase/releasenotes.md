# Cisco Intersight Add-on for Splunk Release Notes

## 1.3.2 - TBD

- Improvements to the equipmentChassis code
- Some general refactoring of how the add-on pops attributes from the JSON

## 1.3.1 - 3 August 2022

- Found a serious bug in checkpointing that might cause Audit Logs and Alerts to never be retrieved for an input
- Additional pruning for cisco:intersight:computePhysicalSummaries and a few other items
- Added cisco:intersight:equipmentChassis to Compute inventory

## 1.3.0 - 28 July 2022

>New Inventory types are not automatically added to existing configurations.  Please review your input configurations after upgrading to enable the new options.

- Added new Inventory option for Intersight licensing
  - cisco:intersight:licenseAccountLicenseData
  - cisco:intersight:licenseLicenseInfos
- Added NetApp, Pure, and Hitachi to Inventory options with new sourcetypes for storage partner inventory
  - cisco:intersight:storageHitachiArrays
  - cisco:intersight:storageHitachiControllers
  - cisco:intersight:storageHitachiVolumes
  - cisco:intersight:storageNetAppClusters
  - cisco:intersight:storageNetAppNodes
  - cisco:intersight:storageNetAppStorageVms
  - cisco:intersight:storageNetAppVolumes
  - cisco:intersight:storagePureArrays
  - cisco:intersight:storagePureControllers
  - cisco:intersight:storagePureVolumes
- In addition, added cisco:intersight:convergedinfraPods to NetApp inventory to support FlexPod, the first Integrated System supported by Intersight
- Added two new sourcetypes to Hyperflex inventory
  - cisco:intersight:hyperflexStorageContainers
  - cisco:intersight:hyperflexLicenses to Hyperflex inventory
- Added a new \`intersight_tags\` macro for converting Tags into fields (see documentation on GitHub for example usage)
- Added field extractions to cisco:intersight:computePhysicalSummaries to attempt to decode the Model field into useful sub-bits (see the following fields: ModelGeneration, ModelSeries, ModelType, ModelVariant)
- Added field extraction to cisco:intersight:networkElementSummaries for the ModelGeneration field
- Set `DATETIME_CONFIG = NONE` in props.conf for all sourcetypes to prevent automatic datetime extraction
- Added some basic field extractions to the Add-on logs (sourcetype=taintersightaddon:log)

## 1.2.9 - 18 July 2022

- Fixed an issue that could cause the add-on to fail while processing an HX cluster that has very stale data
- Added RegisteredDevice to computePhysicalSummaries, networkElementSummaries, and hyperflexClusters
- Added Encryption to hyperflexClusters
- Pruned additional items from the Drives elements of the hyperflexNodes sourcetype to prevent records from exceeding 10k bytes
- Pruned additional items from the hyperflexClusters sourcetype to prevent records from exceeding 10k bytes
- Pruned a few items from all of the inventory types to improve consistency and relevance
- Updated example searches on Github to include RegisteredDevice.ConnectionStatus
- Added an additional log message to warn when records exceed the 10k size limit

## 1.2.8 - 11 July 2022

- Added splunk_em.py to facilitate local testing without a Splunk server
- General code cleanup and refactoring
- Better fixes for the issues that were worked around in 1.2.7

If you're wondering what general code cleanup means...

- converted all the messy strings into much nicer f-strings
- added a bunch of functions for code that was duplicated all over the place
- moved HCL queries inside of the compute inventory
- improved logging

## 1.2.7 - 29 June 2022

Worked around an issue that could cause the addon to fail if an Alarm or Audit Log event happen exactly at the second boundary and didn't leave any fraction of a second.  A more mathematically correct fix will have to wait for a future update.

Worked around an issue that could cause the add-on to fail if the compute HCL query encountered a record that was associated with a server that's no longer licensed for the HCL feature.  This, too, will get a more thorough fix at some point in the future.

## 1.2.6 - 27 June 2022

Fixed an issue that could cause the add-on to fail if the Intersight SaaS account did not have any servers licensed at Essentials or higher when either the Compute inventory (because of the HCL feature) or Advisories Inventory items were selected.

Fixed an issue that would cause the add-on to fail if Hyperflex inventory was selected and no Hyperflex clusters were present.

## 1.2.5 - 24 June 2022

- Added support for v3 API keys from Intersight.  Either v2 or v3 keys may be used now.
- Changed Inventory selection in the input from many checkboxes to a single multiple dropdown.
- Compute HCL status (sourcetype='cisco:intersight:condHclStatuses') data added as a part of compute inventory type.
- Contract Status (sourcetype='cisco:intersight:assetDeviceContractInformations') data added as a new inventory type.
- HTTP Proxy support added
- General code improvements

Unfortunately, the change from checkboxes to a multiple dropdown means that the input must be re-configured if you upgrade from version 1.1.0 to 1.2.0.

Proxy support was tested, but perhaps not as thoroughly as possible.  Please provide feedback if you have a problem.  Only HTTP proxy (and not SOCKS) is supported at this time.

Proxy support is configured at the Add-on level and not per-Input.  Click the `Configuration` tab at the top of the Add-on for this setting.  This means that on a given Splunk server, all Intersight inputs will share the same proxy configuration.

## 1.1.0 - 17 June 2022

- Initial public release
