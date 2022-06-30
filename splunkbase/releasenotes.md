# Cisco Intersight Add-on for Splunk Release Notes

## 1.1.0

- Initial public release

## 1.2.5

- Added support for v3 API keys from Intersight.  Either v2 or v3 keys may be used now.
- Changed Inventory selection in the input from many checkboxes to a single multiple dropdown.
- Compute HCL status (sourcetype='cisco:intersight:condHclStatuses') data added as a part of compute inventory type.
- Contract Status (sourcetype='cisco:intersight:assetDeviceContractInformations') data added as a new inventory type.
- HTTP Proxy support added
- General code improvements

Unfortunately, the change from checkboxes to a mutliple dropdown means that the input must be re-configured if you upgrade from version 1.1.0 to 1.2.0.

Proxy support was tested, but perhaps not as thoroughly as possible.  Please provide feedback if you have a problem.  Only HTTP proxy (and not SOCKS) is supported at this time.

Proxy support is configured at the Add-on level and not per-Input.  Click the `Configuration` tab at the top of the Add-on for this setting.  This means that on a given Splunk server, all Intersight inputs will share the same proxy configuration.

## 1.2.6

Fixed an issue that could cause the add-on to fail if the Intersight SaaS account did not have any servers licensed at Essentials or higher when either the Compute inventory (because of the HCL feature) or Advisories Inventory items were selected.

Fixed an issue that would cause the add-on to fail if Hyperflex inventory was selected and no Hyperflex clusters were present.

## 1.2.7

Worked around an issue that could cause the addon to fail if an Alarm or Audit Log event happen exactly at the second boundary and didn't leave any fraction of a second.  A more mathematically correct fix will have to wait for a future update.

Worked around an issue that could cause the add-on to fail if the compute HCL query encountered a record that was associated with a server that's no longer licensed for the HCL feature.  This, too, will get a more thorough fix at some point in the future.
