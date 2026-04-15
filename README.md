# Azure Sentinel SIEM & Honeypot: Build Guide

Use this guide to build a **cloud-native SIEM lab in Microsoft Sentinel** that captures RDP brute-force activity, enriches failed logon events with geolocation data, and visualizes the results in a workbook dashboard.

## What You Will Build

1. A publicly reachable Windows honeypot VM in Azure.
2. Centralized security logging in Log Analytics Workspace (LAW).
3. Sentinel detection/enrichment pipeline for failed logons (Event ID 4625).
4. A workbook attack map and trend dashboard.

## Prerequisites

- Azure subscription with permission to create VMs, Log Analytics Workspace, and Sentinel resources.
- A resource group for the lab.
- `geoip-summarized.csv` (included in this repo under `references/`).

## Step-by-Step Lab Setup

### 1. Create the Honeypot VM

1. In Azure Portal, create a new virtual machine.
2. Select:
	- Image/OS: Windows 10 Enterprise
	- Size: Standard DC1s v3 (1 vCPU, 8 GiB RAM)
3. Set and save the VM local admin username/password.
4. After deployment, open the VM Network Security Group and create an inbound rule that allows all traffic (`Any` source, `Any` protocol, `Any` port, `Allow`).
5. RDP into the VM.
6. Turn off Windows Defender Firewall profiles from `wf.msc` to make the host intentionally exposed for the lab.

Note: This is intentionally insecure for learning purposes only. Do not reuse this configuration in production.

### 2. Generate and Verify Security Events

1. Before successful login, fail sign-in attempts 3 or more times with a fake username (for example, `employee`).
2. Log in successfully.
3. In Event Viewer, confirm Security Event ID `4625` entries exist.

### 3. Create Logging and Sentinel Resources

1. Create a Log Analytics Workspace (LAW).
2. Create a Microsoft Sentinel instance and connect it to the LAW.
3. In Sentinel Data Connectors, configure `Windows Security Events via AMA`.
4. Create/apply a Data Collection Rule (DCR) so security events from the VM are forwarded to LAW.

Quick validation query:

```kusto
SecurityEvent
| where EventId == 4625
| order by TimeGenerated desc
```

### 4. Import GeoIP Watchlist for Enrichment

1. In Sentinel, create a Watchlist from `references/geoip-summarized.csv`.
2. Use these watchlist values:
	- Name/Alias: `geoip`
	- Source type: Local file
	- Number of lines before row: `0`
	- Search key: `network`
3. Wait for import completion (approximately 54k rows).

### 5. Enrich Failed Logons with Geographic Data

Use this KQL to map failed logons to location data:

```kusto
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent;
WindowsEvents
| where EventID == 4625
| order by TimeGenerated desc
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname
| project FailureCount, AttackerIp = IpAddress, latitude, longitude, city = cityname, country = countryname,
friendly_location = strcat(cityname, " (", countryname, ")")
```

### 6. Build the Workbook Dashboard

1. In Sentinel, create a new Workbook.
2. Add a Query element and use the enriched KQL output.
3. Create at least these visuals:
	- Map: attacker origin by latitude/longitude
	- Username targeting chart: top attacked accounts
	- Time trend chart: failed logons over time

Reference workbook image:

![Global Authentication Failures & Geo-Threat Map](references/workbook.png)

## Companion Query Notes

See [workbook.md](workbook.md) for additional KQL used in this project.

## Cleanup

To avoid unnecessary costs after testing:

1. Stop/deallocate the VM.
2. Delete the VM and attached resources if you are done.
3. Remove Sentinel/LAW resources if no longer needed.

