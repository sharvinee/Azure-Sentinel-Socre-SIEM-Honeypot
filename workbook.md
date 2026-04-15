# Kusto Query Language (KQL) Analysis

Use this companion file to support the Sentinel workbook build. The queries below enrich failed logon events, summarize targeted usernames, and show attack trends for the final dashboard.

## 1. Geo-Threat Map Query (Log Enrichment)
Join failed logon events with the custom `geoip` watchlist so attacker IP addresses can be plotted on the workbook map.

```kusto
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent;
WindowsEvents 
| where EventID == 4625
| order by TimeGenerated desc
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname
| project FailureCount, AttackerIp = IpAddress, latitude, longitude, city = cityname, country = countryname,
friendly_location = strcat(cityname, " (", countryname, ")");
```

## 2. Most Targeted Usernames
Use this query to identify the accounts most frequently targeted by automated brute-force scripts.

```kusto
SecurityEvent
| where EventID == 4625
| summarize Count = count() by TargetAccount
| top 10 by Count
```

## 3. Trends & Forensics (Hourly Analysis)
Use this query to bin failed logons into 1-hour intervals and show the intensity and timing of attack waves.

```kusto
SecurityEvent
| where EventID == 4625
| summarize Attempts = count() by bin(TimeGenerated, 1h)
```