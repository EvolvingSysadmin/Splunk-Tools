# Detections

Reusable detection searches for authentication, network, malware, log integrity, and operational monitoring.

## Authentication and Accounts

### New local admin accounts

Correlates a new account (4720) with its addition to a security group (4732) in the same window.

```spl
index=win_servers sourcetype=windows:security EventCode=4720 OR (EventCode=4732 Administrators)
| transaction Security_ID maxspan=180m
| search EventCode=4720 EventCode=4732
| table _time, EventCode, Security_ID, SamAccountName
```

Event IDs: 4720 new user created, 4732 user added to security group, 4624 successful logon.

### Interactive logins from service accounts

Service accounts (`svc_*`) should not log on interactively.

```spl
index=systems sourcetype=audit_logs user=svc_*
| table _time dest user
```

### Outlier interactive logins from service accounts

Flags service-account logins first seen in the last day.

```spl
index=systems sourcetype=audit_logs user=svc_*
| stats earliest(_time) as earliest latest(_time) as latest by user, dest
| eval isOutlier=if(earliest >= relative_time(now(), "-1d@d"), 1, 0)
| convert ctime(earliest) ctime(latest)
| where isOutlier=1
```

### Brute force attempts

Accounts with at least one success and more than 100 failures.

```spl
index=* sourcetype=win*security user=* user!=""
| stats count(eval(action="success")) as successes count(eval(action="failure")) as failures by user, ComputerName
| where successes>0 AND failures>100
```

## Network and Scanning

### Network and port scanning

One source touching many ports or hosts.

```spl
index=* sourcetype=firewall*
| stats dc(dest_port) as num_dest_port dc(dest_ip) as num_dest_ip by src_ip
| where num_dest_port >500 OR num_dest_ip > 500
```

Internal scanning is more concerning than external.

### Basic TOR detection

```spl
index=network sourcetype=firewall_data app=tor src_ip=*
| table _time src_ip src_port dest_ip dest_port bytes app
```

### Unencrypted communications to a sensitive app

Traffic to an app on a non-TLS port.

```spl
index=* sourcetype=firewall_data dest_port!=443 app=workday*
| table _time user app bytes* src_ip dest_ip dest_port
```

### Large web uploads

Possible exfiltration.

```spl
index=* sourcetype=websense*
| where bytes_out > 35000000
| table _time src_ip bytes* uri
```

### Web users by country

```spl
index=web sourcetype=access_combined
| iplocation clientip
| stats dc(clientip) by Country
```

### Web users by country on a map

```spl
index=web sourcetype=access_combined
| iplocation clientip
| geostats dc(clientip) by Country
```

## Malware and Log Integrity

### Recurring malware on a host

Malware seen repeatedly over a time range (same detection firing again and again).

```spl
index=* sourcetype=symantec:*
| stats count range(_time) as TimeRange by Risk_Name, Computer_Name
| where TimeRange>1800
| eval TimeRange_In_Hours = round(TimeRange/3600,2), TimeRange_In_Days = round (TimeRange/3600/24,2)
```

### Windows audit log tampering

Log clearing and audit service shutdown.

```spl
index=* (sourcetype=wineventlog AND (EventCode=1102 OR EventCode=1100)) OR (sourcetype=wineventlog AND EventCode=104)
| stats count by _time EventCode Message sourcetype host
```

Event IDs: 1102 security log cleared, 1100 event logging service shut down, 104 event log cleared.

### Domains contacted by a host

Strips common benign domains to surface the rest.

```spl
index="botsv1" src_ip="192.168.250.100" source="stream:dns" NOT query=*.local AND NOT query=*.arpa AND NOT query=*.microsoft.com AND query=*.*
| table _time, query
| sort by _time desc
```

### VBScript execution (Sysmon)

```spl
index="botsv1" sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" *.vbs
| eval cmdlen=len(CommandLine)
| table _time, CommandLine, cmdlen
```

### USB device insertion

```spl
index="botsv1" sourcetype=winregistry friendlyname
```

### Hash of an executable (Sysmon)

```spl
index="botsv1" 3791.exe md5 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" CommandLine="3791.exe"
```

## Operations and Performance

### List all sourcetypes in an index

```spl
index="botsv3"
| stats count by sourcetype
```

### Windows security event codes present

```spl
index=win_servers sourcetype=windows:security
| table EventCode
```

### Log volume trending

```spl
| tstats prestats=t count WHERE index=apps by host _time span=1m
| timechart partial=f span=1m count by host limit=0
```

### Memory utilization by host

```spl
index=main sourcetype=vmstat
| timechart max(memUsedPct) by host
```

### Hosts over 80% memory

```spl
index=main sourcetype=vmstat
| stats max(memUsedPct) as memused by host
| where memused>80
```

### Convert bytes to MB

```spl
index=botsv3 earliest=0 frothlywebcode "*.tar.gz" operation="REST.PUT.OBJECT" http_status=200
| table object_size
| eval mb=round(object_size/1024/1024,2)
```
