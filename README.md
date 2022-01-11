# Splunk Tools

Collection of Splunking Tools and Resources

## Table of Contents

- [SPL Examples](#SPL-Examples)
- [Sysmon Monitoring](#Sysmon-Monitoring)
- [Splunk Hunting/IOCs](#Splunk-Hunting-&-IOCs)
- [Threat Intelligence Applications](#Threat-Intelligence-Applications)
- [Document Resources](#Document-Resources)
- [Online Resources](#Online-Resources)


## SPL Examples

### Find Windows Security Event Code Info

```
index=win_servers sourcetype=windows:security
| table EventCode
```

### Find New Local Admin Accounts

```
 index=win_servers sourcetype=windows:security EventCode=4720 OR (EventCode=4732 Administrators)
 | transaction Security_ID maxspan=180m
 | search EventCode=4720 EventCode=4732
 | table _time, EventCode, Security_ID, SamAccountName
```
Note: 
  - 4720: new user created
  - 4732: user added to security group
  - 4624: successful user login

### Detect Network and Port Scanning

```
index=* sourcetype=firewall*
| stats dc(dest_port) as num_dest_port dc(dest_ip) as num_dest_ip by src_ip
| where num_dest_port >500 OR num_dest_ip > 500
```
Note: internal scanning > external scanning

### Find Interactive Logins from Service Accounts

```
index=systems sourcetype=audit_logs user=svc_*
| table _time dest user
```

### Find Outlier Interactive Logins

```
index=systems sourcetype=audit_logs user=svc_*
| stats earliest(_time) as earliest latest(_time) as latest by user, dest
| eval isOutlier=if(earliest >= relative_time(now(), "-1d@d"), 1, 0)
| convert ctime(earliest) ctime(latest)
| where isOutlier=1 
```

### Detect Bruce Force Attacks

```
index=* sourcetype=win*security user=* user!=""
| stats count(eval(action="success")) as successes count(eval(action="failure")) as failures by user, ComputerName
| where successes>0 AND failures>100
```

### Basic TOR Detection

```
index=network sourcetype=firewall_data app=tor src_ip=*
| table _time src_ip src_port dest_ip dest_port bytes app
```

### Detect Recurring Malware on Host

```
index=* sourcetype=symantec:* 
| stats count range(_time) as TimeRange by Risk_Name, Computer_Name
| where TimeRange>1800
| eval TimeRange_In_Hours = round(TimeRange/3600,2), TimeRange_In_Days = round (TimeRange/3600/24,2)
```

### Detect Windows Audit Log Tampering

```
index=* (sourcetype=wineventlog AND (EventCode=1102 OR EventCode=1100)) OR (sourcetype=wineventlog AND EventCode=104)
| stats count by _time EventCode Message sourcetype host
```
Note: 
  - 1102: security log cleared
  - 1100: event logging service shutdown
  - 104: event log cleared

### Find Large Web Uploads

```
index=* sourcetype=websense* 
| where bytes_out > 35000000
| table _time src_ip bytes* uri
```

### List Web Users by Country

```
index=web sourcetype=access_combined
| iplocation clientip
| stats dc(clientip) by Country
```

### List Web Users by Country on Map

```
index=web sourcetype=access_combined
| iplocation clientip
| geostats dc(clientip) by Country
```

### Detect Unencrypted Web Communications

```
index=* sourcetype=firewall_data dest_port!=443 app=workday*
| table _time user app bytes* src_ip dest_ip dest_port
```

### Show Log Volume Trending

```
| tstats prestats=t count WHERE index=apps by host _time span=1m
| timechart partial=f span=1m count by host limit=0
```

### Measure Memory Utilization by Host Chart

```
index=main sourcetype=vmstat
| timechart max(memUsedPct) by host
```

### Show Hosts with High Memory Utilization

```
index=main sourcetype=vmstat
| stats max(memUsedPct) as memused by host
| where memused>80
```

## Sysmon Monitoring

### Install Sysinternals Sysmon Service Driver, Use MD4, Log Modules & Network Connections:

```
sysmon.exe -i -h md5 -l -n
```

### SysInternals

- [Live Sysinternals](https://live.sysinternals.com/)

### Sysmon Configuration File Template

- [sysmonconfig-export.xml](/docs/sysmonconfig-export.xml)
- [SwiftOnSecurity Sysmon Configuration File](https://github.com/SwiftOnSecurity/sysmon-config) 

## Splunk Hunting & IOCs

- Hashes
- IP Addresses
- Domain Names
- Mutex Names
- URL
- File Names
- File Path
- Email Addresses
- Usernames
- Passwords
- Registry Keys
- Registry Values
- Email Subject Lines
- TLS Certificate Serial Numbers
- Service Name
- Coin Address
- MAC Addresses
- Strings
- Geolocation
- DNS Anomolies
- Applications Using Wrong Ports
- Increased network usage
- Unusual privileged account activity
- HTML Response Sizes

## Threat Intelligence Applications

- [Splunk ThreatHunting App](https://splunkbase.splunk.com/app/4305/)
  - [ThreatHunting Resources](https://github.com/olafhartong/ThreatHunting)
  - [ThreatHunting Guide](https://www.linkedin.com/pulse/attckized-splunk-kirtar-oza-cissp-cisa-ms-/)
- [Splunk Enterprise Security](https://www.splunk.com/en_us/software/enterprise-security.html)
  - [Splunk Enterprise Security Guide](https://www.splunk.com/en_us/blog/security/threat-intel-and-splunk-enterprise-security-part-2-adding-local-intel-to-enterprise-security.html )
  - [Detect Sunburst Backdoor using Splunk Enterprise Security](https://www.splunk.com/en_us/blog/security/sunburst-backdoor-detections-in-splunk.html)
- [Splunk Security Essentials](https://splunkbase.splunk.com/app/3435/)
- [Dragos Threat Intelligence](https://splunkbase.splunk.com/app/5232/)

## Document Resources
- [Splunk Quick Reference Guide](/docs/splunk-quick-reference-guide.pdf)


## Online Resources

- [Windows Event Logs Defined](https://www.myeventlog.com/)
- [Windows Security Log Events](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/Default.aspx)
- [Windows Logging Cheat Sheets](https://www.malwarearchaeology.com/cheat-sheets)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [MITRE File Scanning](https://github.com/mitre/multiscanner)
- [ARTHIR](https://www.imfsecurity.com/arthir)
- [Splunk Lookups for IOCs](https://www.nextron-systems.com/2015/09/06/splunk-threat-intel-ioc-integration-via-lookups/)
- [Accelerating Forensic Triage with Splunk](https://medium.com/adarma-tech-blog/accelerating-forensic-triage-with-splunk-59f2112293a5)
- [Splunk for IR and Forensics 1](https://www.digitalforensics.com/blog/splunk-for-ir-and-forensics/)
  - [Splunk for IR and Forensics 2](http://www.irongeek.com/i.php?page=videos/bsidescleveland2016/204-splunk-for-ir-and-forensics-tony-iacobelli)
- [Windows Log Malicious Discover Log-MD](https://www.imfsecurity.com/free)
