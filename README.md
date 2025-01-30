# Splunk Tools

Collection of Splunking Tools, SPL Code and Resources

![Splunk Logo](/splunk-logo.png)

## Table of Contents

- [SPL Examples](#SPL-Examples)
- [Splunk Hunting and IOCs](#Splunk-Hunting-and-IOCs)
- [Sysmon Monitoring](#Sysmon-Monitoring)
- [Threat Intelligence Applications](#Threat-Intelligence-Applications)
- [Document Resources](#Document-Resources)
- [Online Resources](#Online-Resources)

## SPL Examples

### List all Sourcetypes

```
index="botsv3" 
|  stats count by sourcetype
```

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

### Show Brute Forcing Attempts

```
sourcetype=stream:http dest=”<IP address receiving the request>” http_method=POST
```

```
sourcetype=stream:http <input IP or domain> http_method=POST
|stats count BY src, form_data
```

### Find Executable

```
index="botsv1" dest_ip="192.168.250.70" sourcetype="stream:http" "multipart/form-data"
```

### Show MD5 of Executable

```
index="botsv1" 3791.exe md5 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" CommandLine="3791.exe"
```

### Find Brute Force Password

```
sourcetype=stream:http <domain or IP> http_method=POST
|stats count BY src, form_data, timestamp
```

### Find Specific Password by Trial and Error

```
source=stream:http <domain or IP> http_method=POST clocks
| stats count BY src, form_data
```

### Find Correct Password
See if there are successful logins from another IP

```
index=botsv1 sourcetype=stream:http form_data=*username*passwd*
| stats count BY src, form_data, timestamp
```

### Find Average Character Length of Password Attempts

```
index="botsv1" sourcetype=stream:http form_data=*username*passwd*
| rex field=form_data "&passwd=(?<password>[\w\d]+)&"
| eval lenpword=len(password)
| stats avg(lenpword) as avglen
```

### Time Between Brute Force Password Found and Login

```
index="botsv1" sourcetype=stream:http form_data=*username*passwd*
| rex field=form_data "&passwd=(?<password>[\w\d]+)&"
| search password = "batman"
```

### Find Number of Passwords Used in Brute Force Attempt

```
index="botsv1" sourcetype=stream:http form_data=*username*passwd*
| rex field=form_data "&passwd=(?<password>[\w\d]+)&"
```

### Find IP for Hostname

```
index="botsv1" we8105desk
| stats count by src_ip
```

### See What Domains Malware Contacted

```
index="botsv1" src_ip="192.168.250.100" source="stream:dns" NOT query=*.local AND NOT query=*.arpa AND NOT query=*.microsoft.com AND query=*.*
| table _time, query
| sort by _time desc
```

### Find VBS Malware

```
index="botsv1" sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" *.vbs
| eval cmdlen=len(CommandLine)
| table _time,CommandLine, cmdlen
```

### Find USB

```
index="botsv1" sourcetype=winregistry friendlyname
```

### Find File Server Connections

```
index="botsv1" sourcetype="stream:smb" src_ip=192.168.250.100
| stats count by path
```

### Find Number of PDFs Encrypted on File Server

```
index="botsv1" .pdf 
| stats dc(Relative_Target_Name)
```

### Find Number of Encrypted .txt Files for a Specific User

```
index="botsv1" sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" .txt bob.smith TargetFilename="C:\\Users\\bob.smith.WAYNECORPINC\\Desktop\\*"
| stats dc(TargetFilename)
```

### Find Visited Site With Specific Keyword

```
index=botsv2 sourcetype="stream:http" src_ip="10.0.2.101" http_method=GET
| dedup site
| search *beer*
```

### Count Number of IP addresses that Accessed Domain

```
index=botsv2 "www.brewertalk.com"
| stats count by src_ip
| sort -count
| head 5
```

### Count of URI Paths Accessed by IP

```
index=botsv2 src_ip=45.77.65.211
| stats values(form_data) count by uri_path
```

### Searching for XSS 

```
index=botsv2 sourcetype="stream:http" "<script>" 
| dedup form_data
| table _time form_data src_ip
```

### Using Splunk URL Decode

```
index=botsv2 sourcetype="stream:http" "<script>" 
| dedup form_data 
| eval decoded=urldecode(form_data) 
| table _time decoded src_ip
```

### Search for XSS

```
Search for <script> html tags
```

```
index=botsv2 sourcetype="stream:http" "kevin" "<script>" 
```

### Search for CSRF Tokens

Read More: https://portswigger.net/web-security/csrf/tokens

### MB Conversion

```
index=botsv3 earliest=0 frothlywebcode "*.tar.gz" operation="REST.PUT.OBJECT" http_status=200 
| table object_size 
| eval mb=round(object_size/1024/1024,2)
```


## Splunk Hunting and IOCs
Search for changes related to the following items/IOCs during threat-hunting/incident response:

- Applications Using Wrong Ports
- Coin Address
- DNS Anomolies
- Domain Names
- Email Addresses
- Email Subject Lines
- File Names
- File Path
- Geolocation
- Hashes
- HTML Response Sizes
- Increased network usage
- IP Addresses
- MAC Addresses
- Mutex Names
- Passwords
- Registry Keys
- Registry Values
- Service Name
- Strings
- TLS Certificate Serial Numbers
- Unusual privileged account activity
- URL
- Usernames

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
- [Splunk Search Cheat Sheet](/docs/Splunk-Search-Cheatsheet.pdf)
- [Operationalizing Threat Intelligence Using Splunk Enterprise Security](/docs/operationalizing-threat-intelligence-using-splunk-enterprise-security.pdf)
- [Splunk IOCs: Indicators of Crap Presentation](/docs/SEC1111.pdf)
- [Windows LOG-MD ATT&CK Cheat Sheet](/docs/Windows_LOG-MD_ATT&CK_Cheat_Sheet_ver_Sept_2018.pdf)
- [Windows ATT&CK Logging Cheat Sheet](/docs/Windows+ATT&CK_Logging+Cheat+Sheet_ver_Sept_2018.pdf)
- [Windows Logging Cheat Sheet](/docs/Windows+Logging+Cheat+Sheet_ver_Feb_2019.pdf)
- [Windows Advanced Logging Cheat Sheet](/docs/Windows+Advanced+Logging+Cheat+Sheet_ver_Feb_2019_v1.2.pdf)
- [Windows File Auditing Cheat Sheet](/docs/Windows+File+Auditing+Cheat+Sheet+ver+Nov+2017.pdf)
- [Windows PowerShell Logging Cheat Sheet](/docs/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2018+v2.2.pdf)
- [Windows Registry Auditing Cheat Sheet](/docs/Windows+Registry+Auditing+Cheat+Sheet+ver+Aug+2019.pdf)
- [Windows Splunk Logging Cheat Sheet](/docs/Windows+Splunk+Logging+Cheat+Sheet+v2.22.pdf)
- [Windows Sysmon Logging Cheat Sheet](/docs/Windows+Sysmon+Logging+Cheat+Sheet_Jan_2020.pdf)

## Online Resources

- [RegEx 101](https://regex101.com/)
- [Mockaroo fake data generator](https://www.mockaroo.com/)
- [Crontab Guru for Cron Expressions](https://crontab.guru/)
- [whois](https://whois.domaintools.com/)
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
