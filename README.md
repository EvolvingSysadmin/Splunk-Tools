# Splunk Tools
Collection of Splunking Tools and Resources

__ThreatHunting Application__
  * [Splunk ThreatHunting App](https://splunkbase.splunk.com/app/4305/)
  * [ThreatHunting Resources](https://github.com/olafhartong/ThreatHunting)
  * [ThreatHunting Guide](https://www.linkedin.com/pulse/attckized-splunk-kirtar-oza-cissp-cisa-ms-/)


__SPL Examples__
    * [Basic SPL Examples](/docs/basic-spl.md)

https://medium.com/adarma-tech-blog/accelerating-forensic-triage-with-splunk-59f2112293a5

https://www.digitalforensics.com/blog/splunk-for-ir-and-forensics/

http://www.irongeek.com/i.php?page=videos/bsidescleveland2016/204-splunk-for-ir-and-forensics-tony-iacobelli



__Finding New Local Admin Accounts__
```
index=win_servers sourcetype=windows:security
| table EventCode
```

```
 index=win_servers sourcetype=windows:security EventCode=4720 OR (EventCode=4732 Administrators)
 | transaction Security_ID maxspan=180m
 | search EventCode=4720 EventCode=4732
 | table _time, EventCode, Security_ID, SamAccountName
```
Note: 
  4720: new user created
  4732: user added to security group

__Detecting Network and Port Scanning__
```
index=* sourcetype=firewall*
| stats dc(dest_port) as num_dest_port dc(dest_ip) as num_dest_ip by src_ip
| where num_dest_port >500 OR num_dest_ip > 500
```
Note: internal scanning > external scanning

__Interactive Logins from Service Accounts__
```
index=systems sourcetype=audit_logs user=svc_*
| table _time dest user
```
```
index=systems sourcetype=audit_logs user=svc_*
| stats earliest(_time) as earliest latest(_time) as latest by user, dest
| eval isOutlier=if(earliest >= relative_time(now(), "-1d@d"), 1, 0)
| convert ctime(earliest) ctime(latest)
| where isOutlier=1 
```

__Detecting Brute Force Attacks__  
```
index=* sourcetype=win*security user=* user!=""
| stats count(eval(action="success")) as successes count(eval(action="failure")) as failures by user, ComputerName
| where successes>0 AND failures>100
```

__Basic TOR Traffic Detection__
```
index=network sourcetype=firewall_data app=tor src_ip=*
| table _time src_ip src_port dest_ip dest_port bytes app
```

__Detecting Recurring Malware on Host__
```
index=* sourcetype=symantec:* 
| stats count range(_time) as TimeRange by Risk_Name, Computer_Name
| where TimeRange>1800
| eval TimeRange_In_Hours = round(TimeRange/3600,2), TimeRange_In_Days = round (TimeRange/3600/24,2)

```

__Checking for Windows Audit Log Tampering__
```
index=* (sourcetype=wineventlog AND (EventCode=1102 OR EventCode=1100)) OR (sourcetype=wineventlog AND EventCode=104)
| stats count by _time EventCode Message sourcetype host
```
Note: log change events=1102 (application log cleared), 1100 (event logging service shutdown), 104 (application log cleared)

__Finding Large Web Uploads__
```
index=* sourcetype=websense* 
| where bytes_out > 35000000
| table _time src_ip bytes* uri
```

__Identifying Web Users by Country__
```
index=web sourcetype=access_combined
| iplocation clientip
| stats dc(clientip) by Country
```
```
index=web sourcetype=access_combined
| iplocation clientip
| geostats dc(clientip) by Country
```

__Detecting Unencrypted Web Communications__
```
index=* sourcetype=firewall_data dest_port!=443 app=workday*
| table _time user app bytes* src_ip dest_ip dest_port
```

__Log Volume Trending__
```
| tstats prestats=t count WHERE index=apps by host _time span=1m
| timechart partial=f span=1m count by host limit=0
```

__Measuring Memory Utilization by Host__
```
index=main sourcetype=vmstat
| timechart max(memUsedPct) by host
```
```
index=main sourcetype=vmstat
| stats max(memUsedPct) as memused by host
| where memused>80
```
