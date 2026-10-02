# Sysmon

Sysmon produces the detailed process, network, and file telemetry that many of the [detections](searches/detections.md) here depend on. Getting it into Splunk is what makes those searches work.

## Install

Install the Sysinternals Sysmon service and driver, logging MD5 hashes, loaded modules, and network connections:

```text
sysmon.exe -i -h md5 -l -n
```

For production use, install with a tuned configuration file rather than the defaults.

## Configuration

A well-tuned config keeps the signal high and the volume manageable. The widely used starting point is the SwiftOnSecurity template:

* [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
* [sysmon-modular (Olaf Hartong)](https://github.com/olafhartong/sysmon-modular)

Apply or update a config:

```text
sysmon.exe -c sysmonconfig.xml
```

## Getting Sysmon into Splunk

* Install the [Splunk Add-on for Microsoft Sysmon](https://splunkbase.splunk.com/app/1914) to parse the events
* Sysmon logs to `Microsoft-Windows-Sysmon/Operational`; forward that channel with the Universal Forwarder
* Events arrive under `sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`, which is what the Sysmon-based searches here use

## Resources

* [Sysinternals (live)](https://live.sysinternals.com/)
* [Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
