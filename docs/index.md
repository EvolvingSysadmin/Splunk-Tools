# Splunk Tools

A working collection of Splunk SPL searches, detections, and threat-hunting references I use for security monitoring and investigations.

## Sections

| Section | What's Inside |
| :--- | :--- |
| [SPL Searches](searches/index.md) | Ready-to-adapt searches: detections, web and HTTP analysis, and investigation walkthroughs |
| [Threat Hunting and IOCs](hunting-and-iocs.md) | Indicator categories to pivot on during a hunt or incident |
| [Sysmon](sysmon.md) | Installing Sysmon and getting its data into Splunk |
| [Resources](resources.md) | Threat intelligence apps, references, and tools |

## Using These Searches

* Index names, sourcetypes, and field names in these searches reflect the data they were written against (including the public [Boss of the SOC](https://github.com/splunk/botsv3) datasets). Adjust them to your environment's data model.
* The [Investigations](searches/investigations.md) pages are walkthroughs against the BOTS datasets, so they double as a way to practice the technique end to end.
* This is a companion to my [Blue Team Toolkit](https://blueteam.ryanheavican.com); the detection logic there is written in both SPL and KQL.

The source is on [GitHub](https://github.com/EvolvingSysadmin/Splunk-Tools).
