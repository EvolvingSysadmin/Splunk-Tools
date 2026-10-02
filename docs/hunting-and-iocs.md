# Threat Hunting and IOCs

Indicator categories to pivot on during threat hunting and incident response. For each, search for recent changes or anomalies and correlate across data sources.

## Indicator Categories

| Category | Examples to Pivot On |
| :--- | :--- |
| Network | IP addresses, domain names, URLs, MAC addresses, applications using the wrong ports, increased network usage |
| Files | File names, file paths, hashes, mutex names |
| Identity | Usernames, passwords, unusual privileged account activity |
| Email | Email addresses, subject lines |
| Web | HTML response sizes, URLs |
| System | Registry keys, registry values, service names, strings |
| Crypto | Coin addresses, TLS certificate serial numbers |
| Other | DNS anomalies, geolocation |

## How I Use It

I start from whatever indicator the lead gives me (an IP, a hash, a username) and pivot outward across the data sources in the [Detections](searches/detections.md) and [Web Analysis](searches/web-analysis.md) pages. DNS anomalies and applications using non-standard ports are two of the most productive starting points when there is no obvious lead.

## Related

* [Detections](searches/detections.md)
* [Investigations (BOTS)](searches/investigations.md)
* [MITRE ATT&CK](https://attack.mitre.org/)
