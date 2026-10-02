# Investigations (BOTS)

End-to-end walkthroughs against the public [Boss of the SOC](https://github.com/splunk/botsv3) datasets. Each is a chain of searches that follows one scenario, so it works as practice for the technique as much as a reference.

## Brute Force Password Investigation (BOTS v1)

Working a credential brute force against a web login, from detecting it to recovering the password and timing the successful login.

Find the brute forcing against the target:

```spl
sourcetype=stream:http dest="<IP address receiving the request>" http_method=POST
```

Group attempts by source and submitted credentials:

```spl
index=botsv1 sourcetype=stream:http form_data=*username*passwd*
| stats count BY src, form_data, timestamp
```

Extract the password field and measure the average attempt length:

```spl
index="botsv1" sourcetype=stream:http form_data=*username*passwd*
| rex field=form_data "&passwd=(?<password>[\w\d]+)&"
| eval lenpword=len(password)
| stats avg(lenpword) as avglen
```

Count the number of distinct passwords tried:

```spl
index="botsv1" sourcetype=stream:http form_data=*username*passwd*
| rex field=form_data "&passwd=(?<password>[\w\d]+)&"
```

Confirm the password that worked and when it was used:

```spl
index="botsv1" sourcetype=stream:http form_data=*username*passwd*
| rex field=form_data "&passwd=(?<password>[\w\d]+)&"
| search password = "batman"
```

Look for a successful login from a different IP to confirm account takeover:

```spl
index=botsv1 sourcetype=stream:http form_data=*username*passwd*
| stats count BY src, form_data, timestamp
```

## Ransomware / Host Compromise Investigation (BOTS v1)

Following a compromised host (`we8105desk`) through delivery, execution, and encryption of files.

Resolve the hostname to an IP:

```spl
index="botsv1" we8105desk
| stats count by src_ip
```

Find the file server shares the host touched:

```spl
index="botsv1" sourcetype="stream:smb" src_ip=192.168.250.100
| stats count by path
```

Count PDFs encrypted on the file server:

```spl
index="botsv1" .pdf
| stats dc(Relative_Target_Name)
```

Count encrypted `.txt` files for a specific user:

```spl
index="botsv1" sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" .txt bob.smith TargetFilename="C:\\Users\\bob.smith.WAYNECORPINC\\Desktop\\*"
| stats dc(TargetFilename)
```

The same investigation also uses the shared detections on the [Detections](detections.md) page: domains the host contacted, VBScript execution, USB insertion, and the hash of the dropped executable.
