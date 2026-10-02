# Web and HTTP Analysis

Searches against web server and HTTP stream data: injection, enumeration, uploads, and traffic analysis. Many use `sourcetype=stream:http` from Splunk Stream.

## Brute forcing attempts against a login

POST requests to a login endpoint, grouped by source and submitted form data.

```spl
sourcetype=stream:http <input IP or domain> http_method=POST
| stats count BY src, form_data
```

## File upload / executable transfer

Multipart form uploads, useful for spotting a dropped executable.

```spl
index="botsv1" dest_ip="192.168.250.70" sourcetype="stream:http" "multipart/form-data"
```

## Cross-site scripting (XSS)

Requests containing a `<script>` tag.

```spl
index=botsv2 sourcetype="stream:http" "<script>"
| dedup form_data
| table _time form_data src_ip
```

Decode the payload with `urldecode` to read it cleanly:

```spl
index=botsv2 sourcetype="stream:http" "<script>"
| dedup form_data
| eval decoded=urldecode(form_data)
| table _time decoded src_ip
```

Narrow to a specific actor or value:

```spl
index=botsv2 sourcetype="stream:http" "kevin" "<script>"
```

## CSRF tokens

Background on anti-CSRF tokens and how they are validated: [PortSwigger: CSRF tokens](https://portswigger.net/web-security/csrf/tokens).

## Visited site containing a keyword

```spl
index=botsv2 sourcetype="stream:http" src_ip="10.0.2.101" http_method=GET
| dedup site
| search *beer*
```

## Count of IPs that accessed a domain

```spl
index=botsv2 "www.brewertalk.com"
| stats count by src_ip
| sort -count
| head 5
```

## URI paths accessed by an IP

```spl
index=botsv2 src_ip=45.77.65.211
| stats values(form_data) count by uri_path
```
