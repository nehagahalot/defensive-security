# Wireshark Analysis — Dridex

## 1. Objective

The objective of this analysis was to investigate network traffic associated with the Dridex malware using Wireshark.

The analysis focused on identifying suspicious network activity, examining TLS certificates used during post-infection communication, identifying suspicious certificate issuer information, and understanding the characteristics that can be used to create Suricata detection rules.

The analysis was performed on five Dridex infection traffic PCAP files provided by Palo Alto Networks Unit 42.

---

## 2. Reference

The analysis was based on the Unit 42 Dridex Wireshark tutorial:

- Unit 42: Wireshark Tutorial: Dridex Infection Traffic
- PCAP source: Palo Alto Networks Unit 42 Dridex traffic repository

The PCAP files analyzed were:

1. `2020-06-03-Dridex-infection-traffic.pcap`
2. `2020-09-24-Dridex-infection-traffic.pcap`
3. `2020-09-29-Dridex-infection-traffic.pcap`
4. `2020-10-05-Dridex-infection-traffic.pcap`
5. `2020-10-07-Dridex-infection-traffic.pcap`

---

## 3. Initial Wireshark Filter

The following filter was used to identify HTTP requests and TLS Client Hello packets while excluding SSDP traffic:

`(http.request or tls.handshake.type eq 1) and !(ssdp)`

This helped narrow the traffic down to HTTP activity and TLS connections that required further investigation.

---

## 4. TLS Certificate Analysis

After identifying suspicious TLS connections, TLS certificate packets were investigated using the following type of filter:

`tls.handshake.type eq 11`

The filter was combined with suspicious IP addresses when investigating individual PCAP files.

TLS Certificate packets were examined to inspect the certificate Issuer information.

The certificate fields of interest included:

- Country
- State/Province
- Locality
- Organization
- Organizational Unit
- Common Name

The certificate issuer information was particularly useful because several Dridex-related connections contained unusual and apparently randomly generated certificate fields.

---

# 5. PCAP 1 — 2020-06-03

## Internal Host

`10.6.3.101`

## Suspicious IP Addresses

- `185.86.148.68` — TCP port 443
- `212.95.153.36` — TCP port 453

## Wireshark Certificate Filter

`tls.handshake.type eq 11 and (ip.addr eq 185.86.148.68 or ip.addr eq 212.95.153.36)`

## Certificate Findings

The certificate from `185.86.148.68` contained unusual issuer information:

- Country: `VU`
- Locality: `Port Vila`
- Organization: `Whensean Imegdtc SICAV`
- Organizational Unit: `6Tbuthinalq`
- Common Name: `1andfhtittbly.fan`

The certificate from `212.95.153.36` contained:

- Country: `AO`
- Locality: `Luanda`
- Organization: `Msorest KGaA`
- Organizational Unit: `aghat@yongd`
- Common Name: `arashrinwearc.Ourontizes.ly`

The issuer organization, organizational unit, and common name contained unusual/random-looking values.

## Wireshark Observation

The certificate information was inconsistent with what would normally be expected from a legitimate public-facing service.

The combination of a plausible country/locality pair with unusual issuer fields was considered suspicious.

---

# 6. PCAP 2 — 2020-09-24

## Internal Host

`10.9.24.101`

## Initial Network Observations

HTTP requests included traffic to:

`192.185.57.242/app.php`

TLS connections to multiple external IP addresses were also observed.

Some certificates belonged to legitimate Microsoft infrastructure. For example, certificates associated with:

- `204.79.197.200`
- `96.6.230.82`

contained Microsoft-related issuer information.

This provided a useful comparison between normal TLS certificates and the suspicious certificates.

## Suspicious IP Addresses

- `151.236.219.181`
- `62.98.109.30`

## Wireshark Certificate Filter

`tls.handshake.type eq 11 and (ip.addr eq 151.236.219.181 or ip.addr eq 62.98.109.30)`

## Suspicious Certificate — 151.236.219.181

Issuer information included:

- Country: `IL`
- Locality: `Tel Aviv`
- Organization: `Wemadd Hixchac GmBH`
- Organizational Unit: `moasn@emanc`
- Common Name: `heardbellith.Icanwepeh.nagoya`

The organization and other issuer fields appeared unusual and randomly generated.

## Suspicious Certificate — 62.98.109.30

Issuer information included:

- Country: `SS`
- Locality: `Khartoum`
- Organization: `Hedanpr S.p.a.`
- Organizational Unit: `psprponounst.aquarelle`

## Observation

The presence of legitimate Microsoft certificates in the same traffic provided a useful baseline for comparison.

The suspicious certificates had unusual issuer organizations and other randomly appearing certificate fields.

---

# 7. PCAP 3 — 2020-09-29

## Internal Host

`10.9.29.101`

## Suspicious IP Addresses

- `67.79.105.174`
- `144.202.31.138`

## Wireshark Certificate Filter

`tls.handshake.type eq 11 and (ip.addr eq 67.79.105.174 or ip.addr eq 144.202.31.138)`

## Certificate Findings

The certificate associated with `67.79.105.174` contained:

- Country: `MN`
- Locality: `Ulaanbaatar`
- Organization: `Massol SE`

The certificate associated with `144.202.31.138` contained:

- Country: `SS`
- Locality: `Khartoum`
- Organization: `Hedanpr S.p.a.`

The `Hedanpr S.p.a.` issuer pattern was also observed in PCAP 2.

## Observation

The recurring unusual issuer information across different PCAPs strengthened the observation that certificate issuer data could be useful for identifying the analyzed Dridex traffic.

---

# 8. PCAP 4 — 2020-10-05

## Internal Host

`10.10.5.101`

## Suspicious IP Addresses

- `85.114.134.25`
- `85.211.162.44`

## Wireshark Certificate Filter

`tls.handshake.type eq 11 and (ip.addr eq 85.114.134.25 or ip.addr eq 85.211.162.44)`

## Certificate Findings

The certificate associated with `85.114.134.25` contained:

- Country: `NZ`
- Locality: `Wellington`
- Organization: `Lling Lovisq NL`
- Organizational Unit: `Punddtln`

The certificate associated with `85.211.162.44` contained:

- Country: `MY`
- Locality: `Kuala Lumpur`
- Organization: `Ointavi Tagate Unltd.`
- Common Name: `Ateei7thapom.statonrc.loan`

## Additional Observation

TLS 1.0 was observed on one of the connections.

However, TLS version alone was not considered a reliable Dridex detection indicator because an old TLS version is not unique to Dridex.

The suspicious certificate issuer information was considered more useful for this analysis.

---

# 9. PCAP 5 — 2020-10-07

## Internal Host

`10.10.7.101`

## Suspicious IP Addresses

- `177.87.70.3`
- `188.250.8.142`

## Wireshark Certificate Filter

`tls.handshake.type eq 11 and (ip.addr eq 177.87.70.3 or ip.addr eq 188.250.8.142)`

## Certificate Findings

The certificate associated with `177.87.70.3` contained:

- Country: `BS`
- Locality: `Nassau`
- Organization: `Mesureder S.p.a.`

The certificate associated with `188.250.8.142` contained:

- Country: `UA`
- Organization: `Icccodiso Icloneedb Oyj`
- Organizational Unit: `4Zenyfea`
- Common Name: `rebydustat.tci`

## Observation

The issuer organization and other certificate fields again showed unusual/random-looking values.

---

# 10. Common Pattern Observed

Across the five PCAP files, suspicious Dridex-related TLS connections showed several common characteristics.

### Certificate Issuer Characteristics

The suspicious certificates frequently contained:

- Unusual organization names
- Random-looking organizational units
- Random-looking common names
- Unusual combinations of certificate fields
- Country and locality combinations that appeared plausible, while other fields appeared abnormal

Examples of suspicious issuer organizations observed included:

- `Whensean Imegdtc SICAV`
- `Msorest KGaA`
- `Wemadd Hixchac GmBH`
- `Hedanpr S.p.a.`
- `Massol SE`
- `Lling Lovisq NL`
- `Ointavi Tagate Unltd.`
- `Mesureder S.p.a.`
- `Icccodiso Icloneedb Oyj`

A recurring example was:

`C=SS, L=Khartoum, O=Hedanpr S.p.a.`

which appeared in more than one PCAP.

---

# 11. Important Detection Consideration

Country and locality values alone should not be treated as malicious indicators.

For example, a legitimate certificate can contain a real country and capital city.

The suspicious characteristic in these PCAPs was the combination of:

- TLS communication to suspicious infrastructure
- Unusual certificate issuer information
- Random-looking organization, OU, or CN values
- Certificate characteristics consistent with the Dridex traffic described in the Unit 42 analysis

Therefore, the certificate issuer strings used in the Suricata rules should be considered **PCAP-specific indicators derived from the analyzed samples**, rather than universal indicators that can detect every Dridex infection.

---

# 12. Key Wireshark Concepts Learned

During the analysis, the following concepts were studied:

- PCAP files
- Packets and frames
- TCP communication
- HTTP requests
- TLS handshakes
- TLS Client Hello
- TLS Server Hello
- TLS certificates
- Certificate Issuer
- Certificate fields
- Source and destination IP addresses
- TCP ports
- Wireshark display filters
- Identifying suspicious network traffic
- Comparing suspicious certificates with legitimate certificates

---

# 13. Conclusion

The Wireshark analysis demonstrated how network traffic can be investigated to identify suspicious malware-related communication.

The most useful observation in these Dridex samples was the unusual TLS certificate issuer information associated with suspicious external connections.

The analysis of five PCAP files provided the indicators that were later used to create and test Suricata detection rules.

The next stage of the task was to convert these observations into Suricata signatures and replay the PCAP files to verify whether the signatures generated alerts.