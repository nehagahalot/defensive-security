# Suricata Analysis — Dridex Detection

## 1. Objective

The objective of this part of Task 1 was to convert the suspicious TLS certificate patterns identified during Wireshark analysis into Suricata detection signatures.

The signatures were then validated and tested by replaying the original Dridex PCAP files through Suricata.

---

## 2. What is Suricata?

Suricata is an open-source network security engine that can be used as:

- Intrusion Detection System (IDS)
- Intrusion Prevention System (IPS)
- Network Security Monitoring (NSM) engine

For this task, Suricata was used in **IDS-style offline PCAP analysis**.

Instead of monitoring live network traffic, previously captured PCAP files were replayed through Suricata to determine whether the custom rules generated alerts.

---

## 3. Why Suricata was Used

Wireshark was used to investigate the traffic and identify suspicious characteristics.

Suricata was then used to turn those observations into automated detection rules.

The workflow was:

```text
Dridex PCAP
     ↓
Wireshark analysis
     ↓
Identify suspicious TLS certificate patterns
     ↓
Create Suricata rules
     ↓
Validate rules
     ↓
Replay PCAP through Suricata
     ↓
Check generated alerts
```

---

## 4. Suricata Version

Version used:

`7.0.3 RELEASE`

The version was verified using the Suricata command-line interface.

---

# 5. Suricata Rule Structure

A basic Suricata rule follows this structure:

```text
action protocol source_ip source_port -> destination_ip destination_port (options)
```

Example:

```text
alert tls any any -> any any (msg:"Example"; tls.cert_issuer; content:"Example"; sid:1000001; rev:1;)
```

### Important Rule Components

| Component | Meaning |
|---|---|
| `alert` | Generate an alert when the rule matches |
| `tls` | Inspect TLS traffic |
| `any any` | Match any source IP and source port |
| `->` | Direction of traffic |
| `tls.cert_issuer` | Select the TLS certificate Issuer field for inspection |
| `content` | Search for a specific string |
| `sid` | Unique Suricata Signature ID |
| `rev` | Rule revision number |
| `msg` | Description displayed when the rule triggers |

---

# 6. Why `tls.cert_issuer` Was Used

During the Wireshark analysis, suspicious Dridex traffic was associated with unusual TLS certificate issuer information.

Suricata provides the `tls.cert_issuer` keyword to inspect the Issuer field of a TLS certificate.

The rules therefore use:

```text
tls.cert_issuer;
```

followed by:

```text
content:"<suspicious issuer>";
```

This means that Suricata checks whether the specified string appears in the TLS certificate's Issuer field.

---

# 7. Rule 1 — PCAP 1

### Suspicious issuer

`Whensean Imegdtc SICAV`

### Rule

alert tls any any -> any any (msg:"DRIDEX PCAP1 Suspicious TLS Certificate - Whensean Imegdtc SICAV"; tls.cert_issuer; content:"Whensean Imegdtc SICAV"; sid:1000003; rev:1;)
```

### SID

1000003

### Purpose

This rule detects TLS certificates containing the observed suspicious issuer organization from PCAP 1.

---

# 8. Rule 2 — PCAP 2

### Suspicious issuer

Wemadd Hixchac GmBH

### Rule
alert tls any any -> any any (msg:"DRIDEX Suspicious TLS Certificate - Wemadd Hixchac GmBH"; tls.cert_issuer; content:"Wemadd Hixchac GmBH"; sid:1000002; rev:1;)

### SID

1000002

### Purpose

This rule detects TLS certificates containing the suspicious issuer organization observed in PCAP 2.

---

# 9. Rule 3 — PCAP 3

### Suspicious issuer

Massol SE

### Rule

text
alert tls any any -> any any (msg:"DRIDEX PCAP3 Suspicious TLS Certificate - Massol SE"; tls.cert_issuer; content:"Massol SE"; sid:1000004; rev:1;)

### SID

1000004

### Purpose

This rule detects the suspicious certificate issuer observed in PCAP 3.

---

# 10. Rule 4 — PCAP 4

### Suspicious issuer

Lling Lovisq NL

### Rule

alert tls any any -> any any (msg:"DRIDEX PCAP4 Suspicious TLS Certificate - Lling Lovisq NL"; tls.cert_issuer; content:"Lling Lovisq NL"; sid:1000005; rev:1;)

### SID
1000005

### Purpose

This rule detects the suspicious certificate issuer observed in PCAP 4.

---

# 11. Rule 5 — PCAP 5

### Suspicious issuer

`Mesureder S.p.a.`

### Rule

alert tls any any -> any any (msg:"DRIDEX PCAP5 Suspicious TLS Certificate - Mesureder S.p.a."; tls.cert_issuer; content:"Mesureder S.p.a."; sid:1000006; rev:1;)

### SID

1000006

### Purpose

This rule detects the suspicious certificate issuer observed in PCAP 5.

---

# 12. Rule Validation

Before replaying the PCAP files, each custom rule was checked using Suricata's configuration testing mode.

The command used was:
sudo suricata -T -S <rule-file>

### Meaning

- `sudo` — runs Suricata with the required privileges
- `suricata` — starts the Suricata program
- `-T` — tests the configuration and rules without processing traffic
- `-S` — loads the specified rule file exclusively
- `<rule-file>` — path to the custom rule file

A successful validation produced:


Configuration provided was successfully loaded. Exiting.


This confirmed that the custom Suricata rules were syntactically valid.

---

# 13. PCAP Replay

After validation, the PCAP files were replayed using Suricata's offline PCAP mode.

The basic command was:


sudo suricata -r <pcap-file> -S <rule-file> -l <output-directory>


### Meaning

- `-r` — read and analyze packets from a PCAP file
- `-S` — load the specified custom rule file
- `-l` — specify the directory where Suricata writes its logs
- `<pcap-file>` — input network capture
- `<rule-file>` — custom detection signature
- `<output-directory>` — location for Suricata output files

---

# 14. Detection Results

| PCAP | Detection Indicator | SID | Alerts |
|---|---|---:|---:|
| PCAP 1 | `Whensean Imegdtc SICAV` | 1000003 | 4 |
| PCAP 2 | `Wemadd Hixchac GmBH` | 1000002 | 1 |
| PCAP 3 | `Massol SE` | 1000004 | 1 |
| PCAP 4 | `Lling Lovisq NL` | 1000005 | 4 |
| PCAP 5 | `Mesureder S.p.a.` | 1000006 | 1 |

All five custom rules successfully generated alerts when their corresponding PCAP files were replayed.

---

# 15. Example Alert

One of the generated alerts was:

[1:1000002:1] DRIDEX Suspicious TLS Certificate - Wemadd Hixchac GmBH


The alert showed communication involving:


151.236.219.181:443 -> 10.9.24.101:60513


This demonstrated that the Suricata rule successfully matched the suspicious TLS certificate observed during the Wireshark investigation.

---

# 16. Initial Broad Test

Before creating the Dridex-specific rules, a broad test rule was created:


alert tls any any -> any any (msg:"TEST TLS certificate issuer"; tls.cert_issuer; content:"Microsoft Corporation"; sid:1000001; rev:1;)


This rule was tested against PCAP 2.

It generated multiple alerts, including traffic associated with legitimate Microsoft infrastructure.

This demonstrated an important detection-engineering concept:

A rule can technically work but still be too broad and generate false positives.

Therefore, the final rules were based on the more specific suspicious certificate issuer strings identified during the Wireshark investigation.

---

# 17. Detection Limitations

The rules created for this task are based on certificate issuer strings observed in the provided Dridex sample PCAPs.

They should therefore be treated as **sample-specific indicators** rather than universal Dridex signatures.

A threat actor can change:

- Certificate
- Certificate issuer
- Domain
- IP address
- Infrastructure
- Other network characteristics

Therefore, relying on a single certificate issuer string may not detect every Dridex infection.

A production detection strategy should combine multiple indicators and behavioral characteristics.

---

# 18. Key Concepts Learned

Through this stage of the task, the following concepts were studied:

- Suricata
- IDS
- IPS
- Network Security Monitoring
- Suricata rule syntax
- Rule actions
- TLS inspection
- TLS certificate issuer inspection
- Content matching
- Signature IDs
- Rule revisions
- Rule validation
- Offline PCAP analysis
- Suricata logs
- Alerts
- False positives
- Indicator-based detection
- Detection limitations

---

# 19. Conclusion

Wireshark was used to identify suspicious TLS certificate characteristics in the Dridex PCAP files.

These observations were converted into Suricata signatures using the `tls.cert_issuer` and `content` keywords.

The rules were successfully validated and tested against all five provided PCAP files.

The testing demonstrated how network traffic investigation can be converted into automated IDS detection.

The next stage is to document and reproduce the Suricata testing environment using Docker.
