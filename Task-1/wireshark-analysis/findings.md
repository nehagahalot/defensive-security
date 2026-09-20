# Wireshark Analysis — Dridex

## Overview

As part of Task 1, I analyzed five Dridex infection-traffic PCAP files using Wireshark.

The main goal was to understand the network communication, investigate suspicious TLS connections, and examine the certificates associated with those connections. The certificate information found during this analysis was later used to create Suricata detection rules.

The analysis was based on the Dridex Wireshark tutorial published by Palo Alto Networks Unit 42.

## Reference

- [Unit 42 — Wireshark Tutorial: Dridex Infection Traffic](https://unit42.paloaltonetworks.com/wireshark-tutorial-dridex-infection-traffic/)

### PCAPs Analyzed

2020-06-03-Dridex-infection-traffic.pcap
2020-09-24-Dridex-infection-traffic.pcap
2020-09-29-Dridex-infection-traffic.pcap
2020-10-05-Dridex-infection-traffic.pcap
2020-10-07-Dridex-infection-traffic.pcap

##Analysis Approach
I started by filtering the traffic for HTTP requests and TLS Client Hello Packets while excluding SSDP traffic.
(http.request or tls.handshake.type eq 1) and !(ssdp)
This reduced the amount of traffic that needed to be examined and helped identify TLS connections that required further investigation.
For certificate analysis, I used:
tls.handshake.type eq 11
TLS handshake type 11 corresponds to a certificate message.
I then combined this filter with the suspicious IP addresses identified during the investigation and inspected the certificate fields, particularly the Issuer, Organization, Organizational Unit and Common Name.

