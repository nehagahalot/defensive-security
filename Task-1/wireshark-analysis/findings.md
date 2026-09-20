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
