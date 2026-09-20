# Suricata Analysis — Dridex Detection

## Overview

As part of Task 1, I used Suricata to convert suspicious TLS certificate patterns identified during Wireshark analysis into custom IDS detection rules.

The rules were validated and tested by replaying the provided Dridex PCAP files through Suricata.

## Objective

- Identify suspicious TLS certificate patterns from Dridex PCAPs
- Convert the observed indicators into Suricata rules
- Validate the rules using Suricata configuration testing
- Replay the PCAPs and analyze the generated alerts
- Understand the limitations of indicator-based detection

## Tools Used

- Wireshark — Network traffic and TLS certificate analysis
- Suricata 7.0.3 — IDS-style offline detection
- PCAP — Captured network traffic
- Docker — Reproducible Suricata testing environment

## Detection Workflow

Dridex PCAP -> Wireshark Analysis -> Identify TLS Certificate Indicators -> Create Suricata Rules -> Validate Rules -> Replay PCAP -> Analyze Alerts
