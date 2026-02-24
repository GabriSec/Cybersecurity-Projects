# ELK Stack SIEM — Home Lab

A full SIEM pipeline built from scratch on a local Ubuntu VM using the Elastic Stack. The goal was to go through the entire setup end to end and end up with real system data flowing through the pipeline — not just installed services, but something actually working.

## What's in the stack

| Component | Role |
|-----------|------|
| **Elasticsearch** | Stores and indexes all events |
| **Kibana** | Web UI for searching and visualising data |
| **Logstash** | Data pipeline — receives from Beats, forwards to Elasticsearch |
| **Auditbeat** | Collects system-level security events (logins, processes, sockets, users) |
| **Nginx** | Reverse proxy with Basic Auth in front of Kibana |

## Environment

- Platform: VMware Fusion
- OS: Ubuntu 22.04 LTS
- RAM: 4 GB / Storage: 50 GB
- Elastic Stack version: 8.19.10

## What this covers

The full writeup is in `ELK_Stack_SIEM.pdf` and walks through every step:

1. VM setup and system prep
2. Java installation (OpenJDK 11)
3. Elasticsearch — install, configure, verify
4. Kibana — install, configure, open firewall
5. Logstash — install, pipeline config (Beats input + Elasticsearch output)
6. Nginx — reverse proxy with htpasswd authentication
7. Auditbeat — system module, all datasets enabled, dashboards loaded
8. Detection rules — SSH brute force, sudo execution, new user creation
9. KQL queries for hunting through the collected data

## What's coming next

- Detection rules walkthrough with screenshots of alerts firing
- Wazuh EDR integration alongside the ELK stack
- Second VM as a monitored target machine
- Attack simulation (Hydra, Metasploit) with detection results

## Repository structure

```
├── README.md
└── ELK_Stack_SIEM.pdf     # Full step-by-step writeup with screenshots
```
