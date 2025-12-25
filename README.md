# Azure Secure Infrastructure (pfSense Hub Gateway)

A centralized, security-focused Azure lab built around a **pfSense NVA (hub gateway)** to enforce routing, publish services, provide remote access VPN, and enable monitoring + threat detection.

This repository documents the architecture and provides proof screenshots for:
- **Centralized hub-and-spoke routing** using UDRs
- **pfSense** as Firewall/NAT/VPN gateway
- **HAProxy** reverse proxy publishing the web server
- **OpenVPN** remote access
- **VoIP (Asterisk)** reachable through NAT (SIP + RTP)
- **Suricata IDS/IPS**, **Wazuh SIEM**, and **Zabbix monitoring**

---

## Architecture / Topology

The environment is deployed inside an Azure VNet `10.0.0.0/16` with multiple subnets (DC, VoIP, Client, Web, Management). All traffic is routed through the pfSense hub gateway (NVA) using UDRs.

![Topology](docs/screenshots/01-topology.png)

---

## Azure Routing (UDR)

Route table used to force subnets to forward traffic through the pfSense NVA.

![Route table](docs/screenshots/02-route-table.png)

---

## pfSense (Gateway Services)

pfSense provides:
- Firewall policies
- NAT (including VoIP support)
- OpenVPN server
- HAProxy reverse proxy
- (Optional/related) IDS/IPS integration and security visibility

![pfSense dashboard](docs/screenshots/03-pfsense-dashboard.png)

---

## Remote Access VPN (OpenVPN)

OpenVPN is used for secure remote administration access.

**Client connected (OpenVPN Connect):**

![OpenVPN client connected](docs/screenshots/04-openvpn-client-connected.png)

**pfSense OpenVPN status (shows active tunnel client):**

![OpenVPN status](docs/screenshots/05-openvpn-status.png)

Certificate management proof (CA + user certificate):

![OpenVPN CA](docs/screenshots/06-openvpn-ca.png)

![OpenVPN user certificate](docs/screenshots/07-openvpn-user-certificate.png)

---

## Web Publishing (HAProxy → Nginx)

The web server is published behind pfSense using HAProxy.

**HAProxy stats:**

![HAProxy stats](docs/screenshots/08-haproxy-stats.png)

**Web server reachable via domain name:**

![Web server domain](docs/screenshots/19-webserver-domain.png)

---

## VoIP (Asterisk) + NAT (SIP/RTP)

VoIP service (Asterisk PBX) is reachable from outside through pfSense using:
- **SIP UDP 5060**
- **RTP UDP 10000–20000**

Proof of call flow (Zoiper):

![VoIP ringing](docs/screenshots/09-voip-ringing-zoiper.png)

![VoIP incoming](docs/screenshots/10-voip-incoming-zoiper.png)

**Port forwards (SIP + RTP):**

![NAT port forward](docs/screenshots/11-nat-port-forward-voip.png)

**Outbound NAT with static-port (important for RTP stability):**

![Outbound NAT static port](docs/screenshots/12-outbound-nat-static-port.png)

---

## IDS/IPS (Suricata)

Suricata is used for intrusion detection and blocking suspicious behavior.

**Example: Nmap-style probing detected:**

![Suricata Nmap attack](docs/screenshots/13-suricata-nmap-attack.png)

**Alerts view:**

![Suricata alerts](docs/screenshots/14-suricata-alerts.png)

**Blocked host evidence:**

![Suricata IP block](docs/screenshots/15-suricata-ip-block.png)

---

## Monitoring (Zabbix)

Zabbix provides availability and performance monitoring.

![Zabbix dashboard](docs/screenshots/16-zabbix-dashboard.png)

---

## SIEM / Endpoint Visibility (Wazuh)

Wazuh provides SIEM dashboards and host/agent visibility.

![Wazuh dashboard](docs/screenshots/17-wazuh-dashboard.png)

![Wazuh hosts](docs/screenshots/18-wazuh-hosts.png)

---

## Repository Structure

- `docs/screenshots/` — evidence screenshots used in this documentation

---

## Notes

- Screenshots may include private IPs (RFC1918) used in the lab design.
- If you are reproducing this lab, adjust subnets, DNS, certificates, and firewall rules to your environment and security requirements.
