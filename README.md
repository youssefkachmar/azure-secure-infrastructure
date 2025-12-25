# Azure Secure Infrastructure (pfSense Hub Gateway)

A centralized, security-focused Azure lab built around a **pfSense network virtual appliance (hub gateway)** to enforce routing and segmentation, publish internal services securely, and provide monitoring + security visibility.

> **Availability note:** The original Azure subscription used for this lab may be disabled/offline, so any previously public endpoints may not be reachable today. The screenshots in this repository are the validation evidence.

---

## High-level Goals

- Centralized routing and segmentation using **UDR/route tables**
- **pfSense** as the hub gateway (firewall/NAT/VPN/reverse proxy)
- Remote administration through **OpenVPN**
- HTTPS publishing through **HAProxy → Nginx**
- VoIP (Asterisk) reachable through NAT (SIP/RTP)
- Visibility through **Suricata (IDS)**, **Wazuh (SIEM)**, and **Zabbix (monitoring)**

---

## Services & IP Plan (Lab)

- **Azure VNet:** `10.0.0.0/16`

| Subnet | CIDR | Workload(s) | Example IP(s) | Purpose |
|---|---:|---|---|---|
| DCSubnet | `10.0.2.0/24` | Windows Server (AD DS/DNS) | `10.0.2.10` | Identity + DNS |
| VoIPSubnet | `10.0.3.0/24` | Asterisk PBX | `10.0.3.4` | SIP/RTP services |
| ClientSubnet | `10.0.4.0/24` | Windows client | `10.0.4.4` | Testing / domain client |
| WebSubnet | `10.0.5.0/24` | Nginx web server | `10.0.5.10` | Internal web app behind HAProxy |
| Management | `10.0.6.0/24` | Jumpbox, Zabbix, Wazuh | `10.0.6.5`<br>`10.0.6.6`<br>`10.0.6.7` | Operations / monitoring / SIEM |

**pfSense hub gateway (NVA):**
- WAN: `10.0.1.4` (Azure DHCP)
- LAN: `10.0.6.4`

**OpenVPN tunnel network:** `10.200.0.0/24`

---

## Evidence Screenshots (with descriptions)

> All screenshots are stored in: `docs/screenshots/`

---

### 01 — Topology (VNet + subnets + roles)

This diagram summarizes the complete architecture:
- Azure VNet (`10.0.0.0/16`) and the main subnets.
- pfSense acting as the central hub gateway for routing/security.
- Core workloads (AD/DNS, VoIP, web server, management/monitoring).

![01-topology](docs/screenshots/01-topology.png)

---

### 02 — Azure Route Table (UDR)

Proof of centralized routing enforcement in Azure:
- UDR/route table configuration to steer traffic via the pfSense NVA.
- Enables hub-and-spoke behavior and central policy enforcement.

![02-route-table](docs/screenshots/02-route-table.png)

---

### 03 — pfSense Dashboard (Gateway operational)

pfSense dashboard confirming the gateway is online and servicing the lab:
- Central point for firewall rules, NAT, VPN, HAProxy and visibility tooling.
- Used as operational proof of the hub gateway.

![03-pfsense-dashboard](docs/screenshots/03-pfsense-dashboard.png)

---

## Remote Access VPN (OpenVPN)

### 04 — OpenVPN client connected

Client-side proof of remote access:
- OpenVPN tunnel successfully established to pfSense.
- Used to access internal subnets without exposing management ports publicly.

![04-openvpn-client-connected](docs/screenshots/04-openvpn-client-connected.png)

### 05 — pfSense OpenVPN status (active session)

Server-side proof of the same VPN connection:
- Shows an active OpenVPN session.
- Confirms tunnel addressing and session activity from pfSense.

![05-openvpn-status](docs/screenshots/05-openvpn-status.png)

### 06 — OpenVPN Certificate Authority (CA)

Certificate-based authentication evidence:
- A CA is configured on pfSense to issue client certificates.
- Provides stronger authentication than password-only access.

![06-openvpn-ca](docs/screenshots/06-openvpn-ca.png)

### 07 — OpenVPN user certificate

Client identity/certificate evidence:
- Shows a user/client certificate created for VPN authentication.
- Demonstrates PKI usage and per-user access control.

![07-openvpn-user-certificate](docs/screenshots/07-openvpn-user-certificate.png)

---

## Web Publishing (HAProxy → Nginx) over HTTPS

### 08 — HAProxy stats (reverse proxy evidence)

Operational proof of the reverse proxy:
- Frontend/backend visibility and health checks in HAProxy.
- Confirms HTTPS publishing pipeline via pfSense.

![08-haproxy-stats](docs/screenshots/08-haproxy-stats.png)

### 19 — Web server reachable via HTTPS domain (historical evidence)

Publishing proof from the client side:
- Browser shows the site reachable via HTTPS using a public domain during the project.
- Validates the chain: Internet → pfSense/HAProxy → internal Nginx.

> The domain may be offline today due to subscription status; the screenshot is the evidence.

![19-webserver-domain](docs/screenshots/19-webserver-domain.png)

---

## VoIP (Asterisk) + NAT (SIP/RTP)

### 09 — Zoiper ringing (call setup)

VoIP call flow validation:
- Ringing state indicates SIP signaling is reaching the endpoint.
- Confirms reachability through routing + firewall/NAT controls.

![09-voip-ringing-zoiper](docs/screenshots/09-voip-ringing-zoiper.png)

### 10 — Zoiper incoming call

Additional VoIP validation:
- Incoming call screen confirms successful SIP negotiation.
- Used as proof of end-to-end VoIP connectivity.

![10-voip-incoming-zoiper](docs/screenshots/10-voip-incoming-zoiper.png)

### 11 — NAT Port Forward rules (SIP + RTP)

pfSense inbound NAT evidence:
- SIP UDP 5060 forwarded to the Asterisk server.
- RTP UDP range forwarded to support voice media streams.

![11-nat-port-forward-voip](docs/screenshots/11-nat-port-forward-voip.png)

### 12 — Outbound NAT with static-port (RTP stability)

Outbound NAT tuning for VoIP:
- Static-port helps prevent RTP issues caused by port rewriting.
- Common requirement for stable audio through NAT.

![12-outbound-nat-static-port](docs/screenshots/12-outbound-nat-static-port.png)

---

## IDS (Suricata)

Suricata is used primarily for IDS-style inspection:
- Detects suspicious traffic patterns (scans/recon) and generates alerts.
- Blocking/containment is handled through pfSense policy as needed.

### 13 — Detection example (Nmap-style scan)

Reconnaissance detection evidence:
- Suricata flags scan-like behavior consistent with Nmap probing.
- Demonstrates that inspection rules are active.

![13-suricata-nmap-attack](docs/screenshots/13-suricata-nmap-attack.png)

### 14 — Suricata alerts view

Operational IDS evidence:
- Shows the alert view with triggered events.
- Used to validate visibility into suspicious traffic.

![14-suricata-alerts](docs/screenshots/14-suricata-alerts.png)

### 15 — Blocked host evidence

Response/containment evidence:
- Shows a blocked host/IP entry in pfSense context.
- Demonstrates mitigation following detection.

![15-suricata-ip-block](docs/screenshots/15-suricata-ip-block.png)

---

## Monitoring (Zabbix)

### 16 — Zabbix dashboard

Monitoring evidence:
- Confirms infrastructure/service visibility through Zabbix dashboards.
- Used to validate availability/performance monitoring.

![16-zabbix-dashboard](docs/screenshots/16-zabbix-dashboard.png)

---

## SIEM (Wazuh)

### 17 — Wazuh dashboard

SIEM visibility evidence:
- Dashboard view showing security monitoring panels.
- Validates centralized security visibility.

![17-wazuh-dashboard](docs/screenshots/17-wazuh-dashboard.png)

### 18 — Wazuh hosts/agents inventory

Endpoint coverage evidence:
- Shows hosts/agents reporting to Wazuh.
- Confirms agents are enrolled and visible centrally.

![18-wazuh-hosts](docs/screenshots/18-wazuh-hosts.png)

---

## Artifacts

- Web page served by the internal web server: [`web/index.html`](web/index.html)
- pfSense configuration export: [`configs/pfSense full config.xml`](configs/pfSense%20full%20config.xml)

---

## Tech Stack

Azure • pfSense • OpenVPN • HAProxy • Nginx • Asterisk • Suricata • Wazuh • Zabbix • Windows Server (AD/DNS)
