# Azure Secure Infrastructure (pfSense Hub Gateway)

A centralized, security-focused Azure lab deployed on Microsoft Azure. The design uses a **pfSense NVA (hub gateway)** to centralize routing and security controls, publish a web application through a reverse proxy, provide remote administrative access over VPN, and add observability with monitoring + SIEM.

> **Availability note:** This lab was hosted under an Azure subscription that may be **disabled/offline**, so any public endpoints (domain/IP) may not be reachable anymore. The screenshots in this repository are the verification evidence.

---

## 1) High-level Goals

- **Centralized routing & segmentation:** Multiple subnets inside one Azure VNet, with traffic forced through pfSense using UDRs.
- **Secure remote admin:** OpenVPN remote access into the management network.
- **Service publishing:** HAProxy on pfSense publishing an internal Nginx web server over HTTPS.
- **Enterprise services demo:** VoIP (Asterisk PBX) accessible via SIP/RTP with correct NAT behavior.
- **Visibility & detection:** Zabbix monitoring and Wazuh SIEM dashboards, with Suricata IDS alerts for suspicious activity.

---

## 2) Services & IP Plan

### Azure VNet
- **VNet:** `10.0.0.0/16`

### Subnets / Workloads

| Subnet | CIDR | Workload(s) | Example IP(s) | Purpose |
|---|---:|---|---|---|
| DCSubnet | `10.0.2.0/24` | `vm-dc` (Windows Server) | `10.0.2.10` | AD DS / DNS |
| VoIPSubnet | `10.0.3.0/24` | `vm-voip` (Asterisk) | `10.0.3.4` | SIP / RTP PBX |
| ClientSubnet | `10.0.4.0/24` | `vm-client` (Windows 10) | `10.0.4.4` | Domain-joined client / testing |
| WebSubnet | `10.0.5.0/24` | `vm-web` (Nginx) | `10.0.5.10` | Internal web service behind HAProxy |
| Management | `10.0.6.0/24` | Jumpbox, Zabbix, Wazuh | `10.0.6.5`, `10.0.6.6`, `10.0.6.7` | Operations / monitoring / SIEM |

### Hub Gateway (pfSense NVA)
- **pfSense (Hub Gateway/NVA):**
  - WAN IP: `10.0.1.4`
  - LAN IP: `10.0.6.4`
  - Roles: **Firewall, NAT, VPN, Reverse Proxy**

### Remote Admin Access
- **OpenVPN tunnel network:** `10.200.0.0/24` (remote admin PC obtains an IP in this range)

---

## 3) Evidence Screenshots (detailed descriptions)

> All screenshots are stored in: `docs/screenshots/`

---

### 01 — Topology (VNet + subnets + roles)

This diagram summarizes the entire architecture:
- The Azure VNet (`10.0.0.0/16`) and the main subnets.
- The **pfSense NVA** acting as a centralized hub gateway (FW/NAT/VPN).
- The main workloads (AD/DNS, VoIP PBX, Web server, management stack).
- The remote admin path using **OpenVPN**.

![01-topology](docs/screenshots/01-topology.png)

---

### 02 — Azure Route Table (UDR)

This screenshot is the proof of centralized routing in Azure:
- A route table (UDR) is configured to steer subnet traffic through the pfSense NVA.
- This is what enables hub-and-spoke behavior and forces inspection/NAT/firewall policy to happen at pfSense.

![02-route-table](docs/screenshots/02-route-table.png)

---

### 03 — pfSense Dashboard (Gateway operational)

pfSense system dashboard confirming:
- The firewall/NVA VM is up and running.
- Interfaces/services are active (gateway role).
- This is the main control plane for NAT, VPN, HAProxy, and security services.

![03-pfsense-dashboard](docs/screenshots/03-pfsense-dashboard.png)

---

## 4) Remote Access VPN (OpenVPN)

### 04 — OpenVPN client connected (remote admin)

This screenshot demonstrates successful remote access:
- The OpenVPN client establishes the tunnel to pfSense.
- Remote administration is done through the VPN rather than exposing internal management ports publicly.

![04-openvpn-client-connected](docs/screenshots/04-openvpn-client-connected.png)

### 05 — pfSense OpenVPN status (active tunnel session)

pfSense shows the VPN session from the server side:
- Confirms that a client is connected.
- Displays the assigned tunnel/virtual address and session activity.
- Serves as authoritative proof that the VPN is working.

![05-openvpn-status](docs/screenshots/05-openvpn-status.png)

### 06 — OpenVPN Certificate Authority (CA)

Proof of certificate-based authentication:
- A Certificate Authority is configured on pfSense.
- The CA is used to issue client certificates, improving security over password-only access.

![06-openvpn-ca](docs/screenshots/06-openvpn-ca.png)

### 07 — OpenVPN user certificate

Proof of a user/client certificate being created:
- Shows certificate management for a VPN user.
- Demonstrates a proper PKI-based setup for OpenVPN access control.

![07-openvpn-user-certificate](docs/screenshots/07-openvpn-user-certificate.png)

---

## 5) Web Publishing (HAProxy → Nginx) over HTTPS

### 08 — HAProxy stats (reverse proxy evidence)

HAProxy statistics page proving:
- HAProxy is running on pfSense.
- Backends/frontends are configured and passing traffic.
- Useful for visibility (health checks, sessions, traffic counters).

![08-haproxy-stats](docs/screenshots/08-haproxy-stats.png)

### 19 — Web server reachable via HTTPS domain (evidence)

Proof that the web application was successfully published:
- Browser loads the site using a public domain and HTTPS.
- This validates the full chain: **Internet → pfSense/HAProxy → internal Nginx web server**.

> The domain may be offline now due to subscription status; this screenshot is the historical proof.

![19-webserver-domain](docs/screenshots/19-webserver-domain.png)

---

## 6) VoIP (Asterisk) + NAT (SIP/RTP)

### 09 — Zoiper ringing (call flow)

Demonstrates VoIP call setup:
- The softphone receives/rings, indicating SIP signaling is working end-to-end.
- Confirms reachability to the PBX through the network/security layers.

![09-voip-ringing-zoiper](docs/screenshots/09-voip-ringing-zoiper.png)

### 10 — Zoiper incoming call (active signaling)

Additional VoIP validation:
- Shows the incoming call screen, confirming successful SIP negotiation.
- Used as evidence that external-to-internal VoIP connectivity is functional.

![10-voip-incoming-zoiper](docs/screenshots/10-voip-incoming-zoiper.png)

### 11 — NAT Port Forward rules (SIP + RTP → Asterisk)

pfSense NAT configuration proving:
- **SIP UDP 5060** forwarded to the Asterisk server.
- **RTP UDP 10000–20000** forwarded to the Asterisk server.
- Ensures VoIP signaling and audio media can traverse NAT properly.

![11-nat-port-forward-voip](docs/screenshots/11-nat-port-forward-voip.png)

### 12 — Outbound NAT with static-port (VoIP stability)

Outbound NAT proof showing `static-port` enabled:
- Static port NAT helps avoid RTP audio issues caused by port rewriting.
- This is a common best practice for VoIP behind NAT.

![12-outbound-nat-static-port](docs/screenshots/12-outbound-nat-static-port.png)

---

## 7) IDS (Suricata)

Suricata is documented primarily as **IDS (detection)** in this lab:
- It inspects traffic and produces alerts for suspicious patterns (e.g., scans).
- Blocking can be applied via firewall rules depending on policy, but IPS inline mode is not assumed unless explicitly configured.

### 13 — Detection example (Nmap-style scan)

Evidence of reconnaissance detection:
- Suricata flags scan-like behavior consistent with Nmap probing.
- Demonstrates that inspection rules are active and generating useful events.

![13-suricata-nmap-attack](docs/screenshots/13-suricata-nmap-attack.png)

### 14 — Suricata alerts view

Operational evidence of IDS:
- Shows the alerts interface with detected events.
- Used to prove real-time visibility into suspicious traffic.

![14-suricata-alerts](docs/screenshots/14-suricata-alerts.png)

### 15 — Blocked host evidence

Demonstrates response/containment:
- Shows an IP block entry / blocked host evidence in pfSense context.
- Represents mitigation after detection (policy enforcement).

![15-suricata-ip-block](docs/screenshots/15-suricata-ip-block.png)

---

## 8) Monitoring (Zabbix)

### 16 — Zabbix dashboard (observability)

Proof that monitoring is deployed:
- Shows Zabbix dashboard overview of monitored components.
- Confirms availability/performance visibility for the infrastructure.

![16-zabbix-dashboard](docs/screenshots/16-zabbix-dashboard.png)

---

## 9) SIEM (Wazuh)

### 17 — Wazuh dashboard (security visibility)

Proof that SIEM is in place:
- Shows Wazuh dashboard with security monitoring panels.
- Used as evidence of centralized log/security analytics.

![17-wazuh-dashboard](docs/screenshots/17-wazuh-dashboard.png)

### 18 — Wazuh hosts/agents inventory

Evidence of endpoint coverage:
- Shows Wazuh hosts/agents reporting to the manager.
- Demonstrates that endpoints are enrolled and visible in SIEM.

![18-wazuh-hosts](docs/screenshots/18-wazuh-hosts.png)

---

## 10) Repository Structure

- `docs/screenshots/` — evidence screenshots referenced by this README

---

## 11) Notes (Public Repo)

- Screenshots include **private RFC1918 IPs** used in the lab design.
- If you reproduce this lab, use your own domain/certificates and follow secure credential handling (do not commit secrets).
- Suricata is referenced as **IDS** unless explicitly configured in inline IPS mode.
