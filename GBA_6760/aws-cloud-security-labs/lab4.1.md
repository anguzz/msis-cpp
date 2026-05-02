# AWS Lab: VPC Security (Security Groups & NACLs)

## Overview
This lab focused on controlling access inside a VPC using **Security Groups (stateful)** and **Network ACLs (stateless)**. The setup included public proxy servers and a private AppServer.

---

## Architecture
- VPC: `10.0.0.0/16`
- Public Subnets → ProxyServer1, Bastion
- Private Subnet → AppServer (no public IP)
- Internet Gateway → public access  
- NAT Gateway → outbound for private subnet

---

## Key Tasks & Findings

### 1. Initial Access
- AppServer allowed HTTP from `0.0.0.0/0`
- Both proxy servers could access the site

---

### 2. Restrict by IP
- AppServerSG → allow HTTP only from ProxyServer1
- Result:
  - ProxyServer1 - allowed
  - ProxyServer2 - denied

---

### 3. Use Security Group Referencing
- Changed source → `ProxySG` instead of IP
- Assigned ProxyServer2 → ProxySG
- Result: both proxies allowed

---

### 4. Network ACL Behavior
- Added:
  - Rule 99 → DENY HTTP
- Broke access 

- Fixed with:
  - Rule 98 → ALLOW HTTP

### Key Concept
- NACL = **stateless + ordered**
- SG = **stateful**

---

### 5. Bastion Host (SSH)

#### Setup
- ProxyServer2 → Bastion
- BastionSG → allow SSH (22)
- AppServerSG:
```

SSH (22) → BastionPrivateIP/32

```

---

### SSH Flow

```bash
ssh -i labuser.pem -A ec2-user@<BastionPublicIP>
ssh ec2-user@10.0.11.30
````

---

### Issues Encountered

*  Wrong `.pem` permissions → fixed with `icacls`
*  Wrong SG source IP → fixed using BastionPrivateIP
*  SSH hanging → caused by NACL
*  No agent forwarding → fixed with `-A`

---

### Final Step

```bash
touch newfile.txt
```

---

## Alternative Access

Used **Session Manager** to connect without SSH or bastion 

---

## Core Takeaways

* SG controls instance access (stateful)
* NACL controls subnet traffic (stateless)
* Both must allow traffic
* Bastion enables access to private instances
* Session Manager = more secure alternative

---

