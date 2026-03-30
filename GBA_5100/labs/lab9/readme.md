# Windows Server 2025: Deployment, Active Directory, and DNS Lab

## Objectives

By the end of this lab, the following tasks were completed:

* **Deployed a Windows Server 2025 instance** in the AWS Academy Learner Lab environment
* **Configured networking**, including static IP assignment and AWS Security Group (firewall) rules
* **Installed and configured DNS and Active Directory Domain Services (AD DS)**
* **Promoted the server to a Domain Controller** and established a new forest
* **Managed Directory Objects** by creating Organizational Units (OUs), Users, and Groups
* **Implemented Group Policy Objects (GPOs)** to enforce a domain-wide login banner
* **Joined a Windows Client computer to the domain** and verified policy application

---

# Why This Lab Exists

This assignment serves as the foundational infrastructure for all remaining projects in the course. It transitions from managing isolated workgroup computers to a centralized **Enterprise Identity Management** system.

By implementing Active Directory, you move away from managing local accounts on every individual machine and toward a model where security, users, and configurations are managed from a single "Source of Truth."

---

# Traditional Management vs. Active Directory

### Local Workgroup (Before AD)

In a standard workgroup, management is decentralized:

* **User Accounts**: Must be created manually on every single computer.
* **Security**: Policies must be set locally; there is no way to force a global password change.
* **Scale**: Becomes impractical once you have more than a handful of machines.

### Active Directory Environment

This lab implements a centralized architecture:

* **Single Sign-On (SSO)**: A user created in the "Employees" OU can log into any computer joined to the domain
* **Group Policy (GPO)**: Change a setting once, and it propagates to thousands of workstations automatically
* **DNS Integration**: Services and computers find each other using names (e.g., `user.local`) rather than shifting IP addresses

---

# Key Concept: Microsoft’s Patch Cycle

Understanding how servers stay secure is critical for reliability.

* **Patch Tuesday**: Standard updates, security fixes, and bug improvements are released on the **second Tuesday of each month**
* **Out-of-Band (OOB) Updates**: Critical patches released outside the normal schedule when a high-risk vulnerability is being actively exploited
* **Security Importance**: Regular patching reduces the attack surface, preventing common entry points like remote code execution or privilege escalation

---

# The Backbone of AD: FSMO Roles

Active Directory uses **Flexible Single Master Operation (FSMO)** roles to prevent conflicts in the database. While AD is generally "multi-master," these five specific roles must be handled by only one Domain Controller at a time to ensure consistency.

| Role Type       | Name                      | Purpose                                                                                         |
| :-------------- | :------------------------ | :---------------------------------------------------------------------------------------------- |
| **Forest-Wide** | **Schema Master**         | Controls all updates and modifications to the AD schema (definitions of all objects)            |
| **Forest-Wide** | **Domain Naming Master**  | Manages the addition or removal of domains within the forest to ensure unique names             |
| **Domain-Wide** | **RID Master**            | Allocates pools of Relative IDs so Domain Controllers can generate unique SIDs for users/groups |
| **Domain-Wide** | **PDC Emulator**          | Acts as the primary time source and handles password changes and authentication priority        |
| **Domain-Wide** | **Infrastructure Master** | Updates references to objects across domains, ensuring group memberships remain accurate        |

---

# Technical Lab Workflow

## 1. Environment Setup (AWS)

* **Instance**: t3.small (2 vCPUs, 2 GB RAM)
* **AMI**: Microsoft Windows Server 2025 Base
* **Security**: Updated Security Groups to allow internal VPC traffic for Active Directory communication

## 2. Server Personalization & Networking

* **Static IP**: Manually configured the IPv4 address, Subnet Mask, and Gateway found via `ipconfig /all`
* **Naming**: Renamed the server to `CPPusername-2025` to follow organizational standards

## 3. Directory Structure (OU Design)

We organized the domain using **Organizational Units (OUs)** to apply different policies to different groups:

* **Employees OU**: Contained `user1` and `user2`
* **Groups OU**: Contained the `Marketing`, `IT`, and `All Company` security groups
* **Workstations OU**: Targeted for the "Computer Settings" GPO

## 4. GPO Implementation

A "Computer Settings" GPO was linked to the **Workstations OU**.

* **Policy Path**:
  `Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options`

* **Action**: Configured an **Interactive Logon Message** so every user sees a "Welcome to my domain" banner upon login

---

# Summary of Deliverables

By completing these steps, the environment is now fully prepared for advanced administration.

1. **Server 2025** is fully patched and acting as the **Domain Controller**
2. **DNS** is correctly forwarding requests and resolving local domain names
3. **Client Computers** are successfully joined and receiving policies from the server

**Verification Command:**
Use `gpresult /R` on the client machine to confirm that the "Computer Settings" GPO is being applied correctly

