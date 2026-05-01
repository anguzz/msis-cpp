#  AWS Lab 3: Introduction to Amazon EC2

## Overview
This lab provided a comprehensive hands-on experience with **Amazon Elastic Compute Cloud (EC2)**. I practiced the full lifecycle of a virtual server—from automated deployment and monitoring to vertical scaling (resizing) and implementing operational safeguards like Stop and Termination protection.

## Objectives
*   **Provision** an EC2 instance using custom User Data scripts.
*   **Secure** the instance by dynamically updating Security Group rules.
*   **Monitor** performance via CloudWatch metrics and system logs.
*   **Scale Vertically** by modifying instance types and expanding EBS volume capacity.
*   **Implement Guardrails** using Termination and Stop protection to prevent accidental data loss or downtime.

---

##  Technical Implementation Details

### 1. Instance Provisioning & Bootstrapping
I launched an **Amazon Linux 2023** instance (`t2.micro`) into a custom VPC. To automate the web server setup, I utilized the following **User Data** script:

```bash
#!/bin/bash
# Install and start Apache Web Server
dnf install -y httpd
systemctl enable httpd
systemctl start httpd
# Create a custom landing page
echo '<html><h1>Hello From Your Web Server!</h1></html>' > /var/www/html/index.html
```
*   **Operational Insight:** User Data scripts run as `root` only during the initial launch, allowing for "Zero-Touch" provisioning of application environments.

### 2. Operational Safeguards (Guardrails)
To simulate a production environment where accidental deletion could be catastrophic, I enabled:
*   **Termination Protection:** Prevents the instance from being deleted via the console or API.
*   **Stop Protection:** Prevents the instance from being shut down, ensuring continuous availability for critical workloads.

### 3. Monitoring & Troubleshooting
I explored AWS's native monitoring tools to verify system health:
*   **Status Checks:** Verified both **System Status** (AWS hardware health) and **Instance Status** (Guest OS reachability).
*   **System Logs:** Inspected the serial console output to verify that the `dnf install` commands from the User Data script executed successfully.
*   **Instance Screenshots:** Captured a visual representation of the instance console to troubleshoot without requiring SSH access.

---

##  Scaling & Modification


### 4. Vertical Scaling (Resizing)
As resource requirements grew, I performed a vertical scale-up:
1.  **Stop Instance:** Controlled shutdown to prepare for hardware changes.
2.  **Change Instance Type:** Upgraded from `t2.micro` (1 GiB RAM) to `t2.small` (2 GiB RAM).
3.  **EBS Volume Modification:** Increased the root Elastic Block Store (EBS) volume from **8 GiB to 10 GiB**.
    *   **Technical Note:** AWS allows for "Elastic Volumes," meaning storage can often be increased while the volume is in use, though the OS file system may require a resize command to recognize the new space.

### 5. Security Group Refinement
Initially, the web server was unreachable due to the "Default Deny" nature of AWS Security Groups. 
*   **Action:** Modified the `Web Server security group` to allow **Inbound HTTP (Port 80)** from `0.0.0.0/0`.
*   **Result:** Successfully accessed the web server via its Public IPv4 address, confirming the firewall rule was applied instantly.

---

## 🏁 Outcomes & Key Learnings
*   **Final Score:** 100% (Completed all tasks including Stop Protection testing).
*   **Service Quotas:** Explored the **Service Quotas** console to understand default regional limits (e.g., maximum running On-Demand instances), which is critical for capacity planning.
*   **Lifecycle Management:** Gained practical experience in the "Stop-Modify-Start" workflow required for resizing instances while maintaining data persistence on EBS.

