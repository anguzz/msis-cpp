# Lab 1 – RHEL Deployment & Linux Basics

## Overview

This lab covers launching a Red Hat Enterprise Linux (RHEL 9) EC2 instance in AWS, connecting via SSH, managing users with SSH key authentication, basic system inspection commands, Linux file permissions, shell globbing, redirection, and common `ls` usage patterns. This README is intended as **personal study notes** and omits screenshots.

---

## Part 1: Launching a RHEL EC2 Instance (AWS)

**Core AWS Concepts Involved**

* **EC2 (Elastic Compute Cloud):** Provides resizable virtual machines in the cloud.
* **AMI (Amazon Machine Image):** A template that defines the OS and base configuration (RHEL 9 in this lab).
* **Instance Type:** Defines CPU, memory, and network capacity (`t2.micro` for low-cost testing).
* **Key Pair:** Used for SSH authentication instead of passwords (`vockey`).
* **Security Group:** Acts as a virtual firewall controlling inbound and outbound traffic.

**Instance Configuration**

* AMI: Red Hat Enterprise Linux 9 (HVM), SSD Volume Type
* Instance type: `t2.micro`
* Key pair: `vockey`
* Security group: default (modified later)

**AWS Notes**

* EC2 instances are **region-specific**; keys and security groups do not automatically transfer between regions.
* The root EBS volume is **persistent**; stopping an instance does not delete data.
* Terminating an instance deletes the instance and (by default) the root volume.

**Steps (High Level)**

1. AWS Console → EC2 → Launch Instance
2. Select RHEL 9 AMI
3. Choose `t2.micro`
4. Assign key pair (`vockey`)
5. Launch instance

---

## Part 2: Connecting via SSH (PuTTY)

**AWS Networking Concepts**

* **Public IPv4 Address:** Required for SSH access from the internet.
* **Port 22 (SSH):** Must be allowed in the EC2 security group inbound rules.
* **ICMP:** Used for ping testing (added later).

**PuTTY Notes**

* AWS Academy provides a `.ppk` file compatible with PuTTY.
* OpenSSH-based clients (Linux/macOS) use `.pem` instead.

1. Download PuTTY and PuTTYgen
2. Download `.ppk` key from AWS Academy Learner Lab
3. Copy EC2 public IPv4 address
4. PuTTY configuration:

   * Host Name: Public IPv4
   * SSH → Auth → Credentials → Private key file (`labsuser.ppk`)
5. Login as:

```bash
ec2-user
```

---

## Part 3: Creating Linux Users with SSH Keys

### Key Generation (Client Side)

* Generate SSH key pair using `puttygen`
* Save private key as `rheluser1.ppk`

### User Creation (Server Side)

```bash
sudo adduser rheluser1
sudo su - rheluser1
```

### SSH Directory Setup

```bash
mkdir ~/.ssh
chmod 700 ~/.ssh
touch ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

Paste the **public key** into `authorized_keys`.

Repeat the process for:

* `rheluser2`
* `rheluser2.ppk`

---

## Part 4: System Inspection Commands

```bash
uname -a        # Kernel and OS info
dmesg           # Kernel ring buffer
lspci           # PCI devices
ls -la /etc     # Permissions and config files
```

Redirect output:

```bash
ls -la /etc >> ~/etc_listing.txt
cat ~/etc_listing.txt
```

CPU and memory:

```bash
cat /proc/cpuinfo | grep -i -e '^cpu' -e '1$' -e '^$'
free -ht
```

---

## Part 5: System Update

```bash
sudo yum update
```

---

## Part 6: Security Group Modification

**AWS Security Group Notes**

* Security groups are **stateful**: return traffic is automatically allowed.
* Rules apply at the **instance ENI level**, not the OS firewall.
* Changes take effect immediately without restarting the instance.

**Inbound Rules Used**

* SSH (TCP 22): Remote administration
* ICMP (Echo Request): Network reachability testing (ping)

**Steps**

* Navigate to EC2 → Security Groups
* Edit inbound rules
* Add ICMP (ping)

---

## Part 7: File Creation for Globbing Practice

Files created in home directory:

```
feb96
jan12.02
jan19.02
jan26.02
jan5.02
jan95
jan96
jan97
jan98
mar98
memo1
memo10
memo2
memo2.sv
```

---

## Part 8: Shell Globbing Examples

```bash
echo *                # All entries
echo *[!0-9]          # Names not ending in a digit
echo m[a-df-z]*       # Starts with m, second letter not e
echo [A-Z]*           # Uppercase start (none)
echo jan*             # Starts with jan
echo *.*              # Contains a dot
echo ?????             # Exactly 5 characters
echo *02              # Ends with 02
echo jan?? feb?? mar??
echo [fjm][ae][bnr]*
```

---

## Part 9: Pipelines and File Operations

```bash
ls | wc -l          # Count directory entries
rm ???              # Remove 3-character names (none)
who | wc -l         # Logged-in users (variable)
ls *.c | wc -l      # Count .c files
rm *.o              # Remove object files
who | sort          # Sorted login list
cd; pwd             # Go to home directory
cp memo1 ..         # Copy to parent directory (permission dependent)
```

---

## Part 10: Filenames with Spaces

```bash
cp "my file.txt" destination/
rm "my file.txt"
```

---

## Part 11: Redirection Operators

* `>`  overwrite output
* `>>` append output
* `<`  redirect input from file
* `<<` here-document (inline input until delimiter)

Example:

```bash
cat << EOF
line 1
line 2
EOF
```

---

## Part 12: `ls` Command Tips

```bash
ls -C     # Multi-column output
ls -lt    # Sort by most recent modification
ls -l     # Long format with sizes
ls -lh    # Human-readable sizes
ls -1     # Force single-column output
```

---

## Key Takeaways

* SSH key authentication is more secure than passwords
* Shell globbing is expanded before command execution
* Redirection operators are foundational for scripting
* `ls` behavior can be customized heavily via flags

---

## End of Notes
