# Lab 7 – Managing SELinux Security on RHEL (AWS EC2)

## Project Overview

This lab demonstrates how **Security-Enhanced Linux (SELinux)** controls access to files, processes, and system resources on a Red Hat Enterprise Linux server.

SELinux adds an additional security layer beyond standard Linux permissions by enforcing **Mandatory Access Control (MAC)** policies.

Key tasks performed in this lab:

* Checking the current SELinux mode
* Switching between **enforcing** and **permissive**
* Understanding **file contexts**
* Temporarily modifying file labels
* Persistently modifying file labels
* Restoring default contexts

---

# What SELinux Is

SELinux is a **kernel security module** that enforces security policies on Linux systems.

Traditional Linux security uses:

```
User / Group / Other permissions
```

Example:

```
-rw-r--r--
```

This is called **Discretionary Access Control (DAC)** because the file owner controls access.

SELinux adds another layer called **Mandatory Access Control (MAC)** where **the system enforces rules regardless of user permissions**.

Example:

Even if permissions allow access, SELinux can still block it.

This prevents:

* privilege escalation
* compromised services accessing sensitive files
* malware spreading through the system

---

# SELinux Operating Modes

SELinux can run in three modes.

| Mode       | Behavior                                     |
| ---------- | -------------------------------------------- |
| Enforcing  | SELinux actively blocks unauthorized actions |
| Permissive | Violations are logged but not blocked        |
| Disabled   | SELinux completely off                       |

---

# 1. Verify Current SELinux Mode

Command used:

```bash
getenforce
```

Output:

```
Enforcing
```

Meaning:

* SELinux policies are **actively enforced**
* Unauthorized actions will be blocked.

This command checks the **current runtime state** of SELinux.

---

# 2. Change SELinux Mode in Configuration File

Command used:

```bash
sudo vi /etc/selinux/config
```

File location:

```
/etc/selinux/config
```

This file defines the **default SELinux mode at boot**.

Example configuration:

```
SELINUX=enforcing
SELINUXTYPE=targeted
```

After modification:

```
SELINUX=permissive
SELINUXTYPE=targeted
```

Meaning:

* SELinux will run in **permissive mode after reboot**.

---

# Verify Configuration Change

Command:

```bash
sudo grep '^SELINUX' /etc/selinux/config
```

Output:

```
SELINUX=permissive
SELINUXTYPE=targeted
```

This confirms the configuration change was saved.

---

# 3. Change SELinux Mode Immediately

Editing the config file **does not change the running system immediately**.

To change the mode instantly:

```
sudo setenforce 0
```

Mode values:

| Command      | Result     |
| ------------ | ---------- |
| setenforce 0 | Permissive |
| setenforce 1 | Enforcing  |

Verify:

```
getenforce
```

Output:

```
Permissive
```

This confirms the system switched modes.

---

# 4. Return SELinux to Enforcing

Change config file back:

```
SELINUX=enforcing
```

Apply runtime change:

```
sudo setenforce 1
```

Verify:

```
getenforce
```

Output:

```
Enforcing
```

---

# SELinux File Contexts

SELinux assigns **labels (contexts)** to files.

Example command:

```bash
ls -Z
```

Example output:

```
system_u:object_r:etc_t:s0
```

Breakdown of context:

```
user : role : type : level
```

| Field | Meaning            |
| ----- | ------------------ |
| user  | SELinux user       |
| role  | object role        |
| type  | security type      |
| level | MLS security level |

Most important field:

```
TYPE
```

Example:

```
etc_t
```

This means the file belongs to the **/etc configuration context**.

---

# File Context Inheritance

New files inherit the context of their **parent directory**.

Example:

Directory:

```
/etc
```

Context:

```
etc_t
```

Create file:

```
sudo touch /etc/test
```

Check:

```
ls -Z /etc/test
```

Output:

```
unconfined_u:object_r:etc_t:s0
```

The file inherited the **etc_t context**.

---

# 5. Temporary Context Changes (chcon)

Command used:

```
chcon
```

Example:

```
chcon -t samba_share_t test2
```

Result:

```
unconfined_u:object_r:samba_share_t:s0
```

Meaning:

The file is now labeled as a **Samba share file**.

Important:

`chcon` changes are **temporary**.

They can be lost after:

* relabel
* restorecon
* system restore

---

# Restore Default Context

Command:

```
restorecon -v test2
```

Result:

```
Relabeled test2 from samba_share_t → user_home_t
```

This restores the **default SELinux policy context**.

---

# 6. Changing Directory Contexts (Recursive)

Example directory:

```
~/webtest
```

Default context:

```
user_home_t
```

Change directory type to allow Apache access:

```
sudo chcon -R -t httpd_sys_content_t ~/webtest
```

Meaning:

The directory is now accessible to the **Apache HTTP server**.

Verify:

```
ls -Z
```

Output:

```
httpd_sys_content_t
```

---

# Restore Default Context for Directory

Command:

```
sudo restorecon -R -v ~/webtest
```

Result:

Directory and files return to:

```
user_home_t
```

---

# Persistent SELinux Changes

Temporary changes disappear after relabeling.

Persistent changes require:

```
semanage
```

Command:

```
sudo semanage fcontext -a -t samba_share_t /etc/ftest1
```

This **adds a rule to the SELinux policy database**.

Verify:

```
sudo semanage fcontext -C -l
```

Example output:

```
/etc/ftest1 all files system_u:object_r:samba_share_t:s0
```

---

# Apply Persistent Policy

Command:

```
restorecon /etc/ftest1
```

Now the new label is applied permanently.

---

# Why SELinux Exists (Real-World Example)

Imagine a compromised web server.

Without SELinux:

```
Apache exploited → attacker reads /etc/shadow
```

With SELinux:

Apache process is restricted to:

```
httpd_sys_content_t
```

SELinux blocks access to:

```
/etc/shadow
```

Even if file permissions allow it.

This prevents many privilege escalation attacks.

---

# Key Commands Summary

| Command           | Purpose                        |
| ----------------- | ------------------------------ |
| getenforce        | show current SELinux mode      |
| setenforce 0      | switch to permissive           |
| setenforce 1      | switch to enforcing            |
| ls -Z             | view SELinux context           |
| chcon             | temporarily change context     |
| restorecon        | restore default context        |
| semanage fcontext | create persistent context rule |

---

# Lab Outcome

In this lab:

* Verified SELinux status
* Switched between **enforcing and permissive**
* Observed **SELinux file contexts**
* Temporarily modified contexts using **chcon**
* Restored contexts using **restorecon**
* Created persistent context rules using **semanage**

This demonstrated how SELinux enforces **mandatory access control** on a Linux system.

