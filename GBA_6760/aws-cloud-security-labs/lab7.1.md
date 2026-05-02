# AWS Config + Lambda Lab Notes (Security Group Remediation)

**Environment:** AWS Skill Builder Lab (EC2, AWS Config, Lambda, CloudWatch)

---

## Overview

Goal: Automatically detect and fix bad security group rules

Flow:
1. AWS Config monitors security groups
2. Change detected → triggers rule
3. Rule invokes Lambda
4. Lambda removes unwanted ports

---

## Task 1 – IAM Roles

### AwsConfigLambdaSGRole
- Used by Lambda
- Permissions:
  - Modify security groups
  - Write logs to CloudWatch

### AwsConfigRole (UPDATED)
- Added:
  - `AWS_ConfigRole` policy
- Allows AWS Config to:
  - Read resources
  - Track changes

---

## Task 2 – AWS Config Setup

```
Recording: Specific resources
Resource: EC2 SecurityGroup
Frequency: Continuous
IAM Role: AwsConfigRole
```

Notes:

* Creates inventory of resources
* Tracks changes over time

---

## Task 3 – Simulate Incident

Modified **LabSG1**

### Added inbound rules:

* HTTP (80)
* HTTPS (443)
* SMTPS (465) (removed)
* IMAPS (993) (removed)

```
Source: Anywhere IPv4
```

Notes:

* SMTPS + IMAPS = "bad" rules for this lab

---

## Task 4 – Config Rule + Lambda

Created custom rule:

```
Name: EC2SecurityGroup
Trigger: Configuration changes
Resource: EC2 SecurityGroup
Lambda: awsconfig_lambda_security_group
```

### Parameter:

```
debug = true
```

Notes:

* Passes debug logs into Lambda
* Rule runs whenever SG changes

---

## Task 5 – Auto Remediation

After rule runs:

### Result:

* Only:

  * HTTP
  * HTTPS
* Removed:

  * SMTPS 
  * IMAPS 

Notes:

* Lambda enforces "allowed ports"
* Changes get automatically reverted

---

## Task 6 – CloudWatch Logs

Path:

```
CloudWatch → Log groups → awsconfig_lambda_security_group
```

Filter:

```
revoking
```

### Example log:

* Shows Lambda removing:

  * Port 465 (SMTPS)
  * Port 993 (IMAPS)

Notes:

* Confirms remediation worked
* Logs every action taken

---

## Key Concepts

* **AWS Config**

  * Monitors resource changes
  * Triggers rules

* **Lambda**

  * Fixes misconfigurations automatically

* **CloudWatch**

  * Logs actions for auditing

---

## End Result

* Security groups continuously monitored
* Unauthorized ports auto-removed
* Fully automated remediation pipeline

---

## Quick Summary

```
Change SG → Config detects → Lambda runs → Bad rules removed → Logged in CloudWatch
```

---

## Lab Result

* Incident simulated 
* Detection triggered 
* Auto-remediation 
* Logs verified 

