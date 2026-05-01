# AWS Lab 1: Introduction to AWS IAM

## Overview
This lab focused on **AWS Identity and Access Management (IAM)**, demonstrating how to securely manage access to AWS services and resources. I explored the relationships between Users, Groups, and Policies while implementing a real-world security scenario.

## Objectives
* **Explore** pre-created IAM Users and Groups.
* **Inspect** IAM policies (Managed vs. Inline).
* **Assign** users to specific groups to inherit permissions.
* **Verify** access controls by testing service restrictions across different user accounts.

## Business Scenario implemented
I managed access for three distinct roles based on the principle of **Least Privilege**:

| User | Group | Permissions |
| :--- | :--- | :--- |
| **user-1** | S3-Support | Read-Only access to Amazon S3 |
| **user-2** | EC2-Support | Read-Only access to Amazon EC2 |
| **user-3** | EC2-Admin | View, Start, and Stop EC2 instances |

## Key Tasks Performed
1. **IAM Configuration:** Mapped users to their respective functional groups.
2. **Permission Validation:** 
   * Logged in as `user-1` to verify S3 access while being blocked from EC2.
   * Logged in as `user-2` to verify EC2 "Read-Only" status (verified by a failed attempt to stop an instance).
   * Logged in as `user-3` to successfully perform administrative actions (stopping the `LabHost` instance).
3. **Troubleshooting:** Resolved a region-specific visibility issue by ensuring the console was set to `us-east-1` (N. Virginia) to match resource deployment.

## Outcomes
* **Final Score:** 40/40
* **Core Learning:** Gained hands-on experience with how IAM policies dictate the "Effect, Action, and Resource" logic. Confirmed that permissions are granular and region-independent, while resources like EC2 are region-specific.



