# Activity: AWS Storage Services

## Part 1: Understanding AWS Storage Types

| AWS Storage Service | Type of Storage (Object, Block, File) | Typical Use Case | Key Features | Example Application |
|--------------------|----------------------------------------|------------------|--------------|---------------------|
| Amazon S3 | Object | Storing large amounts of unstructured data | High durability (11 9’s), scalable, lifecycle policies, versioning | Data lakes, backups, static website hosting |
| Amazon EBS | Block | Storage for EC2 instances (OS, databases) | Low-latency, persistent storage, snapshots, encryption | Running databases like MySQL on EC2 |
| Amazon EFS | File | Shared file system for multiple instances | Scalable, shared access, NFS support | Web servers sharing files across instances |
| S3 Glacier | Object (Archive) | Long-term archival storage | Very low cost, high durability, retrieval delays | Compliance archives, backups |
| Storage Gateway | Hybrid (File/Block/Object) | On-prem to AWS integration | Caching, hybrid cloud support, seamless migration | Backup local data to AWS |

---

## Part 2: Scenario 1 – Data Lake Architecture

### Questions

**Which AWS storage service(s) should be used as the primary storage layer?**  
Amazon S3 should be used as the primary storage layer.

**What architectural advantages does this service provide?**  
Amazon S3 provides virtually unlimited scalability, making it ideal for storing both structured and unstructured data. It supports high durability (99.999999999%) and integrates well with analytics services like AWS Athena, Redshift, and EMR. Additionally, S3 supports lifecycle policies, allowing automatic movement of data to cheaper storage tiers.

**What security controls should be implemented?**  
- Enable server-side encryption (SSE-S3 or SSE-KMS)  
- Enforce least-privilege IAM policies  
- Block public access at the bucket level  
- Enable logging and monitoring (CloudTrail, S3 access logs)  
- Use versioning and MFA delete for critical data  

---

## Part 3: Scenario 3 – Long-Term Regulatory Compliance

### Questions

**Which AWS storage service should be used?**  
Amazon S3 Glacier (or Glacier Deep Archive)

**How does the service balance cost and durability?**  
S3 Glacier offers extremely low storage costs while maintaining the same high durability as standard S3. It reduces cost by allowing slower retrieval times, which is acceptable for long-term archival data that is rarely accessed.

**What compliance or security considerations should be addressed?**  
- Enable encryption for stored data (SSE-KMS preferred)  
- Use access controls with IAM and bucket policies  
- Enable Object Lock (WORM) to prevent deletion or modification  
- Ensure compliance with regulations like HIPAA  
- Maintain audit logs for access and changes  

---

## Notes

- **Object vs Block vs File vs Hybrid:**
  - Object = store whole files (S3)
  - Block = virtual disk attached to instance (EBS)
  - File = shared network folder (EFS)
  - Hybrid = on-prem + cloud integration (Storage Gateway)

- **When to use each:**
  - S3 → large-scale storage, backups, analytics
  - EBS → databases, OS disks, low-latency apps
  - EFS → shared file access across multiple instances
  - Glacier → long-term archive, rarely accessed data
  - Storage Gateway → bridging on-prem to cloud

- **Key security themes across AWS storage:**
  - Always enable encryption (at rest + in transit)
  - Use least privilege (IAM roles/policies)
  - Block public access unless absolutely required
  - Enable logging/monitoring (CloudTrail, access logs)

- **Common mistake:**  
  Misconfigured S3 buckets (public access) are one of the most common causes of cloud data breaches.






# Introduction to Amazon S3 (Lab Notes)


Below are my AWS training notes for the lab at
- https://skillbuilder.aws/learn/R54NZHEX5K/introduction-to-amazon-simple-storage-service-s3/SKTY8SPYDX

## S3 Basics
- S3 = object storage (files = objects stored in buckets)
- Buckets:
  - Must be globally unique
  - 3–63 chars, lowercase, numbers, hyphens only
  - Cannot be renamed after creation


## Default Behavior
- Everything is **private by default**
- Object URLs return **Access Denied** unless permissions allow access


## Permissions Flow (Important)
- **Bucket settings override object settings**
- If Block Public Access is ON → objects cannot be public
- Must disable it first, then allow access via ACL or bucket policy


## ACL Concepts

### ACLs Enabled
- Allows object-level permissions
- Legacy method (bucket policies preferred)

### Object Writer = Object Owner
- The uploader owns the object
- Important when different services/accounts upload files


## EC2 → S3 Access
- EC2 uses an **IAM Role** (`EC2InstanceProfileRole`)
- Role defines what EC2 can do in S3

### Default Behavior
- Can list/read buckets
- Cannot upload → `AccessDenied`

### Fix (Bucket Policy)
- Add policy with:
  - **Principal** = EC2 Role ARN
  - **Actions** = `s3:GetObject`, `s3:PutObject`
  - **Resource** = `arn:aws:s3:::bucket-name/*`


## Key Rule (Important)
- Bucket-level:
```

arn:aws:s3:::bucket-name

```
- Object-level:
```

arn:aws:s3:::bucket-name/*

```


## Public Access
- Disable Block Public Access (not recommended in real world)
- Then allow via ACL or policy

Example URL:
```

[https://bucket-name.s3.region.amazonaws.com/file.png](https://bucket-name.s3.region.amazonaws.com/file.png)

```
## AWS Policy Generator
- Tool to create IAM / S3 policies without writing JSON manually  
- Lets you select:
  - Policy type (S3, IAM, etc.)
  - Actions (GetObject, PutObject, etc.)
  - Principal (who gets access)
  - Resource (ARN)

- Generates the final JSON policy for you

 - https://awspolicygen.s3.amazonaws.com/policygen.html

> Makes it easier to build correct policies and avoid syntax mistakes :contentReference[oaicite:0]{index=0}

## Versioning
- Enabled at **bucket level only**
- Keeps all versions of objects

### Behavior
- Delete once → adds **delete marker** (recoverable)
- Delete again → permanently deleted
- Default returns **latest version**


## Session Manager (SSM)
- Connect to EC2 via browser (no SSH)
- Uses HTTPS (port 443)
- No open inbound ports required
- Uses IAM for authentication

### Why Better Than SSH
- No exposed ports
- No key management
- Auditable sessions


## Security Notes
- Prefer **Session Manager over SSH**
- Use **least privilege IAM roles**
- Keep S3 private unless needed
- Prefer **bucket policies over ACLs**
- Avoid disabling Block Public Access in production


## Knowledge Check

**1. Purpose of versioning**
- Preserve, retrieve, and restore all versions of objects

**2. Default S3 access**
- Private

**3. What does "Principal" define?**
- Who the policy applies to

**4. If bucket name already exists**
- Creation fails (names are globally unique)

**5. What happens when you upload an object with the same name as an existing object in an S3 bucket?**
- The existing object is overwritten
