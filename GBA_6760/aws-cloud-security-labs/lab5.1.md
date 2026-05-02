# AWS Lab 5.1 – Encrypting Data at Rest (KMS)

**Environment:** AWS Console (S3, KMS, EC2, CloudTrail)

---

## Task 1 – Create KMS Key

### Steps
- Go to **KMS → Customer managed keys**
- Click **Create key**
- Key type: **Symmetric**
- Alias: `MyKMSKey`
- Add:
  - Key admin → `voclabs`
  - Key user → `voclabs`
- Finish

### Notes
- KMS key never leaves AWS
- Used to generate **data keys** for encryption

---

## Task 2 – Upload Encrypted Object (S3)

### Steps
- Go to **S3 → Bucket → Objects → Upload**
- Add `clock.png`
- Expand **Properties**
  - Encryption → **Specify encryption key**
  - Type → **SSE-KMS**
  - Key → `MyKMSKey`
- Upload

### Verify
- Click object → **Properties**
- Should show:
  - **SSE-KMS**
  - KMS Key = `MyKMSKey`

### Notes
- S3 uses KMS to generate a **data key**
- Object encrypted with data key, not KMS key directly

---

## Task 3 – Enable Public Access

### Steps

#### Disable block public access
- S3 → Bucket → **Permissions**
- Edit → Uncheck **Block all public access**
- Save (`confirm`)

#### Enable ACLs
- **Object Ownership → Edit**
- Select **ACLs enabled**
- Save

#### Make object public
- Go to **Objects**
- Select `clock.png`
- **Actions → Make public using ACL**

#### Bucket ACL (important)
- Permissions → **Edit ACL**
- Under **Everyone (public access)**
  - Check **Read**
- Save

### Notes
- Bucket-level + object-level permissions both required
- Default S3 = private

---

## Task 4 – Decrypt Object

### Steps
- Go to **Objects**
- Select `clock.png`
- Click **Open**

### Notes
- This uses **signed request (SigV4)**
- Triggers:
  - S3 → KMS → decrypt data key → decrypt object

### Important
- Opening via URL alone does NOT count
- Must open via **S3 console**

---

## Task 5 – CloudTrail (KMS Logging)

### Steps
- Go to **CloudTrail → Event history**
- Filter: `kms.amazonaws.com`

### Look for:
- `GenerateDataKey` → during upload
- `Decrypt` → when opening object

### Notes
- Shows:
  - Who used the key
  - Which resource
  - What action

---

## Task 6 – Encrypt EC2 Root Volume

### Steps

#### Stop instance
- EC2 → Instances → `LabInstance`
- Stop

#### Create snapshot
- Storage tab → click Volume ID
- Actions → **Create snapshot**
- Name: `Unencrypted Root Volume`

#### Create encrypted volume
- Go to **Snapshots**
- Select snapshot → **Create volume**
  - Same AZ
  - Enable **Encrypt**
  - Key: `MyKMSKey`

#### Swap volumes
- Go to **Volumes**
- Rename:
  - Old → `Old unencrypted root volume`
  - New → `New encrypted root volume`
- Detach old
- Attach new:
  - Instance: `LabInstance`
  - Device: `/dev/xvda`

### Notes
- Root volume must match device name
- Encryption requires snapshot → new volume

---

## Task 7 – Start Encrypted Instance

### Steps
- EC2 → Instances
- Start `LabInstance`

### Notes
- Instance now uses encrypted root volume
- Requires KMS key to decrypt at boot

---

## Key Concepts

### Envelope Encryption
- KMS key → encrypts **data key**
- Data key → encrypts actual data

### SSE-KMS Flow
1. S3 requests data key from KMS
2. KMS returns:
   - Plaintext key
   - Encrypted key
3. S3 encrypts object
4. Stores encrypted key with object

---

## Security Takeaways

- Public access ≠ readable if encrypted
- KMS key controls **actual access**
- Disabling key = data becomes unusable
- CloudTrail logs all key usage

---

## Common Issues

- Forgot to select **SSE-KMS during upload**
- Didn’t enable **ACLs**
- Didn’t make object public via **Actions**
- Didn’t open object via **console (for decrypt)**

---

## Final State

- S3 object encrypted with `MyKMSKey`
- Object publicly accessible but still protected by KMS
- EC2 root volume encrypted
- KMS activity visible in CloudTrail