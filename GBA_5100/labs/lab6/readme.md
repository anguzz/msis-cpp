# Lab 6 – Manage Network-Attached Storage (NFS) on AWS EC2

## Project Overview

This lab demonstrates how to configure a Network File System (NFS) between two Red Hat Enterprise Linux EC2 instances in AWS.

An NFS server exports a directory that is mounted by an NFS client. The mount is configured to persist across reboots using `/etc/fstab`.

---

# Environment Details

| Component             | Value                    |
| --------------------- | ------------------------ |
| NFS Server Private IP | **172.31.19.242**        |
| NFS Client Private IP | **172.31.26.10**         |
| VPC CIDR Block        | **172.31.0.0/16**        |
| OS                    | Red Hat Enterprise Linux |
| Instance Type         | t2.micro / t3.micro      |

---

# 1. NFS Server Configuration

## 1.1 Identify Private IP

```bash
sudo ip address
```

Server Private IPv4:

```
172.31.19.242
```

---

## 1.2 Install Required Packages

```bash
sudo dnf update -y
sudo dnf install rpcbind nfs-utils -y
```

---

## 1.3 Enable and Start NFS Services

```bash
sudo systemctl enable --now nfs-server rpcbind
```

Verify services:

```bash
sudo rpcinfo -p
```

---

## 1.4 Configure Firewall (firewalld)

Install and start firewalld:

```bash
sudo dnf install firewalld -y
sudo systemctl enable --now firewalld
```

Allow NFS services:

```bash
sudo firewall-cmd --permanent --add-service={nfs,rpc-bind,mountd}
sudo firewall-cmd --reload
```

Verify:

```bash
sudo firewall-cmd --list-all
```

---

## 1.5 Create Shared Directory

```bash
sudo mkdir /home/ec2-user/gba5200_my_nfsshare
sudo chmod 777 -R /home/ec2-user/gba5200_my_nfsshare
```

Note:
`777` permissions are used for lab simplicity. This is not recommended in production.

Create test files:

```bash
echo "Server File 1" > /home/ec2-user/gba5200_my_nfsshare/test1.txt
echo "Server File 2" > /home/ec2-user/gba5200_my_nfsshare/test2.txt
```

---

## 1.6 Configure Export

Edit exports file:

```bash
sudo vi /etc/exports
```

Add:

```
/home/ec2-user/gba5200_my_nfsshare 172.31.26.10(rw,no_root_squash)
```

Apply export:

```bash
sudo exportfs -rv
```

Verify export:

```bash
sudo exportfs -v
```

---

# 2. AWS Networking & Security Groups

AWS Security Groups act as stateful virtual firewalls.

## 2.1 Identify VPC CIDR

From the VPC console:

```
172.31.0.0/16
```

This CIDR represents the entire private network range of the VPC.

---

## 2.2 Modify Server Security Group

In the EC2 Console:

1. Select **NFS Server instance**
2. Go to **Security → Security Groups**
3. Edit **Inbound Rules**
4. Add:

| Type        | Source        |
| ----------- | ------------- |
| All traffic | 172.31.0.0/16 |

This allows all instances inside the VPC to communicate with the NFS server.

---

### Production Best Practice (Not Used in Lab)

Instead of allowing the entire VPC:

```
Source: 172.31.26.10/32
```

And limit to:

```
TCP 2049 (NFS)
```

The lab uses broad rules to simplify troubleshooting.

---

# 3. NFS Client Configuration

## 3.1 Install NFS Utilities

```bash
sudo dnf install nfs-utils -y
```

---

## 3.2 Verify Export Availability

```bash
showmount -e 172.31.19.242
```

Expected output:

```
Export list for 172.31.19.242:
/home/ec2-user/gba5200_my_nfsshare 172.31.26.10
```

---

## 3.3 Mount NFS Share

Create mount point:

```bash
sudo mkdir /home/ec2-user/my_share
```

Mount share:

```bash
sudo mount -t nfs 172.31.19.242:/home/ec2-user/gba5200_my_nfsshare /home/ec2-user/my_share
```

---

## 3.4 Verify Mount

```bash
df -h
```

Expected entry:

```
172.31.19.242:/home/ec2-user/gba5200_my_nfsshare
```

List files:

```bash
ls -l /home/ec2-user/my_share
```

Should display:

```
test1.txt
test2.txt
```

---

## 3.5 Create Files from Client

```bash
cd /home/ec2-user/my_share
touch test3.txt
touch test4.txt
```

Verify on server:

```bash
ls /home/ec2-user/gba5200_my_nfsshare
```

You should see all four files.

This confirms bidirectional NFS functionality.

---

# 4. Persist Mount Using /etc/fstab

Without persistence, the mount disappears after reboot.

Edit fstab:

```bash
sudo vi /etc/fstab
```

Add:

```
172.31.19.242:/home/ec2-user/gba5200_my_nfsshare  /home/ec2-user/my_share  nfs  defaults  0 0
```

---

## 4.1 Test Before Rebooting

```bash
sudo umount /home/ec2-user/my_share
sudo mount -a
df -h
```

If the NFS share reappears, configuration is correct.

---

# Technical Notes

## Why No UUID?

UUID is used for local block devices.
NFS is a network filesystem and requires:

```
Server_IP:/Export_Path
```

---

## no_root_squash Explanation

`no_root_squash` allows root on the client to retain root privileges on the server’s shared directory.

This is useful for labs but discouraged in production.

---

## Security Summary

Lab Setup:

* Broad rule: `172.31.0.0/16`
* All traffic allowed

Production Setup:

* Restrict to client IP `/32`
* Allow only required NFS ports (TCP 2049)

---

# Lab Outcome

- NFS Server configured
- Firewall configured
- AWS Security Group configured
- NFS Client mounted share
- File creation verified both directions
- Persistent mount via `/etc/fstab`

