#  AWS Lab 4: Working with EBS Volumes

## Overview
This lab focused on **Amazon Elastic Block Store (EBS)**, providing hands-on experience with persistent block storage for EC2. I performed the end-to-end process of provisioning storage, mounting it within a Linux guest OS, creating point-in-time backups (Snapshots), and demonstrating a successful disaster recovery scenario.



## Objectives
*   **Provision** a new EBS volume and attach it to an existing EC2 instance.
*   **Initialize** and mount the volume using the Linux CLI.
*   **Automate** persistence by updating the filesystem table (`/etc/fstab`).
*   **Protect** data by creating an Amazon EBS Snapshot.
*   **Recover** data by restoring a snapshot into a new EBS volume and verifying file integrity.

---

##  Technical Implementation Details

### 1. Storage Provisioning & Attachment
I created a **1 GiB General Purpose SSD (gp2)** volume in the same Availability Zone as the "Lab" instance. 
*   **Device Mapping:** Attached the volume to the instance as `/dev/sdb`.

### 2. Full Terminal Session Output
The following is the complete, unedited output from the terminal session during the configuration and restoration process:



```shell
sh-5.2$ sudo su -l ec2-user
[ec2-user@ip-10-1-11-80 ~]$ df -h
Filesystem      Size  Used Avail Use% Mounted on
devtmpfs        4.0M     0  4.0M   0% /dev
tmpfs           481M     0  481M   0% /dev/shm
tmpfs           193M  444K  192M   1% /run
/dev/xvda1      8.0G  1.6G  6.4G  20% /
tmpfs           481M     0  481M   0% /tmp
/dev/xvda128     10M  1.3M  8.7M  13% /boot/efi
tmpfs            97M     0   97M   0% /run/user/0
[ec2-user@ip-10-1-11-80 ~]$ sudo mkfs -t ext3 /dev/sdb
mke2fs 1.46.5 (30-Dec-2021)
Creating filesystem with 262144 4k blocks and 65536 inodes
Filesystem UUID: d55f0696-8d76-4178-a0d7-18d51ff61273
Superblock backups stored on blocks:
        32768, 98304, 163840, 229376

Allocating group tables: done
Writing inode tables: done
Creating journal (8192 blocks): done
Writing superblocks and filesystem accounting information: done

[ec2-user@ip-10-1-11-80 ~]$ sudo mkdir /mnt/data-store
[ec2-user@ip-10-1-11-80 ~]$ sudo mount /dev/sdb /mnt/data-store
[ec2-user@ip-10-1-11-80 ~]$ echo "/dev/sdb   /mnt/data-store ext3 defaults,noatime 1 2" | sudo tee -a /etc/fstab
/dev/sdb   /mnt/data-store ext3 defaults,noatime 1 2
[ec2-user@ip-10-1-11-80 ~]$ cat /etc/fstab
#
UUID=81d2a390-b1be-4f50-bb43-1fa424fea57e     /           xfs    defaults,noatime  1   1
UUID=D0B6-1AF2        /boot/efi       vfat    defaults,noatime,uid=0,gid=0,umask=0077,shortname=winnt,x-systemd.automount 0 2
/dev/sdb   /mnt/data-store ext3 defaults,noatime 1 2
[ec2-user@ip-10-1-11-80 ~]$ df -h
Filesystem      Size  Used Avail Use% Mounted on
devtmpfs        4.0M     0  4.0M   0% /dev
tmpfs           481M     0  481M   0% /dev/shm
tmpfs           193M  440K  192M   1% /run
/dev/xvda1      8.0G  1.6G  6.4G  20% /
tmpfs           481M     0  481M   0% /tmp
/dev/xvda128     10M  1.3M  8.7M  13% /boot/efi
tmpfs            97M     0   97M   0% /run/user/0
/dev/xvdb       975M   60K  924M   1% /mnt/data-store
[ec2-user@ip-10-1-11-80 ~]$ sudo sh -c "echo some text has been written > /mnt/data-store/file.txt"
[ec2-user@ip-10-1-11-80 ~]$ cat /mnt/data-store/file.txt
some text has been written
[ec2-user@ip-10-1-11-80 ~]$ sudo rm /mnt/data-store/file.txt
[ec2-user@ip-10-1-11-80 ~]$ ls /mnt/data-store/
lost+found
[ec2-user@ip-10-1-11-80 ~]$ ls /mnt/data-store/
lost+found
[ec2-user@ip-10-1-11-80 ~]$ sudo mkdir /mnt/data-store2
[ec2-user@ip-10-1-11-80 ~]$ sudo mount /dev/sdc /mnt/data-store2
[ec2-user@ip-10-1-11-80 ~]$ ls /mnt/data-store2/
file.txt  lost+found
[ec2-user@ip-10-1-11-80 ~]$
```

---

##  Recovery & Restoration Workflow

### 3. Snapshot and Restoration
I simulated data protection and recovery through the following AWS Console actions:
1.  **Snapshot:** Created a point-in-time copy of `My Volume` named `My Snapshot`.
2.  **Destructive Test:** Deleted `file.txt` from the primary mount point.
3.  **Restoration:** Created a `Restored Volume` from the snapshot and attached it to the instance as `/dev/sdc`.
4.  **Verification:** Mounted the restored device to `/mnt/data-store2` and confirmed the file was recovered.



##  Outcomes & Key Learnings
*   **Final Score:** 100%
*   **Persistence:** Confirmed that EBS volumes persist independently of the EC2 instance, providing a durable storage layer.
*   **Snapshot Efficiency:** Learned that snapshots are incremental, saving only changed blocks, which is vital for cost-efficient backups.
*   **Linux Administration:** Practiced critical disk utility commands (`mkfs`, `mount`, `tee`) and filesystem table management (`/etc/fstab`).


