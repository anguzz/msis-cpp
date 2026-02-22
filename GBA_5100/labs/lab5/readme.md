# Lab 5

## Configuring and Expanding Linux Storage in AWS (RHEL/Amazon Linux 2)

# High Level Workflow

### Environment Assumption

* Running a Linux VM in AWS (EC2)
* Using EBS volumes for block storage
* Managing storage with LVM
* Filesystem used: XFS

## Phase 1 – Add New Storage Volume

### 1. Create a New EBS Volume in AWS

* Create a new 5GB EBS volume
* Must be in the same Availability Zone as the EC2 instance
* Wait for volume state to become “Available”

### 2. Attach Volume to Instance

* Attach to the running EC2 instance
* Device name typically appears as:

  * `/dev/xvdb`
  * `/dev/nvme1n1`
* Confirm attachment from inside Linux using disk utilities

# Linux Storage Configuration

## Confirm New Disk Exists

* Verify the new disk is visible to the OS
* Ensure correct device name
* Confirm size matches expected (5GB)

# Notes on LVM

LVM (Logical Volume Manager) is a storage abstraction layer in Linux. It sits between physical disks and filesystems, letting you resize, combine, or move storage more flexibly than traditional partitions.

Instead of:

```
Disk → Partition → Filesystem
```

LVM works like:

```
Disk → Physical Volume (PV) → Volume Group (VG) → Logical Volume (LV) → Filesystem
```

## LVM Components Explained

### Physical Volume (PV)

* A disk or partition prepared for LVM
* Represents raw storage added into LVM control
* Example device: `/dev/xvdb`

Think of PV as raw storage added to the LVM pool.

### Volume Group (VG)

* A storage pool made from one or more PVs
* Combines disk space into one logical container
* All Logical Volumes pull space from this pool

Think of VG as a storage reservoir.

### Logical Volume (LV)

* A virtual slice carved from the VG
* Functions like a partition
* Filesystem is created on the LV
* Mounted into the Linux directory tree

Think of LV as the usable virtual disk.

## LVM Key Capabilities

LVM allows you to:

* Expand storage without repartitioning
* Combine multiple disks
* Resize volumes dynamically
* Create snapshots
* Move data between physical disks

This flexibility is especially useful in cloud environments.

# Creating the Filesystem

After creating the LV:

1. Format it (XFS in this lab)
2. Create a mount point (e.g., `/mnt/data`)
3. Mount the filesystem
4. Verify using disk usage utilities

Important concept:
Linux does not use drive letters like Windows. Instead, filesystems are mounted to directories in the root filesystem.

# Making the Mount Persistent

Mounting manually is temporary.

To persist across reboots:

1. Retrieve the UUID of the LV
2. Edit `/etc/fstab`
3. Add a new entry for the mount
4. Test using `mount -a`
5. Reboot to confirm persistence

If `/etc/fstab` is misconfigured:

* The system may boot into emergency mode
* Root may mount read-only
* File operations like `touch` will fail

Testing after reboot confirms proper configuration.

# Phase 2 – Expanding the Volume (5GB → 10GB)

Storage expansion requires changes at multiple layers.

Cloud storage expansion does NOT automatically expand Linux volumes.

The workflow:

## Step 1 – Expand the EBS Volume in AWS

* Modify volume from 5GB → 10GB
* Confirm AWS reports new size

## Step 2 – Confirm Linux Sees New Disk Size

* Verify block device reflects 10GB

## Step 3 – Resize the Physical Volume (PV)

* The PV still thinks it is 5GB
* Resize PV so it recognizes full 10GB
* After resizing:

  * PV size increases
  * Free extents become available
  * VG now has free space

Key concept:
Extents are allocation units LVM uses to manage space.

## Step 4 – Extend the Logical Volume (LV)

* LV still shows 5GB
* Extend LV to use available free space
* LV grows from 5GB → 10GB

Important:
This only resizes the block device, not the filesystem yet.

## Step 5 – Grow the Filesystem (XFS)

* Filesystem still shows 5GB
* Use filesystem grow utility
* Verify final size using disk usage command
* Now `/mnt/data` shows 10GB

This is the final step in full stack storage expansion.

# Layered Expansion Model (Very Important)

When expanding storage in LVM, you must grow each layer in order:

```
AWS Disk → Physical Volume → Volume Group → Logical Volume → Filesystem
```

Each layer must be resized individually.

Skipping a layer will result in unused space.

# What This Lab Demonstrated

This lab covered:

* Creating and attaching EBS volumes in AWS
* Configuring LVM from scratch
* Creating and mounting filesystems
* Making mounts persistent via `/etc/fstab`
* Safely expanding storage in a live cloud system
* Understanding layered storage architecture

It demonstrated how cloud storage and Linux LVM interact together in a real-world scenario.

# Resources

Linux Storage Stack Diagram:
[https://blog.codefarm.me/assets/device-mapper/The%20Linux%20Storage%20Stack%20Diagram.svg](https://blog.codefarm.me/assets/device-mapper/The%20Linux%20Storage%20Stack%20Diagram.svg)

