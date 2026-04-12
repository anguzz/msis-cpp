# PowerShell Lab Notes (CH2 & CH3)

**Environment:** Completed on Windows Server 2025 provisioned in AWS

---

## CH2 – Working with Cmdlets

### Get-ChildItem (gci)

* Alias: `gci`, `dir`, `ls`
* Used to list files and directories

```powershell
gci
```

---

### Aliases

* PowerShell provides shortcuts for cmdlets

```powershell
gal -definition Get-ChildItem
```

* Output shows:

  * `dir`
  * `gci`
  * `ls`

---

### Filtering with Where-Object

* Used to filter output from pipelines

```powershell
gci | Where-Object {$_.Length -gt 1000}
```

#### Notes:

* `Length` = file size (only applies to files)
* Directories return null for Length

---

### Pipeline (`|`)

* Passes output from one command into another

```powershell
gci | Where length -gt 1000
```

---

### Clearing Console

```powershell
cls
# or
Clear-Host
```

---

### Get-Member (gm)

* Used to inspect object properties and methods

```powershell
Get-ChildItem | Get-Member -MemberType Property
```

#### Key Properties:

* `Name` → file name
* `Length` → file size
* `CreationTime` → created date
* `LastAccessTime` → last accessed
* `LastWriteTime` → last modified

---

### Filtering by Date

```powershell
Get-ChildItem | Where-Object {$_.LastWriteTime -gt "12/25/2025"}
```

* `-gt` = greater than
* Filters files modified after a specific date

---

### Recursive Search

```powershell
Get-ChildItem -Recurse C:\Windows
```

* Searches all subdirectories
* Can be slow on large directories

---

## CH3 – PowerShell Providers

### What are Providers?

* Allow PowerShell to treat different data stores like a filesystem
* Examples:

  * FileSystem (`C:\`)
  * Registry (`HKLM:\`)
  * Certificate (`Cert:\`)
  * Environment (`env:\`)

---

## Certificate Provider

### Navigate to Cert Drive

```powershell
sl cert:\
```

### List Certificates

```powershell
gci
```

### Recursive Listing

```powershell
gci -Recurse
```

### Output to File

```powershell
gci -Recurse > C:\a.txt
notepad.exe C:\a.txt
```

---

## Environment Provider

### View Environment Variables

```powershell
Get-Item env:\
```

---

### Store in Variable

```powershell
$objEnv = Get-Item env:\
```

---

### Count Variables

```powershell
$objEnv.Count
```

---

### Method vs Property

```powershell
$objEnv.Get_Count()   # method (requires parentheses)
$objEnv.Count         # property
```

---

### Get Object Type

```powershell
$objEnv.GetType()
```

---

## PSDrive (Custom Drives)

### Create Drive

```powershell
New-PSDrive -Name al -PSProvider alias -Root .
```

### Navigate

```powershell
sl al:\
```

### Remove Drive

```powershell
Remove-PSDrive al
```

---

## Key Takeaways

* PowerShell works with objects, not plain text
* `Get-Member` is used to explore object structure
* Pipelines (`|`) pass objects between commands
* `Where-Object` filters data
* Providers allow interaction with files, registry, certificates, and environment variables

---

## Lab Context

This lab focused on:

* Using `Get-ChildItem` and `Get-Member`
* Filtering with `Where-Object`
* Navigating providers such as `Cert:` and `env:` 
