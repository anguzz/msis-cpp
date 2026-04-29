# PowerShell Lab Notes (CH10–CH12)

**Environment:** Windows Server 2025 (AWS EC2 Instance)

---

## CH10 – Working with Services

### Get All Services

```powershell
Get-Service
````

* Lists all services with current status

---

### Sort Services by Status

```powershell
Get-Service | sort status
```

* Groups Running vs Stopped services

---

### Sort Services by Name

```powershell
Get-Service | sort name
```

* Alphabetical listing of services

---

### Sort by Multiple Properties

```powershell
Get-Service | sort status, name
```

* First by status, then by name

---

### Filter by Display Name

```powershell
Get-Service -DisplayName *server*
```

* Finds services containing "server"

---

### Work with a Single Service (BITS)

```powershell
$a = Get-Service -Name BITS
```

---

### Inspect Object

```powershell
$a | gm
```

* Shows properties and methods

---

### Check Service Status

```powershell
$a.status
```

---

### Stop / Start Service

```powershell
Stop-Service -InputObject $a
Start-Service -InputObject $a
```

---

## CH11 – Working with Software (WMI)

### Query Installed Software (Win32_Product)

```powershell
$Query = "Select * from Win32_Product"
Get-CimInstance -Query $Query
```

* Retrieves installed applications (slow operation)

---

### Add Execution Timer

```powershell
$dteStart = Get-Date

$Query = "Select * from Win32_Product"

Write-Host "Counting Installed Products. This may take a while." -ForegroundColor Blue

Get-CimInstance -Query $Query

$dteEnd = Get-Date
$dteDiff = New-TimeSpan $dteStart $dteEnd

Write-Host "It took" $dteDiff.TotalSeconds "seconds to complete"
```

---

### Key Concepts

* `Win32_Product` triggers MSI consistency check (slow)
* `Get-CimInstance` preferred over legacy WMI
* `New-TimeSpan` used for execution timing

---

## CH12 – PowerShell Remoting & WMI

> Lab note: Used **localhost** instead of domain system (`NWTraders\C10`) 

---

### Create CIM Session

```powershell
$session = New-CimSession -ComputerName localhost
```

---

### Get Remote Processes

```powershell
Get-CimInstance -CimSession $session -ClassName Win32_Process
```

---

### Get Services (Name + State, Sorted)

```powershell
Get-CimInstance -CimSession $session -ClassName Win32_Service -Property Name, State |
Sort-Object State |
Format-Table Name, State -AutoSize
```

---

### WMI Query (BIOS Info)

```powershell
$credential = Get-Credential
Get-WmiObject -Class Win32_BIOS -ComputerName localhost -Credential $credential
```

---

### PowerShell Remoting (Invoke-Command)

```powershell
Invoke-Command -ComputerName localhost `
-ScriptBlock { Get-CimInstance Win32_BIOS } `
-Credential $credential
```

---

## Key Takeaways

* `Get-Service` is simple and fast for service info
* `Get-CimInstance` provides deeper system data via WMI
* `Win32_Product` is powerful but slow and should be used cautiously
* CIM sessions allow structured remote queries
* `Invoke-Command` enables full remote execution

---

## Lab Context

This lab focused on:

* Managing Windows services via PowerShell
* Querying installed software using WMI
* Measuring script execution time
* Using CIM sessions for remote queries
* Executing remote commands with PowerShell remoting

