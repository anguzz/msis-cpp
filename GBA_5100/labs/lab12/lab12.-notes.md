
# PowerShell Lab Notes (CH7–CH9)

**Environment:** Windows 10 & 11 / PowerShell ISE

---

## CH7 – Advanced Function (Get-MyBios)

### Creating Function

```powershell
#requires -version 5.0

function Get-MyBios {
    [CmdletBinding()]
    param (
        [Alias("cn")]
        [Parameter(ValueFromPipeline=$true, Position=0, ParameterSetName="remote")]
        [string]$ComputerName
    )

    process {
        switch ($PSCmdlet.ParameterSetName) {
            "remote" { Get-CimInstance -ClassName Win32_BIOS -ComputerName $ComputerName }
            default  { Get-CimInstance -ClassName Win32_BIOS }
        }
    }
}
```

---

### Key Concepts

* Advanced function uses `[CmdletBinding()]`
* Supports parameters like real cmdlets
* Uses `Get-CimInstance` to retrieve BIOS info
* `Switch` handles local vs remote execution

---

### Running Function

```powershell
Get-MyBios
Get-MyBios -cn localhost
```

---

### Viewing Help

```powershell
Get-Help Get-MyBios -Full
```

* Displays syntax, parameters, and examples 

---

## CH8 – Commands Add-on & WMI

### Invoke WMI Method (Create Process)

```powershell
Invoke-WmiMethod -Class Win32_Process -Name create -ArgumentList notepad
```

---

### Run Multiple Programs

```powershell
Invoke-WmiMethod -Class Win32_Process -Name create -ArgumentList "notepad; calc"
```

* `;` separates commands 

---

### Stop Processes

```powershell
Stop-Process -Name notepad, calc
```

---

### Verify Processes

```powershell
Get-Process -Name calc, notepad
```

* Expected result:

  * Errors if processes are not running (this is correct behavior) 

---

## CH9 – PowerShell Profile

### Check Profile

```powershell
Test-Path $PROFILE
```

---

### Create Profile

```powershell
New-Item $PROFILE -ItemType File -Force
```

---

### Open Profile

```powershell
ise $PROFILE
```

---

### Add Function

```powershell
Function Set-Profile {
    ise $PROFILE
}
```

* Stored inside profile file (not separate script)

---

### Test Function

```powershell
Set-Profile
```

* Opens profile in ISE 

---

## Key Takeaways

* Advanced functions behave like cmdlets
* `Get-CimInstance` replaces older WMI commands
* Commands Add-on helps build commands visually (under view tab)
* `Invoke-WmiMethod` can launch processes
* PowerShell profiles persist functions across sessions

---

## Lab Context

This lab focused on:

* Creating advanced PowerShell functions
* Using WMI to manage processes
* Managing PowerShell profiles and persistence 

