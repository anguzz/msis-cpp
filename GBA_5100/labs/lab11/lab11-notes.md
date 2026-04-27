# PowerShell Lab Notes (CH4–CH6)

**Environment:** Completed on Windows Server 2025 provisioned in AWS


## CH4 – PowerShell Remoting & Jobs

### Get-Credential

* Used to store alternate credentials

```powershell
$cred = Get-Credential
```


### Enter Remote Session

```powershell
Enter-PSSession -ComputerName localhost -Credential $cred
```

#### Notes:

* Changes prompt to remote session:

  ```
  [localhost]: PS C:\>
  ```
* Allows running commands as another user


### Verify User Context

```powershell
whoami
```

* Confirms current user identity


### Exit Remote Session

```powershell
exit
```


### WMI with Credentials (Fails Locally)

```powershell
Get-WmiObject -Class Win32_BIOS -ComputerName localhost -Credential $cred
```

#### Notes:

* Fails with:

  * “User credentials cannot be used for local connections”


### Invoke-Command (Fix for WMI)

```powershell
Invoke-Command -ComputerName localhost -ScriptBlock { Get-WmiObject -Class Win32_BIOS } -Credential $cred
```

#### Notes:

* Runs command remotely using credentials
* Works around local WMI credential limitation


### Run Without Credentials

```powershell
Invoke-Command -ComputerName localhost -ScriptBlock { Get-WmiObject -Class Win32_BIOS }
```

* May fail if user lacks remote permissions


### Run Command on Multiple Systems

```powershell
$cn = "localhost","server1","server2"

Invoke-Command -ComputerName $cn -ScriptBlock { Get-WmiObject -Class Win32_BIOS }
```


## CH5 – Creating Multiple Folders (Scripting)

### Variables

```powershell
$intFolders = 10
$i = 1
New-Variable -Name strPrefix -Value "testFolder" -Option Constant
```


### Do...Until Loop

```powershell
do {
    if ($i -lt 10) {
        $intPad = 0
        New-Item -Path C:\mytempfolder -Name $strPrefix$intPad$i -ItemType Directory
    }
    else {
        New-Item -Path C:\mytempfolder -Name $strPrefix$i -ItemType Directory
    }

    $i++
} until ($i -eq $intFolders + 1)
```


### Key Concepts

* Loop creates folders:

  * `testFolder01 → testFolder10`
* `Do...Until` ensures loop runs correct number of times
* `$i++` increments counter


## CH6 – Creating a Function

### Get Approved Verbs

```powershell
Get-Verb
```


### Create Function

```powershell
Function Get-FilesByDate
{
    Param(
        [string[]]$fileTypes,
        [int]$month,
        [int]$year,
        [string[]]$path
    )

    Get-ChildItem -Path $path -Include $fileTypes -Recurse |
    Where-Object {
        $_.LastWriteTime.Month -eq $month -and
        $_.LastWriteTime.Year -eq $year
    }
}
```


### Run Function

```powershell
Get-FilesByDate -fileTypes *.docx -month 5 -year 2025 -path C:\data
```


### Key Concepts

* Functions organize reusable logic
* Parameters allow dynamic input
* `Where-Object` filters by:

  * Month
  * Year
* Recursive search scans directories


## Key Takeaways

* PowerShell remoting allows executing commands on remote systems
* `Invoke-Command` is used for remote execution
* WMI has limitations with local credentials
* Loops (`Do...Until`) automate repetitive tasks
* Functions make scripts reusable and modular


## Lab Context

This lab focused on:

* Using PowerShell remoting and credentials
* Running commands across systems
* Automating folder creation with loops
* Building reusable PowerShell functions
