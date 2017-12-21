<# 
.Synopsis
Script executing commands from SCCM Device node Action extension
.Description
SCCM Action Extension. Allow to start PS Remote Session on selected computer.
.Related links
How to find GUID of SCCM console items: https://blogs.technet.microsoft.com/neilp/2012/03/18/long-live-right-click-tools-system-center-2012-configuration-manager-console-extensions/
SCCM Console Builder: https://blogs.technet.microsoft.com/matt_hinsons_manageability_blog/2013/08/21/using-configmgr-2012-console-builder-create-custom-console-nodes/
General MS How-to: https://msdn.microsoft.com/en-us/library/hh458432.aspx
#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Option,

    [parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$hostname,

    [parameter(Mandatory = $true)]
    [ValidateScript({Test-Connection -ComputerName $_ -Count 1 -Quiet})]
    [ValidateNotNullOrEmpty()]
    [string]$SiteServer
)

function GetUserCred {
Param(
    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$username
)
    $FILE = "$Env:HOMEDRIVE$Env:HOMEPATH\$username.password"
    if ((Test-Path $FILE) -eq $false)
    {
        Read-Host -Prompt "CZ\$username password (will be encrypted into file $FILE)" -AsSecureString | ConvertFrom-SecureString | Out-File $FILE -Force
    }
    Write-Verbose -Message "Reading credentials from file $FILE..."
    $pwd = Get-Content $FILE | ConvertTo-SecureString
    $crd = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "cz\$username", $pwd
    Write-Verbose -Message "Created PSCredentials object"
    return $crd
}

switch ($Option) {
    "RemotePS" {
        Write-Verbose -Message "Testing connection to $hostname..."
        if ((Test-Connection -ComputerName $hostname -Count 2 -Quiet) -eq $true) {
            Write-Verbose -Message "Connection is OK, creating new remote session..."
            $Session = New-PSSession $hostname -Credential (GetUserCred "wkadm") -Authentication Kerberos 
            Enter-PSSession -Session $Session
            Write-Verbose -Message "Remote session connected"
            Invoke-Command -Session $Session -ScriptBlock {Get-WmiObject -Class Win32_ComputerSystem | Select-Object username}
        } else {
            Write-Warning -Message "Computer $($hostname) appears to be offline. Please check conenction first."
        }
    }
    "TestConn" {
        Write-Verbose -Message "Testing connection to $hostname from server $SiteServer..."
        Test-Connection -Source $SiteServer -Credential (GetUserCred "srvadm") -ComputerName $hostname
        Write-Verbose -Message "Testing connection to $hostname from this host..."
        if (Test-Connection -ComputerName $hostname -Count 2 -Quiet) {
            Write-Host "Logged-on " -NoNewline
            Get-WmiObject -ComputerName $hostname -Credential (GetUserCred "wkadm") -Class Win32_ComputerSystem | Select-Object username
        }
    }
}