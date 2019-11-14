########################################################################################################################
##                                                                                                                    ##
##                                          (c) 2019 Mike Contasti-Isaac                                              ##
##                                                                                                                    ##
##                                                    DISCLAIMER                                                      ##
##                                                                                                                    ##
##                        By using this script, you are assuming all risk and liability of damage                     ##
##                                      that this may cause on relevant systems                                       ##
##                                                                                                                    ##
##                                                                                                                    ##
########################################################################################################################

<#
.SYNOPSIS
    LR-TestRPC.ps1 is a powershell script for testing the necessary networking and permissions requirements for remote Windows event log collection
.DESCRIPTION
    LR-TestRPC.ps1 is a powershell script for testing the necessary networking and permissions requirements for remote Windows event log collection.
    The script tests network connectivity on most of the necessary ports, as well as permissions if account credentials are provided.
    The script can take a single host as an input, or a file containing a list of hosts.
    The script is interactive and designed to be run from the command line, although a non-interactive version may make sense in some cases
    Requires Powershell 5.0 or later for proper functionality
.NOTES
    Create by: Mike Contasti-Isaac
    Changelog:
        2019-07-24: Initial commit
        2019-11-05: Fixed some broken variables
    To Do:
        -Test and write and everything
    Future Features:
        -Non-interactive option
.PARAMETER Credential
    When the -Credential switch is used, the script will ask for credentials to use to test permissions against the target host(s).  Without this only network connectivity will be tested
.PARAMETER Target
    Use this option followed by a hostname or IP to test against a single host
.PARAMETER HostFile
    Use this option followed by a filename to test against a list of hosts stored in a text file (one host per line)
.PARAMETER Vvv
    For Verbose, This option, when used with a hostfile, will output results with both pass/fail and descriptive messages
.EXAMPLE
    LR-TestRPC.ps1 -Credential -Target mytestpc.domain.com
    LR-TestRPC.ps1 -Hostfile windowshosts.txt -Credential -Vvv
 #>

 [CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$Credential,
    [Parameter(Mandatory=$false)]
    [string]$Target,
    [Parameter(Mandatory=$false)]
    [string]$HostFile,
    [Parameter(Mandatory=$false)]
    [switch]$Vvv
)

Import-Module netsecurity
$creds = $null

Function Test-NetConnectionCustom {
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$true)]
    [string]$ComputerName,
    [Parameter(Mandatory=$true)]
    [string]$Port
    )
    $test = Test-NetConnection -ComputerName $ComputerName -Port $Port -WarningVariable outmsg -WarningAction SilentlyContinue -ErrorAction SilentlyContinue -ErrorVariable outmsg
    if ($test.TcpTestSucceeded -eq $true) {
        $outmsg = "Network connection test was successful"
    }
    $result = [PSCustomObject]@{
        ComputerName = $test.ComputerName
        RemoteAddress = $test.RemoteAddress
        RemotePort = $test.RemotePort
        InterfaceAlias = $test.InterfaceAlias
        SourceAddress = $test.SourceAddress
        PingSucceeded = $test.PingSucceeded
        IngReplyDetails = $test.PingReplyDetails
        TcpTestSucceeded = $test.TcpTestSucceeded
        OutputMessage = [string]$outmsg
    }
    $result
}

Function Test-Networking ($hostname) {
    Try {
        $Result445 = Test-NetConnectionCustom -ComputerName $hostname -Port 445 # -ErrorAction Stop
    }
    Catch {
        $Result445 = $_
    }
    Try {
        $Result135 = Test-NetConnectionCustom -ComputerName $hostname -Port 135 # ErrorAction Stop
    }
    Catch {
        $Result135 = $_
    }
    Try {
        $Result139 = Test-NetConnectionCustom -ComputerName $hostname -Port 139 # -ErrorAction Stop
    }
    Catch {
        $Result139 = $_
    }
    $netresults = [PSCustomObject]@{
        Result445 = $Result445
        Result135 = $Result135
        Result139 = $Result139
    }
   $result = [PSCustomObject]@{
        Host = $hostname
        Results = $netresults
    }
    $result
}

Function Test-Permissions ($hostname, $cred) {
        Try {
            $sectest = Get-WinEvent -LogName "Security" -MaxEvents 1 -ComputerName $hostname -Credential $cred -ErrorAction Stop
        }
        Catch {
            $sectest = $_
        }
        Try {
            $systest = Get-WinEvent -LogName "System" -MaxEvents 1 -ComputerName $hostname -Credential $cred -ErrorAction Stop
        }
        Catch {
            $systest = $_
        }
        Try {
            $apptest = Get-WinEvent -LogName "Application" -MaxEvents 1 -ComputerName $hostname -Credential $cred -ErrorAction Stop
        }
        Catch { 
            $apptest = $_
        }
        $permresults = [PSCustomObject]@{
            SecTest = $sectest
            SysTest = $systest
            AppTest = $apptest
        }
        $result = [PSCustomObject]@{
            Host = $hostname
            Results = $permresults
        }
        $result
}

Function Test-Hostfile ($filepath) {
    if (-Not (Test-Path -Path $filepath)) {
        Write-Output "Cannot find the provided file: $($filepath)"
        Exit
    }
    $hostresults = @()
    foreach($thishost in Get-Content $filepath) {
        $result = New-Object -TypeName psobject
        $result | Add-Member -MemberType NoteProperty -Name Host -Value $thishost
        $netresult = Test-Networking $thishost
        $result | Add-Member -MemberType NoteProperty -Name NetResult -Value $netresult
        if ($creds -ne $null) {
            $permresult = Test-Permissions $thishost $creds
            $result | Add-Member -MemberType NoteProperty -Name PermResult -Value $permresult
        }
        else {
            $result | Add-Member -MemberType NoteProperty -Name PermResult -Value "N/A"
        }
        $hostresults += $result    
    }
    $hostresults
}

Function Write-NetTestResults ($results) {
    Write-Output "Networking test results for $($results.Host):"
    if ($results.Results.Result135.TcpTestSucceeded -ne $true) {
        Write-Output "TCP 135: Failed - $($results.Results.Result135.OutputMessage)"
    }
    else {
        Write-Output "TCP 135: Passed - $($results.Results.Result135.OutputMessage)"
    }
    if ($results.Results.Result139.TcpTestSucceeded -ne $true) {
        Write-Output "TCP 139: Failed - $($results.Results.Result139.OutputMessage)"
    }
    else {
        Write-Output "TCP 139: Passed - $($results.Results.Result139.OutputMessage)"
    }
    if ($results.Results.Result445.TcpTestSucceeded -ne $true) {
        Write-Output "TCP 445: Failed - $($results.Results.Result445.OutputMessage)"
    }
    else {
        Write-Output "TCP 445: Passed - $($results.Results.Result445.OutputMessage)"
    }
}

Function Write-PermTestResults ($results) {
    Write-Output "Permissions test results for $($results.Host):"
    if ($results.Results.AppTest.GetType() -eq [System.Management.Automation.ErrorRecord]) {
        Write-Output "Application Log: Failed - ($($results.Results.AppTest))"
    }
    else{
        Write-Output "Application Log: Passed - Last Event ID: ($($results.Results.AppTest.Id))"
    }
    if ($results.Results.AppTest.GetType() -eq [System.Management.Automation.ErrorRecord]) {
        Write-Output "Security Log: Failed - ($($results.Results.SecTest))"
    }
    else{
        Write-Output "Security Log: Passed - Last Event ID: ($($results.Results.SecTest.Id))"
    }
    if ($results.Results.AppTest.GetType() -eq [System.Management.Automation.ErrorRecord]) {
        Write-Output "System Log: Failed - ($($results.Results.SysTest))"
    }
    else{
        Write-Output "System Log: Passed - Last Event ID: ($($results.Results.SysTest.Id))"
    }
}

Function Write-ListResults ($results) {
    $parsedresults = @()
    $results | ForEach-Object {
        $thishost = New-Object -TypeName psobject
        $thishost | Add-Member -MemberType NoteProperty -Name Hostname -Value $_.Host
        $thisresult = $_
        Switch ($_.NetResult.Results.Result135.TcpTestSucceeded) {
            $true {
                $Tcp135Result = "Passed"
                $Tcp135Msg = $thisresult.NetResult.Results.Result135.OutputMessage
            }
            $false {
                $Tcp135Result = "Failed"
                $Tcp135Msg = $thisresult.NetResult.Results.Result135.OutputMessage
            }
        }
        Switch ($_.NetResult.Results.Result139.TcpTestSucceeded) {
            $true {
                $Tcp139Result = "Passed"
                $Tcp139Msg = $thisresult.NetResult.Results.Result139.OutputMessage
            }
            $false {
                $Tcp139Result = "Failed"
                $Tcp139Msg = $thisresult.NetResult.Results.Result139.OutputMessage
            }
        }
        Switch ($_.NetResult.Results.Result445.TcpTestSucceeded) {
            $true {
                $Tcp445Result = "Passed"
                $Tcp445Msg = $thisresult.NetResult.Results.Result445.OutputMessage
            }
            $false {
                $Tcp445Result = "Failed"
                $Tcp445Msg = $thisresult.NetResult.Results.Result445.OutputMessage
            }
        }
        $thishost | Add-Member -MemberType NoteProperty -Name Tcp135Result -Value $Tcp135Result
        $thishost | Add-Member -MemberType NoteProperty -Name Tcp139Result -Value $Tcp139Result
        $thishost | Add-Member -MemberType NoteProperty -Name Tcp445Result -Value $Tcp445Result
        $thishost | Add-Member -MemberType NoteProperty -Name Tcp135Msg -Value $Tcp135Msg
        $thishost | Add-Member -MemberType NoteProperty -Name Tcp139Msg -Value $Tcp139Msg
        $thishost | Add-Member -MemberType NoteProperty -Name Tcp445Msg -Value $Tcp445Msg
        If ($creds -eq $null) {
            $thishost | Add-Member -MemberType NoteProperty -Name AppResult -Value "N/A"
            $thishost | Add-Member -MemberType NoteProperty -Name SecResult -Value "N/A"
            $thishost | Add-Member -MemberType NoteProperty -Name SysResult -Value "N/A"
            $thishost | Add-Member -MemberType NoteProperty -Name AppMsg -Value "N/A"
            $thishost | Add-Member -MemberType NoteProperty -Name SecMsg -Value "N/A"
            $thishost | Add-Member -MemberType NoteProperty -Name SysMsg -Value "N/A"
        }
        else {
            Switch ($_.PermResult.Results.AppTest.GetType().ToString()) {
                "System.Management.Automation.ErrorRecord" {
                    $AppResult = "Failed"
                    $AppMsg = $thisresult.PermResult.Results.AppTest
                }
                Default {
                    $AppResult = "Passed"
                    $AppMsg = "Last Log ID: $($thisresult.PermResult.Results.AppTest.ID)"
                }
            }
            Switch ($_.PermResult.Results.SecTest.GetType().ToString()) {
                "System.Management.Automation.ErrorRecord" {
                    $SecResult = "Failed"
                    $SecMsg = $thisresult.PermResult.Results.SecTest
                }
                Default {
                    $SecResult = "Passed"
                    $SecMsg = "Last Log ID: $($thisresult.PermResult.Results.SecTest.ID)"
                }
            }
            Switch ($_.PermResult.Results.SysTest.GetType().ToString()) {
                "System.Management.Automation.ErrorRecord" {
                    $SysResult = "Failed"
                    $SysMsg = $thisresult.PermResult.Results.SysTest
                }
                Default {
                    $SysResult = "Passed"
                    $SysMsg = "Last Log ID: $($thisresult.PermResult.Results.SysTest.ID)"
                }
            }
            $thishost | Add-Member -MemberType NoteProperty -Name AppResult -Value $AppResult
            $thishost | Add-Member -MemberType NoteProperty -Name SecResult -Value $SecResult
            $thishost | Add-Member -MemberType NoteProperty -Name SysResult -Value $SysResult
            $thishost | Add-Member -MemberType NoteProperty -Name AppMsg -Value $AppMsg
            $thishost | Add-Member -MemberType NoteProperty -Name SecMsg -Value $SecMsg
            $thishost | Add-Member -MemberType NoteProperty -Name SysMsg -Value $SysMsg
        }
        $parsedresults += $thishost
    }
    if ($Vvv) {
        $parsedresults | ForEach {[PSCustomObject]$_} | Format-List -Property Hostname, Tcp135Result, Tcp135Msg, Tcp139Result, Tcp139Msg, Tcp445Result, Tcp445Msg, AppResult, AppMsg, SecResult, SecMsg, SysResult, SysMsg
    }
    else {
        $parsedresults | ForEach {[PSCustomObject]$_} | Format-List -Property Hostname, Tcp135Result, Tcp139Result, Tcp445Result, AppResult, SecResult,SysResult
    }
}

if ($Credential -eq $true) {
    $creds = Get-Credential -Message "Please enter credentials for remote log collection"
}

if (($Target -eq "") -And ($HostFile -eq "")) {
    Write-Host "Please provide a host using the -Target paramater, or a file containing a list of hosts using the -HostFile paramater"
    Exit
}
if (($HostFile -ne $null) -and ($Target -eq "")) {
    $fileresults = Test-Hostfile $HostFile
    Write-ListResults $fileresults
}
elseif (($Target -ne "") -and ($HostFile -eq "")) {
    $nettest = Test-Networking $Target
    if ($creds -ne $null) {$permtest = Test-Permissions $Target $creds}
    Write-NetTestResults $nettest
    if ($creds -ne $null) {Write-PermTestResults $permtest}
}
elseif (($Target -ne "") -and ($HostFile -ne "")) {
    Write-Host "Please use either the -Target paramater or the -HostFile paramater"
    Exit
}
