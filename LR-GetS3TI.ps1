########################################################################################################################
##                                                                                                                    ##
##                          Welcome to the best threat intelligence import script in the world                        ##
##                                                                                                                    ##
##                                          (c) 2019 Mike Contasti-Isaac                                              ##
##                                                                                                                    ##
##                                                    DISCLAIMER                                                      ##
##                                                                                                                    ##
##                        By using this script, you are assuming all risk and liability of damage                     ##
##                                      that this may cause on relevant systems                                       ##
##                                                                                                                    ##
##                                                                                                                    ##
##                                                                                                                    ##
########################################################################################################################

<#
.SYNOPSIS
    LR-GetS3TI.ps1 is a powershell script for retreiving Secure Sense Threat Intelligence from ti.securesense.ca via certificate authenticated web requests and writing this data to text file for ingestion by LogRhythm.
.DESCRIPTION
    LR-GetS3TI.ps1 is a powershell script for retreiving Secure Sense Threat Intelligence from ti.securesense.ca via certificate authenticated web requests and writing this data to text file for ingestion by LogRhythm.
    Config file contains basic global configuration, including the client certificate thumbprint to be used for authentication to https://ti.securesense.ca, as well as list information including name, url & filename.
    This script must be run with the appropriate permissions to write to the $ListFilePath, which by default is C:\Program Files\LogRhythm\LogRhythm Job Manager\config\list_import
.NOTES
    Create by: Mike Contasti-Isaac mcontasti@securesense.ca
    Last Modified on: 2019-07-10
    Changelog:
        2019-07-10: Initial commit
    To Do:
        -Test
    Future Features:
        -More robust error logging
        -Include meta-lists (ti.securesense.ca will serve json formatted replies which include lists of lists)
.PARAMETER ConfigFile
    ConfigFile is the full path to the configuration file.  Default is C:\LogRhythm\Scripts\LR-GetS3TI\config.json
.PARAMETER ListFilePath 
    ListFilePath is the path to the directory where the lists should be stored.  Default is C:\Program Files\LogRhythm\LogRhythm Job Manager\config\list_import
.EXAMPLE
    LR-GetS3TI.ps1
.EXAMPLE
    LR-GetS3TI -ConfigFile "C:\myfolder\config.json" -ListFilePath "D:\Program Files\LogRhythm\LogRhythm Job Manager\config\list_import"
 #>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile="C:\LogRhythm\Scripts\LR-GetS3TI\config.json",
    [Parameter(Mandatory=$false)]
    [string]$ListFilePath="C:\Program Files\LogRhythm\LogRhythm Job Manager\config\list_import"
)

# The following code snippit ignores TLS errors - REMOVE THIS IN PRODUCTION
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
$AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy


function Import-Config {
    Try {
        $config = Get-Content -Raw $ConfigFile | ConvertFrom-Json
        Write-Log -Level Info -Message "Successfully imported config."
        $config
    }
    Catch {
        $errMsg = "An error occured reading the config file.  Please ensure the config file exists and is formatted correctly.  Exiting."
        Write-Error $errMsg
        Write-Log -Level Error -Message $errMsg
        Exit 1
    }
}

function Import-Lists($config) {
    $config.lists | ForEach-Object {
        if ($_.enabled -eq "true") {
            $listname = $_.listname
            $listurl = $_.listurl

            Write-Log "Attempting to retrieve $($listname) from $($listurl)"            
            Try {
                $listresponse = Invoke-WebRequest -Uri $listurl # -CertificateThumbprint $config.config.certificatethumbprint   # Re-add this in active testing
                Write-Log "Successfully retrienve $($listname) from $($listurl)"
            }
            Catch {
                Write-Log -Level Warn "There was an error retreiving the list from $($listurl): $($_)"
                Continue
            }
            Write-Log "Outputting list items for $($_.listname) to $($_.listfile)"
            $fullfilepath = $ListFilePath + "\" + $_.listfile
            Try {
                $content = $listresponse.content.Replace("`n","`r`n")
                Write-Output $content | Out-File -FilePath $fullfilepath
                Write-Log "Successfully wrote list to $($fullfilepath)"
            }
            Catch {
                Write-Log -Level Warn "There was an error writing the list to $($fullfilepath): $($_)"
                Continue
            }
        }
        else {
            Write-Log "Skipping $($_.listname)."
        }
    }
}

# This function came from https://gallery.technet.microsoft.com/scriptcenter/Write-Log-PowerShell-999c32d0 retrieved July 10, 2019, and is therefore much more professionally writen than the rest of this script
function Write-Log {
    [CmdletBinding()] 
    Param 
    ( 
        [Parameter(Mandatory=$true, 
                   ValueFromPipelineByPropertyName=$true)] 
        [ValidateNotNullOrEmpty()] 
        [Alias("LogContent")] 
        [string]$Message, 
 
        [Parameter(Mandatory=$false)] 
        [Alias('LogPath')] 
        [string]$Path='C:\LogRhythm\Scripts\LR-GetS3TI\GetS3TI.log', 
         
        [Parameter(Mandatory=$false)] 
        [ValidateSet("Error","Warn","Info")] 
        [string]$Level="Info", 
         
        [Parameter(Mandatory=$false)] 
        [switch]$NoClobber 
    ) 
 
    Begin 
    { 
        # Set VerbosePreference to Continue so that verbose messages are displayed. 
        $VerbosePreference = 'Continue' 
    } 
    Process 
    { 
         
        # If the file already exists and NoClobber was specified, do not write to the log. 
        if ((Test-Path $Path) -AND $NoClobber) { 
            Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name." 
            Return 
            } 
 
        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path. 
        elseif (!(Test-Path $Path)) { 
            Write-Verbose "Creating $Path." 
            $NewLogFile = New-Item $Path -Force -ItemType File 
            } 
 
        else { 
            # Nothing to see here yet. 
            } 
 
        # Format Date for our Log File 
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss" 
 
        # Write message to error, warning, or verbose pipeline and specify $LevelText 
        switch ($Level) { 
            'Error' { 
                Write-Error $Message 
                $LevelText = 'ERROR:' 
                } 
            'Warn' { 
                Write-Warning $Message 
                $LevelText = 'WARNING:' 
                } 
            'Info' { 
                Write-Verbose $Message 
                $LevelText = 'INFO:' 
                } 
            } 
         
        # Write log entry to $Path 
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append 
    } 
    End 
    { 
    } 
}

$conf = Import-Config
Import-Lists $conf