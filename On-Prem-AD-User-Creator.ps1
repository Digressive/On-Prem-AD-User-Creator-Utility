<#PSScriptInfo

.VERSION 21.09.15

.GUID eaaca86c-2a1f-4caf-b2f9-05868186d162

.AUTHOR Mike Galvin Contact: mike@gal.vin / twitter.com/mikegalvin_ / discord.gg/5ZsnJ5k

.COMPANYNAME Mike Galvin

.COPYRIGHT (C) Mike Galvin. All rights reserved.

.TAGS Active Directory User Creation CSV Import

.LICENSEURI

.PROJECTURI https://gal.vin/2017/09/13/powershell-create-ad-users-from-csv/

.ICONURI

.EXTERNALMODULEDEPENDENCIES Active Directory Management PowerShell module.

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES

#>

<#
    .SYNOPSIS
    On-Prem AD User Creator Utility - Configurable Script to create new Active Directory user accounts.

    .DESCRIPTION
    This script will create AD users based on first and last names in a specified CSV file.
    All other options are added via command line switches.

    The command line switches provide configuration for:
    Organisational Unit to create the new users.
    User's UPN.
    Home Drive location.
    Home Drive letter.
    Membership of Active Directory Groups.

    To send a log file via e-mail using ssl and an SMTP password you must generate an encrypted password file.
    The password file is unique to both the user and machine.
    To create the password file run this command as the user and on the machine that will use the file:

    $creds = Get-Credential
    $creds.Password | ConvertFrom-SecureString | Set-Content C:\scripts\ps-script-pwd.txt

    .PARAMETER CSV
    The path and filename of the csv file containing the user information.
    Please see the users-example.csv file for how to structure your own file.

    .PARAMETER OU
    The Organisational Unit to create the users in.

    .PARAMETER UPN
    The Universal Principal Name the users should be configured with.

    .PARAMETER HomeLetter
    The drive letter to use for the home drive path.

    .PARAMETER HomePath
    The path where the location of the home drive should reside.

    .PARAMETER Groups
    The name of the group(s) separated by a comma (,) that all the new users should be a member of.

    .PARAMETER NoBanner
    Use this option to hide the ASCII art title in the console.

    .PARAMETER L
    The path to output the log file to.
    The file name will be On-Prem-AD-User-Creator_YYYY-MM-dd_HH-mm-ss.log
    Do not add a trailing \ backslash.

    .PARAMETER Subject
    The subject line for the e-mail log.
    Encapsulate with single or double quotes.
    If no subject is specified, the default of "New Users AD Log" will be used.

    .PARAMETER SendTo
    The e-mail address the log should be sent to.

    .PARAMETER From
    The e-mail address the log should be sent from.

    .PARAMETER Smtp
    The DNS name or IP address of the SMTP server.

    .PARAMETER Port
    The Port that should be used for the SMTP server.

    .PARAMETER User
    The user account to authenticate to the SMTP server.

    .PARAMETER Pwd
    The txt file containing the encrypted password for SMTP authentication.

    .PARAMETER UseSsl
    Configures the utility to connect to the SMTP server using SSL.

    .EXAMPLE
    On-Prem-AD-User-Creator.ps1 -csv C:\scripts\user-list.csv -upn contoso.com -ou 'OU=User_Accounts,DC=contoso,DC=com' -HomeLetter X -HomePath \\fs01\users$ -Groups UserGroup1,UserGroup2
    -L C:\scripts\logs -Subject 'Server: New Users Log' -SendTo me@contoso.com -From New-Users-AD@contoso.com -Smtp smtp.outlook.com -User user@contoso.com -Pwd C:\scripts\ps-script-pwd.txt -UseSsl

    This will create new users from the names in the csv file located in C:\scripts\user-list.csv and set their Home Drive letter to X and the path to \\fs01\users$\%username%.
    The users will also be added to the groups UserGroup1 and UserGroup2. The log file will be output to C:\scripts\logs and sent via e-mail with a custom subject line.
#>

## Set up command line switches.
[CmdletBinding()]
Param(
    [parameter(Mandatory=$True)]
    [alias("CSV")]
    $UsersList,
    [parameter(Mandatory=$True)]
    [alias("OU")]
    $OrgUnit,
    [parameter(Mandatory=$True)]
    [alias("UPN")]
    $AdUpn,
    [alias("HomeLetter")]
    $HomeDrive,
    [alias("HomePath")]
    $HomeUnc,
    [alias("Groups")]
    $AdGrps,
    [alias("L")]
    [ValidateScript({Test-Path $_ -PathType 'Container'})]
    $LogPath,
    [alias("Subject")]
    $MailSubject,
    [alias("SendTo")]
    $MailTo,
    [alias("From")]
    $MailFrom,
    [alias("Smtp")]
    $SmtpServer,
    [alias("Port")]
    $SmtpPort,
    [alias("User")]
    $SmtpUser,
    [alias("Pwd")]
    [ValidateScript({Test-Path -Path $_ -PathType Leaf})]
    $SmtpPwd,
    [switch]$UseSsl,
    [switch]$NoBanner)

If ($NoBanner -eq $False)
{
    Write-Host -Object ""
    Write-Host -ForegroundColor Yellow -BackgroundColor Black -Object "      _   __                __  __                             "
    Write-Host -ForegroundColor Yellow -BackgroundColor Black -Object "     / | / /__ _      __   / / / /_______  __________          "
    Write-Host -ForegroundColor Yellow -BackgroundColor Black -Object "    /  |/ / _ \ | /| / /  / / / / ___/ _ \/ ___/ ___/          "
    Write-Host -ForegroundColor Yellow -BackgroundColor Black -Object "   / /|  /  __/ |/ |/ /  / /_/ (__  )  __/ /  (__  )           "
    Write-Host -ForegroundColor Yellow -BackgroundColor Black -Object "  /_/ |_/\___/|__/|__/___\____/____/\___/_/  /____/            "
    Write-Host -ForegroundColor Yellow -BackgroundColor Black -Object "     /   |  / __ \   / __ \____     / __ \________  ____ ___   "
    Write-Host -ForegroundColor Yellow -BackgroundColor Black -Object "    / /| | / / / /  / / / / __ \   / /_/ / ___/ _ \/ __ '__ \  "
    Write-Host -ForegroundColor Yellow -BackgroundColor Black -Object "   / ___ |/ /_/ /  / /_/ / / / /  / ____/ /  /  __/ / / / / /  "
    Write-Host -ForegroundColor Yellow -BackgroundColor Black -Object "  /_/  |_/_____/   \____/_/ /_/  /_/   /_/   \___/_/ /_/ /_/   "
    Write-Host -ForegroundColor Yellow -BackgroundColor Black -Object "                                                               "
    Write-Host -ForegroundColor Yellow -BackgroundColor Black -Object "     Mike Galvin   https://gal.vin        Version 21.09.15     "
    Write-Host -ForegroundColor Yellow -BackgroundColor Black -Object "                                                               "
    Write-Host -Object ""
}

## If logging is configured, start logging.
## If the log file already exists, clear it.
If ($LogPath)
{
    $LogFile = ("On-Prem-AD-User-Creator_{0:yyyy-MM-dd_HH-mm-ss}.log" -f (Get-Date))
    $Log = "$LogPath\$LogFile"

    $LogT = Test-Path -Path $Log

    If ($LogT)
    {
        Clear-Content -Path $Log
    }

    Add-Content -Path $Log -Encoding ASCII -Value "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") [INFO] Log started"
}

## Function to get date in specific format.
Function Get-DateFormat
{
    Get-Date -Format "yyyy-MM-dd HH:mm:ss"
}

## Function for logging.
Function Write-Log($Type, $Evt)
{
    If ($Type -eq "Info")
    {
        If ($Null -ne $LogPath)
        {
            Add-Content -Path $Log -Encoding ASCII -Value "$(Get-DateFormat) [INFO] $Evt"
        }
        
        Write-Host -Object "$(Get-DateFormat) [INFO] $Evt"
    }

    If ($Type -eq "Succ")
    {
        If ($Null -ne $LogPath)
        {
            Add-Content -Path $Log -Encoding ASCII -Value "$(Get-DateFormat) [SUCCESS] $Evt"
        }

        Write-Host -ForegroundColor Green -Object "$(Get-DateFormat) [SUCCESS] $Evt"
    }

    If ($Type -eq "Err")
    {
        If ($Null -ne $LogPath)
        {
            Add-Content -Path $Log -Encoding ASCII -Value "$(Get-DateFormat) [ERROR] $Evt"
        }

        Write-Host -ForegroundColor Red -BackgroundColor Black -Object "$(Get-DateFormat) [ERROR] $Evt"
    }

    If ($Type -eq "Conf")
    {
        If ($Null -ne $LogPath)
        {
            Add-Content -Path $Log -Encoding ASCII -Value "$Evt"
        }

        Write-Host -ForegroundColor Cyan -Object "$Evt"
    }
}

##
## Display the current config and log if configured.
##
Write-Log -Type Conf -Evt "************ Running with the following config *************."

Write-Log -Type Conf -Evt "CSV file:..............$UsersList."
Write-Log -Type Conf -Evt "OU for users:..........$OrgUnit."
Write-Log -Type Conf -Evt "UPN to use:............$AdUpn."

If ($Null -ne $HomeDrive)
{
    Write-Log -Type Conf -Evt "Home Letter:...........$HomeDrive."
}

else {
    Write-Log -Type Conf -Evt "Home Letter:...........No Config"
}

If ($Null -ne $HomeUnc)
{
    Write-Log -Type Conf -Evt "Home UNC Path:.........$HomeUnc."
}

else {
    Write-Log -Type Conf -Evt "Home UNC Path:.........No Config"
}

If ($Null -ne $AdGrps)
{
    Write-Log -Type Conf -Evt "Groups for User:......."

    ForEach ($Grp in $AdGrps)
    {
        Write-Log -Type Conf -Evt ".......................$Grp"
    }
}

else {
    Write-Log -Type Conf -Evt "Groups for User:.......No Config"
}

If ($Null -ne $LogPath)
{
    Write-Log -Type Conf -Evt "Logs directory:........$LogPath."
}

else {
    Write-Log -Type Conf -Evt "Logs directory:........No Config"
}

If ($MailTo)
{
    Write-Log -Type Conf -Evt "E-mail log to:.........$MailTo."
}

else {
    Write-Log -Type Conf -Evt "E-mail log to:.........No Config"
}

If ($MailFrom)
{
    Write-Log -Type Conf -Evt "E-mail log from:.......$MailFrom."
}

else {
    Write-Log -Type Conf -Evt "E-mail log from:.......No Config"
}

If ($MailSubject)
{
    Write-Log -Type Conf -Evt "E-mail subject:........$MailSubject."
}

else {
    Write-Log -Type Conf -Evt "E-mail subject:........Default"
}

If ($SmtpServer)
{
    Write-Log -Type Conf -Evt "SMTP server is:........$SmtpServer."
}

else {
    Write-Log -Type Conf -Evt "SMTP server is:........No Config"
}

If ($SmtpPort)
{
    Write-Log -Type Conf -Evt "SMTP Port:...............$SmtpPort."
}

else {
    Write-Log -Type Conf -Evt "SMTP Port:.............Default"
}

If ($SmtpUser)
{
    Write-Log -Type Conf -Evt "SMTP user is:..........$SmtpUser."
}

else {
    Write-Log -Type Conf -Evt "SMTP user is:..........No Config"
}

If ($SmtpPwd)
{
    Write-Log -Type Conf -Evt "SMTP pwd file:.........$SmtpPwd."
}

else {
    Write-Log -Type Conf -Evt "SMTP pwd file:.........No Config"
}

Write-Log -Type Conf -Evt "-UseSSL switch is:.....$UseSsl."
Write-Log -Type Conf -Evt "************************************************************"
Write-Log -Type Info -Evt "Process started"
##
## Display current config ends here.
##

If (Test-Path $UsersList)
{
    Write-Log -Type Info -Evt "Log started"

    ## Use this for password generation
    Add-Type -AssemblyName System.Web

    #Creating array for the sam account names for use later
    $SamsList = @()

    #Get the users names from the CSV
    $UserCsv = Import-Csv -Path $UsersList

    ForEach ($User in $UserCsv) {
        ## Clean ' from first names
        $FirstnameClean = $User.Firstname -replace "[']"

        # Create a random number
        $RandNum = (Get-Random -Minimum 0 -Maximum 999).ToString('000')

        $SamName = $FirstnameClean + $RandNum
        $SamsList += $SamName
        $UserFirstName = $User.Firstname
        $UserLastName = $User.Lastname
        $UserFullName = $UserFirstName + " " + $UserLastName

        ## The UPN set as the new sam account name and the email domain.
        $Upn = $SamName + "@$AdUpn"
        $DisplayName = $UserFullName
        $Pwrd = ([System.Web.Security.Membership]::GeneratePassword(8,0))

        ## If no home letter or path is configured, set to null
        If ($Null -ne $HomeUnc)
        {
            $HomeUncFull = "$HomeUnc\$SamName"
        }
        else {
            $HomeUncFull = $null
            $HomeDrive = $null
        }

        ## Check for existance of existing users with same name
        $UserExist = Get-ADUser -filter "SamAccountName -eq '$SamName'"

        ## If a user does already exist with name sam name, regenerate the nummber and try to create again. Do this until user does not exist.
        do {
            # Create a random number
            $RandNum = (Get-Random -Minimum 0 -Maximum 999).ToString('000')
            $UserExist = Get-ADUser -filter "SamAccountName -eq '$SamName'"

            try {
                New-ADUser -Name "$SamName" -GivenName "$UserFirstName" -Surname "$UserLastName" -DisplayName "$DisplayName" -SamAccountName $SamName -UserPrincipalName $Upn -Path $OrgUnit –AccountPassword (ConvertTo-SecureString $Pwrd -AsPlainText -Force) -ChangePasswordAtLogon $true -Enabled $true -HomeDirectory $HomeUncFull -HomeDrive $HomeDrive
                Write-Log -Type Info -Evt "(User) Creating new user $UserFirstName $UserLastName - Username: $SamName, Password: $Pwrd"
            }
            catch {
                Write-Log -Type Err -Evt $_.Exception.Message
            }

        } until ($null -eq $UserExist)
    }

    ## If Groups are configured, find and add them
    If ($null -ne $AdGrps)
    {
        ForEach ($Sams in $SamsList) {
            ForEach ($AdGrp in $AdGrps) {
                try {
                    Add-ADGroupMember -Identity $AdGrp -Members $Sams
                    Write-Log -Type Info -Evt "(Group) Adding user: $Sams to $AdGrp"
                }
                catch {
                    Write-Log -Type Err -Evt $_.Exception.Message
                }
            }
        }
    }

    ## Jobs done.
    Write-Log -Type Info -Evt "Process finished"
}

## If logging is configured then finish the log file.
If ($LogPath)
{
    Add-Content -Path $Log -Encoding ASCII -Value "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") [INFO] Log finished"

    ## This whole block is for e-mail, if it is configured.
    If ($SmtpServer)
    {
        ## Default e-mail subject if none is configured.
        If ($Null -eq $MailSubject)
        {
            $MailSubject = "New Users AD Log"
        }

        ## Default Smtp Port if none is configured.
        If ($Null -eq $SmtpPort)
        {
            $SmtpPort = "25"
        }

        ## Setting the contents of the log to be the e-mail body.
        $MailBody = Get-Content -Path $Log | Out-String

        ## If an smtp password is configured, get the username and password together for authentication.
        ## If an smtp password is not provided then send the e-mail without authentication and obviously no SSL.
        If ($SmtpPwd)
        {
            $SmtpPwdEncrypt = Get-Content $SmtpPwd | ConvertTo-SecureString
            $SmtpCreds = New-Object System.Management.Automation.PSCredential -ArgumentList ($SmtpUser, $SmtpPwdEncrypt)

            ## If -ssl switch is used, send the email with SSL.
            ## If it isn't then don't use SSL, but still authenticate with the credentials.
            If ($UseSsl)
            {
                Send-MailMessage -To $MailTo -From $MailFrom -Subject $MailSubject -Body $MailBody -SmtpServer $SmtpServer -Port $SmtpPort -UseSsl -Credential $SmtpCreds
            }

            else {
                Send-MailMessage -To $MailTo -From $MailFrom -Subject $MailSubject -Body $MailBody -SmtpServer $SmtpServer -Port $SmtpPort -Credential $SmtpCreds
            }
        }

        else {
            Send-MailMessage -To $MailTo -From $MailFrom -Subject $MailSubject -Body $MailBody -SmtpServer $SmtpServer -Port $SmtpPort
        }
    }
    ## End of Email block
}

## End
