<#PSScriptInfo

.VERSION 1.5

.GUID eaaca86c-2a1f-4caf-b2f9-05868186d162

.AUTHOR Mike Galvin twitter.com/mikegalvin_

.COMPANYNAME

.COPYRIGHT (C) Mike Galvin. All rights reserved.

.TAGS Active Directory User Creation CSV File Import

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
    Creates Active Directory user accounts from a CSV file.

    .DESCRIPTION
    Creates Active Directory user accounts from a CSV file.

    This script will create users based on information provided by a CSV file. All other options are added via command line switches.
    
    The command line switches provide configuration for:

    Organisational Unit in which to create the users.
    The user's UPN.
    Home Drive location.
    Home Drive Letter.
    Membership of an Active Directory Group.
    Account Expiry Date.

    Please note: to send a log file using ssl and an SMTP password you must generate an encrypted
    password file. The password file is unique to both the user and machine.
    
    The command is as follows:

    $creds = Get-Credential
    $creds.Password | ConvertFrom-SecureString | Set-Content c:\foo\ps-script-pwd.txt
    
    .PARAMETER csv
    The path and filename of the csv file containing the user information to create users from.
    Please see the users-example.csv file for how to structure your own file.

    .PARAMETER ou
    The Organisational Unit to create the users in.

    .PARAMETER upn
    The Universal Principal Name the users should be configured with.

    .PARAMETER HomeLetter
    The drive letter to use for the home drive path.

    .PARAMETER HomePath
    The path where the location of the home drive should reside.

    .PARAMETER Group
    The DN of a group that all the new users should be made a member of.

    .PARAMETER Expire
    The expiry date of the new users.
    
    .PARAMETER L
    The path to output the log file to.
    The file name will be AD-Account-Creation-YYYY-MM-dd-HH-mm-ss.log

    .PARAMETER SendTo
    The e-mail address the log should be sent to.

    .PARAMETER From
    The from address the log should be sent from.

    .PARAMETER Smtp
    The DNS or IP address of the SMTP server.

    .PARAMETER User
    The user account to connect to the SMTP server.

    .PARAMETER Pwd
    The password for the user account.

    .PARAMETER UseSsl
    Connect to the SMTP server using SSL.

    .EXAMPLE
    Create-Accounts-CSV.ps1 -Csv C:\foo\users.csv -Ou 'ou=Imported_Accounts,ou=MyUsers,dc=contoso,dc=com' -HomeLetter W: -HomePath \\filesrvr01\UserHomes -Group 'cn=All_Users,ou=Groups_Security,dc=contoso,dc=com' -Expire 31/07/2022 -Upn contoso.com -L C:\scripts\logs -SendTo me@contoso.com -From AD-Account-Creation@contoso.com -Mail exch01.contoso.com
    This will take information from the users.csv file and create the users in the Imported_Accounts OU. The users home drive will be mapped to W: and be located under \\filesrvr01\UserHomes.
    The users will be a memeber of the All_Users AD group, will expire 31/07/2022 and will have the UPN of contoso.com. The log will be output to C:\scripts\logs and e-mailed.
#>

[CmdletBinding()]
Param(
    [parameter(Mandatory=$True)]
    [alias("csv")]
    $UsersList,
    [parameter(Mandatory=$True)]
    [alias("ou")]
    $OrganisationalUnit,
    [parameter(Mandatory=$True)]
    [alias("upn")]
    $AdUpn,
    [alias("HomeLetter")]
    $HomeDrive,
    [alias("HomePath")]
    $HomeUnc,
    [alias("Group")]
    $AdGroup,
    [alias("Expire")]
    $AdExpire,
    [alias("L")]
    $LogPath,
    [alias("SendTo")]
    $MailTo,
    [alias("From")]
    $MailFrom,
    [alias("Smtp")]
    $SmtpServer,
    [alias("User")]
    $SmtpUser,
    [alias("Pwd")]
    $SmtpPwd,
    [switch]$UseSsl)

## If users list csv file exists then run the script
If (Test-Path $UsersList)
{
    ## If logging is configured, start log
    If ($LogPath)
    {
        $LogFile = ("AD-Account-Creation-{0:yyyy-MM-dd-HH-mm-ss}.log" -f (Get-Date))
        $Log = "$LogPath\$LogFile"
    }

    If (Test-Path $UsersList)
    {
        ## Start Log
        If ($LogPath)
        {
            Start-Transcript $Log
        }
    }

    $UserCsv = Import-Csv -Path "$UsersList"

    ForEach ($User In $UserCsv)
    {
        $DisplayName = $User.Firstname + " " + $User.Lastname
        $UserFirstName = $User.Firstname
        $UserLastName = $User.Lastname
        $Sam = $User.SAM
        $Upn = $Sam + "@$AdUpn"
        $Description = $DisplayName
        $Password = $User.Password

        $UserExist = Get-ADUser -Filter "SamAccountName -eq '$Sam'"

        If ($null -eq $UserExist)
        {
            New-ADUser -Name $Sam -DisplayName "$DisplayName" -SamAccountName $Sam -UserPrincipalName $Upn -GivenName "$UserFirstName" -Surname "$UserLastName" -Description "$Description" -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -Force) -Enabled $True -Path "$OrganisationalUnit" -ChangePasswordAtLogon $True –PasswordNeverExpires $False -AccountExpirationDate $AdExpire -Verbose
        
            If ($HomeDrive)
            {
                Set-ADUser $Sam -HomeDirectory $HomeUnc\$Sam -HomeDrive $HomeDrive -Verbose
            }

            If ($AdGroup)
            {
                Add-ADGroupMember "$AdGroup" $Sam -Verbose
            }
        }

        Else
        {
            Write-Host "User with Sam Account Name:$Sam already exists"
        }
    }

    ## If log was configured stop the log
    If ($LogPath)
    {
        Stop-Transcript

        ## If email was configured, set the variables for the email subject and body
        If ($SmtpServer)
        {
            $MailSubject = "AD Account Creation Log"
            $MailBody = Get-Content -Path $Log | Out-String

            ## If an email password was configured, create a variable with the username and password
            If ($SmtpPwd)
            {
                $SmtpPwdEncrypt = Get-Content $SmtpPwd | ConvertTo-SecureString
                $SmtpCreds = New-Object System.Management.Automation.PSCredential -ArgumentList ($SmtpUser, $SmtpPwdEncrypt)

                ## If ssl was configured, send the email with ssl
                If ($UseSsl)
                {
                    Send-MailMessage -To $MailTo -From $MailFrom -Subject $MailSubject -Body $MailBody -SmtpServer $SmtpServer -UseSsl -Credential $SmtpCreds
                }

                ## If ssl wasn't configured, send the email without ssl
                Else
                {
                    Send-MailMessage -To $MailTo -From $MailFrom -Subject $MailSubject -Body $MailBody -SmtpServer $SmtpServer -Credential $SmtpCreds
                }
            }

            ## If an email username and password were not configured, send the email without authentication
            Else
            {
                Send-MailMessage -To $MailTo -From $MailFrom -Subject $MailSubject -Body $MailBody -SmtpServer $SmtpServer
            }
        }
    }
}

Else
{
    Write-Host "There's no user list to work with."
}

## End