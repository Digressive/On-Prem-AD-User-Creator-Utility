<#PSScriptInfo

.VERSION 22.06.06

.GUID eaaca86c-2a1f-4caf-b2f9-05868186d162

.AUTHOR Mike Galvin Contact: mike@gal.vin / twitter.com/mikegalvin_ / discord.gg/5ZsnJ5k

.COMPANYNAME Mike Galvin

.COPYRIGHT (C) Mike Galvin. All rights reserved.

.TAGS Active Directory User Creation CSV Import

.LICENSEURI

.PROJECTURI https://gal.vin/utils/on-prem-ad-user-creator-utility/

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
    Run with -help or no arguments for usage.
#>

## Set up command line switches.
[CmdletBinding()]
Param(
    [alias("CSV")]
    $UsersList,
    [alias("OU")]
    $OrgUnit,
    [alias("UPN")]
    $AdUpn,
    [alias("HomeLetter")]
    $HomeDrive,
    [alias("HomePath")]
    $HomeUncUsr,
    [alias("Groups")]
    $AdGrps,
    [alias("L")]
    $LogPathUsr,
    [alias("LogRotate")]
    $LogHistory,
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
    [switch]$Help,
    [switch]$NoBanner)

If ($NoBanner -eq $False)
{
    Write-Host -ForegroundColor Yellow -BackgroundColor Black -Object "
           ____              ____                         ___    ____                                   
          / __ \____        / __ \________  ____ ___     /   |  / __ \           Mike Galvin            
         / / / / __ \______/ /_/ / ___/ _ \/ __ '__ \   / /| | / / / /         https://gal.vin          
        / /_/ / / / /_____/ ____/ /  /  __/ / / / / /  / ___ |/ /_/ /                                   
        \____/_/_/_/     /_/   /_/ __\___/_/ /_/ /_/  /_/__|_/_____/       __  ____  _ ___ __           
          / / / /_______  _____   / ____/_______  ____ _/ /_____  _____   / / / / /_(_) (_) /___  __    
         / / / / ___/ _ \/ ___/  / /   / ___/ _ \/ __ '/ __/ __ \/ ___/  / / / / __/ / / / __/ / / /    
        / /_/ (__  )  __/ /     / /___/ /  /  __/ /_/ / /_/ /_/ / /     / /_/ / /_/ / / / /_/ /_/ /     
        \____/____/\___/_/      \____/_/   \___/\__,_/\__/\____/_/      \____/\__/_/_/_/\__/\__, /      
                                                                                           /____/       
            Version 22.06.06                                                                            
          See -help for usage               Donate: https://www.paypal.me/digressive                    
"
}

If ($PSBoundParameters.Values.Count -eq 0 -or $Help)
{
    Write-Host -Object "Usage:
    From a terminal run: [path\]On-Prem-AD-User-Creator.ps1 -csv [path\]user-list.csv
    This will create new users from the names in the csv file.
    The user objects will be created in the 'Computers' builtin OU.

    To set the users UPN use: -upn [domain.name]
    To set where the user objects are created: -ou [""'Full OU DN path'""]
    To set the Home letter and Home path: -HomeLetter [drive letter] -HomePath [path]
    To set which group(s) the new users should be a member of: -Groups [UserGroup1,UserGroup2]

    To output a log: -L [path\].
    To remove logs produced by the utility older than X days: -LogRotate [number].
    Run with no ASCII banner: -NoBanner

    To use the 'email log' function:
    Specify the subject line with -Subject ""'[subject line]'"" If you leave this blank a default subject will be used
    Make sure to encapsulate it with double & single quotes as per the example for Powershell to read it correctly.

    Specify the 'to' address with -SendTo [example@contoso.com]
    For multiple address, separate with a comma.

    Specify the 'from' address with -From [example@contoso.com]
    Specify the SMTP server with -Smtp [smtp server name]

    Specify the port to use with the SMTP server with -Port [port number].
    If none is specified then the default of 25 will be used.

    Specify the user to access SMTP with -User [example@contoso.com]
    Specify the password file to use with -Pwd [path\]ps-script-pwd.txt.
    Use SSL for SMTP server connection with -UseSsl.

    To generate an encrypted password file run the following commands
    on the computer and the user that will run the script:
"
    Write-Host -Object '    $creds = Get-Credential
    $creds.Password | ConvertFrom-SecureString | Set-Content [path\]ps-script-pwd.txt'
}

else {
    ## If logging is configured, start logging.
    ## If the log file already exists, clear it.
    If ($LogPathUsr)
    {
        ## Clean User entered string
        $LogPath = $LogPathUsr.trimend('\')

        ## Make sure the log directory exists.
        If ((Test-Path -Path $LogPath) -eq $False)
        {
            New-Item $LogPath -ItemType Directory -Force | Out-Null
        }

        $LogFile = ("On-Prem-AD-User-Creator_{0:yyyy-MM-dd_HH-mm-ss}.log" -f (Get-Date))
        $Log = "$LogPath\$LogFile"

        If (Test-Path -Path $Log)
        {
            Clear-Content -Path $Log
        }
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
            If ($LogPathUsr)
            {
                Add-Content -Path $Log -Encoding ASCII -Value "$(Get-DateFormat) [INFO] $Evt"
            }
            
            Write-Host -Object "$(Get-DateFormat) [INFO] $Evt"
        }

        If ($Type -eq "Succ")
        {
            If ($LogPathUsr)
            {
                Add-Content -Path $Log -Encoding ASCII -Value "$(Get-DateFormat) [SUCCESS] $Evt"
            }

            Write-Host -ForegroundColor Green -Object "$(Get-DateFormat) [SUCCESS] $Evt"
        }

        If ($Type -eq "Err")
        {
            If ($LogPathUsr)
            {
                Add-Content -Path $Log -Encoding ASCII -Value "$(Get-DateFormat) [ERROR] $Evt"
            }

            Write-Host -ForegroundColor Red -BackgroundColor Black -Object "$(Get-DateFormat) [ERROR] $Evt"
        }

        If ($Type -eq "Conf")
        {
            If ($LogPathUsr)
            {
                Add-Content -Path $Log -Encoding ASCII -Value "$Evt"
            }

            Write-Host -ForegroundColor Cyan -Object "$Evt"
        }
    }

    ## Check for required options
    If ($Null -eq $UsersList)
    {
        Write-Log -Type Err -Evt "You must specify a users list with -CSV"
        Exit
    }

    If ($Null -eq $HomeDrive -And $HomeUncUsr)
    {
        Write-Log -Type Err -Evt "You need to set both -HomeLetter and -HomePath"
        Exit
    }

    If ($Null -eq $HomeUncUsr -And $HomeDrive)
    {
        Write-Log -Type Err -Evt "You need to set both -HomeLetter and -HomePath"
        Exit
    }

    # Set variables for options not set
    If ($Null -eq $OrgUnit)
    {
        $OrgUnit = 'CN=Computers,DC=contoso,DC=com'
    }

    If ($Null -eq $AdUpn)
    {
        $AdUpn = Get-addomain | Select-Object Forest -ExpandProperty Forest
    }

    If ($HomeUncUsr)
    {
        $HomeUnc = $HomeUncUsr.trimend('\')
    }

    If ($Null -eq $LogPathUsr -And $SmtpServer)
    {
        Write-Log -Type Err -Evt "You must specify -L [path\] to use the email log function."
        Exit
    }

    ## getting Windows Version info
    $OSVMaj = [environment]::OSVersion.Version | Select-Object -expand major
    $OSVMin = [environment]::OSVersion.Version | Select-Object -expand minor
    $OSVBui = [environment]::OSVersion.Version | Select-Object -expand build
    $OSV = "$OSVMaj" + "." + "$OSVMin" + "." + "$OSVBui"

    ##
    ## Display the current config and log if configured.
    ##
    Write-Log -Type Conf -Evt "************ Running with the following config *************."
    Write-Log -Type Conf -Evt "Utility Version:.......22.06.06"
    Write-Log -Type Conf -Evt "Hostname:..............$Env:ComputerName."
    Write-Log -Type Conf -Evt "Windows Version:.......$OSV."

    If ($UsersList)
    {
        Write-Log -Type Conf -Evt "CSV file:..............$UsersList."
    }

    If ($OrgUnit)
    {
        Write-Log -Type Conf -Evt "OU for users:..........$OrgUnit."
    }

    If ($AdUpn)
    {
        Write-Log -Type Conf -Evt "User UPN:..............$AdUpn."
    }

    If ($HomeDrive)
    {
        Write-Log -Type Conf -Evt "Home Letter:...........$HomeDrive."
    }

    If ($HomeUncUsr)
    {
        Write-Log -Type Conf -Evt "Home UNC Path:.........$HomeUncUsr."
    }

    If ($AdGrps)
    {
        Write-Log -Type Conf -Evt "Groups to add user to:"

        ForEach ($Grp in $AdGrps)
        {
            Write-Log -Type Conf -Evt ".......................$Grp"
        }
    }

    If ($LogPathUsr)
    {
        Write-Log -Type Conf -Evt "Logs directory:........$LogPath."
    }

    If ($Null -ne $LogHistory)
    {
        Write-Log -Type Conf -Evt "Logs to keep:..........$LogHistory days."
    }

    If ($MailTo)
    {
        Write-Log -Type Conf -Evt "E-mail log to:.........$MailTo."
    }

    If ($MailFrom)
    {
        Write-Log -Type Conf -Evt "E-mail log from:.......$MailFrom."
    }

    If ($MailSubject)
    {
        Write-Log -Type Conf -Evt "E-mail subject:........$MailSubject."
    }

    If ($SmtpServer)
    {
        Write-Log -Type Conf -Evt "SMTP server is:........$SmtpServer."
    }

    If ($SmtpPort)
    {
        Write-Log -Type Conf -Evt "SMTP Port:...............$SmtpPort."
    }

    If ($SmtpUser)
    {
        Write-Log -Type Conf -Evt "SMTP user is:..........$SmtpUser."
    }

    If ($SmtpPwd)
    {
        Write-Log -Type Conf -Evt "SMTP pwd file:.........$SmtpPwd."
    }

    If ($SmtpServer)
    {
        Write-Log -Type Conf -Evt "-UseSSL switch is:.....$UseSsl."
    }
    Write-Log -Type Conf -Evt "************************************************************"
    Write-Log -Type Info -Evt "Process started"
    ##
    ## Display current config ends here.
    ##

    If ($Null -ne $UsersList)
    {
        If (Test-Path -Path $UsersList)
        {
            ## Use this for password generation
            Add-Type -AssemblyName System.Web

            #Creating array for the sam account names for use later
            $SamsList = @()

            #Get the users names from the CSV
            $UserCsv = Import-Csv -Path $UsersList

            ForEach ($User in $UserCsv) {
                ## Clean ' from first names
                $FirstnameClean = $User.Firstname -replace "[']"

                ## If firstname is long, shorten for samaccountname limit + rand number
                $NameSafeLen = $FirstnameClean.substring(0, [System.Math]::Min(16, $FirstnameClean.Length))

                # Create a random number
                $RandNum = (Get-Random -Minimum 0 -Maximum 9999).ToString('0000')

                $SamName = $NameSafeLen + $RandNum
                $SamsList += $SamName
                $UserFirstName = $User.Firstname
                $UserLastName = $User.Lastname
                $UserFullName = $UserFirstName + " " + $UserLastName

                ## The UPN set as the new sam account name and the email domain.
                $Upn = $SamName + "@$AdUpn"
                $DisplayName = $UserFullName
                $Pwrd = ([System.Web.Security.Membership]::GeneratePassword(8,0))

                ## If no home letter or path is configured, set to null
                If ($HomeUncUsr)
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
                    $RandNum = (Get-Random -Minimum 0 -Maximum 9999).ToString('0000')
                    $UserExist = Get-ADUser -filter "SamAccountName -eq '$SamName'"

                    try {
                        New-ADUser -Name "$SamName" -GivenName "$UserFirstName" -Surname "$UserLastName" -DisplayName "$DisplayName" -SamAccountName $SamName -UserPrincipalName $Upn -Path $OrgUnit -AccountPassword (ConvertTo-SecureString $Pwrd -AsPlainText -Force) -ChangePasswordAtLogon $true -Enabled $true -HomeDirectory $HomeUncFull -HomeDrive $HomeDrive
                        Write-Log -Type Info -Evt "(User) Creating new user $UserFirstName $UserLastName - Username: $SamName, Password: $Pwrd [END]"
                    }

                    catch {
                        Write-Log -Type Err -Evt $_.Exception.Message
                    }

                } until ($null -eq $UserExist)
            }

            ## If Groups are configured, find and add them
            If ($AdGrps)
            {
                ForEach ($Sams in $SamsList) {
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

        else {
            Write-Log -Type Err -Evt "The specified file was not found."
        }
    }

    else {
        Write-Log -Type Err -Evt "No csv file specified."
    }

    If ($Null -ne $LogHistory)
    {
        ## Cleanup logs.
        Write-Log -Type Info -Evt "Deleting logs older than: $LogHistory days"
        Get-ChildItem -Path "$LogPath\On-Prem-AD-User-Creator_*" -File | Where-Object CreationTime -lt (Get-Date).AddDays(-$LogHistory) | Remove-Item -Recurse
    }

    ## This whole block is for e-mail, if it is configured.
    If ($SmtpServer)
    {
        If (Test-Path -Path $Log)
        {
            ## Default e-mail subject if none is configured.
            If ($Null -eq $MailSubject)
            {
                $MailSubject = "On-Prem AD User Creator Utility Log"
            }

            ## Default Smtp Port if none is configured.
            If ($Null -eq $SmtpPort)
            {
                $SmtpPort = "25"
            }

            ## Setting the contents of the log to be the e-mail body.
            $MailBody = Get-Content -Path $Log | Out-String

            ForEach ($MailAddress in $MailTo)
            {
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
                        Send-MailMessage -To $MailAddress -From $MailFrom -Subject $MailSubject -Body $MailBody -SmtpServer $SmtpServer -Port $SmtpPort -UseSsl -Credential $SmtpCreds
                    }

                    else {
                        Send-MailMessage -To $MailAddress -From $MailFrom -Subject $MailSubject -Body $MailBody -SmtpServer $SmtpServer -Port $SmtpPort -Credential $SmtpCreds
                    }
                }

                else {
                    Send-MailMessage -To $MailAddress -From $MailFrom -Subject $MailSubject -Body $MailBody -SmtpServer $SmtpServer -Port $SmtpPort
                }
            }
        }

        else {
            Write-Host -ForegroundColor Red -BackgroundColor Black -Object "There's no log file to email."
        }
    }
    ## End of Email block
}
## End