# Bulk Create Active Directory Users

PowerShell script to create Active Directory user accounts in bulk

For full instructions and documentation, [visit my blog post](https://gal.vin/posts/powershell-create-ad-users-from-csv)

Bulk Create Active Directory Users can also be downloaded from:

* [The Microsoft TechNet Gallery](https://gallery.technet.microsoft.com/Create-AD-Account-from-CSV-09ee9d39?redir=0)

Tweet me if you have questions: [@mikegalvin_](https://twitter.com/mikegalvin_)

-Mike

## Features and Requirements

This utility requires the Active Directory PowerShell module be installed, which is a part of the Remote Server Administration Tools (RSAT) for client editions of Windows. This utility has been tested running on Windows Server 2016 and Windows Server 2012 R2 Domain Controller’s and on a Windows 10 client.

This utility will create users based on basic information provided in a CSV file. All other options are added via command line options. Options include:

Organisation Unit in which to create the users.

* The UPN that users should have
* Home Drive location
* Home Drive Letter
* Membership of an Active Directory Group
* Account Expiry Date

### The -file Parameter

When running the script via Schedule Tasks or the command prompt be sure to use the -file parameter before specifying the script, so you can use “double quotes” for the command line switches that need them, if you do not use -file, then you should use ‘single quotes’.

### CSV File Formatting

The first line of the CSV file should be the column names so the script (and you) know what each column is for.

Please see the users-example.csv file for how to structure your own file.

### Generating A Password File

The password used for SMTP server authentication must be in an encrypted text file. To generate the password file, run the following command in PowerShell, on the computer that is going to run the script and logged in with the user that will be running the script. When you run the command you will be prompted for a username and password. Enter the username and password you want to use to authenticate to your SMTP server.

Please note: This is only required if you need to authenticate to the SMTP server when send the log via e-mail.

```powershell
$creds = Get-Credential
$creds.Password | ConvertFrom-SecureString | Set-Content c:\scripts\ps-script-pwd.txt
```

After running the commands, you will have a text file containing the encrypted password. When configuring the -Pwd switch enter the path and file name of this file.

### Configuration

Here’s a list of all the command line switches and example configurations.

``` txt
-csv
```

The path and filename of the csv file containing the user information to create users from.

``` txt
-ou
```

The Organisational Unit to create the users in.

``` txt
-upn
```

The Universal Principal Name the users should be configured with.

``` txt
-HomeLetter
```

The drive letter to use for the home drive path.

``` txt
-HomePath
```

The path where the location of the home drive should reside.

``` txt
-Group
```

The DN of a group that all the new users should be made a member of.

``` txt
-Expire
```

The expiry date of the new users.

``` txt
-L
```

The path to output the log file to. The file name will be AD-Account-Creation-YYYY-MM-dd-HH-mm-ss.log

``` txt
-Subject
```

The email subject that the email should have. Encapulate with single or double quotes.

``` txt
-SendTo
```

The e-mail address the log should be sent to.

``` txt
-From
```

The from address the log should be sent from.

``` txt
-Smtp
```

The DNS or IP address of the SMTP server.

``` txt
-User
```

The user account to connect to the SMTP server.

``` txt
-Pwd
```

The password for the user account.

``` txt
-UseSsl
```

Connect to the SMTP server using SSL.

### Example

```txt
Create-Accounts-CSV.ps1 -Csv C:\foo\users.csv -Ou 'ou=Imported_Accounts,ou=MyUsers,dc=contoso,dc=com' -HomeLetter W: -HomePath \\filesrvr01\UserHomes -Group 'cn=All_Users,ou=Groups_Security,dc=contoso,dc=com' -Expire 31/07/2022 -Upn contoso.com -L C:\scripts\logs -Subject 'Server: Created AD Accounts' -SendTo me@contoso.com -From AD-Account-Creation@contoso.com -Mail exch01.contoso.com
```

This will take information from the users.csv file and create the users in the Imported_Accounts OU. The users home drive will be mapped to W: and be located under \\filesrvr01\UserHomes. The users will be a member of the All_Users AD group, will expire 31/07/2022 and will have the UPN of contoso.com. The log will be output to C:\scripts\logs and e-mailed with a custom subject line.
