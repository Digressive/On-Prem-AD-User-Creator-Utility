# On-Prem AD User Creator Utility

Configurable Script For Creating Active Directory User Accounts

``` txt
   ____              ____                         ___    ____                               
  / __ \____        / __ \________  ____ ___     /   |  / __ \                              
 / / / / __ \______/ /_/ / ___/ _ \/ __ '__ \   / /| | / / / /                              
/ /_/ / / / /_____/ ____/ /  /  __/ / / / / /  / ___ |/ /_/ /                               
\____/_/_/_/     /_/   /_/ __\___/_/ /_/ /_/  /_/__|_/_____/       __  ____  _ ___ __       
  / / / /_______  _____   / ____/_______  ____ _/ /_____  _____   / / / / /_(_) (_) /___  __
 / / / / ___/ _ \/ ___/  / /   / ___/ _ \/ __ '/ __/ __ \/ ___/  / / / / __/ / / / __/ / / /
/ /_/ (__  )  __/ /     / /___/ /  /  __/ /_/ / /_/ /_/ / /     / /_/ / /_/ / / / /_/ /_/ / 
\____/____/\___/_/      \____/_/   \___/\__,_/\__/\____/_/      \____/\__/_/_/_/\__/\__, /  
                                                                                   /____/   
   Mike Galvin   https://gal.vin        Version 21.10.23
```

For full instructions and documentation, [visit my site.](https://gal.vin/posts/powershell-create-ad-users-from-csv)

Please consider supporting my work:

* Sign up [using Patreon.](https://www.patreon.com/mikegalvin)
* Support with a one-time payment [using PayPal.](https://www.paypal.me/digressive)

Join the [Discord](http://discord.gg/5ZsnJ5k) or Tweet me if you have questions: [@mikegalvin_](https://twitter.com/mikegalvin_)

-Mike

## Features and Requirements

* Requires the Active Directory PowerShell module be installed.
* Requires A CSV file containing the FirstName and LastName of each user to create.
* Configurable list of groups to add new users to.
* Randomly generated passwords for each user.
* User names are generated from firstname & a 3 digit random number.

This utility has been tested on Windows 10, Windows Server 2019 and Windows Server 2016 (Datacenter and Core Installations) with Windows PowerShell 5.0.

### Generating A Password File

The password used for SMTP server authentication must be in an encrypted text file. To generate the password file, run the following command in PowerShell on the computer and logged in with the user that will be running the utility. When you run the command, you will be prompted for a username and password. Enter the username and password you want to use to authenticate to your SMTP server.

Please note: This is only required if you need to authenticate to the SMTP server when send the log via e-mail.

``` powershell
$creds = Get-Credential
$creds.Password | ConvertFrom-SecureString | Set-Content c:\scripts\ps-script-pwd.txt
```

After running the commands, you will have a text file containing the encrypted password. When configuring the -Pwd switch enter the path and file name of this file.

### Configuration

Here’s a list of all the command line switches and example configurations.

| Command Line Switch | Description | Example |
| ------------------- | ----------- | ------- |
| -csv | The path of the csv file containing the user info. Please see the users-example.csv file for how to structure your own file. | C:\scripts\user-list.csv |
| -ou | The Organisational Unit to create the users in. Encapsulate with 'single quotes' | 'OU=User_Accounts,DC=contoso,DC=com' |
| -upn | The Universal Principal Name the users should be configured with. | contoso.com |
| -HomeLetter | The drive letter to use for the home drive path. | X |
| -HomePath | The path where the location of the home drive should reside. | \\\fs01\users$ |
| -Groups | The name of the group(s) separated by a comma that all the new users should be a member of. | UserGroup1,UserGroup2
| -NoBanner | Use this option to hide the ASCII art title in the console. | N/A |
| -L | The path to output the log file to. The file name will be On-Prem-AD-User-Creator_YYYY-MM-dd_HH-mm-ss.log. Do not add a trailing \ backslash. | C:\scripts\logs |
| -Subject | The subject line for the e-mail log. Encapsulate with single or double quotes. If no subject is specified, the default of "New Users AD Log" will be used. | 'Server: Notification' |
| -SendTo | The e-mail address the log should be sent to. | me@contoso.com |
| -From | The e-mail address the log should be sent from. | New-Users-AD@contoso.com |
| -Smtp | The DNS name or IP address of the SMTP server. | smtp.live.com OR smtp.office365.com |
| -Port | The Port that should be used for the SMTP server. If none is specified then the default of 25 will be used. | 587 |
| -User | The user account to authenticate to the SMTP server. | example@contoso.com |
| -Pwd | The txt file containing the encrypted password for SMTP authentication. | C:\scripts\ps-script-pwd.txt |
| -UseSsl | Configures the utility to connect to the SMTP server using SSL. | N/A |

### Example

``` txt
On-Prem-AD-User-Creator.ps1 -csv C:\scripts\user-list.csv -upn contoso.com -ou 'OU=User_Accounts,DC=contoso,DC=com' -HomeLetter X -HomePath \\fs01\users$ -Groups UserGroup1,UserGroup2 -L C:\scripts\logs -Subject 'Server: New Users Log' -SendTo me@contoso.com -From New-Users-AD@contoso.com -Smtp smtp.outlook.com -User user@contoso.com -Pwd C:\scripts\ps-script-pwd.txt -UseSsl
```

This will create new users from the names in the csv file located in C:\scripts\user-list.csv and set their Home Drive letter to X and the path to \\\fs01\users$\\%username%. The users will also be added to the groups UserGroup1 and UserGroup2. The log file will be output to C:\scripts\logs and sent via e-mail with a custom subject line.
