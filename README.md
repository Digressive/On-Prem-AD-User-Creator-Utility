# On-Prem AD User Creator Utility

Configurable Script For Creating Active Directory User Accounts

For full change log and more information, [visit my site.](https://gal.vin/utils/on-prem-ad-user-creator-utility/)

On-Prem AD User Creator Utility is available from:

* [GitHub](https://github.com/Digressive/On-Prem-AD-User-Creator-Utility)

Please consider supporting my work:

* Sign up using [Patreon](https://www.patreon.com/mikegalvin).
* Support with a one-time donation using [PayPal](https://www.paypal.me/digressive).

If you’d like to contact me, please leave a comment, send me a [tweet or DM](https://twitter.com/mikegalvin_), or you can join my [Discord server](https://discord.gg/5ZsnJ5k).

-Mike

## Features and Requirements

* Requires the Active Directory PowerShell module be installed.
* Requires A CSV file containing the FirstName and LastName of each user to create.
* Configurable list of groups to add new users to.
* Randomly generated passwords for each user.
* User names are generated from first name & a 3 digit random number.
* The utility requires at least PowerShell 5.0.
* This utility has been tested on Windows 11, Windows 10, Windows Server 2022, Windows Server 2019, Windows Server 2016.

## Generating A Password File

The password used for SMTP server authentication must be in an encrypted text file. To generate the password file, run the following command in PowerShell on the computer and logged in with the user that will be running the utility. When you run the command, you will be prompted for a username and password. Enter the username and password you want to use to authenticate to your SMTP server.

Please note: This is only required if you need to authenticate to the SMTP server when send the log via e-mail.

``` powershell
$creds = Get-Credential
$creds.Password | ConvertFrom-SecureString | Set-Content c:\scripts\ps-script-pwd.txt
```

After running the commands, you will have a text file containing the encrypted password. When configuring the -Pwd switch enter the path and file name of this file.

## Configuration

Here’s a list of all the command line switches and example configurations.

| Command Line Switch | Description | Example |
| ------------------- | ----------- | ------- |
| -CSV | The path of the csv file containing the user info. Please see the users-example.csv file for how to structure your own file. | [path\]user-list.csv |
| -OU | The Organisational Unit to create the users in. If none is configured the default Computers OU will be used. | 'OU=User_Accounts,DC=contoso,DC=com' |
| -UPN | The Universal Principal Name the users should be configured with. If none is configured the forest name will be used. | [contoso.com] |
| -HomeLetter | The drive letter to use for the home drive path. | [drive letter] |
| -HomePath | The path where the location of the home drive should reside. | [path\] |
| -Groups | The name of the group(s) separated by a comma that all the new users should be a member of. | [UserGroup1,UserGroup2] |
| -L | The path to output the log file to. | [path\] |
| -LogRotate | Remove logs produced by the utility older than X days | [number] |
| -NoBanner | Use this option to hide the ASCII art title in the console. | N/A |
| -Help | Display usage information. No arguments also displays help. | N/A |
| -Subject | Specify a subject line. If you leave this blank the default subject will be used | "'[Server: Notification]'" |
| -SendTo | The e-mail address the log should be sent to. For multiple address, separate with a comma. | [example@contoso.com] |
| -From | The e-mail address the log should be sent from. | [example@contoso.com] |
| -Smtp | The DNS name or IP address of the SMTP server. | [smtp server address] |
| -Port | The Port that should be used for the SMTP server. If none is specified then the default of 25 will be used. | [port number] |
| -User | The user account to authenticate to the SMTP server. | [example@contoso.com] |
| -Pwd | The txt file containing the encrypted password for SMTP authentication. | [path\]ps-script-pwd.txt |
| -UseSsl | Configures the utility to connect to the SMTP server using SSL. | N/A |

## Example

``` txt
[path\]On-Prem-AD-User-Creator.ps1 -csv [path\]user-list.csv
```

This will create new users from the names in the csv file. The user objects will be created in the 'Computers' builtin OU.
