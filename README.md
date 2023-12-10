# On-Prem AD User Creator Utility

## Configurable Script For Creating Active Directory User Accounts

For full change log and more information, [visit my site.](https://gal.vin/utils/on-prem-ad-user-creator-utility/)

On-Prem AD User Creator Utility is available from:

* [GitHub](https://github.com/Digressive/On-Prem-AD-User-Creator-Utility)

Please consider supporting my work:

* Support with a one-time donation using [PayPal](https://www.paypal.me/digressive).

Please report any problems via the 'issues' tab on GitHub.

Thanks
-Mike

## Features and Requirements

* Requires the Active Directory PowerShell module be installed.
* Requires A CSV file containing the FirstName and LastName of each user to create.
* Configurable list of groups to add new users to.
* Randomly generated passwords for each user.
* User names are generated from first name & a 3 digit random number.
* The utility requires at least PowerShell 5.0.
* Tested on Windows 11, Windows 10, Windows Server 2022, Windows Server 2019, Windows Server 2016.

## Generating A Password File For SMTP Authentication

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
| -OU | The Organizational Unit to create the users in. If none is configured the default Computers OU will be used. | 'OU=User_Accounts,DC=contoso,DC=com' |
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

## Change Log

### 2023-04-28: Version 23.04.28

* Removed specific SMTP config info from config report.
* Added script update checker - shows if an update is available in the log and console. If the internet is not reachable it silently errors out.

### 2022-06-14: Version 22.06.06

* Added new feature: log can now be emailed to multiple addresses.
* Added checks and balances to help with configuration as I'm very aware that the initial configuration can be troublesome. Running the utility manually is a lot more friendly and step-by-step now.
* Added -Help to give usage instructions in the terminal. Running the script with no options will also trigger the -help switch.
* Cleaned user entered paths so that trailing slashes no longer break things or have otherwise unintended results.
* Added -LogRotate [days] to removed old logs created by the utility.
* Streamlined config report so non configured options are not shown.
* Added donation link to the ASCII banner.
* Cleaned up code, removed unneeded log noise.

### 2021-12-08: Version 21.12.08

* Configured logs path now is created, if it does not exist.
* Added OS version info.
* Added Utility version info.
* Added Hostname info.

### 2021-09-20: Version 21.09.20

* Added code to make sure sam account name will never be more than 19 characters, due to the default sam account name length being 20 characters.

### 2021-09-15: Version 21.09.15

* Completely rewritten to streamline the user creation process.
* User passwords are now randomly generated.
* Added option to add users to multiple groups.
* Utility will find groups based on the AD name. No more having to specify the whole DN.
* Added ASCII banner art when run in the console.
* Added option to disable the ASCII banner art.
* Added an option to specify the Port for SMTP communication.

### 2019-09-04 v1.6

* Added custom subject line for e-mail.

### 2017-10-16 v1.5

* Changed SMTP authentication to require an encrypted password file.
* Added instructions on how to generate an encrypted password file.

### 2017-10-07 v1.4

* Added necessary information to add the script to the PowerShell Gallery.

### 2017-09-13 v1.3

* Added check for existence of user before attempting to create user.
* Improved logging to handle the above change.

### 2017-07-22 v1.2

* Improved code commenting for documentation purposes.
* Added authentication and SSL options for e-mail notification.
