#intro-to-dante #windows
# Enumeration

## Nmap portscan

```
nmap -sC -sV -Pn nest.htb
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-09 08:34 EST
Nmap scan report for nest.htb (10.129.128.248)
Host is up (0.18s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT    STATE SERVICE       VERSION
445/tcp open  microsoft-ds?

Host script results:
| smb2-security-mode: 
|   210: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-02-09T13:35:08
|_  start_date: 2023-02-09T12:22:44

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 77.64 seconds
```

## Full Scan

```
nmap -p- -Pn --min-rate 10000 nest.htb
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-09 09:22 EST
Nmap scan report for nest.htb (10.129.128.248)
Host is up (0.19s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT     STATE SERVICE
445/tcp  open  microsoft-ds
4386/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 38.65 seconds
```

## Port specific scan
```
nmap -p 445,4386 -Pn -sV -sC nest.htb
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-09 09:26 EST
Nmap scan report for nest.htb (10.129.128.248)
Host is up (0.19s latency).

PORT     STATE SERVICE       VERSION
445/tcp  open  microsoft-ds?
4386/tcp open  unknown
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, X11Probe: 
|     Reporting Service V1.2
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, RTSPRequest, SIPOptions: 
|     Reporting Service V1.2
|     Unrecognised command
|   Help: 
|     Reporting Service V1.2
|     This service allows users to run queries against databases using the legacy HQK format
|     AVAILABLE COMMANDS ---
|     LIST
|     SETDIR <Directory_Name>
|     RUNQUERY <Query_ID>
|     DEBUG <Password>
|_    HELP <Command>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4386-TCP:V=7.93%I=7%D=2/9%Time=63E502A0%P=x86_64-pc-linux-gnu%r(NUL
SF:L,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(GenericLine
SF:s,3A,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nUnrecognised
SF:\x20command\r\n>")%r(GetRequest,3A,"\r\nHQK\x20Reporting\x20Service\x20
SF:V1\.2\r\n\r\n>\r\nUnrecognised\x20command\r\n>")%r(HTTPOptions,3A,"\r\n
SF:HQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nUnrecognised\x20comman
SF:d\r\n>")%r(RTSPRequest,3A,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n
SF:\r\n>\r\nUnrecognised\x20command\r\n>")%r(RPCCheck,21,"\r\nHQK\x20Repor
SF:ting\x20Service\x20V1\.2\r\n\r\n>")%r(DNSVersionBindReqTCP,21,"\r\nHQK\
SF:x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(DNSStatusRequestTCP,21,"\
SF:r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(Help,F2,"\r\nHQK\x
SF:20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nThis\x20service\x20allows\x
SF:20users\x20to\x20run\x20queries\x20against\x20databases\x20using\x20the
SF:\x20legacy\x20HQK\x20format\r\n\r\n---\x20AVAILABLE\x20COMMANDS\x20---\
SF:r\n\r\nLIST\r\nSETDIR\x20<Directory_Name>\r\nRUNQUERY\x20<Query_ID>\r\n
SF:DEBUG\x20<Password>\r\nHELP\x20<Command>\r\n>")%r(SSLSessionReq,21,"\r\
SF:nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(TerminalServerCookie
SF:,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(TLSSessionRe
SF:q,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(Kerberos,21
SF:,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(SMBProgNeg,21,"
SF:\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(X11Probe,21,"\r\n
SF:HQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(FourOhFourRequest,3A,
SF:"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nUnrecognised\x20c
SF:ommand\r\n>")%r(LPDString,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\
SF:r\n\r\n>")%r(LDAPSearchReq,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2
SF:\r\n\r\n>")%r(LDAPBindReq,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\
SF:r\n\r\n>")%r(SIPOptions,3A,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\
SF:n\r\n>\r\nUnrecognised\x20command\r\n>")%r(LANDesk-RC,21,"\r\nHQK\x20Re
SF:porting\x20Service\x20V1\.2\r\n\r\n>")%r(TerminalServer,21,"\r\nHQK\x20
SF:Reporting\x20Service\x20V1\.2\r\n\r\n>");

Host script results:
|_clock-skew: -1s
| smb2-time: 
|   date: 2023-02-09T14:29:17
|_  start_date: 2023-02-09T12:22:44
| smb2-security-mode: 
|   210: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 204.30 seconds
```


## Check the port 4386 unknown service

### netcat

```
nc nest.htb 4386
HQK Reporting Service V1.2
>help
^C
```
help did not work

### telnet
```
telnet nest.htb 4386       
Trying 10.129.209.6...
Connected to nest.htb.
Escape character is '^]'.

HQK Reporting Service V1.2

>help

This service allows users to run queries against databases using the legacy HQK format

--- AVAILABLE COMMANDS ---

LIST
SETDIR <Directory_Name>
RUNQUERY <Query_ID>
DEBUG <Password>
HELP <Command>
```

Same output as nmap. HQK Reporting Service V1.2

## Check files
```
setdir ..
list

[DIR]  ALL QUERIES
[DIR]  LDAP
[DIR]  Logs
[1]   HqkSvc.exe
[2]   HqkSvc.InstallState
[3]   HQK_Config.xml

Current Directory: HQK
```

```
setdir ..
list
[DIR]  ALL QUERIES
[DIR]  LDAP
[DIR]  Logs
[1]   HqkSvc.exe
[2]   HqkSvc.InstallState
[3]   HQK_Config.xml

Current Directory: HQK
```

```
setdir ..
list
[DIR]  $Recycle.Bin
[DIR]  Boot
[DIR]  Documents and Settings
[DIR]  PerfLogs
[DIR]  Program Files
[DIR]  Program Files (x86)
[DIR]  ProgramData
[DIR]  Recovery
[DIR]  Shares
[DIR]  System Volume Information
[DIR]  Users
[DIR]  Windows
[1]   bootmgr
[2]   BOOTSECT.BAK
[3]   pagefile.sys
[4]   restartsvc.bat

Current Directory: C:
```

### Users
```
[DIR]  Administrator
[DIR]  All Users
[DIR]  C.Smith
[DIR]  Default
[DIR]  Default User
[DIR]  Public
[DIR]  Service_HQK
[DIR]  TempUser
[1]   desktop.ini
```

runquery did not work on desktop.ini
`Invalid database configuration found. Please contact your system administrator`

## SMBmap 
```
smbmap -H nest.htb -u null
[+] Guest session       IP: nest.htb:445        Name: unknown                                           
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        Data                                                    READ ONLY
        IPC$                                                    NO ACCESS       Remote IPC
        Secure$                                                 NO ACCESS
        Users                                                   READ ONLY
                                                                                             
```

### smbclient for users
`smbclient -N //nest.htb/users`

```
recurse on
prompt off
mget *
```
To download folder

```
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
NT_STATUS_ACCESS_DENIED listing \Administrator\*
NT_STATUS_ACCESS_DENIED listing \C.Smith\*
NT_STATUS_ACCESS_DENIED listing \L.Frost\*
NT_STATUS_ACCESS_DENIED listing \R.Thompson\*
NT_STATUS_ACCESS_DENIED listing \TempUser\*
```


### smbclient for data

```
mbclient -N //nest.htb/data
Try "help" to get a list of possible commands.
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
NT_STATUS_ACCESS_DENIED listing \IT\*
NT_STATUS_ACCESS_DENIED listing \Production\*
NT_STATUS_ACCESS_DENIED listing \Reports\*
getting file \Shared\Maintenance\Maintenance Alerts.txt of size 48 as Shared/Maintenance/Maintenance Alerts.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
getting file \Shared\Templates\HR\Welcome Email.txt of size 425 as Shared/Templates/HR/Welcome Email.txt (0.5 KiloBytes/sec) (average 0.3 KiloBytes/sec)
```

## Check files

### /Shared/Maintenance

```
cat Maintenance\ Alerts.txt 
There is currently no scheduled maintenance work                                                                                                                                                    
```

### /Shared/Templates/HR
```
cat Welcome\ Email.txt      
We would like to extend a warm welcome to our newest member of staff, <FIRSTNAME> <SURNAME>

You will find your home folder in the following location: 
\\HTB-NEST\Users\<USERNAME>

If you have any issues accessing specific services or workstations, please inform the 
IT department and use the credentials below until all systems have been set up for you.

Username: TempUser
Password: welcome2019


Thank you
HR    
```

# Foothold
## SMB Enumeration as TempUser

```
smbmap -H nest.htb -u TempUser -p welcome2019
[+] IP: nest.htb:445    Name: unknown                                           
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        Data                                                    READ ONLY
        IPC$                                                    NO ACCESS       Remote IPC
        Secure$                                                 READ ONLY
        Users                                                   READ ONLY
                                                                                                 
```

## Check Secure$
```
smbclient -U TempUser //nest.htb/Secure$  
```
Access denied

## Check Users
Nothing interesting

## Check Data
```
smbclient -U TempUser //nest.htb/data
Password for [WORKGROUP\TempUser]:
Try "help" to get a list of possible commands.
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
getting file \Shared\Maintenance\Maintenance Alerts.txt of size 48 as Shared/Maintenance/Maintenance Alerts.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
getting file \IT\Configs\Adobe\editing.xml of size 246 as IT/Configs/Adobe/editing.xml (0.3 KiloBytes/sec) (average 0.2 KiloBytes/sec)
getting file \IT\Configs\Adobe\Options.txt of size 0 as IT/Configs/Adobe/Options.txt (0.0 KiloBytes/sec) (average 0.1 KiloBytes/sec)
getting file \IT\Configs\Adobe\projects.xml of size 258 as IT/Configs/Adobe/projects.xml (0.3 KiloBytes/sec) (average 0.2 KiloBytes/sec)
getting file \IT\Configs\Adobe\settings.xml of size 1274 as IT/Configs/Adobe/settings.xml (1.0 KiloBytes/sec) (average 0.4 KiloBytes/sec)
getting file \IT\Configs\Atlas\Temp.XML of size 1369 as IT/Configs/Atlas/Temp.XML (1.7 KiloBytes/sec) (average 0.6 KiloBytes/sec)
getting file \IT\Configs\Microsoft\Options.xml of size 4598 as IT/Configs/Microsoft/Options.xml (5.9 KiloBytes/sec) (average 1.3 KiloBytes/sec)
getting file \IT\Configs\NotepadPlusPlus\config.xml of size 6451 as IT/Configs/NotepadPlusPlus/config.xml (8.2 KiloBytes/sec) (average 2.2 KiloBytes/sec)
getting file \IT\Configs\NotepadPlusPlus\shortcuts.xml of size 2108 as IT/Configs/NotepadPlusPlus/shortcuts.xml (2.6 KiloBytes/sec) (average 2.2 KiloBytes/sec)
getting file \IT\Configs\RU Scanner\RU_config.xml of size 270 as IT/Configs/RU Scanner/RU_config.xml (0.3 KiloBytes/sec) (average 2.0 KiloBytes/sec)
getting file \Shared\Templates\HR\Welcome Email.txt of size 425 as Shared/Templates/HR/Welcome Email.txt (0.5 KiloBytes/sec) (average 1.9 KiloBytes/sec)
```


## Check files from Data

```
find . -type f -ls
  3587381      4 -rw-r--r--   1 kali     kali          425 Feb 11 09:51 ./Shared/Templates/HR/Welcome\ Email.txt
  3587369      4 -rw-r--r--   1 kali     kali           48 Feb 11 09:51 ./Shared/Maintenance/Maintenance\ Alerts.txt
  3587376      4 -rw-r--r--   1 kali     kali         1369 Feb 11 09:51 ./IT/Configs/Atlas/Temp.XML
  3587380      4 -rw-r--r--   1 kali     kali          270 Feb 11 09:51 ./IT/Configs/RU\ Scanner/RU_config.xml
  3587377      8 -rw-r--r--   1 kali     kali         4598 Feb 11 09:51 ./IT/Configs/Microsoft/Options.xml
  3587374      4 -rw-r--r--   1 kali     kali          258 Feb 11 09:51 ./IT/Configs/Adobe/projects.xml
  3587372      4 -rw-r--r--   1 kali     kali          246 Feb 11 09:51 ./IT/Configs/Adobe/editing.xml
  3587373      0 -rw-r--r--   1 kali     kali            0 Feb 11 09:51 ./IT/Configs/Adobe/Options.txt
  3587375      4 -rw-r--r--   1 kali     kali         1274 Feb 11 09:51 ./IT/Configs/Adobe/settings.xml
  3587379      4 -rw-r--r--   1 kali     kali         2108 Feb 11 09:51 ./IT/Configs/NotepadPlusPlus/shortcuts.xml
  3587378      8 -rw-r--r--   1 kali     kali         6451 Feb 11 09:51 ./IT/Configs/NotepadPlusPlus/config.xml
```

### Interesting files

in `/IT/Configs/NotepadPlusPlus`
```
    <History nbMaxFile="15" inSubMenu="no" customLength="-1">
        <File filename="C:\windows\System32\drivers\etc\hosts" />
        <File filename="\\HTB-NEST\Secure$\IT\Carl\Temp.txt" />
        <File filename="C:\Users\C.Smith\Desktop\todo.txt" />
    </History>
```
Secure$ has Carl

in `/IT/Configs/RU Scanner`
```
cat RU_config.xml 
<?xml version="1.0"?>
<ConfigFile xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <Port>389</Port>
  <Username>c.smith</Username>
  <Password>fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE=</Password>
</ConfigFile> 
```

The password is encrypted
Trying cyberchef https://gchq.github.io/CyberChef/

![[Pasted image 20230212002546.png]]


## Carl
```
smb: \IT\Carl\> recurse on
smb: \IT\Carl\> prompt off
smb: \IT\Carl\> mget *
getting file \IT\Carl\Docs\ip.txt of size 56 as Docs/ip.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
getting file \IT\Carl\Docs\mmc.txt of size 73 as Docs/mmc.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner.sln of size 871 as VB Projects/WIP/RU/RUScanner.sln (1.1 KiloBytes/sec) (average 0.4 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\ConfigFile.vb of size 772 as VB Projects/WIP/RU/RUScanner/ConfigFile.vb (1.0 KiloBytes/sec) (average 0.6 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\Module1.vb of size 279 as VB Projects/WIP/RU/RUScanner/Module1.vb (0.4 KiloBytes/sec) (average 0.5 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\RU Scanner.vbproj of size 4828 as VB Projects/WIP/RU/RUScanner/RU Scanner.vbproj (6.2 KiloBytes/sec) (average 1.5 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\RU Scanner.vbproj.user of size 143 as VB Projects/WIP/RU/RUScanner/RU Scanner.vbproj.user (0.2 KiloBytes/sec) (average 1.3 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\SsoIntegration.vb of size 133 as VB Projects/WIP/RU/RUScanner/SsoIntegration.vb (0.2 KiloBytes/sec) (average 1.1 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\Utils.vb of size 4888 as VB Projects/WIP/RU/RUScanner/Utils.vb (6.2 KiloBytes/sec) (average 1.7 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\My Project\Application.Designer.vb of size 441 as VB Projects/WIP/RU/RUScanner/My Project/Application.Designer.vb (0.6 KiloBytes/sec) (average 1.6 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\My Project\Application.myapp of size 481 as VB Projects/WIP/RU/RUScanner/My Project/Application.myapp (0.6 KiloBytes/sec) (average 1.5 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\My Project\AssemblyInfo.vb of size 1163 as VB Projects/WIP/RU/RUScanner/My Project/AssemblyInfo.vb (1.5 KiloBytes/sec) (average 1.5 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\My Project\Resources.Designer.vb of size 2776 as VB Projects/WIP/RU/RUScanner/My Project/Resources.Designer.vb (3.5 KiloBytes/sec) (average 1.6 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\My Project\Resources.resx of size 5612 as VB Projects/WIP/RU/RUScanner/My Project/Resources.resx (7.1 KiloBytes/sec) (average 2.0 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\My Project\Settings.Designer.vb of size 2989 as VB Projects/WIP/RU/RUScanner/My Project/Settings.Designer.vb (1.9 KiloBytes/sec) (average 2.0 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\My Project\Settings.settings of size 279 as VB Projects/WIP/RU/RUScanner/My Project/Settings.settings (0.3 KiloBytes/sec) (average 1.9 KiloBytes/sec)
```

## VB file with decryption
There is a solution file with bunch of vb files.

Take the `Util.vb` file and use [fiddle.vb](https://dotnetfiddle.net/) to decrypt the password.

```
Imports System
Imports System.Text
Imports System.Security.Cryptography

Public Module Module1
	Public Sub Main()
		Console.WriteLine("Decrypted: " + DecryptString("fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE="))
	End Sub
	
	Public Function DecryptString(EncryptedString As String) As String
        If String.IsNullOrEmpty(EncryptedString) Then
            Return String.Empty
        Else
            Return Decrypt(EncryptedString, "N3st22", "88552299", 2, "464R5DFA5DL6LE28", 256)
        End If
    End Function

    Public Function EncryptString(PlainString As String) As String
        If String.IsNullOrEmpty(PlainString) Then
            Return String.Empty
        Else
            Return Encrypt(PlainString, "N3st22", "88552299", 2, "464R5DFA5DL6LE28", 256)
        End If
    End Function
	
	Public Function Encrypt(ByVal plainText As String, _
                                   ByVal passPhrase As String, _
                                   ByVal saltValue As String, _
                                    ByVal passwordIterations As Integer, _
                                   ByVal initVector As String, _
                                   ByVal keySize As Integer) _
                           As String

        Dim initVectorBytes As Byte() = Encoding.ASCII.GetBytes(initVector)
        Dim saltValueBytes As Byte() = Encoding.ASCII.GetBytes(saltValue)
        Dim plainTextBytes As Byte() = Encoding.ASCII.GetBytes(plainText)
        Dim password As New Rfc2898DeriveBytes(passPhrase, _
                                           saltValueBytes, _
                                           passwordIterations)
        Dim keyBytes As Byte() = password.GetBytes(CInt(keySize / 8))
        Dim symmetricKey As New AesCryptoServiceProvider
        symmetricKey.Mode = CipherMode.CBC
        Dim encryptor As ICryptoTransform = symmetricKey.CreateEncryptor(keyBytes, initVectorBytes)
        Using memoryStream As New IO.MemoryStream()
            Using cryptoStream As New CryptoStream(memoryStream, _
                                            encryptor, _
                                            CryptoStreamMode.Write)
                cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length)
                cryptoStream.FlushFinalBlock()
                Dim cipherTextBytes As Byte() = memoryStream.ToArray()
                memoryStream.Close()
                cryptoStream.Close()
                Return Convert.ToBase64String(cipherTextBytes)
            End Using
        End Using
    End Function	

    Public Function Decrypt(ByVal cipherText As String, _
                                   ByVal passPhrase As String, _
                                   ByVal saltValue As String, _
                                    ByVal passwordIterations As Integer, _
                                   ByVal initVector As String, _
                                   ByVal keySize As Integer) _
                           As String

        Dim initVectorBytes As Byte()
        initVectorBytes = Encoding.ASCII.GetBytes(initVector)

        Dim saltValueBytes As Byte()
        saltValueBytes = Encoding.ASCII.GetBytes(saltValue)

        Dim cipherTextBytes As Byte()
        cipherTextBytes = Convert.FromBase64String(cipherText)

        Dim password As New Rfc2898DeriveBytes(passPhrase, _
                                           saltValueBytes, _
                                           passwordIterations)

        Dim keyBytes As Byte()
        keyBytes = password.GetBytes(CInt(keySize / 8))

        Dim symmetricKey As New AesCryptoServiceProvider
        symmetricKey.Mode = CipherMode.CBC

        Dim decryptor As ICryptoTransform
        decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes)

        Dim memoryStream As IO.MemoryStream
        memoryStream = New IO.MemoryStream(cipherTextBytes)

        Dim cryptoStream As CryptoStream
        cryptoStream = New CryptoStream(memoryStream, _
                                        decryptor, _
                                        CryptoStreamMode.Read)

        Dim plainTextBytes As Byte()
        ReDim plainTextBytes(cipherTextBytes.Length)

        Dim decryptedByteCount As Integer
        decryptedByteCount = cryptoStream.Read(plainTextBytes, _
                                               0, _
                                               plainTextBytes.Length)

        memoryStream.Close()
        cryptoStream.Close()

        Dim plainText As String
        plainText = Encoding.ASCII.GetString(plainTextBytes, _
                                            0, _
                                            decryptedByteCount)

        Return plainText
    End Function
End Module
```

Result
`Decrypted: xRxRxPANCAK3SxRxRx`

## Access as C.Smith

### smbmap
```
smbmap -H nest.htb -u C.Smith -p xRxRxPANCAK3SxRxRx 
[+] IP: nest.htb:445    Name: unknown                                           
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        Data                                                    READ ONLY
        IPC$                                                    NO ACCESS       Remote IPC
        Secure$                                                 READ ONLY
        Users                                                   READ ONLY
```

### smbclient
login to smbclient using the password above
`smbclient -U C.Smith //nest.htb/users`
under C.Smith, we can find the flag

```
smb: \C.Smith\> mget user.txt
Get file user.txt? y
getting file \C.Smith\user.txt of size 34 as user.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
```

# Priviledge Escalation

## Enumeration

### Check HQK Reporting folder

login as C.Smith again
```
smb: \C.Smith\HQK Reporting\> ls
  .                                   D        0  Thu Aug  8 19:06:17 2019
  ..                                  D        0  Thu Aug  8 19:06:17 2019
  AD Integration Module               D        0  Fri Aug  9 08:18:42 2019
  Debug Mode Password.txt             A        0  Thu Aug  8 19:08:17 2019
  HQK_Config_Backup.xml               A      249  Thu Aug  8 19:09:05 2019

```

get all the files under C.Smith
```
\C.Smith
recurse on
prompt off
mget **
```

Check the files
```
find . -type f -ls         
  3671060     20 -rw-r--r--   1 kali     kali        17408 Feb 12 00:42 ./AD\ Integration\ Module/HqkLdap.exe
  3671058      0 -rw-r--r--   1 kali     kali            0 Feb 12 00:42 ./Debug\ Mode\ Password.txt
  3671059      4 -rw-r--r--   1 kali     kali          249 Feb 12 00:42 ./HQK_Config_Backup.xml
```

### HQK_Config_Backup.xml
```
cat HQK_Config_Backup.xml    
<?xml version="1.0"?>
<ServiceSettings xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <Port>4386</Port>
  <QueryDirectory>C:\Program Files\HQK\ALL QUERIES</QueryDirectory>
</ServiceSettings>  
```

### Debug Mode Password.txt
https://www.howtogeek.com/1325/stupid-geek-tricks-hide-data-in-a-secret-text-file-compartment/

It has 0 bytes so it is empty.

### HqkLdap.exe

```
file HqkLdap.exe           
HqkLdap.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
```

Check the inside using DNSpy

In `MainModule`
```cs
if (MyProject.Application.CommandLineArgs.Count != 1)                    
{                        
	Console.WriteLine("Invalid number of command line arguments");
}else if (!File.Exists(MyProject.Application.CommandLineArgs[0]))                  {
	Console.WriteLine("Specified config file does not exist");
}
else if (!File.Exists("HqkDbImport.exe"))                    
{
	Console.WriteLine("Please ensure the optional database import module is installed");
}
else
{
	LDAP Stuff...
}
```

We need `config file` and `HqkDbImport.exe`?

### LDAP Stuff part

```cs
LdapSearchSettings ldapSearchSettings = new LdapSearchSettings();string[] array = File.ReadAllLines(MyProject.Application.CommandLineArgs[0]);     foreach (string text in array){
	if (text.StartsWith("Domain=", StringComparison.CurrentCultureIgnoreCase))
	{
		ldapSearchSettings.Domain = text.Substring(text.IndexOf('=') + 1);
	}
	else if(text.StartsWith("User=", StringComparison.CurrentCultureIgnoreCase))
	{
		ldapSearchSettings.Username = text.Substring(text.IndexOf('=') + 1);
	}
	else if (text.StartsWith("Password=", StringComparison.CurrentCultureIgnoreCase))
	{
		ldapSearchSettings.Password = CR.DS(text.Substring(text.IndexOf('=') + 1));
	}
}
Ldap ldap = new Ldap();
ldap.Username = ldapSearchSettings.Username;
ldap.Password = ldapSearchSettings.Password;ldap.Domain = ldapSearchSettings.Domain;
Console.WriteLine("Performing LDAP query...");
List<string> list = ldap.FindUsers();
Console.WriteLine(Conversions.ToString(list.Count) + " user accounts found. Importing to database...");
try{
	foreach (string text2 in list){
		Console.WriteLine(text2);
		Process.Start("HqkDbImport.exe /ImportLdapUser " + text2);
	}
}
finally
{
	List<string>.Enumerator enumerator;
	((IDisposable)enumerator).Dispose();
}
```


If we want to get the plaintext password, we need the ciphered text and run this program.
The main module calls CR class and the conf file should have all the information about users and passwords.

### What we want from this code
1.  The code loads conf file as an argument
2.  I assume that the conf file has several users and encrypted password information
3.  The code loads the conf file line by line
4.  Password will be decrypted
5.  Hopefully the conf file as some admin info

