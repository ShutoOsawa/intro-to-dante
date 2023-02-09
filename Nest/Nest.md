
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

