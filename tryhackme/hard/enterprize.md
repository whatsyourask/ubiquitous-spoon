# Enterprize

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

And we have a location of typo3.

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

[http://maintest.enterprize.thm/typo3conf/](http://maintest.enterprize.thm/typo3conf/) reveals interesting file `LocalConfiguration.old`.

## Gaining access

## Privilege escalation
