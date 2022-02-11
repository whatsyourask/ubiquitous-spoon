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

## Gaining access

## Privilege escalation
