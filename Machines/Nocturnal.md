---
file_created: 29 Aug 2025 19:47
title: Nocturnal
difficulty: Easy
difficult_sort: 1
points: 0
os: Linux
target_ip: 10.10.11.64
platform: Hack The Box
category: B2R
box_status: Retired
url:
user_flag:
root_flag:
completed:
date_finish:
tags:
  - htb/machines
feature: thumbnails/autocardlink/f84d1057d64eca75f625e50fded57f84.jpg
thumbnail: thumbnails/resized/c264d578c7eb023f4b5855df327cadc0_b89e22fb.jpg
---
# Resolution summary

>[!summary]
>- Step 1
>- Step 2
- `Nocturnal` is a medium-difficulty Linux machine demonstrating an IDOR vulnerability in a PHP web application, allowing access to other users&amp;#039; uploaded files. 
- Credentials are retrieved to log in to the admin panel, where the application&amp;#039;s source code is accessed.
- A command injection vulnerability is identified, providing a reverse shell as the `www-data` user. 
- Password hashes are extracted from a SQLite database and cracked to obtain SSH access as the `tobias` user. 
- Exploiting [CVE-2023-46818](https://nvd.nist.gov/vuln/detail/CVE-2023-46818) in the `ISPConfig` application grants remote command execution, leading to privilege escalation to the `root` user.
## Tutorial
- [HTB-Writeup](<./attachments/Nocturnal.pdf>)
```cardlink
url: https://www.youtube.com/watch?v=tjA3sXsnPqw
title: "HackTheBox - Nocturnal"
description: "00:00 - Introduction00:50 - Start of nmap02:10 - Running gobuster to find PHP Files04:15 - Uploading a file and playing with the file upload functionality08:..."
host: www.youtube.com
favicon: https://www.youtube.com/s/desktop/271635d3/img/logos/favicon_32x32.png
image: https://i.ytimg.com/vi/tjA3sXsnPqw/maxresdefault.jpg
```
## Improved Skills
- Skill 1
- Skill 2

## Tools Used 
- rustscan ; nmap ; gobuster

---
# Environment Setup
```bash
export HOST_IP=
export TARGET_
export DOMAIN=
{
  echo "HOST_IP=${HOST_IP:-}"
  echo "TARGET_IP=${TARGET_IP:-}"
  echo "DOMAIN=${DOMAIN:-}"
} > .env
source .env
```
---
# Information Gathering

## Scanned all TCP ports:

```bash
rustscan -a $IP -r 1-65535 -t 10000 --ulimit 5000
```

## Enumerated open TCP ports:

```bash
nmap -sC -sV -Pn $IP -p <open-port>
```
## Enumerated Top 200 UDP Ports
Scanned the top 200 UDP ports to ensure no additional services were missed:

```bash
nmap -sU --top-ports 200 -oN $IP
```
---
# Enumeration

## Port 80 - HTTP (Apache)


---
# Exploitation

## SQL Injection


---
# Lateral Movement to xxx

## Local enumeration


## Lateral movement vector

---
# Privilege Escalation to xxx

## Local enumeration


## Privilege Escalation vector


---
# Trophies

## User Flag
```txt

```
## Root Flag
```txt
```
## **/etc/shadow**

```bash

```

---
# Proof
{{image}}