---
file_created: 03 Sep 2025 06:06
title: TheFrizz
difficulty: Medium
difficult_sort: 2
points: 0
os: Windows
target_ip:
platform: Hack The Box
category: B2R
box_status: Retired
url: https://app.hackthebox.com/machines/TheFrizz
user_flag:
root_flag:
completed:
date_finish:
tags: htb/machines
---
# Resolution summary
![](<./attachments/TheFrizz.png>)
>[!summary]
>- Step 1
>- Step 2

TheFrizz` is a medium-difficulty Windows machine featuring a web application showcasing Walkerville Elementary School and a Gibbon CMS instance. 
- The Gibbon-LMS instance is susceptible to unauthenticated arbitrary file write (CVE-2023-45878), which is used to write a PHP shell to the web application and gain access to the target. 
- After gaining access to the system, a database settings file containing credentials to access MySQL includes a hash and salt for the user f.frizzle that can be cracked. 
- After cracking the password, we authenticate to the target using SSH with GSSAPI/Kerberos. 
- We request a TGT, which is then used to authenticate via Kerberos authentication.
- A deleted 7Zip archive is discovered in the `fiona` user&#039;s recycling bin which is extracted revealing a WAPT setup and includes a configuration file with base64-encoded credentials used to authenticate as the `M.Schoolbus` user. `M.Schoolbus` is a member of the `Group Policy Creator Owners`, which allows them to create GPOs within the domain, which is leveraged to escalate privileges to `NT Authority\System`.
## Tutorial
- [HTB-Write-up](<./attachments/TheFrizz.pdf>)
```cardlink
url: https://youtu.be/1fCOHQE6A6c
title: "HackTheBox - TheFrizz"
description: "00:00 - Introduction00:32 - Start of nmap03:20 - Discovering Gibbon LMS is running and enumerating the version04:45 - Using CVEDetails to look at CVE's for G..."
host: youtu.be
favicon: https://www.youtube.com/s/desktop/68a20589/img/favicon_32x32.png
image: https://i.ytimg.com/vi/1fCOHQE6A6c/maxresdefault.jpg
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
export TARGET_IP=
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

---
# Guided-Mode
1. What is the fully qualified domain name for the host domain controller on TheFrizz? 
```sh
frizzdc.frizz.htb
```
2. What framework is the website on TCP port 80 built on? 
 ```sh
 Gibbon
 ```
3. What is the 2023 CVE ID for an unauthenticated arbitrary file write vulnerability in this version of Gibbon that can leave to remote code execution? 
```sh
CVE-2023-45878
```
4. What system user is the website running as?
```sh
w.webservice
```
