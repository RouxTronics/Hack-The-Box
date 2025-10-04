---
file_created: 30 Aug 2025 16:07
title: TwoMillion
difficulty: Easy
difficult_sort: 1
points: 0
os: Linux
target_ip: 10.10.11.221
platform: Hack The Box
category: B2R
box_status: Retired
url: https://app.hackthebox.com/machines/TwoMillion
user_flag:
root_flag:
completed: false
date_finish:
tags:
  - htb/machines
---
# Resolution summary

>[!summary]
>- Step 1
>- Step 2
## About
- The account can be used to enumerate various API endpoints, one of which can be used to elevate the user to an Administrator.
- With administrative access the user can perform a command injection in the admin VPN generation endpoint thus gaining a system shell. 
- An .env file is found to contain database credentials and owed to password re-use the attackers can login as user admin on the box. 
- The system kernel is found to be outdated and CVE-2023-0386 can be used to gain a root shell
## Tutorial
```cardlink
url: https://www.youtube.com/watch?v=Exl4P3fsF7U&themeRefresh=1
title: "HackTheBox - TwoMillion"
description: "00:00 - Intro00:18 - Start of nmap, scanning all ports with min-rate02:35 - Browsing to the web page and taking a trip down memory lane with the HackTheBox v..."
host: www.youtube.com
favicon: https://www.youtube.com/s/desktop/271635d3/img/logos/favicon_32x32.png
image: https://i.ytimg.com/vi/Exl4P3fsF7U/maxresdefault.jpg
```
- [HTB-Write-up](<./attachments/TwoMillion.pdf>)
- [Medium](https://medium.com/@andi.parvanov/twomillion-htb-walkthrough-guided-mode-43e30f3370df)
- [Hacklido](https://hacklido.com/blog/949-2million-htb-walkthrough)
## Improved Skills
- Skill 1
- Skill 2
## Tools Used 
- rustscan ; nmap ; gobuster, Nmap; feroxbuster; Burp Suite
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
384029420a144a18ce13da43d7bcd47a
```

## Root Flag 
```txt
3c657a889861244e717732abfa3f16e7
```

## /etc/shadow
```bash
cat /etc/shadow | grep -F "\$" 
```

```txt                                                               
root:$y$j9T$lMX63DLnmS7C2fo11Mluz0$orSq4ixScTWZCqbOolOvi7GqJtj0h/4oyA..NydDMn7:19508:0:99999:7:::
admin:$y$j9T$M.rrzwF088SlZEp26ePcN/$tkFiTne68BW.DOnV4I90X.wIuGYM/gWU5jTgbOlzztD:19508:0:99999:7:::
```
---
# Proof
![](<./attachments/TwoMillion-pwned.png>)
