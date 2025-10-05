---
file_created: 05 Oct 2025 15:25
title: DarkZero
difficulty: Hard
difficult_sort: 3
points: 40
os: Windows
target_ip: 10.10.11.89
platform: Hack The Box
category: B2R
box_status: Active
url: https://app.hackthebox.com/machines/754
user_flag:
root_flag:
completed:
date_finish:
tags:
  - htb/machines
  - season-9
---
# Resolution summary
![250](<./attachments/DarkZero.png>)
>[!summary]
>Given account: john.w / RFulUtONCOL!
>- Step 1
>- Step 2
## Tutorial

## Improved Skills
- Skill 1
- Skill 2

## Tools Used 
- rustscan ; nmap ; gobuster
---
# Environment Setup
```bash
export HOST_IP=10.10.14.61
export TARGET_IP=10.10.11.89
export DOMAIN=darkzero.htb
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
```

## Enumerated open TCP ports:

```bash
nmap -sC -sV -Pn -vv $TARGET_IP -p 53,88,135,139,389,445,464,593,636,1433,2179,3268,3269,5985,9389,49664,49667,49682,49683,49901,49924,49971,51505,53197

PORT      STATE    SERVICE       REASON      VERSION
53/tcp    open     domain        syn-ack     Simple DNS Plus
88/tcp    open     kerberos-sec  syn-ack     Microsoft Windows Kerberos (server time: 2025-10-05 21:04:08Z)
135/tcp   open     msrpc         syn-ack     Microsoft Windows RPC
139/tcp   open     netbios-ssn   syn-ack     Microsoft Windows netbios-ssn
389/tcp   open     ldap          syn-ack     Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.darkzero.htb
| Issuer: commonName=darkzero-DC01-CA/domainComponent=darkzero
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-07-29T11:40:00
| Not valid after:  2026-07-29T11:40:00
| MD5:   ce57:1ac8:da76:eb62:efe8:4e85:045b:d440
| SHA-1: 603a:f638:aabb:7eaa:1bdb:4256:5869:4de2:98b6:570c
| -----BEGIN CERTIFICATE-----
| MIIHNzCCBR+gAwIBAgITUgAAAAO4Lw91dEi9jwAAAAAAAzANBgkqhkiG9w0BAQsF
| ADBKMRMwEQYKCZImiZPyLGQBGRYDaHRiMRgwFgYKCZImiZPyLGQBGRYIZGFya3pl
| cm8xGTAXBgNVBAMTEGRhcmt6ZXJvLURDMDEtQ0EwHhcNMjUwNzI5MTE0MDAwWhcN
| MjYwNzI5MTE0MDAwWjAcMRowGAYDVQQDExFEQzAxLmRhcmt6ZXJvLmh0YjCCASIw
| DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALtgbmGxyLJnTefHNna7EjMScNUA
| n0C+Q4T4jkD9YjX+wpNOXHgmnrqpo8wYV0gQAGK9bnTYC8RJb7vWSZrI3MP+/dHw
| nB6AuOXvz6ahChE6C6wlnxMjD9NeJtwzq/RSpHjBFRc+sfGPbX32Y2CEjqzJISHR
| yOnbnuldHK3I4UNKVN28miXaB/dqrK3/Z6rFOuPWbnEqMuYV4LQh4tvxYb5QALUA
| jTwITLAp1prBoUQkdF5UAcpc/oIuP6VKYpjvv+m/yMuvaDIS+QtjRkP+4+ES0Tk3
| gZ489D4lkgndvw6Oz7MwZtpTXwAvmEWb6L0Pg+M0Vd5UjnkxNUiUsAGKgAECAwEA
| AaOCA0IwggM+MC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdABy
| AG8AbABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0P
| AQH/BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqG
| SIb3DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQB
| AjALBglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFDd9
| RV4kuWN9NU3bdgWvT4UqaXTjMB8GA1UdIwQYMBaAFGapgxh49WSDZkbTTZ9eZ8L7
| ypx7MIHMBgNVHR8EgcQwgcEwgb6ggbuggbiGgbVsZGFwOi8vL0NOPWRhcmt6ZXJv
| LURDMDEtQ0EsQ049REMwMSxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2Vydmlj
| ZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1kYXJremVybyxEQz1o
| dGI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNS
| TERpc3RyaWJ1dGlvblBvaW50MIHDBggrBgEFBQcBAQSBtjCBszCBsAYIKwYBBQUH
| MAKGgaNsZGFwOi8vL0NOPWRhcmt6ZXJvLURDMDEtQ0EsQ049QUlBLENOPVB1Ymxp
| YyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24s
| REM9ZGFya3plcm8sREM9aHRiP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFz
| cz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MD0GA1UdEQQ2MDSgHwYJKwYBBAGCNxkB
| oBIEEOfsqvw66j9ItSxN2uPjJRqCEURDMDEuZGFya3plcm8uaHRiME4GCSsGAQQB
| gjcZAgRBMD+gPQYKKwYBBAGCNxkCAaAvBC1TLTEtNS0yMS0xMTUyMTc5OTM1LTU4
| OTEwODE4MC0xOTg5ODkyNDYzLTEwMDAwDQYJKoZIhvcNAQELBQADggIBAL28m69f
| CO5DYoe/9OPZ5i7haHUhbbyZSv0LRnJawwCP+YLaA6VWpmqBrqAVZ4lvP74KqRSs
| oEkwwX7C8lYEvSA+C97NcpoBzeH9aWCEWC/EaEz3sEL/QKcG7beM04HpP5qIzurP
| gqFJXBwmJSTvNPD53pN7edGlvC0tFgvuqXP/7L2xDnsxHeAA98RUl8NW8rwAlijj
| Car4Q0gryC682mAISxsHlv3Xp5ID5Ny8XkpIY9/qtVCtBXXDMd4XNzt1lGedHDWs
| 1OaZuQvWJMQjKrdFQ59m/bzpLggMlCF7a2TgMJ4wISuJeVXhyd2WXXBQfMigjQVl
| IfR+jf2n43K7ZJOjpZizW4sInL6efS9KW7A6XE7Tzx+ZLdko4sj444mwbXnLgTgQ
| a9N04FJMp6TKLSRO/Vk0AGD9cpLOwINLM2jgPaepAvfThifKGDX2gA4vfFCEVPp1
| /fLrQDjWwZfKBKchZQZ6RZzj1dfnZDIKhV9JT3Kfy1iIFTl2I8YDSmzumXdS4VgY
| pcDf6d2i1duAjNoNvg2pZj7gPzrhzim2g0ezy1Ipcu1AfeJBZ+zlsxpnZ1vPMnQ6
| j2Pwkxplofr8WFcyMBh1lXce8PrTm8+n70sA3D4InyfEhyydgzKsQTmeNbfQCOSY
| TwaWbho49qkLrdLNpB0KN4kHVKKweu3cvvcF
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
445/tcp   open     microsoft-ds? syn-ack
464/tcp   open     kpasswd5?     syn-ack
593/tcp   open     ncacn_http    syn-ack     Microsoft Windows RPC over HTTP 1.0
636/tcp   open     ssl/ldap      syn-ack     Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.darkzero.htb
| Issuer: commonName=darkzero-DC01-CA/domainComponent=darkzero
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-07-29T11:40:00
| Not valid after:  2026-07-29T11:40:00
| MD5:   ce57:1ac8:da76:eb62:efe8:4e85:045b:d440
| SHA-1: 603a:f638:aabb:7eaa:1bdb:4256:5869:4de2:98b6:570c
| -----BEGIN CERTIFICATE-----
| MIIHNzCCBR+gAwIBAgITUgAAAAO4Lw91dEi9jwAAAAAAAzANBgkqhkiG9w0BAQsF
| ADBKMRMwEQYKCZImiZPyLGQBGRYDaHRiMRgwFgYKCZImiZPyLGQBGRYIZGFya3pl
| cm8xGTAXBgNVBAMTEGRhcmt6ZXJvLURDMDEtQ0EwHhcNMjUwNzI5MTE0MDAwWhcN
| MjYwNzI5MTE0MDAwWjAcMRowGAYDVQQDExFEQzAxLmRhcmt6ZXJvLmh0YjCCASIw
| DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALtgbmGxyLJnTefHNna7EjMScNUA
| n0C+Q4T4jkD9YjX+wpNOXHgmnrqpo8wYV0gQAGK9bnTYC8RJb7vWSZrI3MP+/dHw
| nB6AuOXvz6ahChE6C6wlnxMjD9NeJtwzq/RSpHjBFRc+sfGPbX32Y2CEjqzJISHR
| yOnbnuldHK3I4UNKVN28miXaB/dqrK3/Z6rFOuPWbnEqMuYV4LQh4tvxYb5QALUA
| jTwITLAp1prBoUQkdF5UAcpc/oIuP6VKYpjvv+m/yMuvaDIS+QtjRkP+4+ES0Tk3
| gZ489D4lkgndvw6Oz7MwZtpTXwAvmEWb6L0Pg+M0Vd5UjnkxNUiUsAGKgAECAwEA
| AaOCA0IwggM+MC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdABy
| AG8AbABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0P
| AQH/BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqG
| SIb3DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQB
| AjALBglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFDd9
| RV4kuWN9NU3bdgWvT4UqaXTjMB8GA1UdIwQYMBaAFGapgxh49WSDZkbTTZ9eZ8L7
| ypx7MIHMBgNVHR8EgcQwgcEwgb6ggbuggbiGgbVsZGFwOi8vL0NOPWRhcmt6ZXJv
| LURDMDEtQ0EsQ049REMwMSxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2Vydmlj
| ZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1kYXJremVybyxEQz1o
| dGI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNS
| TERpc3RyaWJ1dGlvblBvaW50MIHDBggrBgEFBQcBAQSBtjCBszCBsAYIKwYBBQUH
| MAKGgaNsZGFwOi8vL0NOPWRhcmt6ZXJvLURDMDEtQ0EsQ049QUlBLENOPVB1Ymxp
| YyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24s
| REM9ZGFya3plcm8sREM9aHRiP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFz
| cz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MD0GA1UdEQQ2MDSgHwYJKwYBBAGCNxkB
| oBIEEOfsqvw66j9ItSxN2uPjJRqCEURDMDEuZGFya3plcm8uaHRiME4GCSsGAQQB
| gjcZAgRBMD+gPQYKKwYBBAGCNxkCAaAvBC1TLTEtNS0yMS0xMTUyMTc5OTM1LTU4
| OTEwODE4MC0xOTg5ODkyNDYzLTEwMDAwDQYJKoZIhvcNAQELBQADggIBAL28m69f
| CO5DYoe/9OPZ5i7haHUhbbyZSv0LRnJawwCP+YLaA6VWpmqBrqAVZ4lvP74KqRSs
| oEkwwX7C8lYEvSA+C97NcpoBzeH9aWCEWC/EaEz3sEL/QKcG7beM04HpP5qIzurP
| gqFJXBwmJSTvNPD53pN7edGlvC0tFgvuqXP/7L2xDnsxHeAA98RUl8NW8rwAlijj
| Car4Q0gryC682mAISxsHlv3Xp5ID5Ny8XkpIY9/qtVCtBXXDMd4XNzt1lGedHDWs
| 1OaZuQvWJMQjKrdFQ59m/bzpLggMlCF7a2TgMJ4wISuJeVXhyd2WXXBQfMigjQVl
| IfR+jf2n43K7ZJOjpZizW4sInL6efS9KW7A6XE7Tzx+ZLdko4sj444mwbXnLgTgQ
| a9N04FJMp6TKLSRO/Vk0AGD9cpLOwINLM2jgPaepAvfThifKGDX2gA4vfFCEVPp1
| /fLrQDjWwZfKBKchZQZ6RZzj1dfnZDIKhV9JT3Kfy1iIFTl2I8YDSmzumXdS4VgY
| pcDf6d2i1duAjNoNvg2pZj7gPzrhzim2g0ezy1Ipcu1AfeJBZ+zlsxpnZ1vPMnQ6
| j2Pwkxplofr8WFcyMBh1lXce8PrTm8+n70sA3D4InyfEhyydgzKsQTmeNbfQCOSY
| TwaWbho49qkLrdLNpB0KN4kHVKKweu3cvvcF
|_-----END CERTIFICATE-----
1433/tcp  open     ms-sql-s      syn-ack     Microsoft SQL Server 2022 16.00.1000.00; RC0+
|_ssl-date: 2025-10-05T21:05:52+00:00; +7h01m15s from scanner time.
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-10-05T20:59:39
| Not valid after:  2055-10-05T20:59:39
| MD5:   8a25:7cc9:cadc:67fc:74e6:31ed:9698:cb85
| SHA-1: 60fc:13b9:306f:2873:2344:653a:19b7:d655:4669:486d
| -----BEGIN CERTIFICATE-----
| MIIEADCCAmigAwIBAgIQKXMaia1G8o1BxOOze0Y0szANBgkqhkiG9w0BAQsFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjUxMDA1MjA1OTM5WhgPMjA1NTEwMDUyMDU5MzlaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAKVPOMx3
| DnVeoD9Nf02eXzp/cxDKqSxjbr6RAXsuqd8zEcCIQAEoeXtBsWDh65QGcO38hTAe
| 1GHScCfYv6HNVz41ossxsSKS2OWQDlNtZI0/meFiVim4Og+YllwhjsOgBNnwbuem
| 9pF48yoOrEpm/H+zWaTrtJfaphn3oZT2YPbi4lmSvngCwvMP1bf9lBoBF4buMSPR
| k9AOolwaQiYrHEbjFMgFWO6nBRyFnKHo1rvqhrtOgJ6/1JYCnqT1FHFuVxUeN6gD
| Phr3Ss6lEzPAHHW9MuW1rbt4OGV3OLXCuLUWdkGAltotTS5QjIhqhbZu3KJ7gKMl
| FTLeUkx1OBlWjoj4pn5/nd5A9NP5d8TOs26C4mSFMvae9bVAPcYhL3I2vHjcQNgL
| QBBdpeHZMg8C95+ZLvNf2FfLI95R3p9hH82wsp96M+F/TW2/2mgAmKQTNLLc5pXB
| 5q1WjsIloY3cOD+iwuUls9pWtseIvbyV11TIVR/KvfkFV82EV6oZf02vCQIDAQAB
| MA0GCSqGSIb3DQEBCwUAA4IBgQCBkhHsQi8NbNeVcK3NHaCPvEG436D9wCN55cRf
| wFYsaLVREVEDYRkhpjm/maNpGOJeSWCKr4aq6iZZEZyzt2zKVKg4aFqhFrjisi5x
| AT8zF9kZmj58CkU/DCt6Z3ipj9lx/GHljShafqZnBMpiZS/Y8A0W/azvUYbie2T0
| aAJ+CX6b78wmTgUjNw6NAqpHJxc+6mWnTXkGY0J9lnaKS30t3ifFp/ij3Orem06f
| QrmrCNaiDjCndJeWMfAep4NYa+IdJGPmMSI1ZlywMWRBB2BvuubW3L8RpumYIs1P
| SAbKt8/FO4XyNH35EEOZd9p3hczk1/rnJIjETdleJGbuRazUSDpeu+aT7GJyCi0o
| 0cSDYY2FJ2OxhuRoTo62MxVXtWnAMoNQ2FW9CWXJON7a7lr5g0sk2T8ABmoS/MhH
| L15Fryryl2giZe2mrmMrFfXjHhopxm/jHqa1P8Wmjgpja5IayvpfKQ5F8/sgiZJg
| ON4RDEvv3TfWjG4zYDU2fs+bAqc=
|_-----END CERTIFICATE-----
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
2179/tcp  open     vmrdp?        syn-ack
3268/tcp  open     ldap          syn-ack     Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.darkzero.htb
| Issuer: commonName=darkzero-DC01-CA/domainComponent=darkzero
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-07-29T11:40:00
| Not valid after:  2026-07-29T11:40:00
| MD5:   ce57:1ac8:da76:eb62:efe8:4e85:045b:d440
| SHA-1: 603a:f638:aabb:7eaa:1bdb:4256:5869:4de2:98b6:570c
| -----BEGIN CERTIFICATE-----
| MIIHNzCCBR+gAwIBAgITUgAAAAO4Lw91dEi9jwAAAAAAAzANBgkqhkiG9w0BAQsF
| ADBKMRMwEQYKCZImiZPyLGQBGRYDaHRiMRgwFgYKCZImiZPyLGQBGRYIZGFya3pl
| cm8xGTAXBgNVBAMTEGRhcmt6ZXJvLURDMDEtQ0EwHhcNMjUwNzI5MTE0MDAwWhcN
| MjYwNzI5MTE0MDAwWjAcMRowGAYDVQQDExFEQzAxLmRhcmt6ZXJvLmh0YjCCASIw
| DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALtgbmGxyLJnTefHNna7EjMScNUA
| n0C+Q4T4jkD9YjX+wpNOXHgmnrqpo8wYV0gQAGK9bnTYC8RJb7vWSZrI3MP+/dHw
| nB6AuOXvz6ahChE6C6wlnxMjD9NeJtwzq/RSpHjBFRc+sfGPbX32Y2CEjqzJISHR
| yOnbnuldHK3I4UNKVN28miXaB/dqrK3/Z6rFOuPWbnEqMuYV4LQh4tvxYb5QALUA
| jTwITLAp1prBoUQkdF5UAcpc/oIuP6VKYpjvv+m/yMuvaDIS+QtjRkP+4+ES0Tk3
| gZ489D4lkgndvw6Oz7MwZtpTXwAvmEWb6L0Pg+M0Vd5UjnkxNUiUsAGKgAECAwEA
| AaOCA0IwggM+MC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdABy
| AG8AbABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0P
| AQH/BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqG
| SIb3DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQB
| AjALBglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFDd9
| RV4kuWN9NU3bdgWvT4UqaXTjMB8GA1UdIwQYMBaAFGapgxh49WSDZkbTTZ9eZ8L7
| ypx7MIHMBgNVHR8EgcQwgcEwgb6ggbuggbiGgbVsZGFwOi8vL0NOPWRhcmt6ZXJv
| LURDMDEtQ0EsQ049REMwMSxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2Vydmlj
| ZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1kYXJremVybyxEQz1o
| dGI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNS
| TERpc3RyaWJ1dGlvblBvaW50MIHDBggrBgEFBQcBAQSBtjCBszCBsAYIKwYBBQUH
| MAKGgaNsZGFwOi8vL0NOPWRhcmt6ZXJvLURDMDEtQ0EsQ049QUlBLENOPVB1Ymxp
| YyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24s
| REM9ZGFya3plcm8sREM9aHRiP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFz
| cz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MD0GA1UdEQQ2MDSgHwYJKwYBBAGCNxkB
| oBIEEOfsqvw66j9ItSxN2uPjJRqCEURDMDEuZGFya3plcm8uaHRiME4GCSsGAQQB
| gjcZAgRBMD+gPQYKKwYBBAGCNxkCAaAvBC1TLTEtNS0yMS0xMTUyMTc5OTM1LTU4
| OTEwODE4MC0xOTg5ODkyNDYzLTEwMDAwDQYJKoZIhvcNAQELBQADggIBAL28m69f
| CO5DYoe/9OPZ5i7haHUhbbyZSv0LRnJawwCP+YLaA6VWpmqBrqAVZ4lvP74KqRSs
| oEkwwX7C8lYEvSA+C97NcpoBzeH9aWCEWC/EaEz3sEL/QKcG7beM04HpP5qIzurP
| gqFJXBwmJSTvNPD53pN7edGlvC0tFgvuqXP/7L2xDnsxHeAA98RUl8NW8rwAlijj
| Car4Q0gryC682mAISxsHlv3Xp5ID5Ny8XkpIY9/qtVCtBXXDMd4XNzt1lGedHDWs
| 1OaZuQvWJMQjKrdFQ59m/bzpLggMlCF7a2TgMJ4wISuJeVXhyd2WXXBQfMigjQVl
| IfR+jf2n43K7ZJOjpZizW4sInL6efS9KW7A6XE7Tzx+ZLdko4sj444mwbXnLgTgQ
| a9N04FJMp6TKLSRO/Vk0AGD9cpLOwINLM2jgPaepAvfThifKGDX2gA4vfFCEVPp1
| /fLrQDjWwZfKBKchZQZ6RZzj1dfnZDIKhV9JT3Kfy1iIFTl2I8YDSmzumXdS4VgY
| pcDf6d2i1duAjNoNvg2pZj7gPzrhzim2g0ezy1Ipcu1AfeJBZ+zlsxpnZ1vPMnQ6
| j2Pwkxplofr8WFcyMBh1lXce8PrTm8+n70sA3D4InyfEhyydgzKsQTmeNbfQCOSY
| TwaWbho49qkLrdLNpB0KN4kHVKKweu3cvvcF
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
3269/tcp  open     ssl/ldap      syn-ack     Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.darkzero.htb
| Issuer: commonName=darkzero-DC01-CA/domainComponent=darkzero
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-07-29T11:40:00
| Not valid after:  2026-07-29T11:40:00
| MD5:   ce57:1ac8:da76:eb62:efe8:4e85:045b:d440
| SHA-1: 603a:f638:aabb:7eaa:1bdb:4256:5869:4de2:98b6:570c
| -----BEGIN CERTIFICATE-----
| MIIHNzCCBR+gAwIBAgITUgAAAAO4Lw91dEi9jwAAAAAAAzANBgkqhkiG9w0BAQsF
| ADBKMRMwEQYKCZImiZPyLGQBGRYDaHRiMRgwFgYKCZImiZPyLGQBGRYIZGFya3pl
| cm8xGTAXBgNVBAMTEGRhcmt6ZXJvLURDMDEtQ0EwHhcNMjUwNzI5MTE0MDAwWhcN
| MjYwNzI5MTE0MDAwWjAcMRowGAYDVQQDExFEQzAxLmRhcmt6ZXJvLmh0YjCCASIw
| DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALtgbmGxyLJnTefHNna7EjMScNUA
| n0C+Q4T4jkD9YjX+wpNOXHgmnrqpo8wYV0gQAGK9bnTYC8RJb7vWSZrI3MP+/dHw
| nB6AuOXvz6ahChE6C6wlnxMjD9NeJtwzq/RSpHjBFRc+sfGPbX32Y2CEjqzJISHR
| yOnbnuldHK3I4UNKVN28miXaB/dqrK3/Z6rFOuPWbnEqMuYV4LQh4tvxYb5QALUA
| jTwITLAp1prBoUQkdF5UAcpc/oIuP6VKYpjvv+m/yMuvaDIS+QtjRkP+4+ES0Tk3
| gZ489D4lkgndvw6Oz7MwZtpTXwAvmEWb6L0Pg+M0Vd5UjnkxNUiUsAGKgAECAwEA
| AaOCA0IwggM+MC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdABy
| AG8AbABsAGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0P
| AQH/BAQDAgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqG
| SIb3DQMEAgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQB
| AjALBglghkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFDd9
| RV4kuWN9NU3bdgWvT4UqaXTjMB8GA1UdIwQYMBaAFGapgxh49WSDZkbTTZ9eZ8L7
| ypx7MIHMBgNVHR8EgcQwgcEwgb6ggbuggbiGgbVsZGFwOi8vL0NOPWRhcmt6ZXJv
| LURDMDEtQ0EsQ049REMwMSxDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2Vydmlj
| ZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1kYXJremVybyxEQz1o
| dGI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNS
| TERpc3RyaWJ1dGlvblBvaW50MIHDBggrBgEFBQcBAQSBtjCBszCBsAYIKwYBBQUH
| MAKGgaNsZGFwOi8vL0NOPWRhcmt6ZXJvLURDMDEtQ0EsQ049QUlBLENOPVB1Ymxp
| YyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24s
| REM9ZGFya3plcm8sREM9aHRiP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFz
| cz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MD0GA1UdEQQ2MDSgHwYJKwYBBAGCNxkB
| oBIEEOfsqvw66j9ItSxN2uPjJRqCEURDMDEuZGFya3plcm8uaHRiME4GCSsGAQQB
| gjcZAgRBMD+gPQYKKwYBBAGCNxkCAaAvBC1TLTEtNS0yMS0xMTUyMTc5OTM1LTU4
| OTEwODE4MC0xOTg5ODkyNDYzLTEwMDAwDQYJKoZIhvcNAQELBQADggIBAL28m69f
| CO5DYoe/9OPZ5i7haHUhbbyZSv0LRnJawwCP+YLaA6VWpmqBrqAVZ4lvP74KqRSs
| oEkwwX7C8lYEvSA+C97NcpoBzeH9aWCEWC/EaEz3sEL/QKcG7beM04HpP5qIzurP
| gqFJXBwmJSTvNPD53pN7edGlvC0tFgvuqXP/7L2xDnsxHeAA98RUl8NW8rwAlijj
| Car4Q0gryC682mAISxsHlv3Xp5ID5Ny8XkpIY9/qtVCtBXXDMd4XNzt1lGedHDWs
| 1OaZuQvWJMQjKrdFQ59m/bzpLggMlCF7a2TgMJ4wISuJeVXhyd2WXXBQfMigjQVl
| IfR+jf2n43K7ZJOjpZizW4sInL6efS9KW7A6XE7Tzx+ZLdko4sj444mwbXnLgTgQ
| a9N04FJMp6TKLSRO/Vk0AGD9cpLOwINLM2jgPaepAvfThifKGDX2gA4vfFCEVPp1
| /fLrQDjWwZfKBKchZQZ6RZzj1dfnZDIKhV9JT3Kfy1iIFTl2I8YDSmzumXdS4VgY
| pcDf6d2i1duAjNoNvg2pZj7gPzrhzim2g0ezy1Ipcu1AfeJBZ+zlsxpnZ1vPMnQ6
| j2Pwkxplofr8WFcyMBh1lXce8PrTm8+n70sA3D4InyfEhyydgzKsQTmeNbfQCOSY
| TwaWbho49qkLrdLNpB0KN4kHVKKweu3cvvcF
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
5985/tcp  open     http          syn-ack     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open     mc-nmf        syn-ack     .NET Message Framing
49664/tcp open     msrpc         syn-ack     Microsoft Windows RPC
49667/tcp filtered unknown       no-response
49682/tcp open     msrpc         syn-ack     Microsoft Windows RPC
49683/tcp open     ncacn_http    syn-ack     Microsoft Windows RPC over HTTP 1.0
49901/tcp filtered unknown       no-response
49924/tcp filtered unknown       no-response
49971/tcp filtered unknown       no-response
51505/tcp filtered unknown       no-response
53197/tcp filtered unknown       no-response
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2025-10-05T21:05:15
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 35679/tcp): CLEAN (Timeout)
|   Check 2 (port 15902/tcp): CLEAN (Timeout)
|   Check 3 (port 7628/udp): CLEAN (Timeout)
|   Check 4 (port 45900/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 7h01m14s, deviation: 0s, median: 7h01m14s
```
## Enumerated Top 200 UDP Ports
Scanned the top 200 UDP ports to ensure no additional services were missed:

```bash
nmap -sU --top-ports 200 -oN $TARGET_IP

PORT    STATE SERVICE
88/udp  open  kerberos-sec
389/udp open  ldap
```

## Key Findings from the Scan
The scan reveals a Windows Active Directory environment (darkzero.htb) on a domain controller (DC01). Here’s a breakdown of the open ports and services:

- **53/tcp**: Simple DNS Plus (DNS service, likely for domain resolution).
- **88/tcp**: Microsoft Windows Kerberos (authentication service for Active Directory).
- **135/tcp**: Microsoft Windows RPC (remote procedure call, common in Windows environments).
- **139/tcp**: NetBIOS-SSN (file/printer sharing, legacy Windows networking).
- **389/tcp**: LDAP (Active Directory LDAP, non-encrypted, domain: darkzero.htb).
- **445/tcp**: Microsoft-DS (SMB, file sharing, and domain services).
- **464/tcp**: Kpasswd5 (Kerberos password change service).
- **593/tcp**: Microsoft Windows RPC over HTTP 1.0 (RPC endpoint mapper over HTTP).
- **636/tcp**: SSL/LDAP (encrypted LDAP for Active Directory, domain: darkzero.htb).
- **1433/tcp**: Microsoft SQL Server 2022 (version 16.00.1000.00, RC0+).
- **2179/tcp**: VMRDP (possibly VM Remote Display Protocol, unclear service).
- **3268/tcp**: LDAP (Active Directory Global Catalog, non-encrypted).
- **3269/tcp**: SSL/LDAP (Active Directory Global Catalog, encrypted).
- **5985/tcp**: Microsoft HTTPAPI httpd 2.0 (WinRM, Windows Remote Management).
- **9389/tcp**: .NET Message Framing (used by Active Directory Federation Services or similar).
- **49664/tcp, 49682/tcp, 49683/tcp**: Microsoft Windows RPC or RPC over HTTP (ephemeral ports for RPC services).

**Filtered Ports** (no response, possibly firewalled or no service running):

- 49667, 49901, 49924, 49971, 51505, 53197.

**Certificates and Security**:

- LDAP ports (389, 636, 3268, 3269) use a certificate for DC01.darkzero.htb, issued by darkzero-DC01-CA, valid from July 29, 2025, to July 29, 2026.
- SQL Server (1433) uses a self-signed fallback certificate, valid until 2055.
- SMB2 security mode requires message signing, indicating a secure configuration.

**Host Information**:

- Hostname: DC01.
- OS: Windows (confirmed by CPE: cpe:/o:microsoft:windows).
- Domain: darkzero.htb
- Clock skew: ~7 hours ahead, suggesting a time zone difference or misconfiguration.

**Script Results**:

- SMB2: Message signing enabled and required.
- P2P-Conficker: Host is clean (no Conficker malware detected).
- MS-SQL: Script execution failed for ms-sql-info and ms-sql-ntlm-info (debug with -d for more details).
---
# Enumeration
- Add Domain and hostname to `/etc/hosts`
```bash
echo "10.10.11.89 darkzero.htb DC01.darkzero.htb" | sudo tee -a /etc/hosts
```
> john.w / RFulUtONCOL!

## Port 445 - SMB 
```bash
smbmap -H 10.10.11.89 -u 'john.w' -p 'RFulUtONCOL!'
```


---
# Exploitation

## SQL Injection


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
{{image}}