---
layout: post
title: HTB Keeper Writeup
category: Writeups
---

## ENUMERATION

```shell
rustscan -a 10.10.11.227
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'.
Open 10.10.11.227:22
Open 10.10.11.227:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-10 04:28 EST
Initiating Ping Scan at 04:28
Scanning 10.10.11.227 [2 ports]
Completed Ping Scan at 04:28, 0.07s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 04:28
Completed Parallel DNS resolution of 1 host. at 04:28, 0.04s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 04:28
Scanning 10.10.11.227 [2 ports]
Discovered open port 22/tcp on 10.10.11.227
Discovered open port 80/tcp on 10.10.11.227
Completed Connect Scan at 04:28, 1.45s elapsed (2 total ports)
Nmap scan report for 10.10.11.227
Host is up, received syn-ack (0.13s latency).
Scanned at 2024-01-10 04:28:50 EST for 2s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1.64 seconds
```

## INITIAL ACCESS

We find RT Ticketing platform with default credentials, inside there is a ticket with user credentials to the machine.
Defaul creds => root:password

## PRIVESC

We find the keepass dump cited in the rt ticket, we then dump the master key password utilizing a known CVE, inside we find the key to access as root.

### Refs

https://github.com/vdohney/keepass-password-dumper
https://github.com/matro7sh/keepass-dump-masterkey
