---
title: Path Traversal
tags:
  - Portswigger
  - Web Security
  - Path Traversal
categories:
  - Portswigger
position: right
cover: '/img/path-traversal-cover.png'
description: 'What I learned after completing Path Traversal path in Portswigger'
date: 2026-07-01 16:51:00
---

>  **Difficulty**: <span style="color:#9fef00">Apprentice</span>

## Introduction
This path covers directory traversal (a.k.a path traversal) attacks, how applications become vulnerable to them, the various techniques used to bypass common defenses, and how to properly prevent them.

<!-- more -->

## Origins Of Path Traversal

Imagine a shopping application that displays images of items for sale. This might load an image using the following HTML:

```html
<img src="/loadImage?filename=218.png">
```

The `loadImage` URL takes a `filename` parameter and returns the contents of the specified file. The image files are stored on disk in the location `/var/www/images/`. To return an image, the application appends the requested filename to this base directory and uses a filesystem API to read the contents of the file. In other words, the application reads from the following file path:

```plain text
/var/www/images/218.png
```

This is exactly the kind of concatenation-with-user-input pattern that also causes <span style="color:#9fef00">CRITICAL</span> vulnerabilities like SQLi, except here the injection point is a filesystem path instead of a query.

## Exploiting The Vulnerability

If the application implements no defenses against path traversal attacks, an attacker can request the following URL to retrieve the `/etc/passwd` file from the server's filesystem:

```plain text
https://insecure-website.com/loadImage?filename=../../../etc/passwd
```

This causes the application to read from the following file path:

```plain text
/var/www/images/../../../etc/passwd
```

The sequence `../` is valid within a file path, and means to step up one level in the directory structure. The three consecutive `../` sequences step up from `/var/www/images/` to the filesystem root, and so the file that is actually read is:

```plain text
/etc/passwd
```

On Windows, both `../` and `..\` are valid directory traversal sequences. The following is an example of an equivalent attack against a Windows-based server:

```plain text
https://insecure-website.com/loadImage?filename=..\..\..\windows\win.ini
```

## Bypassing Common Defenses

If an application strips or blocks directory traversal sequences from the user-supplied filename, it might be possible to bypass the defense using a variety of techniques.

* **Absolute path** - You might be able to use an absolute path from the filesystem root, such as `filename=/etc/passwd`, to directly reference a file without using any traversal sequences.

* **Nested traversal sequences** - You might be able to use nested traversal sequences, such as `....//` or `....\/`. These revert to simple traversal sequences when the inner sequence is stripped.

* **Encoding** - In some contexts, such as in a URL path or the `filename` parameter of a `multipart/form-data` request, web servers may strip any directory traversal sequences before passing your input to the application. You can sometimes bypass this kind of sanitization by URL encoding, or even double URL encoding, the `../` characters. This results in `%2e%2e%2f` and `%252e%252e%252f` respectively. Various non-standard encodings, such as `..%c0%af` or `..%ef%bc%8f`, may also work.

* **Required base folder** - An application may require the user-supplied filename to start with the expected base folder, such as `/var/www/images`. In this case, it might be possible to include the required base folder followed by suitable traversal sequences. For example: `filename=/var/www/images/../../../etc/passwd`.

* **Required file extension** - An application may require the user-supplied filename to end with an expected file extension, such as `.png`. In this case, it might be possible to use a null byte to effectively terminate the file path before the required extension. For example: `filename=../../../etc/passwd%00.png`.

{% note warning %}
**ALWAYS TEST MULTIPLE BYPASS TECHNIQUES TOGETHER, DEFENSES ARE OFTEN STACKED AND A SINGLE ENCODING TRICK MIGHT NOT BE ENOUGH ON ITS OWN**
{% endnote %}

## How To Prevent Path Traversal

The most effective way to prevent path traversal vulnerabilities is to avoid passing user-supplied input to filesystem APIs altogether. Many application functions that do this can be rewritten to deliver the same behavior in a safer way, for example by using a lookup index instead of the actual filename.

If you can't avoid passing user-supplied input to filesystem APIs, we recommend using two layers of defense to prevent attacks:

* Validate the user input before processing it. Ideally, compare the user input with a whitelist of permitted values. If that isn't possible, verify that the input contains only permitted content, such as alphanumeric characters only.
* After validating the supplied input, append the input to the base directory and use a platform filesystem API to canonicalize the path. Verify that the canonicalized path starts with the expected base directory.

Below is an example of some simple Java code to validate the canonical path of a file based on user input:

```java
File file = new File(BASE_DIRECTORY, userInput);
if (file.getCanonicalPath().startsWith(BASE_DIRECTORY)) {
    // process file
}
```

## Summary

Path traversal is a deceptively simple vulnerability, one unsanitized `filename` parameter is all it takes to read arbitrary files off the server. Defenses that strip `../` naively can almost always be bypassed with nesting, encoding, or null bytes, so the only reliable fix is validating input against a whitelist and canonicalizing the resulting path before using it.

{% note info %}
And I highly recommend scripting the lab solvings in python to learn new things and develop the mindset for creating your own tools. 
As a reference here is my repo where I pushed my scripts: [Path Traversal Scripts Repo](https://github.com/0xkoat/portswigger_scripts/tree/main/Path_Traversal)
{% endnote %}

Have a nice day, and see you again in the next Article!
Any feedback in the comments section is very appreciated.
Thank you for your attention.
