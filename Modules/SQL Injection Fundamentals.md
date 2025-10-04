---
file_created: 28 Sep 2025 17:06
description: hack the box module focusing on SQL injection
url:
tags:
  - htb/modules
---
# Summary
- HTB-Cheatsheet:[Sql_Injection_Fundamentals_Module_Cheat_Sheet](<./attachments/Sql_Injection_Fundamentals_Module_Cheat_Sheet.pdf>)
# Intro to MySQL
## Info
### SQL  Uses
**SQL can be used to perform the following actions:**

- Retrieve data
- Update data
- Delete data
- Create new tables and databases
- Add / remove users
- Assign permissions to these users
## Commands
### Command Line
```sql
mysql -u root -p
```
- The `-u` flag is used to supply the username and the `-p` flag for the password.

```sql
mysql -u root -h docker.hackthebox.eu -P 3306 -p 
```
We can specify a remote host and port using the `-h` and `-P` flags.
### Creating a database
- CREATE DATABASE 
```sql
CREATE DATABASE users;
```
- SHOW DATABASES
```sql
SHOW DATABASES;
USE users;
```
## Questions
1. Connect to the database using the MySQL client from the command line. Use the 'show databases;' command to list databases in the DBMS. What is the name of the first database?
```bash 
mysql -u root -h 83.136.252.69 -P 30969 -p
#password
```

```sql
MariaDB [(none)]> SHOW DATABASES;
```
![400](<./attachments/SQL Injection Fundamentals.png>)
- **Answer**
```txt
employees
```
---
# SQL Statements
## Commands
## Questions
 1. What is the department number for the 'Development' department?
```bash
mysql -u root -h 83.136.252.69 -P 30969 -p
# password
```

```sql
MariaDB [(none)]> SHOW DATABASES;
USE employees;
SHOW tables;
SELECT * FROM departments;
```
![](<./attachments/SQL Injection Fundamentals-1.png>)
- **Answer**
```txt
d005
```
# Query Results
## Questions
What is the last name of the employee whose first name starts with "Bar" AND who was hired on 1990-01-01?
```bash
mysql -u root -h 83.136.252.69 -P 30969 -p
# password
```

```sql
MariaDB [(none)]> SHOW DATABASES;
USE employees;
SHOW tables;
SELECT first_name,last_name FROM employees where hire_date = '1990-01-01';
```
![400](<./attachments/SQL Injection Fundamentals-2.png>)
- **Answer**
```txt
Mitchem
```