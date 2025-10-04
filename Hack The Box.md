---
file_created: 25 Sep 2025 17:53
description: Cybersecurity that offers labs and learning modules
tags:
  - platforms
---
# Table of Content
%% Begin Landmark %%
- **Machines**
	- [Artificial](<./Machines/Artificial.md>)
	- [Cap](<./Machines/Cap.md>)
	- [Cobblestone](<./Machines/Cobblestone.md>)
	- [CodePartTwo](<./Machines/CodePartTwo.md>)
	- [Editor](<./Machines/Editor.md>)
	- [Environment](<./Machines/Environment.md>)
	- [Eureka](<./Machines/Eureka.md>)
	- [Expressway](<./Machines/Expressway.md>)
	- [Fluffy](<./Machines/Fluffy.md>)
	- [Imagery](<./Machines/Imagery.md>)
	- [Nocturnal](<./Machines/Nocturnal.md>)
	- [Outbound](<./Machines/Outbound.md>)
	- [Planning](<./Machines/Planning.md>)
	- [Soulmate](<./Machines/Soulmate.md>)
	- [Strutted](<./Machines/Strutted.md>)
	- [tester](<./Machines/tester.md>)
	- [TheFrizz](<./Machines/TheFrizz.md>)
	- [TwoMillion](<./Machines/TwoMillion.md>)
- **Modules**
	- [SQL Injection Fundamentals](<./Modules/SQL Injection Fundamentals.md>)

%% End Landmark %%

---
# Resources
Get Started with the [HTB Beginners Bible](https://www.hackthebox.com/blog/learn-to-hack-beginners-bible)

---
# Machines
```dataview
TABLE without id link(file.link, title) AS "Machine",box_status AS "Status",os AS "OS", difficulty AS "Difficulty",choice(user_flag, "✔", "") AS "User Flag",choice(root_flag, "✔", "") AS "Root Flag"
FROM #htb/machines 
SORT box_status asc, os asc, difficult_sort asc, title asc
```
---
## Completed Machines
### Not Completed
```dataview
TABLE without id link(file.link, title) AS "Machine",os AS "OS", difficulty AS "Difficulty"
FROM #htb/machines 
WHERE completed = false OR !completed
SORT os asc, difficult_sort asc
```
### Completed 
```dataview
TABLE without id link(file.link, title) AS "Machine",os AS "OS", difficulty AS "Difficulty"
FROM #htb/machines 
WHERE completed = true
SORT os asc, difficult_sort asc
```

---
# Modules
```dataview
TABLE without id file.link AS Module, description as Description
FROM #htb/modules 
```

