# Simple-Windows-Event-Log-Forwarder (SWELF) 

# ANNOUNCEMENTS
- Dev work will be on hold for the month of June 18

## Summary:

Having the to many log issue?!! Or maybe just cant find what you want from a log forwarder? Maybe they are just to complicated and you want something simple?
This might help you, you tell it the log source and/or the event ID and/or the key words and/or the number of chars in log and/or the length of the commandline, and/or the length of the log itself and the SWELF app will send just that log to your Log Collection location from a windows machine. Also an interesting case has come up recently, that red team could use this to help simulate a SIEM on a VM testing endpoint. :)

## SWELF Design (After Central Configuration is Pushed)
![swelf design](https://user-images.githubusercontent.com/6934294/36953050-de3a92e6-1fdc-11e8-9d8f-44a3660249b1.PNG)

## The details:

Now in early release. SWELF is designed to be a simple enough for almost anyone to use for windows event log forwarding application. The agent will 1st search your logs for what you want then forward just those logs. 
Since SWELF is early release sofwtare this means there may be bugs that exist. 
But this also means im taking feature requests (even if you dont code), deisgn recommendation, and basically any input you think is relavent.
This app is a log forwarder with the ability to search and forward just the logs you want or at least as close to it as you want. This means that you can tell your log forwarding agent (SWELF) exactly what logs to forward and it wont forward the rest (This will help with that pesky "to many logs", "we cant send those logs its to much noise", or "the SIEM cant handle all the logs" issues with SIEMs and IT Departments). ;D
For example, you want powershell logs (dont lie to yourself every security person does, or at least you better). You know what you want them to have in the log, or what they should looks like, or how long they are, or some keyword, then SWELF will forward in order just those logs.

Known Good Hash for the latest and current relase of SWELF.exe (SHA 256): 3eb84c45c98348f55d2873131a822f246905f645d66a29e06003832ffd4cfd5f

## [Want to know more or have Questions check out the WIKI:](https://github.com/ceramicskate0/SWELF/wiki)

# The Apps Goal
--------------------------------------------------------------------------------
The goal here is ideally between this app, Sysmon (or another way to monitor commandline, network connections on the endpoint, and generate hashs  (sha256) for running stuff), properly configured Powershell Logging (script block logging), configured your other favorite log sources to get everything you want/need, a SIEM or Log collector (SIEM recommended)(To sort through what your do want to forward), and a little review of your log data you could in theory make a leap forward in finding the footprints that alot of security solutions just cant seem to find (fileless). 

![bf icon_v02](https://user-images.githubusercontent.com/6934294/38778422-18790d6c-407f-11e8-8594-be72577b26cd.png)

# Legal Disclaimer:
If you use this software you do so at your own risk and your own responsibility/liability. I do/have NEVER authorized, condoned, or recommend the use of anything in any of my repos for any malicious reason. Do not use for evil, malicious purposes, or on machines you do not own. Test it before you use it.
