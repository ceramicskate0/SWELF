# Simple-Windows-Event-Log-Forwarder (SWELF) 

## Summary:

Having to many log issues?!! This might help you, you tell it the log source and/or the event ID and/or the key words and/or the number of chars in log and/or the length of the commandline, and/or the length of the log itself and the SWELF app with send just that log to your SIEM, from a windows machine and in syslog format. RAW eventlog XML format, and a mixture or eventdata in xml as a syslog message. 

## SWELF Design (After Central Configuration is Pushed)
![swelf design](https://user-images.githubusercontent.com/6934294/36953050-de3a92e6-1fdc-11e8-9d8f-44a3660249b1.PNG)

## The details:

Now in early release. SWELF is designed to be a simple enough for almost anyone to use for windows event log forwarding. The agent that will 1st search your logs for what you want then forward just those logs (if you told it to). 
Since its early release this mean bugs may exist and it could cause issues on a machine its run on (but its unlikely. Issue like app crash or fail to starts...errr). 
But this also means im taking feature requests (even if you dont code).
This app is a log forwarder and with the ability to search and forward just the logs you want or at least as close to it as you want. This means that you can tell your log forwarding agent (SWELF) exactly what logs to forward and it wont forward the rest (This will help with that pesky "to many logs", "we cant send those logs its to much noise", or "the SIEM cant handle all the logs" issues with SIEMs and IT Departments). ;D
For example, you want powershell logs (dont lie to yourself every security person does, or at least you better). You know what you want them to have in the log, or what they should looks like, or how long they are, or some keyword, then SWELF will forward in order just the logs to your network location on syslog (514)/udp. 

## [Want to know more or have Questions check out the WIKI:](https://github.com/ceramicskate0/SWELF/wiki)

# The Apps Goal
--------------------------------------------------------------------------------
The goal here is ideally between this app, Sysmon (or another way to monitor commandline, network connections on the endpoint, and generate hashs  (sha256) for running stuff), properly configured Powershell Logging (script block logging), configured your other favorite log sources to get everything you want/need, a SIEM or Log collector (SIEM recommended)(To sort through what your do want to forward), and a little review of your log data you could in theory make a leap forward in finding the footprints that alot of security solutions just cant seem to find (fileless). 


# Legal Disclaimer:
If you use this software you do so at your own risk and your own responsibility/liability. I do/have NEVER authorized, condoned, or recommend the use of anything in any of my repos for any malicious reason. Do not use for evil, malicious purposes, or on machines you do not own. Test it before you use it.

