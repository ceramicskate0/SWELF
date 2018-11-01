# Simple-Windows-Event-Log-Forwarder (SWELF) 


## Summary:

> Having the to many log issue? Or maybe just cant find what you want from a log forwarder? Want to quickly get the logs you want from local evtx files or IR and them get them in the order they where made? Maybe the other log forwarders are just too complicated and you want something simple that can do it all? 
> SWELF might be able to help you. You tell SWELF the the key words and/or Event Log Name and/or the event ID and it will find it for you. You can event tell it things like the minimum number of characters in log, or the maximum length of the commandline arguemtns, or the length of the log itself, then the SWELF app will send just that log to your Log Collection location from a windows machine in a variety of formats. 
> SWELF is designed to be as small,lightweight, and  windows native as possible with very low requirements and setup and still be a powerful and useful tool.  
>SWELF is designed to put you back in control of your log data adn your log forwarder as much as possible.
>Also, an interesting case has come up recently, that red teamers could use this to help simulate a SIEM on a VM for testing on an endpoint. 

![swelf icon](https://user-images.githubusercontent.com/6934294/47841159-afd30b00-dd86-11e8-8e9d-36c8af61a4db.png)

## [Want to know more or have Questions check out the WIKI:](https://github.com/ceramicskate0/SWELF/wiki)

## What can SWELF do:

1. Read, search, and forward any Windows Eventlog and/or saved evtx (that are not I.O. locked) file for everything or just the log with the data you want.

2. Read and search any local log file for everything or just the log with the data you want.

3. Read, search, and forward any 'Powershell Plugin' (after attempting to force it through Microsoft [AMSI](https://docs.microsoft.com/en-us/windows/desktop/amsi/antimalware-scan-interface-portal)) output (ie that script you like thay you cant get output from at scale) for everything or just the log with the data you want.

## The details:

**Now in early release.** 

> SWELF is designed to be a simple enough for almost anyone to use for windows event log forwarding application with some speedy IR capabilities. As a forwarder the agent will 1st search your logs for what you want, then forward just those logs. 
Since SWELF is early release software this means there may be bugs that exist. 

> But this also means im taking almost any feature request (even if you dont code), deisgn recommendations, and basically any input you think is relavent. I will take it in the form of Twitter (https://twitter.com/Ceramicskate0?lang=en) or as Issue (Feature) request here on Github.

> This app is a mainly a log forwarder with the ability to search, forward, and run your plugins. This means that you can tell your log forwarding agent (SWELF) exactly what logs to forward and it wont forward the rest (This will help with that pesky "to many logs", "we cant send those logs its to much noise", or "the SIEM cant handle all the logs" issues with SIEMs and IT Departments). ;D

> For example, you want powershell logs (dont lie to yourself every security person does, or at least you better). You know what you want them to have in the log, or what they should looks like, or how long they are, or some keyword, then SWELF will forward in order just those logs.

## SWELF Design (After Central Configuration is Pushed)
![swelf design](https://user-images.githubusercontent.com/6934294/41071314-a6c5be2e-69bc-11e8-803a-03fcebab5981.PNG)

# Legal Disclaimer:
> THIS IS OPEN SOURCE SOFTWARE AND NOT READY FOR PRODUCTION, YET! If you use this software you do so at your own risk and the liability is with you. Note that the author is not responsible for the way the product is used and the software comes without warrenty. If you use the software (this means execution of it on a system) you acknowledge that you accept any risk or outcome with the use of the software. I have NEVER authorized, condoned, or recommend the use of anything in any of my repos for any malicious reason. Do not use for evil, malicious purposes, or on machines you do not own. I recommend that you always TEST it before you use it or deploy it. Use at your own risk.
