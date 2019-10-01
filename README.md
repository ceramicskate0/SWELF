# DEV UPDATE: App development stalled unit completion of OSCP cert. Timeline unknown. Dev work on hold not halted.

# [Simple-Windows-Event-Log-Forwarder (SWELF)](https://ceramicskate0.github.io/SWELF/)

<img src="https://user-images.githubusercontent.com/6934294/47841159-afd30b00-dd86-11e8-8e9d-36c8af61a4db.png" width="350" height="300">

## [Get Latest Release](https://github.com/ceramicskate0/SWELF/releases/latest)


## Summary:
If you can type this, 

### Findthis ~ With this EventLog Name(Not required) ~ EventID(Not required)

into a text file ([Searchs.txt](https://github.com/ceramicskate0/SWELF/wiki/%5CLog_Searchs%5CSearch.txt-(SWELF-SEARCH-FILE))) you can find the logs you want from a windows machine and send just those to your SIEM. 

> Why SWELF and how is it diffrent from anything out there? Well, are you having the to many log issue? Or maybe just cant find what you want from a log forwarder? Want to quickly get the logs you want from local evtx files or eventlog service and then get them in the order they where made? Maybe the other log forwarders are just too complicated and you want something simple that can do it all? SWELF might be able to help you. You tell SWELF the the key words and/or Event Log Name and/or the event ID and it will find it for you. You can event tell it things like the minimum number of characters in log, or the maximum length of the command-line arguments, or the length of the log itself, then the SWELF app will send just that log to your Log Collection location from a windows machine in a variety of formats. SWELF is designed to be as small,lightweight, and windows native as possible with very low requirements and setup and still be a powerful and useful tool. SWELF is designed to put you back in control of your log data and your log forwarder as much as possible. Also, an interesting case has come up recently, that red teamers could use this to help simulate a SIEM on a VM for testing on an endpoint. SWELF is designed to be as small,lightweight, and  windows native as possible with very low requirements and setup and still be a powerful and useful tool.   SWELF is designed to put you back in control of your log data adn your log forwarder as much as possible. Also, an interesting case has come up recently, that red teamers could use this to help simulate a SIEM on a VM for testing on an endpoint. 

## [Install:](https://github.com/ceramicskate0/SWELF/wiki/How-to-'install'-SWELF)

## [Usage:](https://github.com/ceramicskate0/SWELF/wiki/How-to-Execute-SWELF)

## [Requirements:](https://github.com/ceramicskate0/SWELF/wiki/SWELF-Requirements)

## [What can SWELF do](https://github.com/ceramicskate0/SWELF/wiki/How-SWELF-Works):

1. Read, search, and forward any Windows Eventlog and/or saved evtx (that are not I.O. locked) file for everything or just the log with the data you want.

2. Read and search any local log file for everything or just the log with the data you want.

3. Read, search, and forward any 'Powershell Plugin' (after attempting to force it through Microsoft [AMSI](https://docs.microsoft.com/en-us/windows/desktop/amsi/antimalware-scan-interface-portal)) output (ie that script you like that you cant get output from at scale) for everything or just the log with the data you want.

## [Want to know more or have Questions check out the WIKI:](https://github.com/ceramicskate0/SWELF/wiki)

## The details:

**Now in early release.** 

> SWELF is designed to be a simple enough for almost anyone to use for windows event log forwarding application with some speedy IR capabilities. As a forwarder the agent will 1st search your logs for what you want, then forward just those logs. 
Since SWELF is early release software this means there may be bugs that exist. 

> But this also means im taking almost any feature request (even if you dont code), deisgn recommendations, and basically any input you think is relavent. I will take it in the form of Twitter (https://twitter.com/Ceramicskate0?lang=en) or as Issue (Feature) request here on Github.

> This app is a mainly a log forwarder with the ability to search, forward, and run your plugins. This means that you can tell your log forwarding agent (SWELF) exactly what logs to forward and it wont forward the rest (This will help with that pesky "to many logs", "we cant send those logs its to much noise", or "the SIEM cant handle all the logs" issues with SIEMs and IT Departments). ;D

> For example, you want powershell logs (dont lie to yourself every security person does, or at least you better). You know what you want them to have in the log, or what they should looks like, or how long they are, or some keyword, then SWELF will forward in order just those logs.

## SWELF Design (After Central Configuration is Pushed)
![swelf design](https://user-images.githubusercontent.com/6934294/41071314-a6c5be2e-69bc-11e8-803a-03fcebab5981.PNG)

## SWELF Sub Projects
- [Offical Plugin Repo](https://github.com/ceramicskate0/SWELF-PluginHelpers)

- [SWELF Desktop Alerting App](https://github.com/ceramicskate0/App_to_Fire_Balloon_Tip_on_passed_CMD_Args)

- [SWELF Starter Splunk Dashboard](https://github.com/ceramicskate0/SWELF/blob/master/Extras/SWELF_SPLUNK_DASHBOARD.xml)

- [SWELF Sysmon Starter Config](https://github.com/ceramicskate0/sysmon-config)

# Legal Disclaimer:
> If you choose to run the software on your machine, you accept the terms of use and any potential adverse actions that may befall your system. If you use this software you do so at your own risk and the liability is then accepted by you on execution. Note that the author is not responsible for the way the product software is used and the software comes without any warrenty. If you use the software (this means execution of it on a system) you acknowledge that you accept any risk or any outcome the use of the software causes. I have NEVER authorized, condoned, or recommend the use of anything in any of my repos for any malicious reason. Do not use for evil, malicious purposes, or on machines you do not own. I recommend that you always TEST it before you use it or deploy it. Use at your own risk. THIS IS OPEN SOURCE SOFTWARE AND IS ALMOST READY FOR PRODUCTION. 

                    GNU AFFERO GENERAL PUBLIC LICENSE
                       Version 3, 19 November 2007

 Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
 Everyone is permitted to copy and distribute verbatim copies
of this license document, but changing it is not allowed.
