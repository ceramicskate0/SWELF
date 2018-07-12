# Simple-Windows-Event-Log-Forwarder (SWELF) 

Known Good Hash for the latest and current relase of SWELF.exe (SHA 256): e667aba758d04321586654e253cc92bcc92cae08e0fc1d2eccefbe69036a2d45

## Summary:

Having the to many log issue?!! Or maybe just cant find what you want from a log forwarder? Want to quickly get the logs you want from local evtx files? Maybe the other log forwarders are just too complicated and you want something simple that can do it all? SWELF might help you. You tell it the log source and/or the event ID and/or the key words and/or the number of chars in log and/or the length of the commandline, and/or the length of the log itself and the SWELF app will send just that log to your Log Collection location from a windows machine. SWELF is designed to be all windows native very low on requirements and setup as well as powerful and useful. Also an interesting case has come up recently, that red team could use this to help simulate a SIEM on a VM testing endpoint. :)

## What can SWELF do:

1. Read, search, and forward any live Windows Eventlog and/or saved evtx file for everything or just the log with the data you want.

2. Read (and soon search) any local log file for everything or just the log with the data you want.

3. Read, search, and forward any 'Powershell Plugin' output (ie that script you like thay you cant get output from at scale) for everything or just the log with the data you want.

## The details:

Now in early release. SWELF is designed to be a simple enough for almost anyone to use for windows event log forwarding application. The agent will 1st search your logs for what you want then forward just those logs. 
Since SWELF is early release sofwtare this means there may be bugs that exist. 
But this also means im taking feature requests (even if you dont code), deisgn recommendation, and basically any input you think is relavent.
This app is a log forwarder with the ability to search and forward just the logs you want or at least as close to it as you want. This means that you can tell your log forwarding agent (SWELF) exactly what logs to forward and it wont forward the rest (This will help with that pesky "to many logs", "we cant send those logs its to much noise", or "the SIEM cant handle all the logs" issues with SIEMs and IT Departments). ;D
For example, you want powershell logs (dont lie to yourself every security person does, or at least you better). You know what you want them to have in the log, or what they should looks like, or how long they are, or some keyword, then SWELF will forward in order just those logs.

## [Want to know more or have Questions check out the WIKI:](https://github.com/ceramicskate0/SWELF/wiki)

## SWELF Design (After Central Configuration is Pushed)
![swelf design](https://user-images.githubusercontent.com/6934294/41071314-a6c5be2e-69bc-11e8-803a-03fcebab5981.PNG)

![bf icon_v02](https://user-images.githubusercontent.com/6934294/38778422-18790d6c-407f-11e8-8594-be72577b26cd.png)

# Legal Disclaimer:
If you use this software you do so at your own risk and your own responsibility/liability. I have NEVER authorized, condoned, or recommend the use of anything in any of my repos for any malicious reason. Do not use for evil, malicious purposes, or on machines you do not own. I recommend that you always Test it before you use it or deploy it.
