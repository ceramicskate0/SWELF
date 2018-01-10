# Simple-Windows-Event-Log-Forwarder (SWELF)
Now in early release and so close to 1st offical release. SWELF is designed to be a simple for almost anyone to use windows event log forwarding agent that will 1st search your logs for what you want then forward just those logs (if you told it to). 
Since its early release this mean bugs may exist and it could cause issues on a machine its run on (but its unlikely. Issue like app crash or fail to starts...errr). 
But this also means im taking feature requests (even if you dont code).
This app is a log forwarder and with the ability to search and forward just the logs you want or at least as close to it as you want. This means that you can tell your log forwarding agent (SWELF) exactly what logs to forward and it wont forward the rest (This will help with that pesky "to many logs", "we cant send those logs its to much noise", or "the SIEM cant handle all the logs" issues with SIEMs and IT Departments). ;D
For example, you want powershell logs (dont lie every security person does) from endpoints and there are just to many. You know what you want them to have in the log, or what they should looks like, or how long they are, or some keyword,then SWELF will forward in order just the logs to your network location on syslog (514)/udp. 

Summary:

You tell it the log source and/or the event ID and/or the key words and/or the number of chars in log and/or the length of the commandline, and/or the length of the log itself and the SWELF app with send just that log to your SIEM.

# The Apps Goal
--------------------------------------------------------------------------------
The goal here is ideally between this app, Sysmon (or another way to monitor commandline, network connections on the endpoint, and generate hashs  (sha256) for running stuff), properly configured Powershell Logging (script block logging), configured your other favorite log sources to get everything you want/need, a SIEM or Log collector (SIEM recommended)(To sort through what your do want to forward), and a little review of your log data you could in theory make a leap forward in finding the footprints that alot of security solutions just cant seem to find (fileless). 
# Sidenote:
- If your using Sysmon and want a starting point for a config file there is a 1 size fits all config file at https://github.com/SwiftOnSecurity/sysmon-config. I also maintain a fork at https://github.com/ceramicskate0/sysmon-config. There is also a good one here https://github.com/ion-storm/sysmon-config.

# App Usage Info:
--------------------------------------------------------------------------------
- Reserved characters in SWELF files are , : =
- For config files all single lines that contain '#' will be treated as comments
- Remember that the event log for the app will need enough space to store logs from all the sources your searching. This will be       important if you want to forward logs and the device is often off the network that the destination is on.


App usage and function:

    - Require rights for proper function (local admin is recommended and needed to read eventlog since the patch the UAC bypass       
    issue)
    - Execution. 
    - Send Log data over 514/UDP to IP in config file you specify.
    - Read from disk and any location on local machine you want it to.
    - App will read and write eventlogs
    - App will use powershell for API calls to windows event    
    - Launch processes (List Below)
        - Powershell.exe (API Calls for eventlog class)
    - App will run in its execution account
    - App will read/write and function in its current folder
    - App takes in not commands
    - App will read whats its told in config file and forward that to where its configured
    - If app is not configured to send log data and no IP given app default is 127.0.0.1  
#
# Security Concerns:
--------------------------------------------------------------------------------
Worried about this being malware ive taken the liberty of having it checked for you on virustotal. https://www.virustotal.com/#/file-analysis/YmZlMmMyMzE0NDVhMzQyZDM2MzRmNTBhMDdiMzVmNDM6MTUxNDc3MjY3NA==.
I also recommend running it in a sandbox of your choice before letting it run in your environment (just a recommendation from a security person). There is no environmental detection code in the app , anti vm/detection, or any kill commands in the code (other than error handling).

#
#
#
# Knowledge Base Stuff:
#
#

## Configuration and Usage Syntax:
--------------------------------------------------------------------------------

## C:\ ..\Config\
  
##  DirectoriesToMonitor.conf
  
      Place path to a directory to monitor (it will monitor all files of type .txt and .log only).
    
--------------------------------------------------------------------------------
     example: C:\FolderName\
--------------------------------------------------------------------------------

##  FilesToMonitor.conf
  
      Place full file path to file to monitor every time app is run
    
--------------------------------------------------------------------------------
     example: C:\FolderName\File.txt 
     
     example: C:\FolderName\File.log
--------------------------------------------------------------------------------

##  Eventlog_with_PlaceKeeper.txt
  
      Logname '=' EventID Number (if 1st run '1' can be used)
    
    
WARNING: Only change to number if you wish to have app rescan logs from beginning.

NOTE: If you forget to add the log here and you want to search it never fear app will handle it for you :)
    
--------------------------------------------------------------------------------
     example: microsoft-windows-sysmon/operational=1
     (Set to 1 to reset log collection)
     
     example: microsoft-windows-powershell/operational=28395756
     (Normal operation of app)
--------------------------------------------------------------------------------

##  ConsoleAppConfig.conf
  
      Log_Collector={IPv4 of place to send some form of eventlog over port 514}
      
      Log_Collector1-5={IPv4 of place to send some form of eventlog over port 514}
      
      outputformat={"xml" or "data" or "syslog" or "syslogxml"}
    
--------------------------------------------------------------------------------
     example(Send Data): Log_Collector=10.0.0.3
     
     example(Send Data): Log_Collector1=10.0.0.1
     
     example(Send Data)(max collector number): Log_Collector5=10.0.0.2
     
     example(Dont Send Data): Log_Collector=
     
     example(Dont Send Data): 
     
     example: outputformat=syslog
--------------------------------------------------------------------------------

## C:\ ..\Log_Searchs\Search.txt
  ### How to:
  --------------------------------------------------------------------------------
  
##  Search Commands:
  
     eventdata_length':'{Minimum chars in eventlog event data section (does this by counting chars in the entire EventData Part of any eventlog)}
     
     count':'{Term or statement to count}':'{Number of times in log before its a counted event}   
     
     commandline_length':'{Number of chars in either target or parent commandline argument (it will evaluate the largest one)(Only works for Sysmon Logs)}
     
     commandline_contains':'{The string in only the command line that you want to forward (Only works for Sysmon Logs)}
--------------------------------------------------------------------------------
     example: eventdata_length:200  
     
     example: count:;:8
     
     example(Only works for Sysmon Logs): commandline_length:500
     
     example(Only works for Sysmon Logs):commandline_contains:<script>
--------------------------------------------------------------------------------  

##  General Searching:

Any combination of the following as long as they are in order. 
   
     {Term or statement to search for} ',' {EventLogName} ',' {EventID}
     
--------------------------------------------------------------------------------
     example: powershell.exe,microsoft-windows-sysmon/operational,1 
     (This will be used to search microsoft-windows-sysmon/operational logs for cmd.exe with event id 1)
    
    example: ,microsoft-windows-sysmon/operational,1
    (Return all event id 1 in sysmon log)
     
     example: cmd.exe,microsoft-windows-sysmon/operational 
     (This will be used to search microsoft-windows-sysmon/operational logs for cmd.exe)
     
     example: cmd.exe,microsoft-windows-powershell/operational 
     (This will be used to search microsoft-windows-sysmon/operational logs)
     
     example: has been restricted by your Administrator by location with policy rule 
     (This will be used to search ALL logs)
     
     example: csc.exe 
     (This will be used to search ALL logs)
     
     example: log file was cleared 
     (This will be used to search ALL logs)
-------------------------------------------------------------------------------- 
  
## C:\ ..\SWELF_Logs\ErrorLog.log

     Location of applications local error log.
     
--------------------------------------------------------------------------------
#
#
#
# SWELF Testing:
--------------------------------------------------------------------------------
Currently testing on windows 10 with configured Device Guard/app whitelisting, UAC, HIDS, locked down powershell configuration, EMET, and AV. App is designed to be run as a scheduled task for now. Im taking recommendations via issues just label as enhancements for design, UI, source code, and features.

Log Collection Platforms or SIEMs being used in testing SWELF:

    - Kibana/ELK

    - Splunk (Needs more testing as of 11/30/17)
