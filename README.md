# Simple-Windows-Event-Log-Forwarder (SWELF)
Now in early release. SWELF is designed to be a simple for almost anyone to use windows event log forwarding agent. This mean bugs may exist and it could cause issues on a machine its run on (but its unlikely. Issue like app crash failed task). This app is a log forwarder and log searching (both eventlog and local log) app. 
Soon (as in not right now) it will have the ablility to intigrate with powershell to allow users to build plugins that the app can use to expand its capability. For example, it could run scripts awesome scripts like https://github.com/sans-blue-team/DeepBlueCLI or https://github.com/danielbohannon/Revoke-Obfuscation (this one will need a little scripting on your end since its a powershell module not a script file) and use their output to create logs to send to your SIEM. This would mean that processing of the logs takes place at the endpoint not the SIEM.

# App Usage Info:
- Reserved characters are , : =
- For config files all single lines that contain '#' will be treated as comments
- Remember that the event log for the app will need enough space to store logs from all the sources your searching. This will be important if you want to forward logs and the device is often off the network that the destinaiton is on.
- App will require rights for (Admin on local machine is recommended):
    - Read/Write/Create Windows Eventlog. 
    - Write to its needed files to the directory the app is loacted at when run. 
    - Execute. 
    - Send Log data over 514/UDP to IP in config file you specify.
    - Read from disk and any location on local machine you want it to.
    - Launch processes (List Below)
        - Powershell.exe
        - Itself
        
# SWELF Testing:
Currently testing on windows 10 with confiured Device Guard/app whitelisting, UAC, HIDS, locked down powershell configuration, EMET, and AV. App is designed to be run as a scheduled task for now. Im taking recommendations via issues just label as enhancements for design, UI, source code, and features.

Log Collection Platforms or SIEMs:

    - Kibana/ELK
    
    - Splunk (Needs more testing as of 11/30/17)
    
    - AlienVault (Needs more testing as of 11/30/17)
    
# Sidenote:
- If your using Sysmon and want a starting point for a config file there is a 1 size fits all config file at https://github.com/SwiftOnSecurity/sysmon-config. I also maintain a fork at https://github.com/ceramicskate0/sysmon-config. There is also a good one here https://github.com/ion-storm/sysmon-config.

# Security Concerns:
If your worried about this being malware ive taken the liberty of having it check for you on virustotal. https://www.virustotal.com/#/file/7170e94b1b1608167c56b3f9f19a8651141d8d4e51f02c7aae4f34a1b2b5d7b8/detection.
I also recommend running it in a sandbox of your choice before letting run in your enviorment (just a recomendation from a security person). There is no eviormental detection code in the app , anti vm/detection, or any kill commands in the code. 

----------------------------------------------------------------------------------------------------------------------------------------
# Knowledge Base Stuff:


# Configuration and Usage Syntax:

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
    
      WARNING: Only change to number if you wish to have app rescan logs from begining.
      NOTE: If you forget to add the log here and you want to search it never fear app will handle it for you :)
    
--------------------------------------------------------------------------------
     example: microsoft-windows-sysmon/operational=1
     (Set to 1 to reset log collection)
     example: microsoft-windows-powershell/operational=28395756
     (Normal operation of app)
--------------------------------------------------------------------------------

##  ConsoleAppConfig.conf
  
      Log_Collector={IPv4 of place to send some form of eventlog over port 514}
      outputformat={"xml" or "data" or "syslog" or "syslogxml"}
    
--------------------------------------------------------------------------------
     example(Send Data): Log_Collector=127.0.0.1
     example(Dont Send Data): Log_Collector=
     example(Dont Send Data): 
     example: outputformat=syslog
--------------------------------------------------------------------------------

## C:\ ..\Searchs\Search.txt
  ### How to:
  
     length':'{Minumum log length before its an event}
     count':'{Term or statement to count}':'{Number of times in log before its a counted event}    
     
--------------------------------------------------------------------------------
     example: length:200    
     example: count:;:8
--------------------------------------------------------------------------------  
     
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
  
## C:\ ..\Logs\ErrorLog.log

     Location of applications local error log.
     
--------------------------------------------------------------------------------


