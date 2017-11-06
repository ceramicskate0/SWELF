# Simple-Windows-Event-Log-Forwarder (SWELF)
Pre-Alpha release of a simple for almost anyone windows event log forwarding agent. Currently testing on windows 10.

# NOTES:
Currenlty its in "testing" and Dev on my local machine. BUT whats being made public some time soon..maybe... will be something that almost anyone can impliment without TODO's built in. If all goes well and as expected if you can schedule a task your good. Actually I may give a how to.....maybe.

# App Usage Info:
- Reserved characters are , : =
- For config files all single lines that contain '#' will be treated as comments
- Remember that the event log for the app will need enough space to store logs from all the sources your searching. This will be important if you want to forward logs and the device is often off the network that the destinaiton is on.
- App will require rights for (Admin on local machine is recommended):
    - Read/Write/Create Windows Eventlog. 
    - Write to its CWD. 
    - Execute. 
    - Send Log data over 514/UDP to IP in config file you specify.
    - Read from disk and any location on local machine you want it to.
    - Launch processes (List Below)
        - Powershell.exe
        - Itself


# Configuration and Usage Syntax:
## C:\ ..\Config\
  ### How to:
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
  
      Log_Collector={IPv4 of place to send xml of eventlog over port 514}
    
--------------------------------------------------------------------------------
     example(Send Data): Log_Collector=127.0.0.1
     example(Dont Send Data): Log_Collector=
     example(Dont Send Data): 
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

# TODO:
- GUI for config of app so its easy to manage settings , get notifications on desktop , and get alerts for findings in GUI

- Network output in more than raw eventlog xml (ie Syslog)

- Plugin to Powershell (Gonna be key word search for script output)

- Make service

- Create installer

- Multi Thread application

- Search Sysmon hash and IP on Virustotal 

- Extract IP and File Hash's in app algo, deal with config issues to turn features on and off, what to do with log data, and pull from more than sysmon log type

- Expand API class

