# Simple-Windows-Event-Log-Forwarder (SWELF)
Pre-Alpha release of a simple for almost anyone windows event log forwarding agent. 

# NOTES:
Currenlty its in "testing" and Dev on my local machine. BUT whats being made public some time soon..maybe... will be something that almost anyone can impliment without TODO's built in. If all goes well and as expected if you can schedule a task your good. Actually I may give a how to.....maybe.


# Usage:
## ..\Config\
  ### How to:
##  DirectoriesToMonitor.conf
  
    Place path to a directory to monitor (it will monitor all files of type .txt and .log only)
    
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
    
    Only change to number if you wish to have app rescan logs from begining
    
--------------------------------------------------------------------------------
example: microsoft-windows-sysmon/operational=1
--------------------------------------------------------------------------------

##  ConsoleAppConfig.conf
  
    Log_Collector={IPv4 of place to send xml of eventlog over port 514}
    
--------------------------------------------------------------------------------
example: Log_Collector=127.0.0.1   
--------------------------------------------------------------------------------

## ..\Searchs\Search.txt

  ### How to:
  
     length':'{Minumum log length beofre its an event}
     count':'{Term or statement to count}':'{Number of times in log before its a counted event}    
     
--------------------------------------------------------------------------------
     example: length:200    
     example: count:;:8
--------------------------------------------------------------------------------  
     
   Any combination of the following as long as they are in order. 
   
     Term or statement to seatch for ','EventLogName','EventID
     
--------------------------------------------------------------------------------
     example: powershell.exe,microsoft-windows-sysmon/operational,1
     
     example: cmd.exe,microsoft-windows-powershell/operational
     
     example: cmd.exe,microsoft-windows-sysmon/operational
     
     example: has been restricted by your Administrator by location with policy rule 
     
     example: csc.exe
     
     example: log file was cleared
-------------------------------------------------------------------------------- 
  
## ..\Logs\ErrorLog.log

     Location of applications local error log.
     
--------------------------------------------------------------------------------

# TODO:

-Plugin to Powershell

-Make service

-Create installer

-Multi Thread application

-Search Sysmon hash and IP on Virustotal 

-Extract IP and File Hash's in app algo, deal with config issues to turn features on and off, what to do with log data, and pull from more than sysmon log type

-Expand API class

