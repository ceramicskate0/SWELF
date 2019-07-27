@echo off
reg delete HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\SWELF /f
RMDIR C:\Users\Host\source\repos\SWELF\SWELF\bin\Debug\Config /q
RMDIR C:\Users\Host\source\repos\SWELF\SWELF\bin\Debug\Log_Searchs /q
RMDIR C:\Users\Host\source\repos\SWELF\SWELF\bin\Debug\Plugins /q
RMDIR C:\Users\Host\source\repos\SWELF\SWELF\bin\Debug\SWELF_Logs /q
set /P c=Do you want to Download Test config[Y/N]?
if /I "%c%" EQU "Y" goto :DownloadCentral

:DownloadCentral 
@powershell -ExecutionPolicy Bypass -nop -c "iex(new-object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/ceramicskate0/SWELF/master/examples/Config/ConsoleAppConfig.conf','C:\Users\Host\source\repos\SWELF\SWELF\bin\Debug\Config\ConsoleAppConfig.conf')"