mkdir C:\Program Files (x86)\SWELF
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile iex (New-Object System.Net.WebClient).DownloadFile("https://github.com/ceramicskate0/SWELF/releases/download/0.1.0.0/ConsoleEventLogAutoSearch.exe", "C:\Program Files (x86)\SWELF\SWELF.exe")
