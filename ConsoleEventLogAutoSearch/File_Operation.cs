using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;

namespace SWELF
{
    class File_Operation
    {
        private static List<string> OutputFileContents = new List<string>();


        public static void Write_Ouput_CSV(string FilePath,Queue<EventLog_Entry> FileContents)
        {
            if (VERIFY_if_File_Exists(FilePath))
             {
                Write_Contents(FilePath,FileContents);
             }
            else
            {
                File.Create(FilePath).Close();
                File.AppendAllText(FilePath, "LogName" + "," + "EventRecordID" + "," + "EventID" + "," + "CreatedTime" + "," + "ComputerName" + "," + "UserID" + "," + "Severity" + "," + "TaskDisplayName" + "," + "EventData" + '\n');
                Write_Contents(FilePath,FileContents);
            }

        }

        public static void Write_Hash_Output(List<string> Hashs)
        {
            for (int x = 0; x < Hashs.Count; ++x)
            {
                try
                {
                    File.AppendAllText(Settings.Hashs_File, Hashs.ElementAt(x) + "\n");
                }
                catch (Exception e)
                {

                }
            }
        }

        public static void Write_IP_Output(List<string> IPs)
        {
            for (int x = 0; x < IPs.Count; ++x)
            {
                try
                {
                    File.AppendAllText(Settings.IPs_File, IPs.ElementAt(x)+"\n");
                }
                catch (Exception e)
                {
                    //File.AppendAllText(Settings.IPs_File, IPs.ElementAt(x) + "()"+"\n");
                }
            }
        }

        public static void Write_Contents(string FilePath, Queue<EventLog_Entry> FileContents)
        {
            for (int x=0; x<FileContents.Count;++x)
            {
               File.AppendAllText(FilePath,FORMAT_Output(FileContents.ElementAt(x)));
            }
        }

        public static string FORMAT_Output(EventLog_Entry EventLog)
        {
            string EventData;
            EventData=EventLog.EventData;
            EventData=EventData.Replace('\n', ' ');
            EventData=EventData.Replace('\r', ' ');
            EventData=EventData.Replace("\n\r", " ");
            EventData=EventData.Replace("\r\n", " ");

            return EventLog.LogName + "," + EventLog.EventRecordID + "," + EventLog.EventID + "," + EventLog.CreatedTime + "," + EventLog.ComputerName + "," + EventLog.UserID + ","  + EventLog.Severity + "," + EventLog.TaskDisplayName + ",\"" + EventData +"\""+ '\n';
        }

        public static void WRITE_EventLogID_Placeholders()
        {
            ;
            File.Delete(Settings.GET_EventLogID_PlaceHolder);
            for (int x = 0; x > Settings.EventLog_w_PlaceKeeper.Count; ++x)
            {
                File.AppendAllText(Settings.GET_EventLogID_PlaceHolder, Settings.EventLog_w_PlaceKeeper.ElementAt(x).Key + Settings.SplitChar_ConfigVariableEquals[0] + Settings.EventLog_w_PlaceKeeper.ElementAt(x).Value.ToString() + "\n");
            }
        }

        public static string WRITE_Default_ConsoleAppConfig_File()
        {
            string log = @"#Most Up to date example at https://github.com/ceramicskate0/SWELF/blob/master/examples/Config/ConsoleAppConfig.conf" +
Settings.CommentCharConfigs + @"log_collector: Must Be IPV4 : {Port num if not 514}{514 is default}
log_collector" + Settings.SplitChar_ConfigVariableEquals[0] + @"127.0.0.1
" +
Settings.CommentCharConfigs + @"output_format: syslogxml,syslog,xml,data,keyvalue
output_format" + Settings.SplitChar_ConfigVariableEquals[0] + @"keyvalue
" +
Settings.CommentCharConfigs + @"log_level: verbose,informataion,warning,critical,failureaudit
" +
"log_level" + Settings.SplitChar_ConfigVariableEquals[0] + @"critical
" +
Settings.CommentCharConfigs + @"output_ips
" +
Settings.CommentCharConfigs + @"ouput_hashs
";
            return log;
        }

        public static string WRITE_Default_Eventlog_with_PlaceKeeper_File()
        {
            string log = @"" + Settings.CommentCharConfigs + @"LOG NAME, START AT INDEX(1 if unknown)
#Most Up to date example at https://github.com/ceramicskate0/SWELF/blob/master/examples/Config/Eventlog_with_PlaceKeeper.txt
application=1
security=1
system=1
windows powershell=1
#amsi/operational=1
#microsoft-windows-sysmon/operational=1
#microsoft-windows-windows defender/operational=1
#microsoft-windows-powershell/operational=1
#microsoft-windows-deviceguard/operational=1
microsoft-windows-wmi-activity/operational=1
microsoft-windows-bits-client/operational=1
Microsoft-Windows-Security-Mitigations/KernelMode=1
Microsoft-WindowsCodeIntegrity/Operational=1
";
            return log;
        }

        public static string WRITE_Default_Logs_WhiteList_Search_File()
        {
            return @"" + Settings.CommentCharConfigs + @"SearchTerm " + Settings.SplitChar_SearchCommandSplit[0] + @" EventLogName " + Settings.SplitChar_SearchCommandSplit[0] + @" EventID";
        }

        public static string WRITE_Default_Logs_Search_File()
        {
            string log = @"" + Settings.CommentCharConfigs + @"SearchTerm/ or Search CMD " + Settings.SplitChar_SearchCommandSplit[0] + @" EventLogName " + Settings.SplitChar_SearchCommandSplit[0] + @" EventID
#Default SWELF Config
#Most Up to date list at https://github.com/ceramicskate0/SWELF/examples/Log_Searchs/Searchs.txt
#Layout of Searchs.txt File for searching:
#SearchTerm~EventLogName~EventID
#commandline_length:500
~System~104
~System~7045
~System~7040
~System~7022
~System~4719
~system~104
~security~1102
~security~517
~Security~7045 
~Security~4720 
#~Security~4688
Logon Type:		9~Security~4624 
Logon Type:		3~Security~4624 
Logon Type:		10~Security~4624
#~Microsoft-Windows-CodeIntegrity/Operational~3004
#~Microsoft-Windows-CodeIntegrity/Operational~3033
~Application~866
~Application~1534
webclient~windows powershell~
hidden~windows powershell~
download~windows powershell~
nowindows~windows powershell~
-nop~windows powershell~
noprofile~windows powershell~
#count:+:5~windows powershell~
#count:-join:2~windows powershell~
#count:|:2~windows powershell~
#~Microsoft-Windows-SoftwareRestrictionPolicies~Application~866
#eventdata_length:10000~Microsoft-Windows-PowerShell/Operational~
#count:-join:2~Microsoft-Windows-PowerShell/Operational~
#count:':30~Microsoft-Windows-PowerShell/Operational~
#count:+:5~Microsoft-Windows-PowerShell/Operational~
#count:;:12~Microsoft-Windows-PowerShell/Operational~
#count:|:2~Microsoft-Windows-PowerShell/Operational~
#base64decode~Microsoft-Windows-PowerShell/Operational~
#webclient~Microsoft-Windows-PowerShell/Operational~
#hidden~Microsoft-Windows-PowerShell/Operational~
#-nop~Microsoft-Windows-PowerShell/Operational~
#~microsoft-Windows-Windows Defender/Operational~1123
#~microsoft-Windows-Windows Defender/Operational~5007
#~microsoft-Windows-Windows Defender/Operational~1007
#~microsoft-Windows-Windows Defender/Operational~1008
#~microsoft-Windows-Windows Defender/Operational~1015
#~microsoft-Windows-Windows Defender/Operational~1116
#~microsoft-Windows-Windows Defender/Operational~1117
#~microsoft-Windows-Windows Defender/Operational~3007
#~microsoft-Windows-Windows Defender/Operational~5001
#~microsoft-Windows-Windows Defender/Operational~5007
#~Microsoft-Windows-Sysmon/Operational~2
#~Microsoft-Windows-Sysmon/Operational~8
#~Microsoft-Windows-Sysmon/Operational~9
#~Microsoft-Windows-Sysmon/Operational~10
#~Microsoft-Windows-Sysmon/Operational~12
#~Microsoft-Windows-Sysmon/Operational~17
#~Microsoft-Windows-Sysmon/Operational~18
#~Microsoft-Windows-Sysmon/Operational~19
#~Microsoft-Windows-Sysmon/Operational~20
#~Microsoft-Windows-Sysmon/Operational~21
#~Microsoft-Windows-Security-Mitigations/KernelMode~3
#~Microsoft-Windows-Security-Mitigations/KernelMode~10
";
            return log;
        }

        public static string WRITE_Default_Powershell_Search_File()
        {
            string log = "" + Settings.CommentCharConfigs + @"#File Path to Powershell Script ~ SearchTerm ~ Powershell Script Arguments";
            return log;
        }

        public static void UPDATE_EventLog_w_PlaceKeeper_File()
        {
            Encryptions.UnLock_File(Settings.GET_EventLogID_PlaceHolder);
            DELETE_AND_CREATE_File(Settings.GET_EventLogID_PlaceHolder);
            for (int x = 0; x < Settings.EventLog_w_PlaceKeeper.Count; ++x)
            {
                File.AppendAllText(Settings.GET_EventLogID_PlaceHolder, Settings.EventLog_w_PlaceKeeper_List.ElementAt(x) + Settings.SplitChar_ConfigVariableEquals[0] + Settings.EventLog_w_PlaceKeeper[Settings.EventLog_w_PlaceKeeper_List.ElementAt(x)] + "\n");
            }
            Encryptions.Lock_File(Settings.GET_EventLogID_PlaceHolder);
        }

        public static void CREATE_NEW_Files_And_Dirs(string Dir, string FileName, string FileData = "")
        {
            if (Directory.Exists(Dir) == false)
            {
                Directory.CreateDirectory(Dir);
            }
            if (VERIFY_if_File_Exists(Dir + "\\" + FileName) == false)
            {
                File.Create(Dir + "\\" + FileName).Close();
                if (string.IsNullOrEmpty(FileData) == false)
                {
                    File.AppendAllText(Dir + "\\" + FileName, FileData);
                }
            }
        }

        public static void DELETE_AND_CREATE_File(string Filepath)
        {
            File.Delete(Filepath);
            File.Create(Filepath).Close();
        }

        public static bool VERIFY_if_File_Exists(string FilePath)
        {
            return File.Exists(FilePath);
        }

        public static void GET_ErrorLog_Ready()
        {
            CREATE_NEW_Files_And_Dirs(Settings.SWELF_Log_File_Location, Settings.ErrorFile);
        }

        public static void GET_Plugin_Scripts_Ready()
        {
            if (!Directory.Exists(Settings.Plugin_Files_Location))
            {
                Directory.CreateDirectory(Settings.Plugin_Files_Location);
            }
            if (!Directory.Exists(Settings.Plugin_Scripts_Location))
            {
                Directory.CreateDirectory(Settings.Plugin_Scripts_Location);
            }
        }

        public static string GET_FilesToMonitor_Path()
        {
            CREATE_NEW_Files_And_Dirs(Settings.Config_File_Location, Settings.FilesToMonitor);
            return Settings.GET_FilesToMonitor;
        }

        public static string GET_DirToMonitor_Path()
        {
            CREATE_NEW_Files_And_Dirs(Settings.Config_File_Location, Settings.DirectoriesToMonitor);
            return Settings.GET_DirectoriesToMonitor;
        }

        public static List<string> READ_File_In(string FielPath)
        {
            return File.ReadAllLines(FielPath).ToList();
        }
    }
}
