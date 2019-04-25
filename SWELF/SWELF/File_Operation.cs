using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;

namespace SWELF
{
    internal static class File_Operation
    {
        internal readonly static DriveInfo Disk = new DriveInfo(Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.System)));
        private static long Drives_Available_Space = Disk.AvailableFreeSpace;

        internal static string GET_Default_ConsoleAppConfig_File_Contents
        {
            get
            {
                string log = @"#Most Up to date example at https://github.com/ceramicskte0/SWELF/blob/master/examples/Config/ConsoleAppConfig.conf" + "\r\n" +

               Settings.CommentCharConfigs + @Settings.SWELF_AppConfig_Args[0] + ": Must Be IPV4 : {Port num if not 514}{514 is default}" + "\r\n" +

               Settings.SWELF_AppConfig_Args[0] + Settings.SplitChar_ConfigVariableEquals[0] + @"127.0.0.1" + "\r\n" +

               Settings.CommentCharConfigs + Settings.SWELF_AppConfig_Args[6] + Settings.SplitChar_ConfigVariableEquals[0] + "https://ceramicskate0.github.io/SWELF/examples/Log_Searchs/Searchs.txt" + "\r\n" +

               Settings.CommentCharConfigs + @"central_app_config" + Settings.SplitChar_ConfigVariableEquals[0] + "https://ceramicskate0.github.io/SWELF/examples/Config/ConsoleAppConfig.conf" + "\r\n" +

               Settings.CommentCharConfigs + Settings.SWELF_AppConfig_Args[8] + Settings.SplitChar_ConfigVariableEquals[0] + "https://ceramicskate0.github.io/SWELF/examples/Plugins/Plugin_Searchs/Searchs.txt" + "\r\n" +

               Settings.CommentCharConfigs + Settings.SWELF_AppConfig_Args[9] + Settings.SplitChar_ConfigVariableEquals[0] + "https://ceramicskate0.github.io/SWELF/examples/Log_Searchs/Whitelist_Searchs.txt" + "\r\n" +

               Settings.CommentCharConfigs + Settings.SWELF_AppConfig_Args[10] + ": syslogxml,syslog,xml,data,keyvalue" + "\r\n" +

               Settings.SWELF_AppConfig_Args[10] + Settings.SplitChar_ConfigVariableEquals[0] + @"keyvalue" + "\r\n" +

               Settings.CommentCharConfigs + Settings.SWELF_AppConfig_Args[17] + ": verbose,informataion,warning,critical,failureaudit" + "\r\n" +

               Settings.SWELF_AppConfig_Args[17] + Settings.SplitChar_ConfigVariableEquals[0] + @"critical" + "\r\n" +

               Settings.CommentCharConfigs + Settings.SWELF_AppConfig_Args[11] + "\r\n" +

               Settings.CommentCharConfigs + Settings.SWELF_AppConfig_Args[12] + Settings.SplitChar_ConfigVariableEquals[0] + "true" + "\r\n" +

               Settings.CommentCharConfigs + Settings.SWELF_AppConfig_Args[13] + Settings.SplitChar_ConfigVariableEquals[0] + "Sysmon64" + "\r\n" +

               Settings.CommentCharConfigs + Settings.SWELF_AppConfig_Args[13] + Settings.SplitChar_ConfigVariableEquals[0] + "Sysmon" + "\r\n" +

               Settings.CommentCharConfigs + Settings.SWELF_AppConfig_Args[14] + Settings.SplitChar_ConfigVariableEquals[0] + "tcp" + "\r\n" +

               Settings.CommentCharConfigs + Settings.SWELF_AppConfig_Args[15] + Settings.SplitChar_ConfigVariableEquals[0] + "true" + "\r\n" +

               Settings.CommentCharConfigs + Settings.SWELF_AppConfig_Args[16] + Settings.SplitChar_ConfigVariableEquals[0] + "true"
           ;
                return log;
            }
        }
        internal static string GET_Default_Eventlog_with_PlaceKeeper_File_Contents
        {
            get
            {
                string log = @"" + Settings.CommentCharConfigs + @"LOG NAME, START AT INDEX(1 if unknown)
#Most Up to date example at https://github.com/ceramicskate0/SWELF/blob/master/examples/Config/Eventlog_with_PlaceKeeper.txt
application=1
security=1
system=1
windows powershell=1
#amsi/operational=1
microsoft-windows-sysmon/operational=1
microsoft-windows-windows defender/operational=1
microsoft-windows-powershell/operational=1
microsoft-windows-deviceguard/operational=1
microsoft-windows-wmi-activity/operational=1
#microsoft-windows-bits-client/operational=1
Microsoft-Windows-Security-Mitigations/KernelMode=1
Microsoft-WindowsCodeIntegrity/Operational=1
";
                return log;
            }
        }
        internal static string GET_Default_Logs_Search_File_Contents
        {
            get
            {
                string log = @"" + Settings.CommentCharConfigs + @"SearchTerm/ or Search CMD " + Settings.SplitChar_SearchCommandSplit[0] + @" EventLogName " + Settings.SplitChar_SearchCommandSplit[0] + @" EventID
#Default SWELF Config
#Most Up to date list at https://github.com/ceramicskate0/SWELF/examples/Log_Searchs/Searchs.txt
#Layout of Searchs.txt File for searching:
#SearchTerm~EventLogName~EventID
~System~
~Security~
~Microsoft-Windows-Security-Mitigations/KernelMode~
~Microsoft-Windows-CodeIntegrity/Operational~
~#microsoft-windows-deviceguard/operational~
#~Application~
~microsoft-windows-wmi-activity/operational~
~windows powershell~
~Microsoft-Windows-SoftwareRestrictionPolicies~Application~
~Microsoft-Windows-PowerShell/Operational~
~microsoft-Windows-Windows Defender/Operational~
~Microsoft-Windows-Sysmon/Operational~
~Microsoft-Windows-Security-Mitigations/KernelMode~
";
                return log;
            }
        }
        internal static string GET_Default_Whitelist_File_Contents
        {
            get
            {
                string log = "" + Settings.CommentCharConfigs + @"#SearchTerm ~ EventLogName ~ EventID. Visit one of the following links for the docs " + @"https://github.com/ceramicskate0/SWELF/wiki/%5CLog_Searchs%5CWhiteList_Search.txt--(WhiteListing)" + "or https://github.com/ceramicskate0/SWELF/wiki/Plugins";
                return log;
            }
        }
        internal static string GET_Default_Powershell_Plugins_File_Contents
        {
            get
            {
                string log = "" + Settings.CommentCharConfigs + @"#File Path to Powershell Script ~ SearchTerm ~ Powershell Script Arguments \n\r#See this link for some ideas on plugins https://github.com/ceramicskate0/SWELF/wiki/Plugins";
                return log;
            }
        }

        internal static void CHECK_File_Size(string FilePath, double MaxSizeRatio = .0001)
        {
            FileInfo Log_App_Log_File = new FileInfo(FilePath);

            if (Log_App_Log_File.Length > Drives_Available_Space * MaxSizeRatio)
            {
                DELETE_AND_CREATE_File(FilePath);
            }
        }

        internal static void Write_Ouput_CSV(string FilePath, Queue<EventLog_Entry> FileContents)
        {
            if (CHECK_if_File_Exists(FilePath))
            {
                Write_Contents(FilePath, FileContents);
            }
            else
            {
                File.Create(FilePath).Close();
                File.AppendAllText(FilePath, "LogName" + "," + "EventRecordID" + "," + "EventID" + "," + "CreatedTime" + "," + "ComputerName" + "," + "UserID" + "," + "Severity" + "," + "TaskDisplayName" + "," + "EventData" + '\n');
                Write_Contents(FilePath, FileContents);
            }

        }

        internal static void Write_Hash_Output(List<string> Hashs)
        {
            File.Delete(Settings.Hashs_File_Path);
            File.Create(Settings.Hashs_File_Path).Close();
            for (int x = 0; x < Hashs.Count; ++x)
            {
                try
                {
                    File.AppendAllText(Settings.Hashs_File_Path, Hashs.ElementAt(x) + "\n");
                }
                catch (Exception e)
                {
                    Error_Operation.WRITE_Errors_To_Log("Write_Hash_Output()", e.Message.ToString(), Error_Operation.LogSeverity.Informataion);
                }
            }
            CHECK_File_Size(Settings.Hashs_File_Path, .0002);
        }

        internal static void Write_IP_Output(List<string> IPs)
        {
            File.Delete(Settings.IPs_File_Path);
            File.Create(Settings.IPs_File_Path).Close();
            for (int x = 0; x < IPs.Count; ++x)
            {
                try
                {
                    File.AppendAllText(Settings.IPs_File_Path, IPs.ElementAt(x) + "\n");
                }
                catch (Exception e)
                {
                    Error_Operation.WRITE_Errors_To_Log("Write_IP_Output()", e.Message.ToString(), Error_Operation.LogSeverity.Informataion);
                }
            }
            CHECK_File_Size(Settings.IPs_File_Path, .0002);
        }

        internal static void Write_Contents(string FilePath, Queue<EventLog_Entry> FileContents)
        {
            for (int x = 0; x < FileContents.Count; ++x)
            {
                File.AppendAllText(FilePath, FORMAT_Output(FileContents.ElementAt(x)));
            }
        }

        internal static string FORMAT_Output(EventLog_Entry EventLog)
        {
            string EventData;
            EventData = EventLog.EventData;
            EventData = EventData.Replace('\n', ' ');
            EventData = EventData.Replace('\r', ' ');
            EventData = EventData.Replace("\n\r", " ");
            EventData = EventData.Replace("\r\n", " ");

            return EventLog.LogName + "," + EventLog.EventRecordID + "," + EventLog.EventID + "," + EventLog.CreatedTime + "," + EventLog.ComputerName + "," + EventLog.UserID + "," + EventLog.Severity + "," + EventLog.TaskDisplayName + ",\"" + EventData + "\"" + '\n';
        }

        internal static void CREATE_NEW_Files_And_Dirs(string Dir, string FileName, string FileData = "", bool Overwrite = false)
        {
            try
            {
                if (Directory.Exists(Dir) == false)
                {
                    Directory.CreateDirectory(Dir);
                }
                if (CHECK_if_File_Exists(Dir + "\\" + FileName) == false || Overwrite)
                {
                    File.Create(Dir + "\\" + FileName).Close();

                    if (string.IsNullOrEmpty(FileData) == false || Overwrite)
                    {
                        File.AppendAllText(Dir + "\\" + FileName, FileData);
                    }
                }
            }
            catch (Exception e)
            {
                Settings.Stop(Settings.SWELF_CRIT_ERROR_EXIT_CODE, "CREATE_NEW_Files_And_Dirs() check IO restrictions on machine for app.", e.Message.ToString());
            }
        }

        internal static void DELETE_AND_CREATE_File(string Filepath)
        {
            File.Delete(Filepath);
            File.Create(Filepath).Close();
        }

        internal static bool CHECK_if_File_Exists(string FilePath)
        {
            try
            {
                return File.Exists(FilePath);
            }
            catch (Exception e)
            {
                return false;
            }
        }

        internal static bool CHECK_If_ALL_SWELF_Config_Files_Exist()
        {
            if (CHECK_if_File_Exists(Settings.GET_AppConfigFile_Path) == false)
            {
                return false;
            }
            else if (CHECK_if_File_Exists(Settings.GET_ErrorLog_Location) == false)
            {
                return false;
            }
            else if (CHECK_if_File_Exists(Settings.GET_EventLogID_PlaceHolder_Path) == false)
            {
                return false;
            }
            else if (CHECK_if_File_Exists(Settings.GET_SearchTermsFile_Path) == false)
            {
                return false;
            }
            else if (CHECK_if_File_Exists(Settings.GET_WhiteList_SearchTermsFile_Path) == false)
            {
                return false;
            }
            else if (CHECK_if_File_Exists(Settings.GET_WhiteList_SearchTermsFile_PLUGIN_Path) == false)
            {
                return false;
            }
            else if (CHECK_if_File_Exists(Settings.GET_SearchTermsFile_PLUGIN_Path) == false)
            {
                return false;
            }
            else
            {
                return true;
            }
        }

        internal static void GET_Plugin_Scripts_Ready()
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

        internal static string GET_FilesToMonitor_Path()
        {
            CREATE_NEW_Files_And_Dirs(Settings.Config_File_Location, Settings.FilesToMonitor_FileName);
            return Settings.GET_FilesToMonitor_Path;
        }

        internal static string GET_DirToMonitor_Path()
        {
            CREATE_NEW_Files_And_Dirs(Settings.Config_File_Location, Settings.DirectoriesToMonitor_FileName);
            return Settings.GET_DirectoriesToMonitor_Path;
        }

        internal static void VERIFY_AppConfig_Default_Files_Ready()
        {
            if (!CHECK_if_File_Exists(Settings.GET_AppConfigFile_Path))
            {
                CREATE_NEW_Files_And_Dirs(Settings.Config_File_Location, Settings.AppConfigFile_FileName, GET_Default_ConsoleAppConfig_File_Contents);
                Crypto_Operation.Secure_File(Settings.GET_AppConfigFile_Path);
            }
            if (!CHECK_if_File_Exists(Settings.GET_EventLogID_PlaceHolder_Path))
            {
                CREATE_NEW_Files_And_Dirs(Settings.Config_File_Location, Settings.EventLogID_PlaceHolde_FileName, GET_Default_Eventlog_with_PlaceKeeper_File_Contents);
                Crypto_Operation.Secure_File(Settings.GET_EventLogID_PlaceHolder_Path);
            }
            if (!CHECK_if_File_Exists(Settings.GET_FilesToMonitor_Path))
            {
                CREATE_NEW_Files_And_Dirs(Settings.Config_File_Location, Settings.FilesToMonitor_FileName, @"#C:\MyCustomApp\LogFile.log");
            }
            if (!CHECK_if_File_Exists(Settings.GET_DirectoriesToMonitor_Path))
            {
                CREATE_NEW_Files_And_Dirs(Settings.Config_File_Location, Settings.DirectoriesToMonitor_FileName, @"#%SystemDrive%\inetpub\logs\LogFiles");
            }
        }

        internal static void VERIFY_Search_Default_Files_Ready()
        {
            if (!CHECK_if_File_Exists(Settings.GET_SearchTermsFile_Path))
            {
                CREATE_NEW_Files_And_Dirs(Settings.Search_File_Location, Settings.SearchTermsFileName_FileName, GET_Default_Logs_Search_File_Contents);
                Crypto_Operation.Secure_File(Settings.GET_SearchTermsFile_Path);
            }
            if (!CHECK_if_File_Exists(Settings.GET_WhiteList_SearchTermsFile_Path))
            {
                CREATE_NEW_Files_And_Dirs(Settings.GET_WhiteList_SearchTermsFile_Path, Settings.Search_WhiteList_FileName, GET_Default_Whitelist_File_Contents);
                Crypto_Operation.Secure_File(Settings.GET_WhiteList_SearchTermsFile_Path);
            }
        }

        internal static void HIDDEN_File(string path)
        {
            File.SetAttributes(path, FileAttributes.Hidden);
        }

        internal static string GET_CreationTime(string path)
        {
            try
            {
                return File.GetCreationTime(path).ToString();
            }
            catch (Exception e)
            {
                if (e.Message.Contains("FileNotFoundException"))
                {
                    File.Create(path);
                    return DateTime.Now.ToString();
                }
                else
                {
                    Error_Operation.Log_Error("GET_CreationTime()", e.Message.ToString(), Error_Operation.LogSeverity.Informataion);
                    return null;
                }
            }
        }

        internal static List<string> READ_File_In_List(string FilePath)
        {
            if (CHECK_File_Encrypted(FilePath) == true)
            {
                Crypto_Operation.UnSecure_File(FilePath);
                List<string> TEMP_Contents = File.ReadAllLines(FilePath).ToList();
                Crypto_Operation.Secure_File(FilePath);
                return TEMP_Contents;
            }
            else
            {
                return File.ReadAllLines(FilePath).ToList();
            }
        }

        internal static string[] READ_File_In_StringArray(string FilePath)
        {
            if (CHECK_if_File_Exists(FilePath))
            {
                Crypto_Operation.UnSecure_File(FilePath);
                string[] Contents = File.ReadAllLines(FilePath);
                Crypto_Operation.Secure_File(FilePath);
                return Contents;
            }
            else
            {
                Error_Operation.Log_Error("READ_File_In_StringArray()", "File not found " + FilePath, Error_Operation.LogSeverity.Informataion);
                return File.ReadAllLines(FilePath);
            }
        }

        internal static string READ_AllText(string FilePath)
        {
            bool FIleExists = CHECK_if_File_Exists(FilePath);

            if (FIleExists && CHECK_File_Encrypted(FilePath))
            {
                Crypto_Operation.UnSecure_File(FilePath);
                string Contents = File.ReadAllText(FilePath);
                Crypto_Operation.Secure_File(FilePath);
                return Contents;

            }
            else
            {
                if (FIleExists == false)
                {
                    Error_Operation.Log_Error("READ_AllText()", "File not found " + FilePath, Error_Operation.LogSeverity.Informataion);
                    return null;
                }
                else
                {
                    return File.ReadAllText(FilePath);
                }
            }
        }

        internal static bool CHECK_File_Encrypted(string FilePath)
        {
            try
            {
                FileInfo fi = new FileInfo(FilePath);
                string Check = File.ReadAllText(FilePath);

                if ((Check.Any(s => Crypto_Operation.Common_Encrypted_Chars.Contains(s)) && Check.Any(s => s >= 128)) && fi.Attributes.HasFlag(FileAttributes.Encrypted))
                {
                    return true;//File Encrypted
                }
                else
                {
                    if ((Check.Any(s => Crypto_Operation.Common_Encrypted_Chars.Contains(s)) && Check.Any(s => s >= 128)) && fi.Attributes.HasFlag(FileAttributes.Encrypted) == false)
                    {
                        File.Encrypt(FilePath);
                        return true;//File needed encrypted attrib and was encrypted
                    }
                    else
                    {
                       return false;//File not encrypted
                    }
                }
            }
            catch (Exception e)
            {
                return false;//File NOT Encrypted
            }
        }

        internal static bool CHECK_Data_Encrypted(string Data)
        {
            if ((Data.Any(s => Crypto_Operation.Common_Encrypted_Chars.Contains(s)) && Data.Any(s => s >= 128)))
            {
                return true;//File Encrypted
            }
            else
            {
                return false;//File NOT Encrypted
            }
        }

        internal static void Turnicate_File(string FilePath, byte[] Contents = null)
        {
            try
            {
                using (FileStream SourceStream = File.Open(FilePath, FileMode.Truncate))
                {
                    try
                    {
                        if (Contents != null)
                        {
                            SourceStream.Write(Contents, 0, Contents.Length);
                        }
                    }
                    catch (Exception e)
                    {
                        //could not open stream
                    }
                }
            }
            catch (Exception e)
            {
                //error in file stream
            }
        }

        internal static bool READ_Config_File_For_Value(string valueToFind, string FileToRead)
        {
            if (CHECK_if_File_Exists(FileToRead))
            {
                foreach (string ConfigFileline in READ_File_In_List(FileToRead))//File_Args are read in here 1 by 1
                {
                    if (!ConfigFileline.Contains(Settings.CommentCharConfigs) && ConfigFileline.Contains(Settings.SplitChar_ConfigVariableEquals[0]) && ConfigFileline.Split(Settings.SplitChar_ConfigVariableEquals, StringSplitOptions.RemoveEmptyEntries).ToList().ElementAt(0).ToLower().Contains(valueToFind.ToLower()))//split the read in arg
                    {
                        return true;
                    }
                }
                return false;
            }
            else
            {
                return false;
            }
        }

        internal static void APPEND_Data_To_File(string FilePath, string Values)
        {
            if (CHECK_if_File_Exists(FilePath))
            {
                if (CHECK_Data_Encrypted(FilePath))
                {
                    Crypto_Operation.UnSecure_File(FilePath);
                    File.AppendAllText(FilePath,Values);
                    Crypto_Operation.Secure_File(FilePath);

                }
                else
                {
                    File.AppendAllText(FilePath, Values);
                }
            }
        }

        internal static void DELETE_File(string FilePath)
        {
            File.Delete(FilePath);
        }

        internal static void APPEND_AllTXT(string FilePath,string Content)
        {
            File.WriteAllText(FilePath, Content);
        }
    }
}
