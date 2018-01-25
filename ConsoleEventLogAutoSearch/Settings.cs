//Written by Ceramicskate0
//Copyright 2017
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices;
using System.Security.Cryptography;
using System.Threading;

namespace SWELF
{
    class Settings
    {
        public static int Log_Forward_Location_Port = 514;

        public static List<string> EventLogs_ListOfAvaliable = EventLogSession.GlobalSession.GetLogNames().ToList();
        public static Dictionary<string, long> EventLog_w_PlaceKeeper = new Dictionary<string, long>();
        public static List<string> EventLog_w_PlaceKeeper_List = new List<string>();
        public static Dictionary<string, string> Args = new Dictionary<string, string>();//program config arguements
        public static List<string> Logs_Search_Terms_Unparsed = new List<string>();
        public static List<string> Plugin_Search_Terms_Unparsed = new List<string>();
        public static List<string> Plugin_Scripts_to_Run = new List<string>();
        public static Queue<EventLogEntry> CriticalEvents = new Queue<EventLogEntry>();
        private static Dictionary<string, long> EventLog_w_PlaceKeeper_Backup = new Dictionary<string, long>();

        private static string Config_File_Location = Directory.GetCurrentDirectory() + "\\Config";
        private static string Search_File_Location = Directory.GetCurrentDirectory() + "\\Log_Searchs";
        private static string SWELF_Log_File_Location = Directory.GetCurrentDirectory() + "\\SWELF_Logs";
        private static string Plugin_Files_Location = Directory.GetCurrentDirectory() + "\\Plugins";
        private static string Plugin_Scripts_Location = Plugin_Files_Location + "\\Scripts";
        private static string Plugin_Search_Location = Plugin_Files_Location + "\\Plugin_Searchs";

        private static string ErrorFile = "Error_Log.log";
        private static string AppConfigFile = "ConsoleAppConfig.conf";
        private static string SHA256_AppConfigFile_HASH;
        private static string EventLogID_PlaceHolder = "Eventlog_with_PlaceKeeper.txt";
        private static string SearchTermsFileName = "Searchs.txt";
        private static string FilesToMonitor = "Files_To_Monitor.conf";
        private static string DirectoriesToMonitor = "Directories_To_Monitor.conf";

        public static string CommentCharConfigs = "#";
        public static char[] SplitChar_Regex = { '~' };
        public static char[] SplitChar_SearchCommandParse = { '~' };
        public static char[] SplitChar_ConfigVariableEquals = { '=' };
        public static char[] SplitChar_UNCPath = { '\\' };

        public static string ComputerName = Environment.MachineName;

        private static string SWELF_EventLog_Name = "SWELF_Events_of_Interest";

        public static EventLog EvtLog = new EventLog();

        public static string GET_ErrorLog_Location
        {
            get
            {
                return SWELF_Log_File_Location + "\\" + ErrorFile;
            }
        }

        public static void InitializeAppSettings()
        {
            GET_ErrorLog_Ready();
            SET_WindowsEventLog_Loc();
            READ_App_Config_File();
            READ_EventLogID_Placeholders();
            READ_Search_Terms_File(Search_File_Location + "\\" + SearchTermsFileName);
            CHECK_if_all_Search_Terms_have_Indexed_LogsSources();
            //GET_Plugins_Ready();
            //READ_All_Plugin_Scripts_To_Run();
            //READ_Powershell_SearchTerms();
        }

        private static void READ_Central_Search_Config_File(string LocalFilePath, string UNC_FilePath)
        {
            string Sysvol_DomainController = UNC_FilePath.Split(SplitChar_UNCPath, StringSplitOptions.RemoveEmptyEntries).ToList().ElementAt(1);//get IP/hostname
            IPHostEntry hostEntry;
            hostEntry = Dns.GetHostEntry(Sysvol_DomainController);

            if (hostEntry.AddressList.Length > 0 && UNC_FilePath.Substring(0, 2) == @"\\" && LocalFilePath.Contains(SearchTermsFileName) && Domain.GetComputerDomain().DomainControllers.Count > 1 && Enumerate_and_Verify_Domain_Controllers(Sysvol_DomainController))//security check and unc path verification
            {
                READ_Search_Terms_File(UNC_FilePath);
            }
            else
            {
                Errors.Log_Error("ALERT: SWELF APP ERROR: ", "UNC path for central config supplied. It failed network check, error checks, and/or security checks.");
            }
        }

        private static void READ_Central_Plugin_Config_File(string LocalFilePath, string UNC_FilePath)
        {
            string Sysvol_DomainController = UNC_FilePath.Split(SplitChar_UNCPath, StringSplitOptions.RemoveEmptyEntries).ToList().ElementAt(1);//get IP/hostname
            IPHostEntry hostEntry;
            hostEntry = Dns.GetHostEntry(Sysvol_DomainController);

            if (hostEntry.AddressList.Length > 0 && UNC_FilePath.Substring(0, 2) == @"\\" && LocalFilePath.Contains(Plugin_Files_Location) && Domain.GetComputerDomain().DomainControllers.Count > 1 && Enumerate_and_Verify_Domain_Controllers(Sysvol_DomainController))//security check and unc path verification
            {
                READ_Search_Terms_File(UNC_FilePath);
            }
            else
            {
                Errors.Log_Error("ALERT: SWELF APP ERROR: ", "UNC path for central config supplied. It failed network check, error checks, and/or security checks.");
            }
        }

        private static void READ_Central_App_Config_File(string LocalFilePath, string UNC_FilePath)
        {
            string Sysvol_DomainController = UNC_FilePath.Split(SplitChar_UNCPath, StringSplitOptions.RemoveEmptyEntries).ToList().ElementAt(1);//get IP/hostname
            IPHostEntry hostEntry;
            hostEntry = Dns.GetHostEntry(Sysvol_DomainController);

            if (hostEntry.AddressList.Length > 0 && UNC_FilePath.Substring(0, 2) == @"\\" && LocalFilePath.Contains(AppConfigFile) && Domain.GetComputerDomain().DomainControllers.Count > 1 && Enumerate_and_Verify_Domain_Controllers(Sysvol_DomainController))//security check and unc path verification
            {
                READ_App_Config_File(UNC_FilePath);
            }
            else
            {
                Errors.Log_Error("ALERT: SWELF APP ERROR: ", "UNC path for central config supplied. It failed network check, error checks, and/or security checks.");
            }
        }

        /// <summary>
        /// 0=App config read and hash match
        /// 1=Hash not match 
        /// 2= nUnable to read app config from Sysvol
        /// </summary>
        /// <param name="filename">UNC locatio on central config file./param>
        /// <returns></returns>
        public static int VERIFY_Central_File_Config_Hash(String filename)
        {
            Random ran = new Random(10000);
            int randoNum = ran.Next(20000, 600000);
            int Num_Of_Tries = 0;

            while (true || Num_Of_Tries==10)
            {
                try
                {
                    SHA256_AppConfigFile_HASH=Calculate_SHA256_For_Trusted_Config(filename);
                    if (SHA256_AppConfigFile_HASH == Args["central_app_config_hash"])
                    {
                        return 0;//app hash match 
                    }
                    else
                    {
                        return 1; //app hash not match
                    }
                }
                catch 
                {
                }
                Thread.Sleep(randoNum);
                Num_Of_Tries++;
            }
            Errors.WRITE_Errors_To_Log("ERROR: unable to get central App config. Central config  file locked.");
            return 2;//unable to get app config from sysvol
        }

        private static string Calculate_SHA256_For_Trusted_Config(string filename)
        {
            using (var sha256 = SHA256.Create())
            {
                using (var stream = File.OpenRead(filename))
                {
                    var hash = sha256.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }
            }
        }

        private static void READ_App_Config_File(string UNC_FilePath = "")
        {
            try
            {
                string FileLocation;
                if (!string.IsNullOrEmpty(UNC_FilePath))
                {
                    FileLocation = UNC_FilePath;
                }
                else
                {
                    FileLocation = Config_File_Location + "\\" + AppConfigFile;
                }
                string[] ConfgiFilelines = File.ReadAllLines(FileLocation);
                List<string> methods_args = new List<string>();
                foreach (string ConfgiFileline in ConfgiFilelines)
                {
                    if (!ConfgiFileline.Contains(Settings.CommentCharConfigs) && ConfgiFileline.Contains(SplitChar_ConfigVariableEquals[0]))
                    {
                        methods_args = ConfgiFileline.Split(Settings.SplitChar_ConfigVariableEquals,StringSplitOptions.RemoveEmptyEntries).ToList();
                        Args.Add(methods_args.ElementAt(0).ToLower(), methods_args.ElementAt(1).ToLower());
                        methods_args.Clear();
                    }
                }
                if (Args.ContainsKey("central_app_config"))
                {
                    int HashEqualed = VERIFY_Central_File_Config_Hash(UNC_FilePath);
                    if (HashEqualed == 0)
                    {
                        READ_Central_App_Config_File(FileLocation, Args["central_app_config"]);
                        methods_args.Clear();
                        Args.Clear();
                    }
                    else if (HashEqualed == 1)
                    {
                        Errors.Log_Error("ERROR: ", Settings.ComputerName + " was unable to verify its central config file. Hash did not match. It was looking at " + UNC_FilePath);
                        Errors.WRITE_Errors_To_Log("ERROR: " + Settings.ComputerName + " was unable to verify its central config file. Hash did not match. It was looking at " + UNC_FilePath);
                        methods_args.Clear();
                        Args.Clear();
                    }
                    else
                    {
                        Errors.Log_Error("ERROR: ", Settings.ComputerName + " was unable to verify its central config file. File Locked. It was looking at " + UNC_FilePath);
                        Errors.WRITE_Errors_To_Log("ERROR: " + Settings.ComputerName + " was unable to verify its central config file. File Locked. It was looking at " + UNC_FilePath);
                        methods_args.Clear();
                        Args.Clear();
                    }
                }
            }
            catch
            {
                CREATE_Files_And_Dirs(Config_File_Location,AppConfigFile, WRITE_Default_ConsoleAppConfig_File());
            }
        }

        private static void READ_Search_Terms_File(string LocalFilePath, string UNC_FilePath="")
        {
            try
            {
                string line;
                string FileLocation;
                if (!string.IsNullOrEmpty(UNC_FilePath))
                {
                    FileLocation = UNC_FilePath;
                }
                else
                {
                    FileLocation = Search_File_Location + "\\" + SearchTermsFileName;
                }
                CREATE_Files_And_Dirs(Search_File_Location, SearchTermsFileName, WRITE_Default_Logs_Search_File());
                StreamReader file = new StreamReader(FileLocation);
                while ((line = file.ReadLine()) != null)
                {
                    if (line.StartsWith("#") == false)
                    {
                        Logs_Search_Terms_Unparsed.Add(line.ToLower());
                    }
                }
                file.Close();
                if (Args.ContainsKey("central_search_config"))
                {
                    READ_Central_Search_Config_File(FileLocation, Args["central_search_config"]);
                    Logs_Search_Terms_Unparsed.Clear();
                }
            }
            catch
            { 
            CREATE_Files_And_Dirs(Search_File_Location,SearchTermsFileName, WRITE_Default_Logs_Search_File());
            }
        }

        private static void READ_EventLogID_Placeholders()
        {
            try
            {
                string line;
                CREATE_Files_And_Dirs(Config_File_Location, EventLogID_PlaceHolder, WRITE_Default_Eventlog_with_PlaceKeeper_File());
                StreamReader file = new StreamReader(Config_File_Location + "\\" + EventLogID_PlaceHolder);
                while ((line = file.ReadLine()) != null)
                {
                    if (!line.Contains(Settings.CommentCharConfigs))
                    {
                        string[] lines = line.Split(Settings.SplitChar_ConfigVariableEquals, StringSplitOptions.RemoveEmptyEntries).ToArray();
                        EventLog_w_PlaceKeeper.Add(lines[0].ToLower(), Convert.ToInt64(lines[1]));
                        EventLog_w_PlaceKeeper_List.Add(lines[0].ToLower());
                    }
                }
                file.Close();
            }
            catch
            {
                CREATE_Files_And_Dirs(Config_File_Location, EventLogID_PlaceHolder, WRITE_Default_Eventlog_with_PlaceKeeper_File());
            }
        }

        private static void READ_Powershell_SearchTerms(string LocalFilePath, string UNC_FilePath = "")
        {
            try
            {
                string line;
                string FileLocation;
                if (!string.IsNullOrEmpty(UNC_FilePath))
                {
                    FileLocation = UNC_FilePath;
                }
                else
                {
                    FileLocation = Search_File_Location + "\\" + SearchTermsFileName;
                }
                CREATE_Files_And_Dirs(Plugin_Search_Location,SearchTermsFileName, WRITE_Default_Powershell_Search_File());
                StreamReader file = new StreamReader(FileLocation);
                while ((line = file.ReadLine()) != null)
                {
                    Plugin_Search_Terms_Unparsed.Add(line.ToLower());
                }
                file.Close();
                if (Args.ContainsKey("central_plugin_config"))
                {
                    READ_Central_Plugin_Config_File(FileLocation, Args["central_plugin_config"]);
                }
            }
            catch 
            {
                CREATE_Files_And_Dirs(Plugin_Search_Location,SearchTermsFileName, WRITE_Default_Powershell_Search_File());
            }
        }

        private static void READ_All_Plugin_Scripts_To_Run()
        {
            Plugin_Scripts_to_Run = Directory.GetFiles(Plugin_Scripts_Location,"*.ps1",SearchOption.TopDirectoryOnly).ToList();
        }

        private static bool Enumerate_and_Verify_Domain_Controllers(string DomainController)
        {
            Domain domain = Domain.GetCurrentDomain();
            foreach (DomainController dc in domain.DomainControllers)
            {
                if (Dns.GetHostEntry(dc.Name).HostName.ToLower() == Dns.GetHostEntry(DomainController).HostName.ToLower())//make sure the config is the current domain controller on the domain the machine is on
                    return true;
            }
            return false;
        }

        public static void GET_ErrorLog_Ready()
        {
            CREATE_Files_And_Dirs(SWELF_Log_File_Location,ErrorFile);
        }

        private static void GET_Plugins_Ready()
        {
            if (!Directory.Exists(Plugin_Files_Location))
            {
                Directory.CreateDirectory(Plugin_Files_Location);
            }
            if (!Directory.Exists(Plugin_Scripts_Location))
            {
                Directory.CreateDirectory(Plugin_Scripts_Location);
            }
            if (!Directory.Exists(Plugin_Search_Location))
            {
                Directory.CreateDirectory(Plugin_Search_Location);
            }
        }

        public static string GET_FilesToMonitor_Path()
        {
            CREATE_Files_And_Dirs(Config_File_Location, FilesToMonitor);
            return Config_File_Location + "\\" + FilesToMonitor;
        }

        public static string GET_DirToMonitor_Path()
        {
            CREATE_Files_And_Dirs(Config_File_Location, DirectoriesToMonitor);
            return Config_File_Location + "\\" + DirectoriesToMonitor;
        }

        public static List<IPAddress> GET_LogCollector_Location()
        {
            List<IPAddress> IPAddr = new List<IPAddress>();

            if (Args.ContainsKey("log_collector") == true && !String.IsNullOrEmpty(Args["log_collector"]))
            {
                IPAddr.Add(IPAddress.Parse(Args["log_collector"]));
            }
            if (Args.ContainsKey("log_collector1") == true && !String.IsNullOrEmpty(Args["log_collector1"]))
            {
                IPAddr.Add(IPAddress.Parse(Args["log_collector1"]));
            }
            if (Args.ContainsKey("log_collector2") == true && !String.IsNullOrEmpty(Args["log_collector2"]))
            {
                IPAddr.Add(IPAddress.Parse(Args["log_collector2"]));
            }
            if (Args.ContainsKey("log_collector3") == true && !String.IsNullOrEmpty(Args["log_collector3"]))
            {
                IPAddr.Add(IPAddress.Parse(Args["log_collector3"]));
            }
            if (Args.ContainsKey("log_collector4") == true && !String.IsNullOrEmpty(Args["log_collector4"]))
            {
                IPAddr.Add(IPAddress.Parse(Args["log_collector4"]));
            }
            if (Args.ContainsKey("log_collector5") == true && !String.IsNullOrEmpty(Args["log_collector5"]))
            {
                IPAddr.Add(IPAddress.Parse(Args["log_collector5"]));
            }

            if (IPAddr.Count <= 0)
            {
                IPAddr.Add(IPAddress.Parse("127.0.0.1"));
            }

            IPAddr = IPAddr.Distinct().ToList();
            return IPAddr;
        }

        private static void CHECK_if_all_Search_Terms_have_Indexed_LogsSources()
        {
            foreach (string SearchLogType in Logs_Search_Terms_Unparsed)//search terms
            {
                string[] SearchsArgs = SearchLogType.Split(Settings.SplitChar_SearchCommandParse, StringSplitOptions.RemoveEmptyEntries).ToArray();
                bool LogSoucreIsInToBeIndexQueue = false;
                if (SearchsArgs.Length > 1)
                {
                    if (String.IsNullOrEmpty(SearchsArgs[1]) == false && SearchLogType.StartsWith(Settings.CommentCharConfigs) == false)
                    {
                        foreach (string LogSource in EventLog_w_PlaceKeeper_List)//eventlogs to index
                        {
                            if (SearchsArgs[1].ToLower() == LogSource)
                            {
                                LogSoucreIsInToBeIndexQueue = true;
                            }
                        }
                    }
                    if (LogSoucreIsInToBeIndexQueue == false && String.IsNullOrEmpty(SearchsArgs[1]) == false && SearchLogType.StartsWith(Settings.CommentCharConfigs) == false && Settings.FIND_EventLog_Exsits(SearchsArgs[1]))
                    {
                        EventLog_w_PlaceKeeper.Add(SearchsArgs[1].ToLower(), 1);
                        EventLog_w_PlaceKeeper_List.Add(SearchsArgs[1].ToLower());
                        EventLog_w_PlaceKeeper_List.Reverse();
                    }
                }
            }
            EventLog_w_PlaceKeeper_Backup = EventLog_w_PlaceKeeper;
        }

        public static bool FIND_EventLog_Exsits(string EventLog_ToFind)
        {
            for (int x = 0; x < Settings.EventLogs_ListOfAvaliable.Count; ++x)
            {
                if (Settings.EventLogs_ListOfAvaliable.ElementAt(x).ToLower() == EventLog_ToFind)
                {
                    return true;
                }
            }
            return false;
        }

        private static void SET_WindowsEventLog_Loc()
        {
            try
            {
                if (!EventLog.SourceExists(SWELF_EventLog_Name))
                {
                    EventLog.CreateEventSource("SWELF", SWELF_EventLog_Name);
                    EvtLog.Source = SWELF_EventLog_Name;
                }
                else
                {
                    EvtLog.Source = SWELF_EventLog_Name;
                }
            }
            catch
            {
                EventLog.CreateEventSource("SWELF", SWELF_EventLog_Name);
                EvtLog.Source = SWELF_EventLog_Name;
            }
        }

        public static void UPDATE_EventLog_w_PlaceKeeper_File()
        {
            DELETE_AND_CREATE_File(Config_File_Location + "\\" + EventLogID_PlaceHolder);
            for (int x=0; x < EventLog_w_PlaceKeeper.Count;++x)
            {
                File.AppendAllText(Config_File_Location + "\\" + EventLogID_PlaceHolder, EventLog_w_PlaceKeeper_List.ElementAt(x) + SplitChar_ConfigVariableEquals[0] + EventLog_w_PlaceKeeper[EventLog_w_PlaceKeeper_List.ElementAt(x)]+"\n");
            }
        }

        public static void WRITE_EventLogID_Placeholders()
        {
            string ConfigFile = Config_File_Location + "\\" + EventLogID_PlaceHolder;
            File.Delete(ConfigFile);
            for (int x = 0; x > EventLog_w_PlaceKeeper.Count; ++x)
            {
                File.AppendAllText(ConfigFile, EventLog_w_PlaceKeeper.ElementAt(x).Key + SplitChar_ConfigVariableEquals[0] + EventLog_w_PlaceKeeper.ElementAt(x).Value.ToString() + "\n");
            }
        }

        private static string WRITE_Default_ConsoleAppConfig_File()
        {
            string log = @"#Must Be IPV4 
log_collector=127.0.0.1
#syslogxml,syslog,xml,data
outputformat=syslog";
            return log;
        }

        private static string WRITE_Default_Eventlog_with_PlaceKeeper_File()
        {
            string log= @"#LOG NAME, START AT INDEX(1 if unknown)
Microsoft-Windows-PowerShell/Operational=1
Windows PowerShell=1
Microsoft-Windows-Sysmon/Operational=1
Security=1
Microsoft-Windows-DeviceGuard/Operational=1
Microsoft-Windows-WMI-Activity/Operational=1
Microsoft-Windows-Bits-Client/Operational=1
";
            return log;
        }

        private static string WRITE_Default_Logs_Search_File()
        {
            string log = @"#SearchTerm, EventLogName, EventID
commandline_length:400
commandline_contains:<script>
commandline_contains:mshta -Enbedding
commandline_contains:mshta javascript
commandline_contains:rundll32.exe javascript
commandline_contains:$env
count:;:20
count:':50
count:+:12
eventdata_length:10000
iex,windows powershell,
webclient,windows powershell,
mshta.exe javascript:
mshta vbscript:
regsvr32.exe /s /u /i:
bitsadmin.exe  /transfer
bitsadmin.exe /download 
sc create
base64encoded";
            return log;
        }

        private static string WRITE_Default_Powershell_Search_File()
        {
            string log = "#Powershell Script To Run FullPath, SearchTerm";
            return log;
        }

        public static void ADD_Eventlog_to_CriticalEvents(string Data, string EventName)
        {
            EventLogEntry Eventlog = new EventLogEntry();
            Eventlog.LogName = SWELF_EventLog_Name;
            Eventlog.Severity = "Critical";
            Eventlog.TaskDisplayName = EventName;
            Eventlog.ComputerName = Settings.ComputerName;
            Eventlog.UserID = Environment.UserName;
            Eventlog.EventData = Data;
            Eventlog.EventID = 1;
            Eventlog.CreatedTime = DateTime.Now;

            CriticalEvents.Enqueue(Eventlog);
        }

        public static void Log_Storage_Location_Unavailable(string e)
        {
            EventLog_w_PlaceKeeper = EventLog_w_PlaceKeeper_Backup;
            Errors.WRITE_Errors_To_Log("NETWORK ERROR: " + e + " Access to log storage location may not be available.");
        }

        public static void DELETE_AND_CREATE_File(string Filepath)
        {
            File.Delete(Filepath);
            File.Create(Filepath).Close();
        }

        public static void CREATE_Files_And_Dirs(string Dir,string FileName,string FileData="")
        {
            if (Directory.Exists(Dir)==false)
            {
                Directory.CreateDirectory(Dir);
            }
            if (File.Exists(Dir + "\\" + FileName)==false)
            {
                File.Create(Dir + "\\" + FileName).Close();
                if (string.IsNullOrEmpty(FileData) == false)
                {
                    File.AppendAllText(Dir + "\\" + FileName, FileData);
                }
            }
        }
    }
}

