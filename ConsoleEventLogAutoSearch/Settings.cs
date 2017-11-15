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

namespace ConsoleEventLogAutoSearch
{
    class Settings
    {
        public static int LogForwardLocation_Port = 514;
        public static List<string> EventLogs_ListOfAvaliable = EventLogSession.GlobalSession.GetLogNames().ToList();
        public static Dictionary<string, long> EventLog_w_PlaceKeeper = new Dictionary<string, long>();
        public static List<string> EventLog_w_PlaceKeeper_List = new List<string>();
        public static Dictionary<string, string> Args = new Dictionary<string, string>();//program config arguements
        public static List<string> Searchs_Terms_Unparsed = new List<string>();
        public static Queue<EventLogEntry> CriticalEvents = new Queue<EventLogEntry>();
        private static Dictionary<string, long> EventLog_w_PlaceKeeper_Backup = new Dictionary<string, long>();

        private static string Config_File_Location = Directory.GetCurrentDirectory() + "\\Config";
        private static string Search_File_Location = Directory.GetCurrentDirectory() + "\\Searchs";
        private static string Log_File_Location = Directory.GetCurrentDirectory() + "\\Logs";

        private static string ErrorFile = "ErrorLog.log";
        private static string AppConfigFile = "ConsoleAppConfig.conf";
        private static string EventLogID_PlaceHolder = "Eventlog_with_PlaceKeeper.txt";
        private static string SearchTerms = "Search.txt";
        private static string FilesToMonitor = "FilesToMonitor.conf";
        private static string DirectoriesToMonitor = "DirectoriesToMonitor.conf";

        public static string Virus_Total_API_Key = "";

        private static string WHELA_EventLog_Name = "WHELA_Events_of_Interest";

        public static EventLog EvtLog = new EventLog();


        public static string GET_ErrorLog_Location
        {
            get
            {
                return Log_File_Location + "\\" + ErrorFile;
            }
        }

        public static void InitializeAppSettings()
        {
            READ_AppConfigFile();
            READ_EventLogID_Placeholders();
            READ_SearchTerms();
            CHECK_if_all_Search_Terms_have_Indexed_LogsSources();
            SET_WindowsEventLog_Loc();
        }

        private static void READ_AppConfigFile()
        {
            try
            {
                string[] ConfgiFilelines = File.ReadAllLines(Config_File_Location + "\\" + AppConfigFile);
                List<string> args = new List<string>();
                foreach (string ConfgiFileline in ConfgiFilelines)
                {
                    if (!ConfgiFileline.Contains("#"))
                    {
                        args = ConfgiFileline.Split('=').ToList();
                        Args.Add(args.ElementAt(0), args.ElementAt(1));
                        args.Clear();
                    }
                }  
            }
            catch (Exception e)
            {
                if (!Directory.Exists(Config_File_Location))
                {
                    Directory.CreateDirectory(Config_File_Location);
                }
                if (File.Exists(Config_File_Location + "\\" + AppConfigFile))
                {
                    File.Create(Config_File_Location + "\\" + AppConfigFile).Close();
                }
                File.AppendAllText(Config_File_Location + "\\" + AppConfigFile, WRITE_Default_ConsoleAppConfig_File());
            }
        }

        public static IPAddress GET_LogCollector_Location()
        {
            IPAddress IPAddr;
            if (Args.ContainsKey("log_collector")==true && !String.IsNullOrEmpty(Args["log_collector"]))
            {
                IPAddr = IPAddress.Parse(Args["log_collector"]);
            }
            else
            {
                IPAddr = IPAddress.Parse("127.0.0.1");
            }
            return IPAddr;
        }

        private static void CHECK_if_all_Search_Terms_have_Indexed_LogsSources()
        {
            foreach (string SearchLogType in Searchs_Terms_Unparsed)//search terms
            {
                string[] SearchsArgs = SearchLogType.Split(',').ToArray();
                bool LogSoucreIsInToBeIndexQueue = false;
                if (SearchsArgs.Length > 1)
                {
                    if (String.IsNullOrEmpty(SearchsArgs[1]) == false && SearchLogType.Contains('#') == false)
                    {
                        foreach (string LogSource in EventLog_w_PlaceKeeper_List)//eventlogs to index
                        {
                            if (SearchsArgs[1].ToLower() == LogSource)
                            {
                                LogSoucreIsInToBeIndexQueue = true;
                            }
                        }
                    }
                    if (LogSoucreIsInToBeIndexQueue == false && String.IsNullOrEmpty(SearchsArgs[1]) == false && SearchLogType.Contains('#') == false)
                    {
                        EventLog_w_PlaceKeeper.Add(SearchsArgs[1].ToLower(), 1);
                        EventLog_w_PlaceKeeper_List.Add(SearchsArgs[1].ToLower());
                        EventLog_w_PlaceKeeper_List.Reverse();
                    }
                }
            }
            EventLog_w_PlaceKeeper_Backup = EventLog_w_PlaceKeeper;
        }

        private static void READ_SearchTerms()
        {
            try
            {
                string line;
                if (!File.Exists(Search_File_Location + "\\" + SearchTerms))
                {
                    File.Create(Search_File_Location + "\\" + SearchTerms).Close();
                    File.AppendAllText(Search_File_Location + "\\" + SearchTerms, WRITE_Default_Search_File());
                }
                StreamReader file = new StreamReader(Search_File_Location + "\\" + SearchTerms);
                while ((line = file.ReadLine()) != null)
                {
                    Searchs_Terms_Unparsed.Add(line.ToLower());
                }
                file.Close();
                
            }
            catch (Exception e)
            {
                if (!Directory.Exists(Search_File_Location))
                {
                    Directory.CreateDirectory(Search_File_Location);
                }
                if (!File.Exists(Search_File_Location + "\\" + SearchTerms))
                {
                    File.Create(Search_File_Location + "\\" + SearchTerms).Close();
                }
                File.AppendAllText(Search_File_Location + "\\" + SearchTerms, WRITE_Default_Search_File());
            }
        }

        public static void GET_ErrorLog_Ready()
        {
            if (!Directory.Exists(Log_File_Location))
            {
                Directory.CreateDirectory(Log_File_Location);
            }
            if (!File.Exists(Log_File_Location + "\\" + ErrorFile))
            {
                File.Create(Log_File_Location + "\\" + ErrorFile).Close();
            }
        }

        public static string GET_FilesToMonitor_Path()
        {
            if (!Directory.Exists(Config_File_Location))
            {
                Directory.CreateDirectory(Config_File_Location);
            }
            if (!File.Exists(Config_File_Location + "\\" + FilesToMonitor))
            {
                File.Create(Config_File_Location + "\\" + FilesToMonitor).Close();
            }
            return Config_File_Location + "\\" + FilesToMonitor;
        }

        public static string GET_DirToMonitor_Path()
        {
            if (!Directory.Exists(Config_File_Location))
            {
                Directory.CreateDirectory(Config_File_Location);
            }
            if (!File.Exists(Config_File_Location + "\\" + DirectoriesToMonitor))
            {
                File.Create(Config_File_Location + "\\" + DirectoriesToMonitor).Close();
            }
            return Config_File_Location + "\\" + DirectoriesToMonitor;
        }

        private static void READ_EventLogID_Placeholders()
        {
            try
            {
                string line;
                if (!Directory.Exists(Config_File_Location))
                {
                    Directory.CreateDirectory(Config_File_Location);
                }
                if (!File.Exists(Config_File_Location + "\\" + EventLogID_PlaceHolder))
                {
                    File.Create(Config_File_Location + "\\" + EventLogID_PlaceHolder).Close();
                    File.AppendAllText(Config_File_Location + "\\" + EventLogID_PlaceHolder, WRITE_Default_Eventlog_with_PlaceKeeper_File());
                }
                else
                {
                    StreamReader file = new StreamReader(Config_File_Location + "\\" + EventLogID_PlaceHolder);
                    while ((line = file.ReadLine()) != null)
                    {
                        if (!line.Contains("#"))
                        {
                            string[] lines = line.Split('=').ToArray();
                            EventLog_w_PlaceKeeper.Add(lines[0].ToLower(), Convert.ToInt64(lines[1]));
                            EventLog_w_PlaceKeeper_List.Add(lines[0].ToLower());
                        }
                    }
                    file.Close();
                }
            }
            catch (Exception e)
            {
                if (!Directory.Exists(Config_File_Location))
                {
                    Directory.CreateDirectory(Config_File_Location);
                }
                if (!File.Exists(Config_File_Location + "\\" + EventLogID_PlaceHolder))
                {
                    File.Create(Config_File_Location + "\\" + EventLogID_PlaceHolder).Close();
                }
                File.AppendAllText(Config_File_Location + "\\" + EventLogID_PlaceHolder, WRITE_Default_Eventlog_with_PlaceKeeper_File());
            }
        }

        public static void WRITE_EventLogID_Placeholders()
        {
            string ConfigFile = Config_File_Location + "\\" + EventLogID_PlaceHolder;
            File.Delete(ConfigFile);
            for (int x = 0; x > EventLog_w_PlaceKeeper.Count; ++x)
            {
                File.AppendAllText(ConfigFile, EventLog_w_PlaceKeeper.ElementAt(x).Key + "=" + EventLog_w_PlaceKeeper.ElementAt(x).Value.ToString() + "\n");
            }
        }

        private static void SET_WindowsEventLog_Loc()
        {
            if (!EventLog.SourceExists(WHELA_EventLog_Name))
            {
                EventLog.CreateEventSource("WHELA", WHELA_EventLog_Name);
                EvtLog.Source = WHELA_EventLog_Name;
            }
            else
            {
                EvtLog.Source = WHELA_EventLog_Name;
            }
        }

        public static void UPDATE_EventLog_w_PlaceKeeper_File()
        {
            File.Delete(Config_File_Location + "\\" + EventLogID_PlaceHolder);
            File.Create(Config_File_Location + "\\" + EventLogID_PlaceHolder).Close();
            for (int x=0; x < EventLog_w_PlaceKeeper.Count;++x)
            {
                File.AppendAllText(Config_File_Location + "\\" + EventLogID_PlaceHolder, EventLog_w_PlaceKeeper_List.ElementAt(x) + "=" + EventLog_w_PlaceKeeper[EventLog_w_PlaceKeeper_List.ElementAt(x)]+"\n");
            }
        }

        private static string WRITE_Default_ConsoleAppConfig_File()
        {
            string log = "#Must Be IPV4 \nLog_Collector=127.0.0.1\n#syslogxml,syslog,xml,data\noutputformat=syslog";
            return log;
        }

        private static string WRITE_Default_Eventlog_with_PlaceKeeper_File()
        {
            string log= "#LOG NAME,START AT INDEX(1 if unknown)\nMicrosoft-Windows-PowerShell/Operational=1\nWindows PowerShell=1\nMicrosoft-Windows-WMI-Activity/Operational=1\nMicrosoft-Windows-Sysmon/Operational=1\nSecurity=1\n";
            return log;
        }

        private static string WRITE_Default_Search_File()
        {
            string log = "#SearchTerm,EventLogName,EventID\ncmd.exe\npowershell.exe\ncsc.exe\ncleared\niex\nwebclient\n";
            return log;
        }

        public static void ADD_Eventlog_to_CriticalEvents(string Data, string EventName)
        {
            EventLogEntry Eventlog = new EventLogEntry();
            Eventlog.LogName = WHELA_EventLog_Name;
            Eventlog.Severity = "Critical";
            Eventlog.TaskDisplayName = EventName;
            Eventlog.ComputerName = Environment.MachineName;
            Eventlog.UserID = Environment.UserName;
            Eventlog.EventData = Data;
            Eventlog.EventID = 1;
            Eventlog.CreatedTime = DateTime.Now;

            CriticalEvents.Enqueue(Eventlog);
        }

        public static void Log_Storage_Location_Unavailable(string e)
        {
            EventLog_w_PlaceKeeper = EventLog_w_PlaceKeeper_Backup;
            string errormsg= "NETWORK ERROR: " + e + " Access to log storage location may not be available.";
            Errors.WriteErrorsToLog(errormsg);
        }
            
    }
}
