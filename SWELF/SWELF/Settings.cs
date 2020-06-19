//Written by Ceramicskate0
//Copyright 2020
using System;
using System.Collections.Generic;
using System.Linq;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading;
using System.Collections.Concurrent;
using System.Windows.Forms;

namespace SWELF
{
    internal static class Settings
    {
        //SWELF MEM Storage central for app
        private static List<string> eventLogs_List_Of_Avaliable = EventLogSession.GlobalSession.GetLogNames().ToList();
        internal static List<string> EventLogs_List_Of_Avaliable
        {
            get
            {
                return eventLogs_List_Of_Avaliable;
            }
        }
        internal static Dictionary<string, long> EventLog_w_PlaceKeeper = new Dictionary<string, long>();
        internal static List<string> EventLog_w_PlaceKeeper_List = new List<string>();//Tracks Eventlog readingf
        private static Dictionary<string, long> EventLog_w_PlaceKeeper_Backup = new Dictionary<string, long>();

        //cached values to reduce IO, web requests, and other reads
        internal static Dictionary<string, string> REG_Keys = new Dictionary<string, string>();
        private static readonly String[] sWELF_AppConfig_Args = new String[]{
            "log_collector", "log_collector1","log_collector2","log_collector3","log_collector4","log_collector5",
            "central_search_config","central_app_config","central_plugin_search_config","central_whitelist_search_config",
            "output_format","output_ips","output_hashs","check_service_up","transport_protocol","delete_local_log_files_when_done","debug","logging_level",
            "parse_sysmon_logs"
        };
        internal static String[] SWELF_AppConfig_Args
        {
            get
            {
                return sWELF_AppConfig_Args;
            }
        }
        internal static Dictionary<string, string> AppConfig_File_Args = new Dictionary<string, string>();//program config arguements from file. consoleconfig.con
        internal static Dictionary<string, string> Backup_Config_File_Args;//program config arguements
        internal static String[] Backup_Config_File_Args_Array;//program config arguements

        internal static List<string> Search_Rules_Unparsed = new List<string>();//search.txt file line by lone reads
        internal static List<string> Plugin_Search_Terms_Unparsed = new List<string>();//Powershell plugins filepath list
        internal static List<string> WhiteList_Search_Terms_Unparsed = new List<string>();//search.txt file line by lone reads

        internal static List<string> Services_To_Check_Up = new List<string>();//List of services to check are up and running in Sec_Checks

        internal static List<string> IP_List_EVT_Logs = new List<string>();
        internal static List<string> Hashs_From_EVT_Logs = new List<string>();
        internal static List<string> Evtx_Files = new List<string>();
        internal static bool output_csv = false;

        //SWELF Security Check Info
        internal static Process SWELF_PROC_Name
        {
            get
            {
                return Process.GetCurrentProcess();
            }
        }

        //SWELF data settings
        internal readonly static int SWELF_CRIT_ERROR_EXIT_CODE = 1265;
        internal readonly static char CommentCharConfigs = '#';
        internal readonly static string ComputerName = Environment.MachineName;
        internal readonly static string SWELF_EventLog_Name = SWELF_PROC_Name.ProcessName + "_Events_of_Interest";

        internal readonly static int Log_Forward_Location_Port = 514;
        internal static List<string> Log_Forwarders_HostNames = new List<string>();
        internal static List<int> Log_Forwarders_Port = new List<int>();

        private readonly static System.Reflection.Assembly assembly = System.Reflection.Assembly.GetExecutingAssembly();//not loading bad things im getting version info, see next line
        internal static FileVersionInfo fvi = FileVersionInfo.GetVersionInfo(assembly.Location);
        internal readonly static string SWELF_Version = fvi.FileVersion;

        //MultiThread settings
        internal static bool PS_PluginDone = false;
        internal static int Running_Thread_Count = 0;
        internal static int Total_Threads_Run = 0;
        internal readonly static int Thread_Sleep_Time = 1;

        //Hashs and ips files
        internal readonly static string SWELF_CWD = Directory.GetCurrentDirectory();
        internal readonly static string Hashs_File_Path = SWELF_CWD + "\\" + SWELF_AppConfig_Args[11]+".txt";
        internal readonly static string IPs_File_Path = SWELF_CWD + "\\" + SWELF_AppConfig_Args[12]+".txt";

        //folder info
        internal readonly static string Config_File_Location = SWELF_CWD + "\\Config";
        internal readonly static string Search_File_Location = SWELF_CWD + "\\Log_Searchs";
        internal readonly static string SWELF_Log_File_Location = SWELF_CWD + "\\SWELF_Logs";
        internal readonly static string Plugin_Files_Location = SWELF_CWD + "\\Plugins";
        internal readonly static string Plugin_Scripts_Location = Plugin_Files_Location + "\\Scripts";
        internal readonly static string Plugin_Search_Location = Plugin_Files_Location + "\\Plugin_Searchs";

        //Filename info
        internal readonly static string ErrorFile_FileName = "Error_Log.log";
        internal readonly static string AppConfigFile_FileName = "ConsoleAppConfig.conf";
        internal readonly static string EventLogID_PlaceHolde_FileName = "Eventlog_with_PlaceKeeper.txt";
        internal readonly static string SearchTermsFileName_FileName = "Searchs.txt";
        internal readonly static string FilesToMonitor_FileName = "Files_To_Monitor.conf";
        internal readonly static string DirectoriesToMonitor_FileName = "Directories_To_Monitor.conf";
        internal readonly static string Search_WhiteList_FileName = "Whitelist_Searchs.txt";

        //Search cmd info
        private readonly static String[] search_Commands = new String[]{ "count:", "eventdata_length:", "commandline_length:", "commandline_contains:", "commandline_count:", "regex:", SWELF_AppConfig_Args[17]+":", "not_in_log:","search_multiple:" , "network_connect:" };
        
        internal static String[] Search_Commands
        {
            get
            {
                return search_Commands;
            }
        }

        private readonly static String[] eventLogEntry_splitter = new String[]{ "\n", "\r", " ", "  " };
        internal static String[] EventLogEntry_splitter
        {
            get
            {
                return eventLogEntry_splitter;
            }
        }
        private readonly static char[] splitChar_Regex = new char[]{ '~' };
        internal static char[] SplitChar_Regex
        {
            get
            {
                return splitChar_Regex;
            }
        }
        private readonly static char[] splitChar_SearchCommandSplit = new char[]{ '~' };
        internal static char[] SplitChar_SearchCommandSplit
        {
            get
            {
                return splitChar_SearchCommandSplit;
            }
        }
        private readonly static char[] splitChar_ConfigVariableEquals = new char[] { '=' };
        public static string[] SplitNewLine= new string[] { "\n","\r" };
        internal static char[] SplitChar_ConfigVariableEquals
        {
            get
            {
                return splitChar_ConfigVariableEquals;
            }
        }
        private readonly static char[] splitChar_UNCPath = new char[] { '\\' };
        private readonly static String[] splitChar_Search_Command_Parser_Multi_Search = new String[] { Search_Commands[8], "`","'"};
        internal static String[] SplitChar_Search_Command_Parser_Multi_Search
        {
            get
            {
                return splitChar_Search_Command_Parser_Multi_Search;
            }
        }
        private readonly static char[] splitChar_Search_Command_Parsers = new char[]{ ':', '~' };
        internal static char[] SplitChar_Search_Command_Parsers
        {
            get
            {
                return splitChar_Search_Command_Parsers;
            }
        }
        internal readonly static Regex IP_RegX = new Regex(@"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b");
        internal readonly static Regex Hostname_RegX = new Regex(@"^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$");
        internal readonly static Regex SHA256_RegX = new Regex(@"\b[A-Fa-f0-9]{64}\b");

        //Central config info
        internal static string CMDLine_EVTX_File = "";
        internal static string CMDLine_Output_CSV = SWELF_PROC_Name.ProcessName + "_Events_Of_Interest_Output.csv";
        internal static string CMDLine_Search_Terms = "";
        internal static string CMDLine_Find_SEARCHTERM = "";
        internal static bool CMDLine_Dissolve = false;
        internal static bool EVTX_Override = false;
        internal static string Logging_Level_To_Report = Error_Operation.Severity_Levels[Error_Operation.Logging_Level_To_Report];
        internal static EventLog SWELF_EvtLog_OBJ = new EventLog();
        internal readonly static string SWELF_Date_Time_Format = "MMM dd yyyy HH:mm:ss";
        internal static bool Network_Connectivity = Web_Operation.IsNetworkAvailable();

        //SWELF File Location accessors
        internal static string GET_ErrorLog_Location
        {
            get
            {
                return SWELF_Log_File_Location + "\\" + ErrorFile_FileName;
            }
        }
        internal static string GET_AppConfigFile_Path
        {
            get
            {
                return Config_File_Location + "\\" + AppConfigFile_FileName;
            }
        }
        internal static string GET_EventLogID_PlaceHolder_Path
        {
            get
            {
                return Config_File_Location + "\\" + EventLogID_PlaceHolde_FileName;
            }
        }
        internal static string GET_SearchTermsFile_Path
        {
            get
            {
                return Search_File_Location + "\\" + SearchTermsFileName_FileName;
            }
        }
        internal static string GET_SearchTermsFile_PLUGIN_Path
        {
            get
            {
                return Plugin_Search_Location + "\\" + SearchTermsFileName_FileName;
            }
        }
        internal static string GET_WhiteList_SearchTermsFile_PLUGIN_Path
        {
            get
            {
                return Plugin_Search_Location + "\\" + Search_WhiteList_FileName;
            }
        }
        internal static string GET_WhiteList_SearchTermsFile_Path
        {
            get
            {
                return Search_File_Location + "\\" + Search_WhiteList_FileName;
            }
        }
        internal static string GET_FilesToMonitor_Path
        {
            get
            {
                return Config_File_Location + "\\" + FilesToMonitor_FileName;
            }
        }
        internal static string GET_DirectoriesToMonitor_Path
        {
            get
            {
                return Config_File_Location + "\\" + DirectoriesToMonitor_FileName;
            }
        }

        //SWELF run status. keeps track of if logs got sent to collectors
        internal static bool Logs_Sent_to_ALL_Collectors = true;

        //Settings ThreadInfo 1 per file
        private static int ThreadsDone_Setup = 0;

        //cached
        internal static Dictionary<string, string> Central_Config_Hashs = new Dictionary<string, string>();

        //-----------------------------End Settings Config------------------------------------


      
        internal static void InitializeAppSettings()
        {
            GET_ErrorLog_Ready();
            SET_WindowsEventLog_Location();

            Reg_Operation.READ_ALL_SWELF_Reg_Keys();

            RUN_Setup_AppConfig();

            RUN_Setup_SearchFile();

            Thread EventLogIDPlacekeepers_Thread = new Thread(() => RUN_Thread_EventLogIDPLacekeepers());
            EventLogIDPlacekeepers_Thread.IsBackground = true;
            EventLogIDPlacekeepers_Thread.Start();

            Thread Whitelist_Thread = new Thread(() => RUN_Thread_Whitelist_SearchFile());
            Whitelist_Thread.IsBackground = true;
            Whitelist_Thread.Start();

            Thread Pluging_Thread = new Thread(() => RUN_Thread_Plugins());
            Pluging_Thread.IsBackground = true;
            Pluging_Thread.Start();

            CHECK_SWELF_Version();

            while (ThreadsDone_Setup != 5) { Thread.Sleep(5000); }

            EventLogIDPlacekeepers_Thread.Abort();
            Whitelist_Thread.Abort();
            Pluging_Thread.Abort();

            Central_Config_Hashs.Clear();
            GC.Collect();
        }

        private static void RUN_Setup_AppConfig()
        {
            if (Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.ConsoleAppConfig_Contents))//use reg
            {
                READ_and_Parse_Console_App_Config_Contents(Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_Contents));
            }
            else if (File_Operation.CHECK_if_File_Exists(GET_AppConfigFile_Path))//no reg, look for file
            {
                READ_and_Parse_Console_App_Config_Contents(File_Operation.READ_AllText(GET_AppConfigFile_Path));
                File_Operation.DELETE_File(GET_AppConfigFile_Path);
            }
            else//no file, no reg, Create Default then load it into the reg to use later
            {
                File_Operation.VERIFY_AppConfig_Default_Files_Ready();
                READ_and_Parse_Console_App_Config_Contents(File_Operation.READ_AllText(GET_AppConfigFile_Path));
                Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_Contents, File_Operation.READ_AllText(GET_AppConfigFile_Path));
            }

            //Check for CENTRAL CONFIG's, if yes check for update, update if needed.
            //Appconfig
            if (AppConfig_File_Args.ContainsKey(SWELF_AppConfig_Args[7]))//arg for central app config
            {
                if (Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.ConsoleAppConfig_Contents)==false)
                {
                    Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_Contents, "");
                }
                if (Web_Operation.VERIFY_Central_Reg_Config_Hash(AppConfig_File_Args[SWELF_AppConfig_Args[7]],Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_Contents))==false)
                {
                    if (Web_Operation.Connection_Successful)
                    {
                        Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_Contents, Web_Operation.UPDATE_Reg_Config_With_Central_Config(AppConfig_File_Args[SWELF_AppConfig_Args[7]].ToString()));
                        Error_Operation.Log_Error("RUN_Setup_AppConfig()", "Reg key for Central Config ConsoleAppConfig_Contents source updated from web source.", "", Error_Operation.LogSeverity.Informataion, Error_Operation.EventID.SWELF_Central_Config_Changed);
                    }
                }
            }
            //Searchterms
            if (AppConfig_File_Args.ContainsKey(SWELF_AppConfig_Args[6]))//arg for central search config
            {
                if (Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.SearchTerms_File_Contents) == false)
                {
                    Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.SearchTerms_File_Contents, "");
                }
                if (Web_Operation.VERIFY_Central_Reg_Config_Hash(AppConfig_File_Args[SWELF_AppConfig_Args[6]], Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.SearchTerms_File_Contents))==false)
                {
                    if (Web_Operation.Connection_Successful)
                    {
                        Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.SearchTerms_File_Contents, Web_Operation.UPDATE_Reg_Config_With_Central_Config(AppConfig_File_Args[SWELF_AppConfig_Args[6]].ToString()));
                        Error_Operation.Log_Error("RUN_Setup_AppConfig()", "Reg key for Central Config SearchTerms_File_Contents source updated from web source.", "", Error_Operation.LogSeverity.Informataion, Error_Operation.EventID.SWELF_Central_Config_Changed);

                    }
                }
            }
            //Whitelist
            if (AppConfig_File_Args.ContainsKey(SWELF_AppConfig_Args[9]))//arg for central search config
            {
                if (Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.WhiteList_SearchTerms_File_Contents) == false)
                {
                    Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.WhiteList_SearchTerms_File_Contents, "");
                }
                if (Web_Operation.VERIFY_Central_Reg_Config_Hash(AppConfig_File_Args[SWELF_AppConfig_Args[9]], Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.WhiteList_SearchTerms_File_Contents)) == false)
                {
                    if (Web_Operation.Connection_Successful)
                    {
                        Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.WhiteList_SearchTerms_File_Contents, Web_Operation.UPDATE_Reg_Config_With_Central_Config(AppConfig_File_Args[SWELF_AppConfig_Args[9]].ToString()));
                        Error_Operation.Log_Error("RUN_Setup_AppConfig()", "Reg key for Central Config WhiteList_SearchTerms_File_Contents source updated from web source.", "", Error_Operation.LogSeverity.Informataion, Error_Operation.EventID.SWELF_Central_Config_Changed);

                    }
                }
            }
            //Powershell plugin
            if (AppConfig_File_Args.ContainsKey(SWELF_AppConfig_Args[8]))//arg for central search config
            {
                if (Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.PLUGIN_SearchTerms_File_Contents) == false)
                {
                    Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.PLUGIN_SearchTerms_File_Contents, "");
                }
                if (Web_Operation.VERIFY_Central_Reg_Config_Hash(AppConfig_File_Args[SWELF_AppConfig_Args[8]], Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.PLUGIN_SearchTerms_File_Contents)) == false)
                {
                    if (Web_Operation.Connection_Successful)
                    {
                        Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.PLUGIN_SearchTerms_File_Contents, Web_Operation.UPDATE_Reg_Config_With_Central_Config(AppConfig_File_Args[SWELF_AppConfig_Args[8]].ToString()));
                        Error_Operation.Log_Error("RUN_Setup_AppConfig()", "Reg key for Central Config PLUGIN_SearchTerms_File_Contents source updated from web source.", "", Error_Operation.LogSeverity.Informataion, Error_Operation.EventID.SWELF_Central_Config_Changed);

                    }
                }
            }
            Log_Forwarders_HostNames = GET_LogCollector_Locations();//GatherLog Collector Locations
            ++ThreadsDone_Setup;
            if (AppConfig_File_Args.ContainsKey(SWELF_AppConfig_Args[16]))
            {
                Logging_Level_To_Report = "verbose";
            }
        }

        private static void READ_and_Parse_Console_App_Config_Contents(string Contents)
        {
            if (String.IsNullOrEmpty(Contents) == false || String.IsNullOrWhiteSpace(Contents) == false)
            {
                foreach (string arg in Contents.Split(SplitNewLine, StringSplitOptions.RemoveEmptyEntries))
                {
                    if (arg.ElementAt(0) != CommentCharConfigs && (String.IsNullOrEmpty(arg) == false && String.IsNullOrWhiteSpace(arg) == false))
                    {
                        if ((arg.ElementAt(0).ToString() == SWELF_AppConfig_Args[11] || arg.ElementAt(0).ToString() == SWELF_AppConfig_Args[12]))
                        {
                            AppConfig_File_Args.Add(arg.Split('=').ElementAt(0), "true");
                        }
                        else
                        {
                            AppConfig_File_Args.Add(arg.Split('=').ElementAt(0).ToLower(), Regex.Replace(arg.Split('=').ElementAt(1), @"\n|\r|\t|\r\n|\n\r", String.Empty));
                        }
                    }
                }
            }
            else
            {
                foreach (string arg in File_Operation.GET_Default_ConsoleAppConfig_File_Contents.Split(SplitNewLine,StringSplitOptions.RemoveEmptyEntries))
                {
                    if (arg.ElementAt(0) != CommentCharConfigs && (String.IsNullOrEmpty(arg) == false && String.IsNullOrWhiteSpace(arg) == false))
                    {
                        if ((arg.ElementAt(0).ToString() == SWELF_AppConfig_Args[11] || arg.ElementAt(0).ToString() == SWELF_AppConfig_Args[12]))
                        {
                            AppConfig_File_Args.Add(arg.Split('=').ElementAt(0), "true");
                        }
                        else
                        {
                            AppConfig_File_Args.Add(arg.Split('=').ElementAt(0), Regex.Replace(arg.Split('=').ElementAt(1), @"\n|\r|\t|\r\n|\n\r", String.Empty));
                        }
                    }
                }
            }
            Backup_Config_File_Args = AppConfig_File_Args;
        }

        private static void RUN_Setup_SearchFile()
        {
            if (Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.SearchTerms_File_Contents))//use reg
            {
                READ_Search_Terms_File(Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.SearchTerms_File_Contents));
            }
            else if (File_Operation.CHECK_if_File_Exists(GET_SearchTermsFile_Path))//no reg, look for file
            {
                READ_Search_Terms_File(File_Operation.READ_AllText(GET_SearchTermsFile_Path));
                File_Operation.DELETE_File(GET_SearchTermsFile_Path);
            }
            else//no file, no reg, Create Default then load it into the reg to use later
            {
                File_Operation.VERIFY_Search_Default_Files_Ready();
                READ_Search_Terms_File(File_Operation.READ_AllText(GET_SearchTermsFile_Path));
                Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.SearchTerms_File_Contents, File_Operation.READ_AllText(GET_SearchTermsFile_Path));
            }
            ++ThreadsDone_Setup;
        }

        internal static void READ_Search_Terms_File(string Contents)
        {
            List<string> ConfigLines = Contents.Split(SplitNewLine, StringSplitOptions.RemoveEmptyEntries).ToList();

            for (int x = 0; x < ConfigLines.Count; ++x)
            {
                if (ConfigLines.ElementAt(x).StartsWith(CommentCharConfigs.ToString()) == false && String.IsNullOrWhiteSpace(ConfigLines.ElementAt(x)) == false)
                {
                    Search_Rules_Unparsed.Add(ConfigLines.ElementAt(x).Replace("\r", String.Empty).ToLower());
                }
            }
        }

        private static void RUN_Thread_Whitelist_SearchFile()
        {
            if (Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.WhiteList_SearchTerms_File_Contents))//use reg
            {
                READ_WhiteList_Search_Terms_File(Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.WhiteList_SearchTerms_File_Contents));
            }
            else if (File_Operation.CHECK_if_File_Exists(GET_WhiteList_SearchTermsFile_Path))//no reg, look for file
            {
                READ_WhiteList_Search_Terms_File(File_Operation.READ_AllText(GET_WhiteList_SearchTermsFile_Path));
                File_Operation.DELETE_File(GET_WhiteList_SearchTermsFile_Path);
            }
            else//no file, no reg, Create Default then load it into the reg to use later
            {
                File_Operation.VERIFY_Search_Default_Files_Ready();
                READ_WhiteList_Search_Terms_File(File_Operation.READ_AllText(GET_WhiteList_SearchTermsFile_Path));
                Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.WhiteList_SearchTerms_File_Contents, File_Operation.READ_AllText(GET_WhiteList_SearchTermsFile_Path));
            }
            ++ThreadsDone_Setup;
        }

        private static void RUN_Thread_Plugins()
        {
            if (Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.PLUGIN_SearchTerms_File_Contents))//use reg
            {
                READ_Powershell_SearchTerms(Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.PLUGIN_SearchTerms_File_Contents));
            }
            else if (File_Operation.CHECK_if_File_Exists(Settings.GET_SearchTermsFile_PLUGIN_Path))//no reg, look for file
            {
                READ_Powershell_SearchTerms(File_Operation.READ_AllText(GET_SearchTermsFile_PLUGIN_Path));
                File_Operation.DELETE_File(GET_SearchTermsFile_PLUGIN_Path);
            }
            else//no file, no reg, Create Default then load it into the reg to use later
            {
                File_Operation.VERIFY_Search_Default_Files_Ready();
                File_Operation.GET_Plugin_Scripts_Ready();
                READ_Powershell_SearchTerms(File_Operation.READ_AllText(GET_SearchTermsFile_PLUGIN_Path));
                Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.PLUGIN_SearchTerms_File_Contents, File_Operation.READ_AllText(GET_SearchTermsFile_PLUGIN_Path));
            }
            ++ThreadsDone_Setup;
        }

        private static void RUN_Thread_EventLogIDPLacekeepers()
        {
            Reg_Operation.READ_ALL_SWELF_Reg_Keys();
            CHECK_if_all_Search_Terms_have_Indexed_LogsSources();
            ++ThreadsDone_Setup;
        }

        private static void READ_WhiteList_Search_Terms_File(string Contents)
        {
            try
            {
                List<string> ConfigLines = Contents.Split(SplitNewLine, StringSplitOptions.RemoveEmptyEntries).ToList();

                for (int x = 0; x < ConfigLines.Count; ++x)
                {
                    if (ConfigLines.ElementAt(x).StartsWith(CommentCharConfigs.ToString()) == false && String.IsNullOrWhiteSpace(ConfigLines.ElementAt(x)) == false)
                    {
                        WhiteList_Search_Terms_Unparsed.Add(ConfigLines.ElementAt(x).Replace("\r", String.Empty).ToLower());
                    }
                }
            }
            catch (Exception e)
            {
                Error_Operation.Log_Error("READ_WhiteList_Search_Terms_File() " , e.Message.ToString(), e.StackTrace.ToString(), Error_Operation.LogSeverity.Critical);
                File_Operation.CREATE_NEW_Files_And_Dirs(Search_File_Location, Search_WhiteList_FileName, "#SearchTerm ~ EventLogName ~ EventID");
            }
        }

        private static void CHECK_if_all_Search_Terms_have_Indexed_LogsSources()
        {
            List<string> Searchs = new List<string>();

            try
            {
                foreach (string SearchLogType in Search_Rules_Unparsed)//search terms
                {
                    string[] SearchsArgs = SearchLogType.Split(SplitChar_SearchCommandSplit, StringSplitOptions.RemoveEmptyEntries).ToArray();
                        if (SearchsArgs.Length > 1 && String.IsNullOrEmpty(SearchsArgs[1]) == false && SearchLogType.StartsWith(CommentCharConfigs.ToString()) == false)
                        {
                            try
                            {
                                if (CHECK_If_EventLog_Exsits(SearchsArgs[0]))
                                {
                                    Searchs.Add(SearchsArgs[0]);
                                }
                                else if (SearchsArgs.Length > 1 && (String.IsNullOrEmpty(SearchsArgs[1]) == false && SearchLogType.StartsWith(CommentCharConfigs.ToString()) == false && Settings.CHECK_If_EventLog_Exsits(SearchsArgs[1])))
                                {
                                    Searchs.Add(SearchsArgs[1]);
                                }
                                else if (SearchsArgs.Length > 2 && (String.IsNullOrEmpty(SearchsArgs[2]) == false && SearchLogType.StartsWith(CommentCharConfigs.ToString()) == false && Settings.CHECK_If_EventLog_Exsits(SearchsArgs[2])))
                                {
                                    Searchs.Add(SearchsArgs[2]);
                                }
                            }
                            catch (Exception e)
                            {
                                Searchs = Searchs.Distinct().ToList();
                                Error_Operation.Log_Error("CHECK_if_all_Search_Terms_have_Indexed_LogsSources()", e.Message.ToString() + Searchs.Count, e.StackTrace.ToString(), Error_Operation.LogSeverity.Warning);
                            }
                        }
                }
                EventLog_w_PlaceKeeper_List = Searchs.Distinct().ToList();
                Searchs.Clear();
                for (int x = 0; x < EventLog_w_PlaceKeeper_List.Count; ++x)
                {
                    try
                    {
                        if (REG_Keys.ContainsKey(EventLog_w_PlaceKeeper_List.ElementAt(x).ToLower()) == false)
                        {
                            EventLog_w_PlaceKeeper.Add(EventLog_w_PlaceKeeper_List.ElementAt(x).ToLower(), 1);
                            Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(EventLog_w_PlaceKeeper_List.ElementAt(x).ToLower(), "1");
                            EventLog_w_PlaceKeeper_List.Add(EventLog_w_PlaceKeeper_List.ElementAt(x).ToLower());
                        }
                        else
                        {
                            EventLog_w_PlaceKeeper_Backup.Add(EventLog_w_PlaceKeeper_List.ElementAt(x), Convert.ToInt64(REG_Keys[EventLog_w_PlaceKeeper_List.ElementAt(x).ToLower()]));
                            EventLog_w_PlaceKeeper.Add(EventLog_w_PlaceKeeper_List.ElementAt(x), Convert.ToInt64(REG_Keys[EventLog_w_PlaceKeeper_List.ElementAt(x).ToLower()]));
                        }
                    }
                    catch (Exception e)
                    {
                        //skip already present
                    }
                }
                EventLog_w_PlaceKeeper_List =EventLog_w_PlaceKeeper_List.Distinct().ToList();
                EventLog_w_PlaceKeeper_List.Sort();
                EventLog_w_PlaceKeeper_Backup = EventLog_w_PlaceKeeper;
            }
            catch (Exception e)
            {
                Searchs = Searchs.Distinct().ToList();
                Stop(SWELF_CRIT_ERROR_EXIT_CODE, "CHECK_if_all_Search_Terms_have_Indexed_LogsSources() ", e.Message.ToString() + Searchs.Count,e.StackTrace.ToString(), Error_Operation.LogSeverity.Critical);
            }
        }

        internal static bool CHECK_If_EventLog_Exsits(string EventLog_ToFind)
        {
            try
            {
                return EventLogs_List_Of_Avaliable.Any(s => string.Equals(s.ToLower(), EventLog_ToFind.ToLower(), StringComparison.OrdinalIgnoreCase));
            }
            catch (Exception e)
            {
                return false;
            }
        }

        private static void READ_Powershell_SearchTerms(string Contents)
        {
            try
            {
                List<string> ConfigLines = Contents.Split(SplitNewLine, StringSplitOptions.RemoveEmptyEntries).ToList();

                for (int x = 0; x < ConfigLines.Count; ++x)
                {
                    if (ConfigLines.ElementAt(x).StartsWith(CommentCharConfigs.ToString()) == false && String.IsNullOrWhiteSpace(ConfigLines.ElementAt(x)) == false)
                    {
                        Plugin_Search_Terms_Unparsed.Add(ConfigLines.ElementAt(x).Replace("\r", String.Empty).ToLower());
                    }
                }
            }
            catch (Exception e)
            {  
                EventLog_SWELF.WRITE_FailureAudit_Error_To_EventLog("READ_Powershell_SearchTerms()  " + e.Message.ToString());
                File_Operation.CREATE_NEW_Files_And_Dirs(Plugin_Search_Location, SearchTermsFileName_FileName, "#File Path to Powershell Script~ SearchTerm~ Powershell Script Arguments");
            }
        }

        internal static void UPDATE_EventLog_w_PlaceKeeper_RegKeys()
        {
            if (Logs_Sent_to_ALL_Collectors)
            {
                for (int x = 0; x < EventLog_w_PlaceKeeper.Count; ++x)
                {
                    Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(EventLog_w_PlaceKeeper.ElementAt(x).Key, EventLog_w_PlaceKeeper.ElementAt(x).Value.ToString());
                }
            }
        }

        private static void GET_ErrorLog_Ready()
        {
            File_Operation.CREATE_NEW_Files_And_Dirs(SWELF_Log_File_Location, ErrorFile_FileName);
        }

        private static List<string> GET_LogCollector_Locations()
        {
            string CollectorName = SWELF_AppConfig_Args[0];

            for (int x = 0; x < 6; x++)
            {
                try
                {
                    if (x == 0)
                    {
                        CollectorName = SWELF_AppConfig_Args[0];
                    }
                    else
                    {
                        CollectorName = SWELF_AppConfig_Args[0] + x;
                    }
                    if (AppConfig_File_Args.ContainsKey(CollectorName))
                    {
                        Log_Forwarders_HostNames.Add(Web_Operation.GET_HostName(AppConfig_File_Args[CollectorName]).Replace("\r", String.Empty).ToLower());
                        Log_Forwarders_Port.Add(Log_Network_Forwarder.Get_Port_from_Socket(AppConfig_File_Args[CollectorName]));
                    }
                }
                catch (Exception e)
                {
                    Error_Operation.Log_Error("GET_LogCollector_Locations()", "Unable to get a log_collector["+x+"] location setup done. "+e.Message.ToString(), e.StackTrace.ToString(), Error_Operation.LogSeverity.Critical);
                }
            }
           
            if (Log_Forwarders_HostNames.Count <= 0)
            {
                Log_Forwarders_HostNames.Add("127.0.0.1");
            }
            if (Log_Forwarders_Port.Count <= 0)
            {
                Log_Forwarders_Port.Add(Log_Forward_Location_Port);
            }
            //Log_Forwarders_Port = Log_Forwarders_Port.Distinct().ToList();
            Log_Forwarders_HostNames = Log_Forwarders_HostNames.Distinct().ToList();
            return Log_Forwarders_HostNames;
        }

        private static void SET_WindowsEventLog_Location()
        {
            try
            {
                if (!EventLog.SourceExists(SWELF_EventLog_Name))
                {
                    EventLog.CreateEventSource(SWELF_PROC_Name.ProcessName, SWELF_EventLog_Name);
                    SWELF_EvtLog_OBJ.Source = SWELF_EventLog_Name;

                    if (Reg_Operation.CHECK_Eventlog_SWELF_Reg_Key_Exists(Reg_Operation.EventLog_Base_Key+ "\\"+SWELF_EventLog_Name))
                    {
                        Reg_Operation.SET_Event_Log_MaxSize(SWELF_EventLog_Name);
                    }
                }
                else
                {
                    SWELF_EvtLog_OBJ.Source = SWELF_EventLog_Name;
                }
            }
            catch (Exception e)
            {
                EventLog.CreateEventSource(SWELF_PROC_Name.ProcessName, SWELF_EventLog_Name);
                Error_Operation.Log_Error("SET_WindowsEventLog_Loc() ", e.Message.ToString(), e.StackTrace.ToString(), Error_Operation.LogSeverity.Critical);
                SWELF_EvtLog_OBJ.Source = SWELF_EventLog_Name;
            }
        }

        internal static void Log_Storage_Location_Unavailable(string e)
        {
            EventLog_w_PlaceKeeper = EventLog_w_PlaceKeeper_Backup;
            Error_Operation.Log_Error("Log_Storage_Location_Unavailable(string"+ e + ")",e,"",Error_Operation.LogSeverity.Warning);
        }

        internal static void SHOW_Help_Menu()
        {
            System.Windows.Forms.MessageBox.Show(@"
This is the SWELF Help Menu if you are using commandline operations the the binary will not be able to read a live EVTX file.
The app must be setup properly to do that and doesnt take commandline input when it does it.
Commands do not care about case. 
If your unsure of how this appeared never fear SWELF stopped itself (due to cmdline input error and only showed this help menu :) check you local eventlogs for more details.

-------------------------------------------------------------
                 |Commands Menu:|
-------------------------------------------------------------
|Update Config:|
-------------------------------------------------------------
-c 
    Example: -c C:\...\SWELF\Config\ConsoleAppConfig.conf
    This command will update SWELF App Config and Searchs.txt and WhiteListSearchs.txt. If folders are there. 
    This will overwrite any central configuration stored in registry.
    This will only allow you to update the ConsoleAppConfig.conf file, that file is SWELF expects.
    SWELF will then search its predefined folder structure (show in github wiki) for Searchs and whitelist files.
    The -c Option must point to the ConsoleAppConfig.conf
-------------------------------------------------------------
EVTX COMMANDS:
-------------------------------------------------------------

-EVTX_File 
     Example: C:\..\..\evtx.evtx
     Filepath to EVTX file

-Output_CSV 
     Example: C:\..\..\Fileoutput.csv
     Output Matchs as CSV
     If no file path provided it will output to local windows eventlog

-EVTX_Folder 
     Example: C:\..\..\EVTX Files\
     Folder Path to EVTX files

-------------------------------------------------------------
|Searching Commands:|
-------------------------------------------------------------

-Search_Terms 
     Example: C:\..\..\Searchs.txt
     FileMust be the same as Search.txt when app is installed

-Find 
     Example: SEARCHTERM
     Search EVTX file for the single SEARCHTERM

-------------------------------------------------------------
|Other Commands:|
-------------------------------------------------------------
-Help
     Display this menu

-------------------------------------------------------------

Example:
SWELF.exe -c C:\...\SWELF\Config\ConsoleAppConfig.conf

SWELF.exe -EVTX_File C:\Filepath\SuspiciousWindowsEvntLog.evtx -OutputCSV Findings.csv -Search_Terms C:\Filepath\Searchs.txt

SWELF.exe -EVTX_File C:\Filepath\SuspiciousWindowsEvntLog.evtx -OutputCSV C:\FilePath\FleName.csv -Find SEARCHTERMTOFIND 

SWELF.exe -EVTX_Folder C:\Filepath\ -OutputCSV Findings.csv -Find detected -Dissolve

Manual Located At:https://github.com/ceramicskate0/SWELF/wiki/CommandLine-Inputs-Args-for-local-usage
""", "Simmple Windows EventLog Forwarder (SWELF)",MessageBoxButtons.OK,MessageBoxIcon.Question,MessageBoxDefaultButton.Button1,MessageBoxOptions.DefaultDesktopOnly);
        }

        internal static void Stop(int error_code,string ErrorMethod,string Message,string StackInfo,Error_Operation.LogSeverity Ls)
        {
            EventLog_SWELF.WRITE_FailureAudit_Error_To_EventLog("ALERT: SWELF MAIN UNSALVAGEABLE ERROR: "+ ErrorMethod + "   " + Message +" "+ StackInfo, Error_Operation.EventID.SWELF_MAIN_APP_ERROR);
            Error_Operation.Log_Error("STOP(" + error_code + ErrorMethod + ")", Message, StackInfo, Ls);
            Environment.Exit(error_code);
        }

        private static void CHECK_SWELF_Version()
        {
            if (Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.SWELF_Current_Version) != fvi.FileVersion)
            {
                Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.SWELF_Current_Version, fvi.FileVersion);
            }
            //TODO ADD Updaqte feature here
        }

        internal static void WRITE_Default_Configs_Files_and_Reg()
        {
            File_Operation.Turnicate_File(GET_AppConfigFile_Path);
            File_Operation.Turnicate_File(GET_EventLogID_PlaceHolder_Path);
            File_Operation.Turnicate_File(GET_SearchTermsFile_Path);
            File_Operation.Turnicate_File(GET_WhiteList_SearchTermsFile_Path);
            File_Operation.Turnicate_File(GET_SearchTermsFile_PLUGIN_Path);

            File_Operation.CREATE_NEW_Files_And_Dirs(Config_File_Location, AppConfigFile_FileName, File_Operation.GET_Default_ConsoleAppConfig_File_Contents,true);
            File_Operation.CREATE_NEW_Files_And_Dirs(Config_File_Location, EventLogID_PlaceHolde_FileName, File_Operation.GET_Default_Eventlog_with_PlaceKeeper_File_Contents, true);

            File_Operation.CREATE_NEW_Files_And_Dirs(Search_File_Location, SearchTermsFileName_FileName, File_Operation.GET_Default_Logs_Search_File_Contents, true);
            File_Operation.CREATE_NEW_Files_And_Dirs(Search_File_Location, Search_WhiteList_FileName, "", true);

            File_Operation.CREATE_NEW_Files_And_Dirs(Plugin_Search_Location, SearchTermsFileName_FileName, File_Operation.GET_Default_Powershell_Plugins_File_Contents, true);

            Reg_Operation.WRITE_Default_SWELF_Reg_Keys();

            Error_Operation.Log_Error("WRITE_Default_Configs()", "SWELF created new default config files for all settings","", Error_Operation.LogSeverity.FailureAudit);
        }
    }
}
