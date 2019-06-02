//Written by Ceramicskate0
//Copyright
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
        internal static Queue<EventLog_Entry> SWELF_Events_Of_Interest_Matching_EventLogs = new Queue<EventLog_Entry>();
        internal static Queue<EventLog_Entry> PS_Plugin_SWELF_Events_Of_Interest_Matching_EventLogs = new Queue<EventLog_Entry>();

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
        internal static List<string> EventLog_w_PlaceKeeper_List = new List<string>();//Tracks Eventlog reading
        internal static Dictionary<string, string> AppConfig_File_Args = new Dictionary<string, string>();//program config arguements from file. consoleconfig.conf

        //cached values to reduce IO, web requests, and other reads
        internal static Dictionary<string, string> REG_Keys = new Dictionary<string, string>();

        private static readonly String[] sWELF_AppConfig_Args = new String[]{
            "log_collector", "log_collector1","log_collector2","log_collector3","log_collector4","log_collector5",
            "central_search_config","central_app_config","central_plugin_search_config","central_whitelist_search_config",
            "output_format","output_ips","output_hashs","check_service_up","transport_protocol","delete_local_log_files_when_done","debug","logging_level"
        };
        internal static String[] SWELF_AppConfig_Args
        {
            get
            {
                return sWELF_AppConfig_Args;
            }
        }

        internal static Dictionary<string, string> Backup_Config_File_Args;//program config arguements
        internal static String[] Backup_Config_File_Args_Array;//program config arguements
        internal static List<string> Search_Terms_Unparsed = new List<string>();//search.txt file line by lone reads
        internal static List<string> WhiteList_Search_Terms_Unparsed = new List<string>();//search.txt file line by lone reads
        internal static List<string> Plugin_Search_Terms_Unparsed = new List<string>();//Powershell plugins filepath list
        internal static Queue<EventLog_Entry> CriticalEvents = new Queue<EventLog_Entry>();//APP events that must be logged
        private static Dictionary<string, long> EventLog_w_PlaceKeeper_Backup = new Dictionary<string, long>();
        internal static List<string> Services_To_Check_Up = new List<string>();//List of services to check are up and running in Sec_Checks

        internal static List<string> IP_List_EVT_Logs = new List<string>();
        internal static List<string> Hashs_From_EVT_Logs = new List<string>();
        internal static List<string> Evtx_Files = new List<string>();
        internal static bool output_csv = false;

        //SWELF Security Check Info
        private static Process sWELF_PROC_Name = Process.GetCurrentProcess();
        internal static Process SWELF_PROC_Name
        {
            get
            {
                return sWELF_PROC_Name;
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
        private readonly static System.Reflection.Assembly assembly = System.Reflection.Assembly.GetExecutingAssembly();
        internal static FileVersionInfo fvi = FileVersionInfo.GetVersionInfo(assembly.Location);
        internal readonly static string SWELF_Version = fvi.FileVersion;

        //MultiThread settings
        internal static int Max_Thread_Count = 1;//Environment.ProcessorCount / 2; TODO: change this to multi thread. storage structs not thread safe
        internal static bool PS_PluginDone = false;
        internal static int Running_Thread_Count = 0;
        internal static int Total_Threads_Run = 0;
        internal readonly static int Thread_Sleep_Time = 5000;

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
        internal static char[] SplitChar_ConfigVariableEquals
        {
            get
            {
                return splitChar_ConfigVariableEquals;
            }
        }
        private readonly static char[] splitChar_UNCPath = new char[] { '\\' };
        internal static char[] SplitChar_UNCPath
        {
            get
            {
                return splitChar_UNCPath;
            }
        }
        private readonly static String[] splitChar_Search_Command_Parser_Multi_Search = new String[] { Search_Commands[8]+":", "`"};
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
        internal static bool Network_Connectivity = true;

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

        //cahced
        internal static Dictionary<string, string> Central_Config_Hashs = new Dictionary<string, string>();

        //-----------------------------End Settings Config------------------------------------






        internal static void InitializeAppSettings()
        {
            GET_ErrorLog_Ready();
            SET_WindowsEventLog_Location();
            Reg_Operation.READ_ALL_SWELF_Reg_Keys();

            File_Operation.VERIFY_AppConfig_Default_Files_Ready();
            File_Operation.VERIFY_Search_Default_Files_Ready();

            Thread Appconfig_Thread = new Thread(() => RUN_Thread_AppConfig());
            Appconfig_Thread.Start();
            while (ThreadsDone_Setup != 1) { Thread.Sleep(1000);}

            Thread Search_Thread = new Thread(() => RUN_Thread_SearchFile());
            Search_Thread.Start();
            while (ThreadsDone_Setup != 2) { Thread.Sleep(1000); }

            Thread EventLogIDPLacekeepers_Thread = new Thread(() => RUN_Thread_EventLogIDPLacekeepers());
            EventLogIDPLacekeepers_Thread.IsBackground = true;
            EventLogIDPLacekeepers_Thread.Start();

            Thread Whitelist_Thread = new Thread(() => RUN_Thread_Whitelist_SearchFile());
            Whitelist_Thread.IsBackground = true;
            Whitelist_Thread.Start();

            Thread Pluging_Thread = new Thread(() => RUN_Thread_Plugins());
            Pluging_Thread.IsBackground = true;
            Pluging_Thread.Start();

            CHECK_SWELF_Version();
            
            while (ThreadsDone_Setup != 5) { Thread.Sleep(5000); }
            Central_Config_Hashs.Clear();
            GC.Collect();
        }

        private static void RUN_Thread_AppConfig()
        {
            if (REG_Keys.ContainsKey(SWELF_AppConfig_Args[7]) == false)//no central app config
            {
                READ_App_Config_File();
            }
            else//use central app config
            {
                Backup_Config_File_Args = AppConfig_File_Args;
                READ_CENTRAL_APP_Config_Folder();
                AppConfig_File_Args.Clear();
                READ_App_Config_File();
            }
            Log_Forwarders_HostNames = GET_LogCollector_Locations();//GatherLog Collector Locations
            ++ThreadsDone_Setup;
            if (AppConfig_File_Args.ContainsKey(SWELF_AppConfig_Args[16]))
            {
                Logging_Level_To_Report = "verbose";
            }
        }

        private static void RUN_Thread_SearchFile()
        {
            if (REG_Keys.ContainsKey(SWELF_AppConfig_Args[6]) == false)
            {
                READ_Search_Terms_File();
            }
            else
            {
                try
                {
                    READ_CENTRAL_SEARCH_Config_File(AppConfig_File_Args[SWELF_AppConfig_Args[6]]);
                    Array.Clear(Backup_Config_File_Args_Array, 0, Backup_Config_File_Args_Array.Length);
                    READ_Search_Terms_File(true);
                }
                catch (Exception e)
                {
                    if (e.Message.Contains("The given key was not present in the dictionary"))
                    {
                        if (string.IsNullOrEmpty(Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_search_config))==false && File_Operation.CHECK_File_Encrypted(GET_SearchTermsFile_Path)==true && File_Operation.READ_Config_File_For_Value(SWELF_AppConfig_Args[6], GET_SearchTermsFile_Path) ==false)
                        {
                            Reg_Operation.DELETE_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_search_config);
                            REG_Keys.Remove(SWELF_AppConfig_Args[6]);
                            if (REG_Keys.ContainsKey(SWELF_AppConfig_Args[6]) == false)
                            {
                                READ_Search_Terms_File();
                            }
                            else
                            {
                                READ_CENTRAL_SEARCH_Config_File(AppConfig_File_Args[SWELF_AppConfig_Args[6]]);
                                Array.Clear(Backup_Config_File_Args_Array, 0, Backup_Config_File_Args_Array.Length);
                                READ_Search_Terms_File(true);
                            }
                        }
                        else
                        {
                            File_Operation.APPEND_Data_To_File(GET_SearchTermsFile_Path, SWELF_AppConfig_Args[6]+"="+ Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_search_config));
                        }
                    }
                }
            }
            ++ThreadsDone_Setup;
        }

        private static void RUN_Thread_Whitelist_SearchFile()
        {
            if (REG_Keys.ContainsKey(SWELF_AppConfig_Args[9]) == false)
            {
                READ_WhiteList_Search_Terms_File();
            }
            else
            {
                try
                {
                    READ_CENTRAL_WHITELIST_SEARCH_Config_File(AppConfig_File_Args[SWELF_AppConfig_Args[9]]);
                    Array.Clear(Backup_Config_File_Args_Array, 0, Backup_Config_File_Args_Array.Length);
                    READ_WhiteList_Search_Terms_File();
                }
                catch (Exception e)
                {
                    if (e.Message.Contains("The given key was not present in the dictionary"))
                    {
                        if (string.IsNullOrEmpty(Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_whitelist_search_config)) == false && File_Operation.CHECK_File_Encrypted(GET_WhiteList_SearchTermsFile_Path) == true && File_Operation.READ_Config_File_For_Value(SWELF_AppConfig_Args[9], GET_WhiteList_SearchTermsFile_Path) == false)
                        {
                            Reg_Operation.DELETE_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_whitelist_search_config);
                            REG_Keys.Remove(SWELF_AppConfig_Args[9]);
                            READ_WhiteList_Search_Terms_File();
                        }
                        else
                        {
                            File_Operation.APPEND_Data_To_File(GET_WhiteList_SearchTermsFile_Path, SWELF_AppConfig_Args[9] + "=" + Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_whitelist_search_config));
                            READ_CENTRAL_WHITELIST_SEARCH_Config_File(AppConfig_File_Args[SWELF_AppConfig_Args[9]]);
                            Array.Clear(Backup_Config_File_Args_Array, 0, Backup_Config_File_Args_Array.Length);
                            READ_WhiteList_Search_Terms_File();
                        }
                    }
                }
            }
            ++ThreadsDone_Setup;
        }

        private static void RUN_Thread_Plugins()
        {
            File_Operation.GET_Plugin_Scripts_Ready();
            if (REG_Keys.ContainsKey(SWELF_AppConfig_Args[8]) == false)
            {
                READ_Powershell_SearchTerms();
            }
            else
            {
                READ_CENTRAL_PLUGINS_Folders();
                Array.Clear(Backup_Config_File_Args_Array, 0, Backup_Config_File_Args_Array.Length);
                READ_Powershell_SearchTerms();
            }
            ++ThreadsDone_Setup;
        }

        private static void RUN_Thread_EventLogIDPLacekeepers()
        {
            READ_EventLogID_Placeholders();
            CHECK_Eventlog_Placekeepers_for_Missing_vs_Reg();
            CHECK_if_all_Search_Terms_have_Indexed_LogsSources();
            Reg_Operation.READ_ALL_SWELF_Reg_Keys();
            ++ThreadsDone_Setup;
        }

        private static void READ_CENTRAL_APP_Config_Folder()
        {
            try
            {
                //if reg key Central app config location is == to config file
                if (File_Operation.CHECK_File_Encrypted(GET_AppConfigFile_Path) == true)
                {
                    //Check if file encrypted AND is creation date == to Reg key
                    if (File_Operation.GET_CreationTime(GET_AppConfigFile_Path) == Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_CreationDate))
                    {
                        READ_and_Parse_Console_App_Config_Contents();
                        if (AppConfig_File_Args[SWELF_AppConfig_Args[7]] != Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_app_config))
                        {
                            Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_app_config, AppConfig_File_Args[SWELF_AppConfig_Args[7]]);
                        }
                        AppConfig_File_Args[SWELF_AppConfig_Args[7]] = Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_app_config);
                    }
                    else//if file creation date is not == to REG
                    {
                        Sec_Checks.LOG_SEC_CHECK_Fail("READ_CENTRAL_APP_Config_Folder() SWELF " + SWELF_AppConfig_Args[7] + " updated in local host Reg entry, possible tampering with local host config. SWELF will attempt to get Config from what is stored in Reg as dest of central config.");
                    }
                }
                else if (File_Operation.CHECK_File_Encrypted(GET_AppConfigFile_Path) == false && Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.central_app_config) == true)
                {
                    //Check if file encrypted AND is creation date == to Reg key
                    if (File_Operation.GET_CreationTime(GET_AppConfigFile_Path) == Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_CreationDate))
                    {
                        READ_and_Parse_Console_App_Config_Contents();
                        if (AppConfig_File_Args[SWELF_AppConfig_Args[7]] != Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_app_config))
                        {
                            Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_app_config, AppConfig_File_Args[SWELF_AppConfig_Args[7]]);
                        }
                        AppConfig_File_Args[SWELF_AppConfig_Args[7]] = Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_app_config);
                    }
                    else//if file creation date is not == to REG
                    {
                        Sec_Checks.LOG_SEC_CHECK_Fail("READ_CENTRAL_APP_Config_Folder() SWELF " + SWELF_AppConfig_Args[7] + " updated in local host Reg entry, possible tampering with local host config. SWELF will attempt to get Config from what is stored in Reg as dest of central config.");
                    }
                }
                else if (File_Operation.CHECK_File_Encrypted(GET_AppConfigFile_Path) == false && Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.central_app_config) == false)
                {
                    READ_and_Parse_Console_App_Config_Contents();
                }
                else
                {
                    AppConfig_File_Args[SWELF_AppConfig_Args[7]] = Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_app_config);
                }

                Web_Operation.GET_All_Files_HTTP(Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_app_config));//get files from web server

                for (int x = 0; x < Web_Operation.Config_Files_on_the_Web_Server.Count; ++x)
                {
                    List<string> WebFiles = Web_Operation.Config_Files_on_the_Web_Server.ElementAt(x).Split('/').ToList();//Seperate all the files out

                    //Appcoinfig
                    if (WebFiles.ElementAt(WebFiles.Count - 1).Equals(AppConfigFile_FileName) && !Web_Operation.VERIFY_Central_File_Config_Hash(Web_Operation.Config_Files_on_the_Web_Server.ElementAt(x), GET_AppConfigFile_Path))//check hash of file on web server to local files
                    {
                        Web_Operation.UPDATE_Local_Config_With_Central_Config(Web_Operation.Config_Files_on_the_Web_Server.ElementAt(x), GET_AppConfigFile_Path, AppConfigFile_FileName);
                        Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_Contents, File_Operation.READ_AllText(GET_AppConfigFile_Path));
                        Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_CreationDate, File.GetCreationTime(GET_AppConfigFile_Path).ToString());
                    }//FilesToMonitor
                    else if (WebFiles.ElementAt(WebFiles.Count - 1).Equals(FilesToMonitor_FileName) && !Web_Operation.VERIFY_Central_File_Config_Hash(Web_Operation.Config_Files_on_the_Web_Server.ElementAt(x), GET_FilesToMonitor_Path))//check hash of file on web server to local files
                    {
                        Web_Operation.UPDATE_Local_Config_With_Central_Config(Web_Operation.Config_Files_on_the_Web_Server.ElementAt(x), GET_FilesToMonitor_Path, FilesToMonitor_FileName);
                    }//DirectoriesToMonitor
                    else if (WebFiles.ElementAt(WebFiles.Count - 1).Equals(DirectoriesToMonitor_FileName) && !Web_Operation.VERIFY_Central_File_Config_Hash(Web_Operation.Config_Files_on_the_Web_Server.ElementAt(x), GET_DirectoriesToMonitor_Path))//check hash of file on web server to local files
                    {
                        Web_Operation.UPDATE_Local_Config_With_Central_Config(Web_Operation.Config_Files_on_the_Web_Server.ElementAt(x), GET_DirectoriesToMonitor_Path, DirectoriesToMonitor_FileName);
                    }//EventLogID_PlaceHolder
                    else if (WebFiles.ElementAt(WebFiles.Count - 1).Equals(EventLogID_PlaceHolde_FileName) && !Web_Operation.VERIFY_Central_File_Config_Hash(Web_Operation.Config_Files_on_the_Web_Server.ElementAt(x), GET_EventLogID_PlaceHolder_Path))//check hash of file on web server to local files
                    {
                        Web_Operation.UPDATE_Local_Config_With_Central_Config(Web_Operation.Config_Files_on_the_Web_Server.ElementAt(x), GET_EventLogID_PlaceHolder_Path, EventLogID_PlaceHolde_FileName);
                        READ_EventLogID_Placeholders(true);
                    }

                }
                Web_Operation.Config_Files_on_the_Web_Server.Clear();
            }
            catch (Exception e)
            {
                AppConfig_File_Args = Backup_Config_File_Args;
                if (e.Message.Contains("The operation has timed out") || e.Message.Contains("The remote name could not be resolved: "))
                {
                    Network_Connectivity = false;
                    AppConfig_File_Args = new Dictionary<string, string>();
                    READ_App_Config_File();
                }
                else
                {
                    READ_App_Config_File();
                    Error_Operation.Log_Error("READ_CENTRAL_APP_Config_File() ", e.Message.ToString(), Error_Operation.LogSeverity.Warning);
                    Error_Operation.SEND_Errors_To_Central_Location();
                }
                //if error here for bad key in dict no worries the  READ_App_Config_File() will pull it down b4 read
            }
        }

        private static void READ_CENTRAL_PLUGINS_Folders()
        {
            try
            {
                if (Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.central_plugin_search_config) == false || string.IsNullOrEmpty(Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_plugin_search_config)) == true)
                {
                   Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_plugin_search_config, AppConfig_File_Args[SWELF_AppConfig_Args[8]]);
                }

                Web_Operation.GET_All_Files_HTTP(AppConfig_File_Args[SWELF_AppConfig_Args[8]]);//get files from web server - Plugin_search/*

                for (int x = 0; x < Web_Operation.Config_Files_on_the_Web_Server.Count; ++x)
                {
                    List<string> WebFiles = Web_Operation.Config_Files_on_the_Web_Server.ElementAt(x).Split('/').ToList();//Seperate all the files out

                    //Plugin_search/searchs.txt
                    if (WebFiles.ElementAt(WebFiles.Count - 1).Equals(SearchTermsFileName_FileName) && !Web_Operation.VERIFY_Central_File_Config_Hash(Web_Operation.Config_Files_on_the_Web_Server.ElementAt(x), GET_SearchTermsFile_PLUGIN_Path))//check hash of file on web server to local files
                    {
                        Web_Operation.UPDATE_Local_Config_With_Central_Config(Web_Operation.Config_Files_on_the_Web_Server.ElementAt(x), GET_SearchTermsFile_PLUGIN_Path, SearchTermsFileName_FileName);
                    }
                }

                Web_Operation.Config_Files_on_the_Web_Server.Clear();
            }
            catch (Exception e)
            {
                try
                {
                    if (File_Operation.CHECK_File_Encrypted(GET_SearchTermsFile_PLUGIN_Path) == false)
                    {
                        Error_Operation.Log_Error("READ_CENTRAL_PLUGINS_Folders() ", e.Message.ToString(), Error_Operation.LogSeverity.Informataion);
                        Error_Operation.SEND_Errors_To_Central_Location();
                    }
                }
                catch (Exception ex)
                {
                    //no central config arg exists so no need to do this
                }
            }
        }

        internal static void READ_CENTRAL_SEARCH_Config_File(string Central_Location = "")
        {
            string Central_Loc;
            string SearchTermRegContents = File_Operation.READ_AllText(GET_SearchTermsFile_Path);
            bool Reg_and_Search_File_Match = Reg_Operation.Compare_Values(Reg_Operation.REG_KEY.SearchTerms_File_Contents, SearchTermRegContents);

            //Below is to safely change and detect change to search central config
            if (Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.central_search_config) == false || string.IsNullOrEmpty(Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_search_config)) == true)
            {
                Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_search_config, AppConfig_File_Args[SWELF_AppConfig_Args[6]]);
                Central_Location = Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_search_config);
            }
            else if (File_Operation.CHECK_File_Encrypted(GET_SearchTermsFile_Path) && Reg_and_Search_File_Match==true)
            {//normal desired case
                AppConfig_File_Args[SWELF_AppConfig_Args[6]] = Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_search_config);
                Central_Location = AppConfig_File_Args[SWELF_AppConfig_Args[6]];
            }
            else if (File_Operation.CHECK_File_Encrypted(GET_SearchTermsFile_Path) && Reg_and_Search_File_Match == false)
            {
                AppConfig_File_Args[SWELF_AppConfig_Args[6]] = Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_search_config);
                Central_Location = AppConfig_File_Args[SWELF_AppConfig_Args[6]];
            }
            else if (File_Operation.CHECK_File_Encrypted(GET_SearchTermsFile_Path)==false && Reg_and_Search_File_Match == false)
            {
                Error_Operation.Log_Error("READ_CENTRAL_SEARCH_Config_File()", "Local search file found not secure. Back search config did not match central. Attempting to download from last good source.", Error_Operation.LogSeverity.Warning);
                AppConfig_File_Args[SWELF_AppConfig_Args[6]] = Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_search_config);
                Central_Location = AppConfig_File_Args[SWELF_AppConfig_Args[6]];
            }
            else
            {
                AppConfig_File_Args[SWELF_AppConfig_Args[6]] = Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_search_config);
            }

            if (string.IsNullOrEmpty(Central_Location) == false)
            {
                Central_Loc = Central_Location;
            }
            else
            {
                Central_Loc = AppConfig_File_Args[SWELF_AppConfig_Args[6]];
            }
            try
            {
                Backup_Config_File_Args_Array = SearchTermRegContents.Split('\n').ToArray();

                Web_Operation.GET_All_Files_HTTP(Central_Loc);//get files from web server. and checkif they are there

                for (int x = 0; x < Web_Operation.Config_Files_on_the_Web_Server.Count; ++x)
                {
                    List<string> WebFiles = Web_Operation.Config_Files_on_the_Web_Server.ElementAt(x).Split('/').ToList();//Seperate all the files out
                    //SearchConfig
                    //check hash of file on web server to local files
                    if (WebFiles.ElementAt(WebFiles.Count - 1).Equals(SearchTermsFileName_FileName) && Web_Operation.VERIFY_Central_File_Config_Hash(Web_Operation.Config_Files_on_the_Web_Server.ElementAt(x), GET_SearchTermsFile_Path)==false)
                    {
                        Web_Operation.UPDATE_Local_Config_With_Central_Config(Web_Operation.Config_Files_on_the_Web_Server.ElementAt(x), GET_SearchTermsFile_Path, SearchTermsFileName_FileName);
                    }
                }
                Web_Operation.Config_Files_on_the_Web_Server.Clear();
                Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.SearchTerms_File_Contents, File_Operation.READ_AllText(GET_SearchTermsFile_Path));
            }
            catch (Exception e)
            {
                if (e.Message.Contains("The operation has timed out") || e.Message.Contains("The remote name could not be resolved: "))
                {
                    if (File_Operation.CHECK_File_Encrypted(GET_SearchTermsFile_Path)==false)
                    {
                        if (string.IsNullOrEmpty(Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.SearchTerms_File_Contents)) == false)
                        {
                            File_Operation.WRITE_ALLTXT(GET_SearchTermsFile_Path, Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.SearchTerms_File_Contents));
                            Crypto_Operation.Secure_File(GET_SearchTermsFile_Path);
                        }
                    }
                    else
                    {
                        File_Operation.WRITE_ALLTXT(GET_SearchTermsFile_Path, Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.SearchTerms_File_Contents));
                        Crypto_Operation.Secure_File(GET_SearchTermsFile_Path);
                    }
                }
                else if (File_Operation.CHECK_File_Encrypted(GET_SearchTermsFile_Path) == false)
                {
                    File.WriteAllLines(GET_SearchTermsFile_Path, Backup_Config_File_Args_Array);
                    Crypto_Operation.Secure_File(GET_SearchTermsFile_Path);
                }
                Error_Operation.Log_Error("READ_CENTRAL_SEARCH_Config_File() ", "Attempted to connect to central config error was "+e.Message.ToString(), Error_Operation.LogSeverity.Informataion);
                Error_Operation.SEND_Errors_To_Central_Location();
            }
        }

        private static void READ_CENTRAL_WHITELIST_SEARCH_Config_File(string Central_Location = "")
        {
            string Central_Loc;

            if (Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.central_whitelist_search_config) == false || string.IsNullOrEmpty(Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_whitelist_search_config)) == true)
            {
                Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_whitelist_search_config, AppConfig_File_Args[SWELF_AppConfig_Args[9]]);
                Central_Location = Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_whitelist_search_config);
            }
            else if (File_Operation.CHECK_File_Encrypted(GET_WhiteList_SearchTermsFile_Path) && Web_Operation.VERIFY_Central_File_Config_Hash(Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_whitelist_search_config), GET_WhiteList_SearchTermsFile_Path))
            {//desired state
                AppConfig_File_Args[SWELF_AppConfig_Args[9]] = Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_whitelist_search_config);
            }
            else if (File_Operation.CHECK_File_Encrypted(GET_WhiteList_SearchTermsFile_Path) && Web_Operation.VERIFY_Central_File_Config_Hash(Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_whitelist_search_config), GET_WhiteList_SearchTermsFile_Path) == false)
            {
                Error_Operation.Log_Error("READ_CENTRAL_WHITELIST_SEARCH_Config_File()", "SWELF Central_WhiteList_Search_Arg updated in localhost Reg entry", Error_Operation.LogSeverity.Informataion);
                Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_whitelist_search_config, AppConfig_File_Args[SWELF_AppConfig_Args[9]]);
                AppConfig_File_Args[SWELF_AppConfig_Args[9]] = Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_whitelist_search_config);
            }
            else
            {
                AppConfig_File_Args[SWELF_AppConfig_Args[9]] = Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_whitelist_search_config);
            }

            if (string.IsNullOrEmpty(Central_Location) == false)
            {
                Central_Loc = Central_Location;
            }
            else
            {
                Central_Loc = AppConfig_File_Args[SWELF_AppConfig_Args[9]];
            }
            try
            {
                Backup_Config_File_Args_Array = File_Operation.READ_File_In_StringArray(GET_WhiteList_SearchTermsFile_Path);
                Web_Operation.GET_All_Files_HTTP(Central_Loc);//get files from web server

                for (int x = 0; x < Web_Operation.Config_Files_on_the_Web_Server.Count; ++x)
                {
                    List<string> WebFiles = Web_Operation.Config_Files_on_the_Web_Server.ElementAt(x).Split('/').ToList();//Seperate all the files out

                    if (WebFiles.ElementAt(WebFiles.Count - 1).Equals(Search_WhiteList_FileName) && !Web_Operation.VERIFY_Central_File_Config_Hash(Web_Operation.Config_Files_on_the_Web_Server.ElementAt(x), GET_WhiteList_SearchTermsFile_Path))//check hash of file on web server to local files
                    {
                        Web_Operation.UPDATE_Local_Config_With_Central_Config(Web_Operation.Config_Files_on_the_Web_Server.ElementAt(x), GET_WhiteList_SearchTermsFile_Path, Search_WhiteList_FileName);
                    }
                }
                Web_Operation.Config_Files_on_the_Web_Server.Clear();
            }
            catch (Exception e)
            {
                if (File_Operation.CHECK_File_Encrypted(GET_WhiteList_SearchTermsFile_Path) == false)
                {
                    File.WriteAllLines(GET_WhiteList_SearchTermsFile_Path, Backup_Config_File_Args_Array);
                }
                Error_Operation.Log_Error("READ_CENTRAL_WHITELIST_SEARCH_Config_File() ", e.Message.ToString(), Error_Operation.LogSeverity.Informataion);
                Error_Operation.SEND_Errors_To_Central_Location();
            }
        }

        private static void READ_App_Config_File()
        {
            bool FileEncrypted = File_Operation.CHECK_File_Encrypted(GET_AppConfigFile_Path);

            if (Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.central_app_config) && Network_Connectivity == true)//Check if centrally configured via reg
            {
                if (Web_Operation.VERIFY_Central_File_Config_Hash(Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_app_config), GET_AppConfigFile_Path)==false)//check to see if the web config is diffrent from one on disk
                {
                    Web_Operation.UPDATE_Local_Config_With_Central_Config(Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_app_config), GET_AppConfigFile_Path, AppConfigFile_FileName);
                }
                Crypto_Operation.UnSecure_File(GET_AppConfigFile_Path);
                READ_and_Parse_Console_App_Config_Contents();
                Crypto_Operation.Secure_File(GET_AppConfigFile_Path);
            }
            else if (FileEncrypted && File.GetCreationTime(GET_AppConfigFile_Path).ToString() == Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_CreationDate) && Network_Connectivity == true)//no central config, check if encrypted and same datetime as reg
            {
                try
                {
                    Crypto_Operation.UnSecure_File(GET_AppConfigFile_Path);

                    READ_and_Parse_Console_App_Config_Contents();

                    Crypto_Operation.Secure_File(GET_AppConfigFile_Path);
                }
                catch (Exception e)//ISSUE !!! A APP_CONFIG ARG did not work
                {
                    AppConfig_File_Args = Backup_Config_File_Args;
                    Error_Operation.WRITE_Errors_To_Log("READ_App_Config_File()", e.Message.ToString(), Error_Operation.LogSeverity.Critical);
                    File_Operation.CREATE_NEW_Files_And_Dirs(Config_File_Location, AppConfigFile_FileName, File_Operation.GET_Default_ConsoleAppConfig_File_Contents);
                }
            }
            else if (Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.central_app_config) && Network_Connectivity == false)
            {
                try
                {
                    File_Operation.WRITE_ALLTXT(GET_AppConfigFile_Path, Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_Contents));
                    Crypto_Operation.UnSecure_File(GET_AppConfigFile_Path);
                    READ_and_Parse_Console_App_Config_Contents();
                    Crypto_Operation.Secure_File(GET_AppConfigFile_Path);
                }
                catch (Exception e)//ISSUE !!! A APP_CONFIG ARG did not work
                {
                    AppConfig_File_Args = Backup_Config_File_Args;
                    Error_Operation.WRITE_Errors_To_Log("READ_App_Config_File()", "Network_Connectivity == false"+e.Message.ToString(), Error_Operation.LogSeverity.Critical);
                    File_Operation.CREATE_NEW_Files_And_Dirs(Config_File_Location, AppConfigFile_FileName, File_Operation.GET_Default_ConsoleAppConfig_File_Contents);
                }
            }
            else//no central config, not same file as in reg.
            {
                if (Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.ConsoleAppConfig_Contents) && Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_Contents) != File_Operation.READ_AllText(GET_AppConfigFile_Path))
                {
                    if (FileEncrypted)
                    {
                        Crypto_Operation.UnSecure_File(GET_AppConfigFile_Path);
                        Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_CreationDate, File.GetCreationTime(GET_AppConfigFile_Path).ToString());
                        READ_and_Parse_Console_App_Config_Contents();
                        Crypto_Operation.Secure_File(GET_AppConfigFile_Path);
                    }
                    else//Appconfig was updated. no app config central config setup
                    {
                        READ_and_Parse_Console_App_Config_Contents();
                        Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_CreationDate, File.GetCreationTime(GET_AppConfigFile_Path).ToString());
                        Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_Contents, File_Operation.READ_AllText(GET_AppConfigFile_Path));
                        Crypto_Operation.Secure_File(GET_AppConfigFile_Path);
                        Error_Operation.Log_Error("READ_App_Config_File()", "No central config and not same in file as on disk in config folder as was previousley saved in reg. Appconfig not encrypted. Appears to be appconfig file update on " + ComputerName+". Reg keys updated to reflect. " +
                        " File Info from OS to folllow... ConsoleAppConfig.conf has a Date Created:"+File.GetCreationTime(GET_AppConfigFile_Path ) + " ConsoleAppConfig.conf File Last Modified: " + File.GetLastWriteTime(GET_AppConfigFile_Path )+ " SWELF Last ConsoleAppConfig.conf reg value says it was created via stored info: " + Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_CreationDate), Error_Operation.LogSeverity.Critical, Error_Operation.EventID.SWELF_Warning);
                    }
                }
                else if (FileEncrypted==true)//assume not central conf and no reg valid entry
                {
                    Crypto_Operation.UnSecure_File(GET_AppConfigFile_Path);
                    READ_and_Parse_Console_App_Config_Contents();
                    Crypto_Operation.Secure_File(GET_AppConfigFile_Path);
                }
                else if (FileEncrypted==false)
                {
                    READ_and_Parse_Console_App_Config_Contents();
                    Error_Operation.Log_Error("READ_App_Config_File()", "No central config in registry and the ones in appconfig file are not the same in file as in reg. Appconfig file also not encrypted. Appears to be appconfig file update on " + ComputerName + ". Reg keys updated to reflect. " +
                    " File Info from OS to folllow... ConsoleAppConfig.conf has a Date Created:" + File.GetCreationTime(GET_AppConfigFile_Path) + " ConsoleAppConfig.conf File Last Modified: " + File.GetLastWriteTime(GET_AppConfigFile_Path) + " SWELF Last ConsoleAppConfig.conf reg value says it was created via stored info: " + Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_CreationDate), Error_Operation.LogSeverity.Critical, Error_Operation.EventID.SWELF_Warning);
                }
                else
                {
                    Error_Operation.Log_Error("READ_App_Config_File()", "No consoleappconfig.conf and not same file on disk in config folder as was previousley saved in reg. File not encrypted. Appears to be appconfig file update on " + ComputerName + ".",Error_Operation.LogSeverity.Critical);
                }
            }
        }

        private static void READ_and_Parse_Console_App_Config_Contents()
        {
            List<string> methods_args = new List<string>();

            foreach (string ConfigFileline in File_Operation.READ_File_In_List(GET_AppConfigFile_Path))//AppConfig_File_Args are read in here 1 by 1
            {
                if (!ConfigFileline.Contains(CommentCharConfigs) && ConfigFileline.Contains(SplitChar_ConfigVariableEquals[0]))//split the read in arg
                {
                    methods_args = ConfigFileline.Split(SplitChar_ConfigVariableEquals, StringSplitOptions.RemoveEmptyEntries).ToList();

                    READ_App_Config_For_CentralConfig_Options(methods_args);
                }
            }
            if (AppConfig_File_Args.ContainsKey(Reg_Operation.REG_KEY.central_app_config.ToString()) == false)
            {
                Reg_Operation.DELETE_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_app_config);
            }
            if (AppConfig_File_Args.ContainsKey(Reg_Operation.REG_KEY.central_plugin_search_config.ToString()) == false)
            {
                Reg_Operation.DELETE_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_plugin_search_config);
            }
            if (AppConfig_File_Args.ContainsKey(Reg_Operation.REG_KEY.central_search_config.ToString()) == false)
            {
                Reg_Operation.DELETE_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_search_config);
            }
            if (AppConfig_File_Args.ContainsKey(Reg_Operation.REG_KEY.central_whitelist_search_config.ToString())==false)
            {
                Reg_Operation.DELETE_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_whitelist_search_config);
            }
        }

        private static void READ_App_Config_For_CentralConfig_Options(List<string> methods_args)
        {
            if (methods_args.ElementAt(0).ToLower().Contains(SWELF_AppConfig_Args[7]) == true)//central_app_config
            {
                try
                {
                    AppConfig_File_Args.Add(methods_args.ElementAt(0).ToLower(), methods_args.ElementAt(1));
                    if (Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.central_app_config) == false)
                    {
                        Error_Operation.Log_Error("READ_App_Config_For_CentralConfig_Options()", "The ConsoleAppConfig.conf on " + ComputerName + " has been set to be centrally configured from " + methods_args.ElementAt(1), Error_Operation.LogSeverity.Critical, Error_Operation.EventID.SWELF_Central_Config_Changed);
                    }
                    Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_app_config, methods_args.ElementAt(1));
                }
                catch (Exception e)
                {
                    AppConfig_File_Args.Remove(methods_args.ElementAt(0).ToLower());
                    AppConfig_File_Args.Add(methods_args.ElementAt(0).ToLower(), methods_args.ElementAt(1));
                }
            }//central_app_config
            else if (methods_args.ElementAt(0).ToLower().Contains(SWELF_AppConfig_Args[6]) == true)//central_search_config
            {
                try
                {
                    AppConfig_File_Args.Add(methods_args.ElementAt(0).ToLower(), methods_args.ElementAt(1));
                    Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_search_config, methods_args.ElementAt(1));
                }
                catch (Exception e)
                {
                    AppConfig_File_Args.Remove(methods_args.ElementAt(0).ToLower());
                    AppConfig_File_Args.Add(methods_args.ElementAt(0).ToLower(), methods_args.ElementAt(1));
                }
            }//central_search_config
            else if (methods_args.ElementAt(0).ToLower().Contains(SWELF_AppConfig_Args[8]) == true)//central_plugin_search_config
            {
                try
                {
                    AppConfig_File_Args.Add(methods_args.ElementAt(0).ToLower(), methods_args.ElementAt(1));
                    Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_plugin_search_config, methods_args.ElementAt(1));
                }
                catch (Exception e)
                {
                    AppConfig_File_Args.Remove(methods_args.ElementAt(0).ToLower());
                    AppConfig_File_Args.Add(methods_args.ElementAt(0).ToLower(), methods_args.ElementAt(1));
                }
            }//central_plugin_search_config
            else if (methods_args.ElementAt(0).ToLower().Contains(SWELF_AppConfig_Args[9]) == true)//central_whitelist_search_config
            {
                try
                {
                    AppConfig_File_Args.Add(methods_args.ElementAt(0).ToLower(), methods_args.ElementAt(1));
                    Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.central_whitelist_search_config, methods_args.ElementAt(1));
                }
                catch (Exception e)
                {
                    AppConfig_File_Args.Remove(methods_args.ElementAt(0).ToLower());
                    AppConfig_File_Args.Add(methods_args.ElementAt(0).ToLower(), methods_args.ElementAt(1));
                }
            }//central_whitelist_search_config
            else if (methods_args.ElementAt(0).ToLower().Contains(SWELF_AppConfig_Args[13]) == true)
            {
                if (Services_To_Check_Up.Count <= 25)
                {
                    Services_To_Check_Up.Add(methods_args.ElementAt(1));
                }
                else
                {
                    Error_Operation.WRITE_Errors_To_Log("READ_App_Config_File()", "SWELF config has to many services to check are up. Max is 25.", Error_Operation.LogSeverity.Warning);
                }
            }//check_service_up
            else//all other configs
            {
                try
                {
                    AppConfig_File_Args.Add(methods_args.ElementAt(0).ToLower(), methods_args.ElementAt(1));
                }
                catch (Exception e)
                {
                    if (e.Message.ToString().Contains("An item with the same key has already been added.") == false)
                    {
                        AppConfig_File_Args.Remove(methods_args.ElementAt(0).ToLower());
                        AppConfig_File_Args.Add(methods_args.ElementAt(0).ToLower(), methods_args.ElementAt(1));
                    }
                }
            }
        }

        internal static void READ_Search_Terms_File(bool CentralConfig = false, bool EncryptFile = true)
        {
            string line = "";
            if (CentralConfig == false)//reading local searchs.txt file
            {
                try
                {
                    bool FileEncrypted = File_Operation.CHECK_File_Encrypted(GET_SearchTermsFile_Path);

                    Crypto_Operation.UnSecure_File(GET_SearchTermsFile_Path);
                    StreamReader file = new StreamReader(GET_SearchTermsFile_Path);
                    while ((line = file.ReadLine()) != null)
                    {
                        if (line.StartsWith(CommentCharConfigs.ToString()) == false && String.IsNullOrWhiteSpace(line) == false)
                        {
                            Search_Terms_Unparsed.Add(line.ToLower());
                        }
                    }
                    file.Close();
                    Search_Terms_Unparsed = Search_Terms_Unparsed.Distinct().ToList();

                    if (Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.SearchTerms_File_Contents) == false)
                    {
                        Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.SearchTerms_File_Contents, File.ReadAllText(GET_SearchTermsFile_Path));
                    }
                    else if (Crypto_Operation.Hash(Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.SearchTerms_File_Contents)) != Crypto_Operation.Hash(File.ReadAllText(GET_SearchTermsFile_Path)))
                    {
                        if (FileEncrypted == false)
                        {
                            Error_Operation.Log_Error("READ_Search_Terms_File()", "SWELF found that the Searchs.txt file changed from what was stored in Registry on local machine. FileHash=" + Crypto_Operation.Hash(File.ReadAllText(GET_SearchTermsFile_Path)) + " StoredHash=" + Crypto_Operation.Hash(Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.SearchTerms_File_Contents)), Error_Operation.LogSeverity.Critical);
                        }
                        Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.SearchTerms_File_Contents, File.ReadAllText(GET_SearchTermsFile_Path));
                    }
                    if (EncryptFile)
                    {
                        Crypto_Operation.Secure_File(GET_SearchTermsFile_Path);
                    }
                }
                catch (Exception e)
                {
                    Error_Operation.Log_Error("READ_Search_Terms_File()", "line=" + line + " " + e.Message.ToString(), Error_Operation.LogSeverity.Critical);
                    File_Operation.CREATE_NEW_Files_And_Dirs(Search_File_Location, SearchTermsFileName_FileName, File_Operation.GET_Default_Logs_Search_File_Contents);
                }
            }
            else//using central configuration
            {
                List<string> ConfigLines = Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.SearchTerms_File_Contents).Split('\n').ToList();

                for (int x = 0; x < ConfigLines.Count; ++x)
                {
                    if (ConfigLines.ElementAt(x).StartsWith(CommentCharConfigs.ToString()) == false && String.IsNullOrWhiteSpace(ConfigLines.ElementAt(x)) == false)
                    {
                        Search_Terms_Unparsed.Add(ConfigLines.ElementAt(x).Replace('\r', ' ').ToLower());
                    }
                }
                Search_Terms_Unparsed = Search_Terms_Unparsed.Distinct().ToList();
                ConfigLines.Clear();
            }
        }

        private static void READ_WhiteList_Search_Terms_File()
        {
            string line = "";
            try
            {
                Crypto_Operation.UnSecure_File(GET_WhiteList_SearchTermsFile_Path);
                StreamReader file = new StreamReader(GET_WhiteList_SearchTermsFile_Path);
                while ((line = file.ReadLine()) != null)
                {
                    if (line.StartsWith(CommentCharConfigs.ToString()) == false && String.IsNullOrWhiteSpace(line) == false)
                    {
                        WhiteList_Search_Terms_Unparsed.Add(line.ToLower());
                    }
                }
                file.Close();
                Crypto_Operation.Secure_File(GET_WhiteList_SearchTermsFile_Path);
            }
            catch (Exception e)
            {
                Error_Operation.Log_Error("READ_WhiteList_Search_Terms_File() " , "line=" + line + " " + e.Message.ToString(),Error_Operation.LogSeverity.Critical);
                File_Operation.CREATE_NEW_Files_And_Dirs(Search_File_Location, Search_WhiteList_FileName, "#SearchTerm ~ EventLogName ~ EventID");
            }
        }

        private static void READ_EventLogID_Placeholders(bool Clear_PlaceKeepers_and_Restart_Log_Query = false)
        {
                string EventLog_w_PlaceKeeper_FileLine = "";

                try
                {
                    Reg_Operation.READ_ALL_SWELF_Reg_Keys();
                    Crypto_Operation.UnSecure_File(GET_EventLogID_PlaceHolder_Path);
                    StreamReader EventLog_w_PlaceKeeper_File = new StreamReader(GET_EventLogID_PlaceHolder_Path);

                    while ((EventLog_w_PlaceKeeper_FileLine = EventLog_w_PlaceKeeper_File.ReadLine()) != null)
                    {
                        if (EventLog_w_PlaceKeeper_FileLine.Contains(CommentCharConfigs) == false && string.IsNullOrWhiteSpace(EventLog_w_PlaceKeeper_FileLine) == false)
                        {
                            string[] EventLogInfo = EventLog_w_PlaceKeeper_FileLine.Split(SplitChar_ConfigVariableEquals, StringSplitOptions.RemoveEmptyEntries).ToArray();
                            bool RegValueExists = Reg_Operation.CHECK_SWELF_Reg_Key_Exists(EventLogInfo[0]);
                            long RegValue = 1;
                            try
                            {
                                RegValue = Convert.ToInt64(Reg_Operation.READ_Eventlog_SWELF_Reg_Key(EventLogInfo[0]));
                            }
                            catch (Exception e)
                            {
                                if (e.Message.Contains("Input string was not in a correct format."))
                                {
                                    try
                                    {
                                        RegValue = Convert.ToInt64(Reg_Operation.READ_Eventlog_SWELF_Reg_Key(EventLogInfo[0].ToLower()));
                                    }
                                    catch (Exception ex)
                                    {
                                        RegValue = Convert.ToInt64(EventLogInfo[1]);
                                    }
                                }
                                //This mean reg value did not exist
                                if (RegValueExists)
                                {
                                    Reg_Operation.ADD_or_CHANGE_Non_SWELF_Reg_Key(EventLogInfo[0].ToLower(), "1");
                                    EventLogInfo[1] = "1";
                                }
                                else
                                {
                                    Error_Operation.Log_Error("READ_EventLogID_Placeholders()", "EventLog " + EventLogInfo[0] + " does not exist on the machine " + ComputerName + " unable to track or read event logs for that subscriber.", Error_Operation.LogSeverity.Warning);
                                }
                            }

                            if (Convert.ToInt64(EventLogInfo[1]) != 1 && (RegValueExists == false || RegValue != Convert.ToInt64(EventLogInfo[1])))
                            {
                                Sec_Checks.LOG_SEC_CHECK_Fail("Check if reg vs file for eventlog placekeeper FAILED. This means modification to log has occured for unknown reasons. Reg=" + RegValue + " EventLogFileValue=" + Convert.ToInt64(EventLogInfo[1]));
                            try
                            {
                                if (RegValue <= Convert.ToInt64(EventLogInfo[1]))
                                {
                                    EventLog_w_PlaceKeeper.Add(EventLogInfo[0].ToLower(), RegValue);
                                }
                                else
                                {
                                    EventLog_w_PlaceKeeper.Add(EventLogInfo[0].ToLower(), 1);
                                }
                            }
                            catch(Exception ex)
                            {
                                if (ex.Message.ToString().Contains("An item with the same key has already been added."))
                                {
                                    Error_Operation.Log_Error("READ_EventLogID_Placeholders()", "Duplicate event log in input file.", Error_Operation.LogSeverity.Verbose);
                                }
                            }
                            }
                            else
                            {
                                EventLog_w_PlaceKeeper.Add(EventLogInfo[0].ToLower(), Convert.ToInt64(EventLogInfo[1]));

                                if (RegValueExists == false)
                                {
                                    Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(EventLogInfo[0], Convert.ToInt64(EventLogInfo[1]).ToString());
                                }
                                EventLog_w_PlaceKeeper_List.Add(EventLogInfo[0].ToLower());
                            }
                        }
                    }
                    EventLog_w_PlaceKeeper_File.Close();
                    Crypto_Operation.Secure_File(GET_EventLogID_PlaceHolder_Path);
                }
                catch (Exception e)
                {
                    EventLog_SWELF.WRITE_FailureAudit_Error_To_EventLog("READ_EventLogID_Placeholders() line=" + EventLog_w_PlaceKeeper_FileLine + " " + e.Message.ToString());
                    File_Operation.CREATE_NEW_Files_And_Dirs(Config_File_Location, EventLogID_PlaceHolde_FileName, File_Operation.GET_Default_Eventlog_with_PlaceKeeper_File_Contents);
                }
            EventLog_w_PlaceKeeper_List = EventLog_w_PlaceKeeper_List.Distinct().ToList();
        }

        private static void CHECK_Eventlog_Placekeepers_for_Missing_vs_Reg()
        {
            Reg_Operation.READ_ALL_SWELF_Reg_Keys();
            if (REG_Keys.Count > 0)
            {
                for (int x = 0; x < REG_Keys.Count; ++x)
                {
                    for (int y = 0; y < EventLogs_List_Of_Avaliable.Count; ++y)//what reg key is eventlog
                    {
                        if (REG_Keys.ElementAt(x).Key.ToLower() == EventLogs_List_Of_Avaliable.ElementAt(y).ToLower())
                        {
                            for (int z = 0; z < EventLog_w_PlaceKeeper_List.Count; ++z)//is eventlog/reg key in the list of ones we need to track
                            {
                                if (EventLog_w_PlaceKeeper_List.ElementAt(z).ToLower() == EventLogs_List_Of_Avaliable.ElementAt(y).ToLower())
                                {
                                    break;
                                }
                                else if (z == EventLog_w_PlaceKeeper_List.Count)
                                {
                                    EventLog_w_PlaceKeeper_List.Add(EventLogs_List_Of_Avaliable.ElementAt(y));
                                    EventLog_w_PlaceKeeper_Backup.Add(EventLogs_List_Of_Avaliable.ElementAt(y), Convert.ToInt64(REG_Keys[REG_Keys.ElementAt(x).Key]));
                                    EventLog_w_PlaceKeeper.Add(EventLogs_List_Of_Avaliable.ElementAt(y), Convert.ToInt64(REG_Keys[REG_Keys.ElementAt(x).Key]));
                                }
                            }
                        }
                    }
                }
            }
        }

        private static void CHECK_if_all_Search_Terms_have_Indexed_LogsSources()
        {
            List<string> Searchs = new List<string>();

            try
            {
                foreach (string SearchLogType in Search_Terms_Unparsed)//search terms
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
                                Error_Operation.Log_Error("CHECK_if_all_Search_Terms_have_Indexed_LogsSources()", e.Message.ToString() + Searchs.Count, Error_Operation.LogSeverity.Warning);
                            }
                        }
                }
                List<string> MissingEventLogs = Searchs.Distinct().Except(EventLog_w_PlaceKeeper_List.Distinct()).ToList();
                Searchs.Clear();
                for (int x = 0; x < MissingEventLogs.Count; ++x)
                {
                    try
                    {
                        EventLog_w_PlaceKeeper.Add(MissingEventLogs.ElementAt(x).ToLower(), 1);
                        Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(MissingEventLogs.ElementAt(x).ToLower(), "1");
                        EventLog_w_PlaceKeeper_List.Add(MissingEventLogs.ElementAt(x).ToLower());
                    }
                    catch (Exception e)
                    {
                        //skip already present
                    }
                }
                EventLog_w_PlaceKeeper_List=EventLog_w_PlaceKeeper_List.Distinct().ToList();
                EventLog_w_PlaceKeeper_List.Sort();
                EventLog_w_PlaceKeeper_Backup = EventLog_w_PlaceKeeper;
            }
            catch (Exception e)
            {
                Searchs = Searchs.Distinct().ToList();
                Stop(SWELF_CRIT_ERROR_EXIT_CODE, "CHECK_if_all_Search_Terms_have_Indexed_LogsSources() ", e.Message.ToString() + Searchs.Count);
            }
        }

        internal static bool CHECK_If_EventLog_Exsits(string EventLog_ToFind)
        {
            return EventLogs_List_Of_Avaliable.Any(s => string.Equals(s.ToLower(), EventLog_ToFind.ToLower(), StringComparison.OrdinalIgnoreCase));
        }

        private static void READ_Powershell_SearchTerms()
        {
            string line = "";
            try
            {
                Crypto_Operation.UnSecure_File(GET_SearchTermsFile_PLUGIN_Path);
                StreamReader file = new StreamReader(GET_SearchTermsFile_PLUGIN_Path);
                while ((line = file.ReadLine()) != null)
                {
                    if (!line.Contains(CommentCharConfigs) && String.IsNullOrWhiteSpace(line) == false)
                    {
                        Plugin_Search_Terms_Unparsed.Add(line.ToLower());
                    }
                }
                file.Close();
                Crypto_Operation.Secure_File(GET_SearchTermsFile_PLUGIN_Path);
            }
            catch (Exception e)
            {
                EventLog_SWELF.WRITE_FailureAudit_Error_To_EventLog("READ_Powershell_SearchTerms() line="+line+ " " + e.Message.ToString());
                File_Operation.CREATE_NEW_Files_And_Dirs(Plugin_Search_Location, SearchTermsFileName_FileName, "#File Path to Powershell Script~ SearchTerm~ Powershell Script Arguments");
            }
        }

        internal static void UPDATE_EventLog_w_PlaceKeeper_File()
        {
            if (Logs_Sent_to_ALL_Collectors)
            {
                String Contents = "";
                Crypto_Operation.UnSecure_File(GET_EventLogID_PlaceHolder_Path);
                for (int x = 0; x < EventLog_w_PlaceKeeper.Count; ++x)
                {
                    Contents += EventLog_w_PlaceKeeper.ElementAt(x).Key + SplitChar_ConfigVariableEquals[0] + EventLog_w_PlaceKeeper.ElementAt(x).Value + "\n";
                    Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(EventLog_w_PlaceKeeper.ElementAt(x).Key, EventLog_w_PlaceKeeper.ElementAt(x).Value.ToString());
                }
                File.WriteAllText(GET_EventLogID_PlaceHolder_Path, Contents);
                Crypto_Operation.Secure_File(GET_EventLogID_PlaceHolder_Path);
            }
        }

        private static void GET_ErrorLog_Ready()
        {
            File_Operation.CREATE_NEW_Files_And_Dirs(SWELF_Log_File_Location, ErrorFile_FileName);
        }

        private static List<string> GET_LogCollector_Locations()
        {
            string CurrentConsoleConfCreationDate = File_Operation.GET_CreationTime(GET_AppConfigFile_Path);

            for (int x = 0; x < 6; x++)
            {
                try
                {
                    if (x != 0)
                    {
                        if (AppConfig_File_Args.ContainsKey(SWELF_AppConfig_Args[0] + x) && !String.IsNullOrEmpty(AppConfig_File_Args[SWELF_AppConfig_Args[0]+ x]))
                        {
                            if (Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.ConsoleAppConfig_CreationDate))
                            {
                                if (Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_CreationDate, false) == CurrentConsoleConfCreationDate)// Does current value==reg key
                                {
                                    switch (x)
                                    {
                                        case 1:
                                            if (Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.LogCollecter_1))
                                            {
                                                if (Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.LogCollecter_1, false) == AppConfig_File_Args[SWELF_AppConfig_Args [0]+ x])
                                                {
                                                    AppConfig_File_Args[SWELF_AppConfig_Args[0] + x] = Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.LogCollecter_1, false);//if yes read reg value
                                                    Log_Forwarders_HostNames.Add(AppConfig_File_Args[SWELF_AppConfig_Args[0] + x]);
                                                    Log_Forwarders_Port.Add(Log_Network_Forwarder.Get_Port_from_Socket(AppConfig_File_Args[SWELF_AppConfig_Args[0] + x]));
                                                }
                                                else//the reg hostname != to the config hostname
                                                {
                                                    Sec_Checks.LOG_SEC_CHECK_Fail("SEC_Check Fail the reg hostname != to the config hostname for " +SWELF_AppConfig_Args[0] + x + ". Possible SWELF config integrity issue. SWELF did change the reg value just in case its a config update.");
                                                    AppConfig_File_Args[SWELF_AppConfig_Args[0] + x] = Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.LogCollecter_1, false);//if yes read reg value
                                                    Log_Forwarders_HostNames.Add(AppConfig_File_Args[SWELF_AppConfig_Args[0] + x]);
                                                    Log_Forwarders_Port.Add(Log_Network_Forwarder.Get_Port_from_Socket(AppConfig_File_Args[SWELF_AppConfig_Args[0] + x]));
                                                }
                                            }
                                            else if (AppConfig_File_Args.ContainsKey(SWELF_AppConfig_Args[0] + x))//No reg key but valid config
                                            {
                                                Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.LogCollecter_1, Web_Operation.GET_HostName(AppConfig_File_Args[SWELF_AppConfig_Args[0] + x]));
                                            }
                                            break;
                                        case 2:
                                            if (Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.LogCollecter_2))
                                            {
                                                if (Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.LogCollecter_2, false) == AppConfig_File_Args[SWELF_AppConfig_Args[0] + x])
                                                {
                                                    AppConfig_File_Args[SWELF_AppConfig_Args[0] + x] = Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.LogCollecter_2, false);//if yes read reg value
                                                    Log_Forwarders_HostNames.Add(AppConfig_File_Args[SWELF_AppConfig_Args[0] + x]);
                                                    Log_Forwarders_Port.Add(Log_Network_Forwarder.Get_Port_from_Socket(AppConfig_File_Args[SWELF_AppConfig_Args[0] + x]));
                                                }
                                                else//the reg hostname != to the config hostname
                                                {
                                                    Sec_Checks.LOG_SEC_CHECK_Fail("SEC_Check Fail the reg hostname != to the config hostname for " +SWELF_AppConfig_Args[0] + x + ". Possible SWELF config integrity issue. SWELF did change the reg value just in case its a config update.");
                                                    AppConfig_File_Args[SWELF_AppConfig_Args[0] + x] = Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.LogCollecter_2, false);//if yes read reg value
                                                    Log_Forwarders_HostNames.Add(Web_Operation.GET_HostName(AppConfig_File_Args[SWELF_AppConfig_Args[0] + x]));
                                                    Log_Forwarders_Port.Add(Log_Network_Forwarder.Get_Port_from_Socket(AppConfig_File_Args[SWELF_AppConfig_Args[0] + x]));
                                                }
                                            }
                                            else if (AppConfig_File_Args.ContainsKey(SWELF_AppConfig_Args[0] + x))//No reg key but valid config
                                            {
                                                Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.LogCollecter_2, Web_Operation.GET_HostName(AppConfig_File_Args[SWELF_AppConfig_Args[0] + x]));
                                            }
                                            break;
                                        case 3:
                                            if (Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.LogCollecter_3))
                                            {
                                                if (Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.LogCollecter_3, false) == AppConfig_File_Args[SWELF_AppConfig_Args[0] + x])
                                                {
                                                    AppConfig_File_Args[SWELF_AppConfig_Args[0] + x] = Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.LogCollecter_3, false);//if yes read reg value
                                                    Log_Forwarders_HostNames.Add(AppConfig_File_Args[SWELF_AppConfig_Args[0] + x]);
                                                    Log_Forwarders_Port.Add(Log_Network_Forwarder.Get_Port_from_Socket(AppConfig_File_Args[SWELF_AppConfig_Args[0] + x]));
                                                }
                                                else//the reg hostname != to the config hostname
                                                {
                                                    Sec_Checks.LOG_SEC_CHECK_Fail("SEC_Check Fail the reg hostname != to the config hostname for " + SWELF_AppConfig_Args[0] + x + ". Possible SWELF config integrity issue. SWELF did change the reg value just in case its a config update.");
                                                    AppConfig_File_Args[SWELF_AppConfig_Args[0] + x] = Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.LogCollecter_3, false);//if yes read reg value
                                                    Log_Forwarders_HostNames.Add(Web_Operation.GET_HostName(AppConfig_File_Args[SWELF_AppConfig_Args[0] + x]));
                                                    Log_Forwarders_Port.Add(Log_Network_Forwarder.Get_Port_from_Socket(AppConfig_File_Args[SWELF_AppConfig_Args[0] + x]));
                                                }
                                            }
                                            else if (AppConfig_File_Args.ContainsKey(SWELF_AppConfig_Args[0] + x))//No reg key but valid config
                                            {
                                                Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.LogCollecter_3, Web_Operation.GET_HostName(AppConfig_File_Args[SWELF_AppConfig_Args[0] + x]));
                                            }
                                            break;
                                        case 4:
                                            if (Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.LogCollecter_4))
                                            {
                                                if (Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.LogCollecter_4, false) == Web_Operation.GET_HostName(AppConfig_File_Args[SWELF_AppConfig_Args[0] + x]))
                                                {
                                                    AppConfig_File_Args[SWELF_AppConfig_Args[0] + x] = Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.LogCollecter_4, false);//if yes read reg value
                                                    Log_Forwarders_HostNames.Add(AppConfig_File_Args[SWELF_AppConfig_Args[0] + x]);
                                                    Log_Forwarders_Port.Add(Log_Network_Forwarder.Get_Port_from_Socket(AppConfig_File_Args[SWELF_AppConfig_Args[0] + x]));
                                                }
                                                else//the reg hostname != to the config hostname
                                                {
                                                    Sec_Checks.LOG_SEC_CHECK_Fail("SEC_Check Fail the reg hostname != to the config hostname for " + SWELF_AppConfig_Args[0] + x + ". Possible SWELF config integrity issue. SWELF did change the reg value just in case its a config update.");
                                                    AppConfig_File_Args[SWELF_AppConfig_Args[0] + x] = Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.LogCollecter_4, false);//if yes read reg value
                                                    Log_Forwarders_HostNames.Add(Web_Operation.GET_HostName(AppConfig_File_Args[SWELF_AppConfig_Args[0] + x]));
                                                    Log_Forwarders_Port.Add(Log_Network_Forwarder.Get_Port_from_Socket(AppConfig_File_Args[SWELF_AppConfig_Args[0] + x]));
                                                }
                                            }
                                            else if (AppConfig_File_Args.ContainsKey(SWELF_AppConfig_Args[0] + x))//No reg key but valid config
                                            {
                                                Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.LogCollecter_4, Web_Operation.GET_HostName(AppConfig_File_Args[SWELF_AppConfig_Args[0] + x]));
                                            }
                                            break;
                                        case 5:
                                            if (Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.LogCollecter_5))
                                            {
                                                if (Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.LogCollecter_5, false) == AppConfig_File_Args[SWELF_AppConfig_Args[0] + x])
                                                {
                                                    AppConfig_File_Args[SWELF_AppConfig_Args[0] + x] = Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.LogCollecter_5, false);//if yes read reg value
                                                    Log_Forwarders_HostNames.Add(AppConfig_File_Args[SWELF_AppConfig_Args[0] + x]);
                                                    Log_Forwarders_Port.Add(Log_Network_Forwarder.Get_Port_from_Socket(AppConfig_File_Args[SWELF_AppConfig_Args[0] + x]));
                                                }
                                                else//the reg hostname != to the config hostname
                                                {
                                                    Sec_Checks.LOG_SEC_CHECK_Fail("SEC_Check Fail the reg hostname != to the config hostname for " + SWELF_AppConfig_Args[0] + x + ". Possible SWELF config integrity issue. SWELF did change the reg value just in case its a config update.");
                                                    Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.LogCollecter_5, AppConfig_File_Args[SWELF_AppConfig_Args[0] + x]);
                                                    Log_Forwarders_HostNames.Add(Web_Operation.GET_HostName(AppConfig_File_Args[SWELF_AppConfig_Args[0] + x]));
                                                    Log_Forwarders_Port.Add(Log_Network_Forwarder.Get_Port_from_Socket(AppConfig_File_Args[SWELF_AppConfig_Args[0] + x]));
                                                }
                                            }
                                            else if (AppConfig_File_Args.ContainsKey(SWELF_AppConfig_Args[0] + x))//No reg key but valid config
                                            {
                                                Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.LogCollecter_5, Web_Operation.GET_HostName(AppConfig_File_Args[SWELF_AppConfig_Args[0] + x]));
                                            }
                                            break;
                                    }
                                }
                                else//if no log error and check consoleconfig.conf file creation date if its same as reg creation date(make reg key for consoloeconf.conf creation date) change
                                {
                                    if (Convert.ToDateTime(Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_CreationDate, false)).Date < Convert.ToDateTime(CurrentConsoleConfCreationDate).Date)
                                    {
                                        Sec_Checks.LOG_SEC_CHECK_Fail("SEC_Check Fail ConsoleAppConfig_CreationDate is newer than the reg entry. Possible SWELF config integrity issue. SWELF did change the reg value just in case its a config update.");
                                        Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_CreationDate, CurrentConsoleConfCreationDate);
                                    }
                                    else
                                    {
                                        Sec_Checks.LOG_SEC_CHECK_Fail("SEC_Check Fail " +SWELF_AppConfig_Args[0] + x+" value in consoleconfig not same as in local machine reg value. Possible tampering. Also the value in the reg was newer than the current consoleconfig value.");
                                    }
                                }
                            }
                            else if (File_Operation.CHECK_if_File_Exists(GET_AppConfigFile_Path))//if no and file exists
                            {//create reg key for creation date and all log collector values
                                Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_CreationDate, DateTime.Now.ToString());
                                Error_Operation.Log_Error("GET_LogCollector_Locations()", "Logging no reg key for ConsoleAppConfig_CreationDate on machine for SWELF.", Error_Operation.LogSeverity.Warning);
                            }
                            else//if no and file doesnt exists
                            {
                                File_Operation.VERIFY_AppConfig_Default_Files_Ready();//create file and reg keys lt
                                Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_CreationDate, DateTime.Now.ToString());
                                Error_Operation.Log_Error("GET_LogCollector_Locations()", "Logging no reg key for ConsoleAppConfig_CreationDate on machine for SWELF. Possible 1st run as the ConsoleAppConfig.conf was also missing.", Error_Operation.LogSeverity.Informataion);//log errors
                            }
                        }
                    }
                    else//log_collector
                    {
                        if (Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.ConsoleAppConfig_CreationDate))
                        {
                            if (Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_CreationDate, false) == CurrentConsoleConfCreationDate)// Does current value==reg key
                            {

                                if (Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.LogCollecter, false) == AppConfig_File_Args[SWELF_AppConfig_Args[0]])
                                {
                                    AppConfig_File_Args[SWELF_AppConfig_Args[0]] = Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.LogCollecter, false);//if yes read reg value
                                    Log_Forwarders_HostNames.Add(AppConfig_File_Args[SWELF_AppConfig_Args[0]]);
                                    Log_Forwarders_Port.Add(Log_Network_Forwarder.Get_Port_from_Socket(AppConfig_File_Args[SWELF_AppConfig_Args[0]]));
                                }
                                else if(Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.LogCollecter) == false)
                                {
                                    Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.LogCollecter, AppConfig_File_Args[SWELF_AppConfig_Args[0]]);
                                    AppConfig_File_Args[SWELF_AppConfig_Args[0]] = Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.LogCollecter, false);//if yes read reg value
                                    Log_Forwarders_HostNames.Add(Web_Operation.GET_HostName(AppConfig_File_Args[SWELF_AppConfig_Args[0]]));
                                    Log_Forwarders_Port.Add(Log_Network_Forwarder.Get_Port_from_Socket(AppConfig_File_Args[SWELF_AppConfig_Args[0]]));
                                }
                                else//the reg hostname != to the config hostname
                                {
                                    Sec_Checks.LOG_SEC_CHECK_Fail("SEC_Check Fail the AppConfig_File_Args[\"log_collector\"] != to the config hostname for Reg.REG_KEY.LogCollecter. Possible SWELF config integrity issue. SWELF did change the reg value just in case its a config update.Also could be config update.");
                                    Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.LogCollecter, AppConfig_File_Args[SWELF_AppConfig_Args[0]]);
                                    Log_Forwarders_HostNames.Add(Web_Operation.GET_HostName(AppConfig_File_Args[SWELF_AppConfig_Args[0]]));
                                    Log_Forwarders_Port.Add(Log_Network_Forwarder.Get_Port_from_Socket(AppConfig_File_Args[SWELF_AppConfig_Args[0]]));
                                }
                            }
                            else//if no log error and check consoleconfig.conf file creation date if its same as reg creation date(make reg key for consoloeconf.conf creation date) change
                            {
                                if (Convert.ToDateTime(Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_CreationDate, false)).Date < Convert.ToDateTime(CurrentConsoleConfCreationDate).Date)
                                {
                                    Sec_Checks.LOG_SEC_CHECK_Fail("SEC_Check Fail ConsoleAppConfig_CreationDate is newer than the reg entry. Possible SWELF config integrity issue. SWELF did change the reg value just in case its a config update.");
                                    Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_CreationDate, CurrentConsoleConfCreationDate);
                                }
                                else
                                {
                                    Sec_Checks.LOG_SEC_CHECK_Fail("SEC_Check Fail " + SWELF_AppConfig_Args[0]+" value in consoleconfig not same as in local machine reg value. Possible tampering. Also the value in the reg was newer than the current consoleconfig value.");
                                }
                            }
                        }
                        else if (File_Operation.CHECK_if_File_Exists(GET_AppConfigFile_Path))//if no and file exists
                        {//create reg key for creation date and all log collector values
                            Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_CreationDate, File_Operation.GET_CreationTime(GET_AppConfigFile_Path));
                            Error_Operation.Log_Error("GET_LogCollector_Locations()", "Logging no reg key for ConsoleAppConfig_CreationDate on machine for SWELF.", Error_Operation.LogSeverity.Warning);
                        }
                        else//if no and file doesnt exists
                        {
                            File_Operation.VERIFY_AppConfig_Default_Files_Ready();//create file and reg keys 
                            Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_CreationDate, DateTime.Now.ToString());
                            Error_Operation.Log_Error("GET_LogCollector_Locations()", "Logging no reg key for ConsoleAppConfig_CreationDate on machine for SWELF. Possible 1st run as the ConsoleAppConfig.conf was also missing.", Error_Operation.LogSeverity.Informataion);//log errors
                        }
                    }
                }
                catch (Exception e)
                {
                    Error_Operation.Log_Error("GET_LogCollector_Locations()", "Unable to get a log_collector["+x+"] location setup done.", Error_Operation.LogSeverity.Critical);
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
            Log_Forwarders_Port = Log_Forwarders_Port.Distinct().ToList();
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
                Error_Operation.Log_Error("SET_WindowsEventLog_Loc() ", e.Message.ToString(), Error_Operation.LogSeverity.Critical);
                SWELF_EvtLog_OBJ.Source = SWELF_EventLog_Name;
            }
        }

        internal static void Log_Storage_Location_Unavailable(string e)
        {
            EventLog_w_PlaceKeeper = EventLog_w_PlaceKeeper_Backup;
            Error_Operation.WRITE_Errors_To_Log("Log_Storage_Location_Unavailable(string e)", e + " Access to log storage location may not be available.", Error_Operation.LogSeverity.Critical);
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
|I/O Commands:|
-------------------------------------------------------------

-EVTX_File 
     C:\..\..\evtx.evtx
     Filepath to EVTX file

-Output_CSV 
     C:\..\..\Fileoutput.csv
     Output Matchs as CSV
     If no file path provided it will output to local windows eventlog

-EVTX_Folder 
     C:\..\..\EVTX Files\
     Folder Path to EVTX files

-------------------------------------------------------------
|Searching Commands:|
-------------------------------------------------------------

-Search_Terms 
     C:\..\..\Searchs.txt
     FileMust be the same as Search.txt when app is installed

-Find 
     SEARCHTERM
     Search EVTX file for the single SEARCHTERM

-------------------------------------------------------------
|Other Commands:|
-------------------------------------------------------------

-Dissolve
     Try to Disolve app when its complete

-Help
     Display this menu

-------------------------------------------------------------

Example:
SWELF.exe -EVTX_File C:\Filepath\SuspiciousWindowsEvntLog.evtx -OutputCSV Findings.csv -Search_Terms C:\Filepath\Searchs.txt

SWELF.exe -EVTX_File C:\Filepath\SuspiciousWindowsEvntLog.evtx -OutputCSV C:\FilePath\FleName.csv -Find SEARCHTERMTOFIND 

SWELF.exe -EVTX_Folder C:\Filepath\ -OutputCSV Findings.csv -Find detected -Dissolve

Manual Located At:https://github.com/ceramicskate0/SWELF/wiki/CommandLine-Inputs-Args-for-local-usage
""", "Simmple Windows EventLog Forwarder (SWELF)",MessageBoxButtons.OK,MessageBoxIcon.Question,MessageBoxDefaultButton.Button1,MessageBoxOptions.DefaultDesktopOnly);
        }

        internal static void Dissolve()
        {
            EventLog_SWELF.WRITE_FailureAudit_Error_To_EventLog("SWELF WAS TOLD TO SELF DELETE. After it ran.");
            Process.Start("cmd.exe", "/C choice /C Y /N /D Y /T 3 & Del /Q " + SWELF_CWD + "\\"+ SWELF_PROC_Name);
            Environment.Exit(0);
        }

        internal static void Stop(int error_code,string ErrorMethod,string Message)
        {
            EventLog_SWELF.WRITE_FailureAudit_Error_To_EventLog("ALERT: SWELF MAIN UNSALVAGEABLE ERROR: "+ ErrorMethod + "   " + Message,Error_Operation.EventID.SWELF_MAIN_APP_ERROR);
            Error_Operation.WRITE_Stored_Errors();
            Error_Operation.SEND_Errors_To_Central_Location();
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

            Error_Operation.WRITE_Errors_To_Log("WRITE_Default_Configs()", "SWELF created new default config files for all settings", Error_Operation.LogSeverity.FailureAudit);
        }
    }
}
