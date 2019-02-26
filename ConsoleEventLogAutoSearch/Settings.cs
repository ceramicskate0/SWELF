//Written by Ceramicskate0
//Copyright 2018
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using System.Security.Cryptography;

namespace SWELF
{
    public class Settings
    {
        public static Queue<EventLog_Entry> SWELF_Events_Of_Interest_Matching_EventLogs = new Queue<EventLog_Entry>();
        public static Queue<EventLog_Entry> PS_Plugin_SWELF_Events_Of_Interest_Matching_EventLogs = new Queue<EventLog_Entry>();

        //SWELF MEM Storage central for app
        public static List<string> EventLogs_List_Of_Avaliable = EventLogSession.GlobalSession.GetLogNames().ToList();
        public static Dictionary<string, long> EventLog_w_PlaceKeeper = new Dictionary<string, long>();
        public static List<string> EventLog_w_PlaceKeeper_List = new List<string>();//Tracks Eventlog reading
        public static Dictionary<string, string> AppConfig_File_Args = new Dictionary<string, string>();//program config arguements from file. consoleconfig.conf

        public static Dictionary<string, string> Backup_Config_File_Args;//program config arguements
        public static string[] Backup_Config_File_Args_Array;//program config arguements
        public static List<string> Search_Terms_Unparsed = new List<string>();//search.txt file line by lone reads
        public static List<string> WhiteList_Search_Terms_Unparsed = new List<string>();//search.txt file line by lone reads
        public static List<string> Plugin_Search_Terms_Unparsed = new List<string>();//Powershell plugins filepath list
        public static Queue<EventLog_Entry> CriticalEvents = new Queue<EventLog_Entry>();//APP events that must be logged
        private static Dictionary<string, long> EventLog_w_PlaceKeeper_Backup = new Dictionary<string, long>();
        private static WebClient Wclient = new WebClient();//.net webclient to pull down central config file
        public static List<string> Config_Files_on_the_Web_Server = new List<string>();
        public static List<string> Services_To_Check_Up = new List<string>();//List of services to check are up and running in Sec_Checks

        public static List<string> IP_List_EVT_Logs = new List<string>();
        public static List<string> Hashs_From_EVT_Logs = new List<string>();
        public static List<string> Evtx_Files = new List<string>();
        public static bool output_csv = false;

        //SWELF Security Check Info
        public static Process SWELF_PROC_Name = Process.GetCurrentProcess();
        //public static int ThreadsCount = Process.GetCurrentProcess().Threads.Count;
        //public static int SWELF_Starting_Dlls = Settings.SWELF_PROC_Name.Modules.Count;
        //public static AppDomain SWELF_Start_currentDomain = AppDomain.CurrentDomain;
        //public static Evidence SWELF_Start_asEvidence = SWELF_Start_currentDomain.Evidence;
        //public static Assembly[] SWELF_Start_Assemblys = SWELF_Start_currentDomain.GetAssemblies();

        //SWELF data settings
        public static string CommentCharConfigs = "#";
        public static string ComputerName = Environment.MachineName;
        public static string SWELF_EventLog_Name = SWELF_PROC_Name.ProcessName + "_Events_of_Interest";
        public static int Log_Forward_Location_Port = 514;
        public static List<string> Log_Forwarders_HostNames = new List<string>();
        private static System.Reflection.Assembly assembly = System.Reflection.Assembly.GetExecutingAssembly();
        private static FileVersionInfo fvi = FileVersionInfo.GetVersionInfo(assembly.Location);
        public static string SWELF_Version = fvi.FileVersion;
        public static int SWELF_CRIT_ERROR_EXIT_CODE = 1265;

        //MultiThread settings
        public static int Max_Thread_Count = 1;//Environment.ProcessorCount / 2; TODO: change this to multi thread. storage structs not thread safe
        public static bool PS_PluginDone = false;
        public static int Running_Thread_Count = 0;
        public static int Total_Threads_Run = 0;
        public static int Thread_Sleep_Time = 5000;

        //Hashs and ips files
        public static string Hashs_File = Directory.GetCurrentDirectory() + "\\" + "hashs.txt";
        public static string IPs_File = Directory.GetCurrentDirectory() + "\\" + "ips.txt";

        //folder info
        public static string SWELF_CWD = Directory.GetCurrentDirectory();
        public static string Config_File_Location = Directory.GetCurrentDirectory() + "\\Config";
        public static string Search_File_Location = Directory.GetCurrentDirectory() + "\\Log_Searchs";
        public static string SWELF_Log_File_Location = Directory.GetCurrentDirectory() + "\\SWELF_Logs";
        public static string Plugin_Files_Location = Directory.GetCurrentDirectory() + "\\Plugins";
        public static string Plugin_Scripts_Location = Plugin_Files_Location + "\\Scripts";
        public static string Plugin_Search_Location = Plugin_Files_Location + "\\Plugin_Searchs";

        //Filename info
        public static string ErrorFile = "Error_Log.log";
        public static string AppConfigFile = "ConsoleAppConfig.conf";
        public static string EventLogID_PlaceHolder = "Eventlog_with_PlaceKeeper.txt";
        public static string SearchTermsFileName = "Searchs.txt";
        public static string FilesToMonitor = "Files_To_Monitor.conf";
        public static string DirectoriesToMonitor = "Directories_To_Monitor.conf";
        public static string Search_WhiteList = "WhiteList_Searchs.txt";

        //Search cmd info
        public static string[] Search_Commands = { "count:", "eventdata_length:", "commandline_length:", "commandline_contains:", "commandline_count:", "regex:", "logging_level:", "not_in_log:","search_multiple:" , "network_connect:" };
        public static string[] EventLogEntry_splitter = { "\n", "\r", " ", "  " };
        public static char[] SplitChar_Regex = { '~' };
        public static char[] SplitChar_SearchCommandSplit = { '~' };
        public static char[] SplitChar_ConfigVariableEquals = { '=' };
        public static char[] SplitChar_UNCPath = { '\\' };
        public static string[] SplitChar_Search_Command_Parser_Multi_Search = { "search_multiple:", "`"};
        public static char[] SplitChar_Search_Command_Parsers = { ':', '~' };
        public static Regex IP_RegX = new Regex(@"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b");
        public static Regex Hostname_RegX = new Regex(@"^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$");
        public static Regex SHA256_RegX = new Regex(@"\b[A-Fa-f0-9]{64}\b");

        //Central config info
        public static string CMDLine_EVTX_File = "";
        public static string CMDLine_Output_CSV = SWELF_PROC_Name.ProcessName + "_Events_Of_Interest_Output.csv";
        public static string CMDLine_Search_Terms = "";
        public static string CMDLine_Find_SEARCHTERM = "";
        public static bool CMDLine_Dissolve = false;
        public static bool EVTX_Override = false;
        public static string Logging_Level_To_Report = "information";
        public static EventLog SWELF_EvtLog_OBJ = new EventLog();
        public static string SWELF_Date_Time_Format = "MMM dd yyyy HH:mm:ss";

        //SWELF Central config commands
        private static string SWELF_Central_App_Config_Arg = "central_app_config";
        public static string SWELF_Central_Search_Arg = "central_search_config";
        public static string SWELF_Central_WhiteList_Search_Arg = "central_whitelist_search_config";
        private static string SWELF_Central_Plugin_Search_Arg = "central_plugin_search_config";

        //SWELF File Location accessors
        public static string GET_ErrorLog_Location
        {
            get
            {
                return SWELF_Log_File_Location + "\\" + ErrorFile;
            }
        }
        public static string GET_AppConfigFile
        {
            get
            {
                return Config_File_Location + "\\" + AppConfigFile;
            }
        }
        public static string GET_EventLogID_PlaceHolder
        {
            get
            {
                return Config_File_Location + "\\" + EventLogID_PlaceHolder;
            }
        }
        public static string GET_SearchTermsFile
        {
            get
            {
                return Search_File_Location + "\\" + SearchTermsFileName;
            }
        }
        public static string GET_SearchTermsFile_PLUGIN
        {
            get
            {
                return Plugin_Search_Location + "\\" + SearchTermsFileName;
            }
        }
        public static string GET_WhiteList_SearchTermsFile_PLUGIN
        {
            get
            {
                return Plugin_Search_Location + "\\" + Search_WhiteList;
            }
        }
        public static string GET_WhiteList_SearchTermsFile
        {
            get
            {
                return Search_File_Location + "\\" + Search_WhiteList;
            }
        }
        public static string GET_FilesToMonitor
        {
            get
            {
                return Config_File_Location + "\\" + FilesToMonitor;
            }
        }
        public static string GET_DirectoriesToMonitor
        {
            get
            {
                return Config_File_Location + "\\" + DirectoriesToMonitor;
            }
        }

        //SWELF run status
        public static bool Logs_Sent_to_ALL_Collectors = true;


        public static void InitializeAppSettings()
        {
            GET_ErrorLog_Ready();
            SET_WindowsEventLog_Location();
            READ_App_Config_File();
            READ_EventLogID_Placeholders();
            READ_Search_Terms_File();
            READ_WhiteList_Search_Terms_File();
            READ_Powershell_SearchTerms();

            File_Operation.GET_Plugin_Scripts_Ready();

            if (AppConfig_File_Args.ContainsKey(SWELF_Central_App_Config_Arg))//central config APP
            {
                Backup_Config_File_Args = AppConfig_File_Args;
                READ_CENTRAL_APP_Config_Folder();
                AppConfig_File_Args.Clear();
                READ_App_Config_File();
            }
            if (AppConfig_File_Args.ContainsKey(SWELF_Central_Search_Arg))//central config SEARCH
            {
                READ_CENTRAL_SEARCH_Config_File(AppConfig_File_Args[SWELF_Central_Search_Arg]);
                Array.Clear(Backup_Config_File_Args_Array, 0, Backup_Config_File_Args_Array.Length);
                READ_Search_Terms_File();
            }
            if (AppConfig_File_Args.ContainsKey(SWELF_Central_WhiteList_Search_Arg))//central config WHITELIST SEARCH FILE
            {
                READ_CENTRAL_WHITELIST_SEARCH_Config_File(AppConfig_File_Args[SWELF_Central_WhiteList_Search_Arg]);
                Array.Clear(Backup_Config_File_Args_Array, 0, Backup_Config_File_Args_Array.Length);
                READ_WhiteList_Search_Terms_File();
            }
            if (AppConfig_File_Args.ContainsKey(SWELF_Central_Plugin_Search_Arg))//central config Plugin SEARCH
            {
                READ_CENTRAL_PLUGINS_Folders();
                Array.Clear(Backup_Config_File_Args_Array, 0, Backup_Config_File_Args_Array.Length);
                //TODO Take search file parse and read in all the files on the list
                READ_Powershell_SearchTerms();
            }
            CHECK_if_all_Search_Terms_have_Indexed_LogsSources();

            //READ_REG_Config();

            if (Settings.AppConfig_File_Args.ContainsKey("debug"))
            {
                Logging_Level_To_Report = "verbose";
            }

            //CHECK_SWELF_EventLog_Sources_Ready();
        }


        private static void READ_REG_Config()
        {
            Reg.READ_All_SWELF_Reg_Keys();

            if (Reg.Reg_Keys_and_Values.Count<=0)
            {
                Reg.WRITE_Default_SWELF_Reg_Keys();
            }

            if (File.Exists(GET_AppConfigFile))
            {
                if (Reg.READ_SWELF_Reg_Key(Reg.REG_KEY.logging_level).ToLower() != AppConfig_File_Args["logging_level"].ToLower())
                {
                    Errors.Log_Error("READ_REG_Config()", "Reg.READ_Reg_Key(Reg.REG_KEY.logging_level).ToLower() != AppConfig_File_Args[\"logging_level\"].ToLower()", Errors.LogSeverity.Warning);
                    Reg.CHANGE_SWELF_Reg_Key(Reg.REG_KEY.logging_level, AppConfig_File_Args["logging_level"]);
                }
            }
        }

        private static void READ_CENTRAL_APP_Config_Folder()
        {
            try
            {
                GET_All_Files_HTTP(AppConfig_File_Args[SWELF_Central_App_Config_Arg]);//get files from web server

                for (int x = 0; x < Config_Files_on_the_Web_Server.Count; ++x)
                {
                    List<string> WebFiles = Config_Files_on_the_Web_Server.ElementAt(x).Split('/').ToList();//Seperate all the files out

                    //Appcoinfig
                    if (WebFiles.ElementAt(WebFiles.Count - 1).Equals(AppConfigFile) && !VERIFY_Central_File_Config_Hash(Config_Files_on_the_Web_Server.ElementAt(x), GET_AppConfigFile))//check hash of file on web server to local files
                    {
                        GET_Central_Config_File(Config_Files_on_the_Web_Server.ElementAt(x), GET_AppConfigFile, AppConfigFile);
                    }//FilesToMonitor
                    else if (WebFiles.ElementAt(WebFiles.Count - 1).Equals(FilesToMonitor) && !VERIFY_Central_File_Config_Hash(Config_Files_on_the_Web_Server.ElementAt(x), GET_FilesToMonitor))//check hash of file on web server to local files
                    {
                        GET_Central_Config_File(Config_Files_on_the_Web_Server.ElementAt(x), GET_FilesToMonitor, FilesToMonitor);
                    }//DirectoriesToMonitor
                    else if (WebFiles.ElementAt(WebFiles.Count - 1).Equals(DirectoriesToMonitor) && !VERIFY_Central_File_Config_Hash(Config_Files_on_the_Web_Server.ElementAt(x), GET_DirectoriesToMonitor))//check hash of file on web server to local files
                    {
                        GET_Central_Config_File(Config_Files_on_the_Web_Server.ElementAt(x), GET_DirectoriesToMonitor, DirectoriesToMonitor);
                    }//EventLogID_PlaceHolder
                    else if (WebFiles.ElementAt(WebFiles.Count - 1).Equals(EventLogID_PlaceHolder) && !VERIFY_Central_File_Config_Hash(Config_Files_on_the_Web_Server.ElementAt(x), GET_EventLogID_PlaceHolder))//check hash of file on web server to local files
                    {
                        GET_Central_Config_File(Config_Files_on_the_Web_Server.ElementAt(x), GET_EventLogID_PlaceHolder, EventLogID_PlaceHolder);
                        READ_EventLogID_Placeholders(true);
                    }
                }
                Config_Files_on_the_Web_Server.Clear();
            }
            catch (Exception e)
            {
                AppConfig_File_Args = Backup_Config_File_Args;
                READ_App_Config_File();
                Errors.Log_Error("READ_CENTRAL_APP_Config_File() ", e.Message.ToString(), Errors.LogSeverity.Critical);
                Errors.SEND_Errors_To_Central_Location();
            }
        }

        private static void READ_CENTRAL_PLUGINS_Folders()
        {
            try
            {
                GET_All_Files_HTTP(AppConfig_File_Args[SWELF_Central_Plugin_Search_Arg]);//get files from web server - Plugin_search/*

                for (int x = 0; x < Config_Files_on_the_Web_Server.Count; ++x)
                {
                    List<string> WebFiles = Config_Files_on_the_Web_Server.ElementAt(x).Split('/').ToList();//Seperate all the files out

                    //Plugin_search/searchs.txt
                    if (WebFiles.ElementAt(WebFiles.Count - 1).Equals(SearchTermsFileName) && !VERIFY_Central_File_Config_Hash(Config_Files_on_the_Web_Server.ElementAt(x), GET_SearchTermsFile_PLUGIN))//check hash of file on web server to local files
                    {
                        GET_Central_Config_File(Config_Files_on_the_Web_Server.ElementAt(x), GET_SearchTermsFile_PLUGIN, SearchTermsFileName);
                    }//Plugin_search/Search_WhiteList.txt
                    //else if (WebFiles.ElementAt(WebFiles.Count - 1).Equals(Search_WhiteList) && !VERIFY_Central_File_Config_Hash(Config_Files_on_the_Web_Server.ElementAt(x), GET_WhiteList_SearchTermsFile_PLUGIN))//check hash of file on web server to local files
                    //{
                    //    GET_Central_Config_File(Config_Files_on_the_Web_Server.ElementAt(x), GET_WhiteList_SearchTermsFile_PLUGIN, Search_WhiteList);
                    //}//scripts/* downlaod will not be supported
                }
                Config_Files_on_the_Web_Server.Clear();
            }
            catch (Exception e)
            {
                File.WriteAllLines(GET_SearchTermsFile_PLUGIN, Backup_Config_File_Args_Array);
                Errors.Log_Error("READ_CENTRAL_PLUGINS_Folders() ", e.Message.ToString(), Errors.LogSeverity.Warning);
                Errors.SEND_Errors_To_Central_Location();
            }
        }

        public static void READ_CENTRAL_SEARCH_Config_File(string Central_Location = "")
        {
            string Central_Loc;

            if (string.IsNullOrEmpty(Central_Location) == false)
            {
                Central_Loc = Central_Location;
            }
            else
            {
                Central_Loc = AppConfig_File_Args[SWELF_Central_Search_Arg];
            }
            try
            {
                Backup_Config_File_Args_Array = File.ReadAllLines(GET_SearchTermsFile);

                GET_All_Files_HTTP(Central_Loc);//get files from web server

                for (int x = 0; x < Config_Files_on_the_Web_Server.Count; ++x)
                {
                    List<string> WebFiles = Config_Files_on_the_Web_Server.ElementAt(x).Split('/').ToList();//Seperate all the files out
                    //SearchConfig
                    if (WebFiles.ElementAt(WebFiles.Count - 1).Equals(SearchTermsFileName) && !VERIFY_Central_File_Config_Hash(Config_Files_on_the_Web_Server.ElementAt(x), GET_SearchTermsFile))//check hash of file on web server to local files
                    {
                        GET_Central_Config_File(Config_Files_on_the_Web_Server.ElementAt(x), GET_SearchTermsFile, SearchTermsFileName);
                    }
                }
                Config_Files_on_the_Web_Server.Clear();
            }
            catch (Exception e)
            {
                File.WriteAllLines(GET_SearchTermsFile, Backup_Config_File_Args_Array);
                Errors.Log_Error("READ_CENTRAL_SEARCH_Config_File() ", e.Message.ToString(), Errors.LogSeverity.Warning);
                Errors.SEND_Errors_To_Central_Location();
            }
        }

        public static void READ_CENTRAL_WHITELIST_SEARCH_Config_File(string Central_Location = "")
        {
            string Central_Loc;

            if (string.IsNullOrEmpty(Central_Location) == false)
            {
                Central_Loc = Central_Location;
            }
            else
            {
                Central_Loc = AppConfig_File_Args[SWELF_Central_Search_Arg];
            }
            try
            {
                Backup_Config_File_Args_Array = File.ReadAllLines(GET_WhiteList_SearchTermsFile);
                GET_All_Files_HTTP(Central_Loc);//get files from web server

                for (int x = 0; x < Config_Files_on_the_Web_Server.Count; ++x)
                {
                    List<string> WebFiles = Config_Files_on_the_Web_Server.ElementAt(x).Split('/').ToList();//Seperate all the files out

                    if (WebFiles.ElementAt(WebFiles.Count - 1).Equals(Search_WhiteList) && !VERIFY_Central_File_Config_Hash(Config_Files_on_the_Web_Server.ElementAt(x), GET_WhiteList_SearchTermsFile))//check hash of file on web server to local files
                    {
                        GET_Central_Config_File(Config_Files_on_the_Web_Server.ElementAt(x), GET_WhiteList_SearchTermsFile, Search_WhiteList);
                    }
                }
                Config_Files_on_the_Web_Server.Clear();
            }
            catch (Exception e)
            {
                File.WriteAllLines(GET_WhiteList_SearchTermsFile, Backup_Config_File_Args_Array);
                Errors.Log_Error("READ_CENTRAL_WHITELIST_SEARCH_Config_File() ", e.Message.ToString(), Errors.LogSeverity.Warning);
                Errors.SEND_Errors_To_Central_Location();
            }
        }

        private static void READ_App_Config_File()
        {
            List<string> methods_args = new List<string>();

            File_Operation.GET_AppConfig_Files_Ready();

            try
            {
                File.Decrypt(GET_AppConfigFile);

                foreach (string ConfigFileline in File.ReadAllLines(GET_AppConfigFile))//AppConfig_File_Args are set here
                {
                    if (!ConfigFileline.Contains(CommentCharConfigs) && ConfigFileline.Contains(SplitChar_ConfigVariableEquals[0]))
                    {
                        methods_args = ConfigFileline.Split(SplitChar_ConfigVariableEquals, StringSplitOptions.RemoveEmptyEntries).ToList();
                        if (methods_args.ElementAt(0).ToLower().Contains(SWELF_Central_App_Config_Arg) == true)
                        {
                            try
                            {
                                AppConfig_File_Args.Add(methods_args.ElementAt(0).ToLower(), methods_args.ElementAt(1));
                            }
                            catch (Exception e)
                            {
                                AppConfig_File_Args.Remove(methods_args.ElementAt(0).ToLower());
                                AppConfig_File_Args.Add(methods_args.ElementAt(0).ToLower(), methods_args.ElementAt(1));
                            }
                        }
                        else if (methods_args.ElementAt(0).ToLower().Contains(SWELF_Central_Search_Arg) == true)
                        {
                            try
                            {
                                AppConfig_File_Args.Add(methods_args.ElementAt(0).ToLower(), methods_args.ElementAt(1));
                            }
                            catch (Exception e)
                            {
                                AppConfig_File_Args.Remove(methods_args.ElementAt(0).ToLower());
                                AppConfig_File_Args.Add(methods_args.ElementAt(0).ToLower(), methods_args.ElementAt(1));
                            }
                        }
                        else if (methods_args.ElementAt(0).ToLower().Contains(SWELF_Central_Plugin_Search_Arg) == true)
                        {
                            try
                            {
                                AppConfig_File_Args.Add(methods_args.ElementAt(0).ToLower(), methods_args.ElementAt(1));
                            }
                            catch (Exception e)
                            {
                                AppConfig_File_Args.Remove(methods_args.ElementAt(0).ToLower());
                                AppConfig_File_Args.Add(methods_args.ElementAt(0).ToLower(), methods_args.ElementAt(1));
                            }
                        }
                        else if (methods_args.ElementAt(0).ToLower().Contains(SWELF_Central_WhiteList_Search_Arg) == true)
                        {
                            try
                            {
                                AppConfig_File_Args.Add(methods_args.ElementAt(0).ToLower(), methods_args.ElementAt(1));
                            }
                            catch (Exception e)
                            {
                                AppConfig_File_Args.Remove(methods_args.ElementAt(0).ToLower());
                                AppConfig_File_Args.Add(methods_args.ElementAt(0).ToLower(), methods_args.ElementAt(1));
                            }
                        }
                        else if (methods_args.ElementAt(0).ToLower().Contains("check_service_up") == true)
                        {
                            if (Services_To_Check_Up.Count <= 25)
                            {
                                Services_To_Check_Up.Add(methods_args.ElementAt(1));
                            }
                            else
                            {
                                Errors.WRITE_Errors_To_Log("READ_App_Config_File()", "SWELF config has to many services to check are up. Max is 25.", Errors.LogSeverity.Warning);
                            }
                        }
                        else
                        {
                            try
                            {
                               AppConfig_File_Args.Add(methods_args.ElementAt(0).ToLower(), methods_args.ElementAt(1));
                            }
                            catch (Exception e)
                            {
                                AppConfig_File_Args.Remove(methods_args.ElementAt(0).ToLower());
                                AppConfig_File_Args.Add(methods_args.ElementAt(0).ToLower(), methods_args.ElementAt(1));
                            }
                        }
                        methods_args.Clear();
                    }
                }
                File.Encrypt(GET_AppConfigFile);
            }
            catch (Exception e)
            {
                AppConfig_File_Args = Backup_Config_File_Args;
                Errors.WRITE_Errors_To_Log("READ_App_Config_File()", methods_args.ElementAt(0).ToLower()+" "+ methods_args.ElementAt(1) + " "+e.Message.ToString(), Errors.LogSeverity.Critical);
                File_Operation.CREATE_NEW_Files_And_Dirs(Config_File_Location, AppConfigFile, File_Operation.GET_Default_ConsoleAppConfig_File_Contents);
            }
        }

        public static void READ_Search_Terms_File()
        {
            string line = "";

            try
            {
                File.Decrypt(GET_SearchTermsFile);
                StreamReader file = new StreamReader(GET_SearchTermsFile);
                while ((line = file.ReadLine()) != null)
                {
                    if (line.StartsWith(CommentCharConfigs) == false && String.IsNullOrWhiteSpace(line) == false)
                    {
                        Search_Terms_Unparsed.Add(line.ToLower());
                    }
                }
                file.Close();
                Search_Terms_Unparsed = Search_Terms_Unparsed.Distinct().ToList();
                File.Encrypt(GET_SearchTermsFile);
            }
            catch (Exception e)
            {
                Errors.Log_Error("READ_Search_Terms_File()" ,"line="+ line+" "+ e.Message.ToString(),Errors.LogSeverity.Critical);
                File_Operation.CREATE_NEW_Files_And_Dirs(Search_File_Location, SearchTermsFileName, File_Operation.GET_Default_Logs_Search_File_Contents);
            }
        }

        public static void READ_WhiteList_Search_Terms_File()
        {
            string line = "";
            try
            {
                File.Decrypt(GET_WhiteList_SearchTermsFile);
                StreamReader file = new StreamReader(GET_WhiteList_SearchTermsFile);
                while ((line = file.ReadLine()) != null)
                {
                    if (line.StartsWith(CommentCharConfigs) == false && String.IsNullOrWhiteSpace(line) == false)
                    {
                        WhiteList_Search_Terms_Unparsed.Add(line.ToLower());
                    }
                }
                file.Close();
                File.Encrypt(GET_WhiteList_SearchTermsFile);
            }
            catch (Exception e)
            {
                Errors.Log_Error("READ_WhiteList_Search_Terms_File() " , "line=" + line + " " + e.Message.ToString(),Errors.LogSeverity.Critical);
                File_Operation.CREATE_NEW_Files_And_Dirs(Search_File_Location, Search_WhiteList, "#SearchTerm ~ EventLogName ~ EventID");
            }
        }

        private static void READ_EventLogID_Placeholders(bool Clear_PlaceKeepers_and_Restart_Log_Query = false)
        {
            if (Clear_PlaceKeepers_and_Restart_Log_Query)//do this for central config read
            {
                string line = "";
                try
                {
                    File.Decrypt(GET_EventLogID_PlaceHolder);
                    EventLog_w_PlaceKeeper.Clear();
                    EventLog_w_PlaceKeeper_List.Clear();

                    StreamReader file = new StreamReader(GET_EventLogID_PlaceHolder);
                    while ((line = file.ReadLine()) != null)
                    {
                        if (!line.Contains(CommentCharConfigs))
                        {
                            string[] lines = line.Split(SplitChar_ConfigVariableEquals, StringSplitOptions.RemoveEmptyEntries).ToArray();
                            EventLog_w_PlaceKeeper.Add(lines[0].ToLower(), 1);
                            EventLog_w_PlaceKeeper_List.Add(lines[0].ToLower());
                        }
                    }
                    file.Close();
                    File.Encrypt(GET_EventLogID_PlaceHolder);
                }
                catch (Exception e)
                {
                    Errors.Log_Error("READ_EventLogID_Placeholders()"," if (Clear_PlaceKeepers_and_Restart_Log_Query) line=" +line +" "+ e.Message.ToString(),Errors.LogSeverity.Critical);
                    File_Operation.CREATE_NEW_Files_And_Dirs(Config_File_Location, EventLogID_PlaceHolder, File_Operation.GET_Default_Eventlog_with_PlaceKeeper_File_Contents);
                }
            }
            else//reading local file not central config
            {
                string line = "";
                try
                {
                    File.Decrypt(GET_EventLogID_PlaceHolder);
                    StreamReader file = new StreamReader(GET_EventLogID_PlaceHolder);
                    while ((line = file.ReadLine()) != null)
                    {
                        if (!line.Contains(Settings.CommentCharConfigs) && string.IsNullOrWhiteSpace(line)==false)
                        {
                            string[] lines = line.Split(Settings.SplitChar_ConfigVariableEquals, StringSplitOptions.RemoveEmptyEntries).ToArray();
                            EventLog_w_PlaceKeeper.Add(lines[0].ToLower(), Convert.ToInt64(lines[1]));
                            Reg.ADD_or_CHANGE_SWELF_Reg_Key(lines[0].ToLower(), Convert.ToInt64(lines[1]).ToString());
                            EventLog_w_PlaceKeeper_List.Add(lines[0].ToLower());
                        }
                    }
                    file.Close();
                    File.Encrypt(GET_EventLogID_PlaceHolder);
                }
                catch (Exception e)
                {
                    EventLog_SWELF.WRITE_Critical_EventLog("READ_EventLogID_Placeholders() line=" + line + " " + e.Message.ToString());
                    File_Operation.CREATE_NEW_Files_And_Dirs(Config_File_Location, EventLogID_PlaceHolder, File_Operation.GET_Default_Eventlog_with_PlaceKeeper_File_Contents);
                }
            }
        }

        private static void READ_Powershell_SearchTerms()
        {
            string line = "";
            try
            {
                File.Decrypt(Plugin_Search_Location + "\\" + SearchTermsFileName);
                StreamReader file = new StreamReader(Plugin_Search_Location + "\\" + SearchTermsFileName);
                while ((line = file.ReadLine()) != null)
                {
                    if (!line.Contains(CommentCharConfigs) && String.IsNullOrWhiteSpace(line) == false)
                    {
                        Plugin_Search_Terms_Unparsed.Add(line.ToLower());
                    }
                }
                file.Close();
                File.Encrypt(Plugin_Search_Location + "\\" + SearchTermsFileName);
            }
            catch (Exception e)
            {
                EventLog_SWELF.WRITE_Critical_EventLog("READ_Powershell_SearchTerms() line="+line+ " " + e.Message.ToString());
                File_Operation.CREATE_NEW_Files_And_Dirs(Plugin_Search_Location, SearchTermsFileName, "#File Path to Powershell Script~ SearchTerm~ Powershell Script Arguments");
            }
        }

        private static void GET_Central_Config_File(string WebPath, string LocalPath, string FileName)
        {
            File.Delete(LocalPath);//remove old config file
            Wclient.DownloadFile(WebPath, LocalPath); //if match read local files
            Errors.Log_Error("GET_Central_Config_File()", "Updated " + FileName + " from " + WebPath + ". It was downloaded to " + LocalPath, Errors.LogSeverity.Informataion,EventLog_SWELF.SWELF_Central_Config_Changed_EVTID);//log change
        }

        public static void UPDATE_EventLog_w_PlaceKeeper_File()
        {
            if (Logs_Sent_to_ALL_Collectors == true)
            {
                File.Decrypt(GET_EventLogID_PlaceHolder);
                File_Operation.DELETE_AND_CREATE_File(GET_EventLogID_PlaceHolder);
                for (int x = 0; x < EventLog_w_PlaceKeeper.Count; ++x)
                {
                    File.AppendAllText(GET_EventLogID_PlaceHolder, EventLog_w_PlaceKeeper.ElementAt(x).Key + SplitChar_ConfigVariableEquals[0] + EventLog_w_PlaceKeeper.ElementAt(x).Value + "\n");
                    Reg.ADD_or_CHANGE_SWELF_Reg_Key(EventLog_w_PlaceKeeper.ElementAt(x).Key, EventLog_w_PlaceKeeper.ElementAt(x).Value.ToString());
                }
                File.Encrypt(GET_EventLogID_PlaceHolder);
            }
        }

        public static bool VERIFY_Central_File_Config_Hash(string HTTP_File_Path, string Local_File_Path)
        {
            string httpFile;
            string LocalFIle;
            try
            {
                using (var sha256 = SHA256.Create())
                {
                    httpFile = BitConverter.ToString(sha256.ComputeHash(Encoding.ASCII.GetBytes(Encoding.ASCII.GetString(Wclient.DownloadData(HTTP_File_Path)).Trim().Replace('\n', ' ').ToCharArray()))).ToLowerInvariant();
                }
                using (var sha2562 = SHA256.Create())
                {
                    LocalFIle = BitConverter.ToString(sha2562.ComputeHash(Encoding.ASCII.GetBytes(Encoding.ASCII.GetString(File.ReadAllBytes(Local_File_Path)).Trim().Replace('\n', ' ').ToCharArray()))).ToLowerInvariant();
                }

                if (httpFile == LocalFIle)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch (Exception e)
            {
                Errors.WRITE_Errors_To_Log("VERIFY_Central_File_Config_Hash()", "Error " + e.Message.ToString(), Errors.LogSeverity.Warning);//log change
                return false;
            }
        }

        public static void GET_ErrorLog_Ready()
        {
            File_Operation.CREATE_NEW_Files_And_Dirs(Settings.SWELF_Log_File_Location, Settings.ErrorFile);
        }

        public static List<string> GET_LogCollector_Location()
        {
            List<string> Dest_IP_or_HostName = new List<string>();

            if (AppConfig_File_Args.ContainsKey("log_collector") == true && !String.IsNullOrEmpty(AppConfig_File_Args["log_collector"]))
            {
                Dest_IP_or_HostName.Add(AppConfig_File_Args["log_collector"]);
                try
                {
                    Log_Forwarders_HostNames.Add(GET_HostName(AppConfig_File_Args["log_collector"]));
                }
                catch (Exception e)
                {
                    Log_Forwarders_HostNames.Add(AppConfig_File_Args["log_collector"]);
                }
            }
            if (AppConfig_File_Args.ContainsKey("log_collector1") == true && !String.IsNullOrEmpty(AppConfig_File_Args["log_collector1"]))
            {
                Dest_IP_or_HostName.Add(AppConfig_File_Args["log_collector1"]);
                try
                {
                    Log_Forwarders_HostNames.Add(GET_HostName(AppConfig_File_Args["log_collector1"]));
                }
                catch (Exception e)
                {
                    Log_Forwarders_HostNames.Add(AppConfig_File_Args["log_collector1"]);
                }
            }
            if (AppConfig_File_Args.ContainsKey("log_collector2") == true && !String.IsNullOrEmpty(AppConfig_File_Args["log_collector2"]))
            {
                Dest_IP_or_HostName.Add(AppConfig_File_Args["log_collector2"]);
                try
                {
                    Log_Forwarders_HostNames.Add(GET_HostName(AppConfig_File_Args["log_collector2"]));
                }
                catch (Exception e)
                {
                    Log_Forwarders_HostNames.Add(AppConfig_File_Args["log_collector2"]);
                }
            }
            if (AppConfig_File_Args.ContainsKey("log_collector3") == true && !String.IsNullOrEmpty(AppConfig_File_Args["log_collector3"]))
            {
                Dest_IP_or_HostName.Add(AppConfig_File_Args["log_collector3"]);
                try
                {
                    Log_Forwarders_HostNames.Add(GET_HostName(AppConfig_File_Args["log_collector3"]));
                }
                catch (Exception e)
                {
                    Log_Forwarders_HostNames.Add(AppConfig_File_Args["log_collector3"]);
                }
            }
            if (AppConfig_File_Args.ContainsKey("log_collector4") == true && !String.IsNullOrEmpty(AppConfig_File_Args["log_collector4"]))
            {
                Dest_IP_or_HostName.Add(AppConfig_File_Args["log_collector4"]);
                try
                {
                    Log_Forwarders_HostNames.Add(GET_HostName(AppConfig_File_Args["log_collector4"]));
                }
                catch(Exception e)
                {
                    Log_Forwarders_HostNames.Add(AppConfig_File_Args["log_collector4"]);
                }
            }
            if (AppConfig_File_Args.ContainsKey("log_collector5") == true && !String.IsNullOrEmpty(AppConfig_File_Args["log_collector5"]))
            {
                Dest_IP_or_HostName.Add(AppConfig_File_Args["log_collector5"]);
                try
                {
                    Log_Forwarders_HostNames.Add(GET_HostName(AppConfig_File_Args["log_collector5"]));
                }
                catch
                {
                    Log_Forwarders_HostNames.Add(AppConfig_File_Args["log_collector5"]);
                }
            }

            Log_Forwarders_HostNames.Distinct();
            if (Dest_IP_or_HostName.Count <= 0)
            {
                Dest_IP_or_HostName.Add("127.0.0.1");
            }

            Dest_IP_or_HostName = Dest_IP_or_HostName.Distinct().ToList();
            return Dest_IP_or_HostName;
        }

        private static void CHECK_if_all_Search_Terms_have_Indexed_LogsSources()
        {
            List<string> Searchs = new List<string>();

            try
            {
                foreach (string SearchLogType in Search_Terms_Unparsed)//search terms
                {
                    string[] SearchsArgs = SearchLogType.Split(Settings.SplitChar_SearchCommandSplit, StringSplitOptions.RemoveEmptyEntries).ToArray();

                    if (SearchsArgs.Length > 1)
                    {
                        if (String.IsNullOrEmpty(SearchsArgs[1]) == false && SearchLogType.StartsWith(Settings.CommentCharConfigs) == false)
                        {
                            foreach (string LogSource in EventLog_w_PlaceKeeper_List)//eventlogs to index
                            {
                                try
                                {
                                    if (Settings.CHECK_If_EventLog_Exsits(SearchsArgs[0]))
                                    {
                                        Searchs.Add(SearchsArgs[0]);
                                        if (Reg.CHECK_SWELF_Reg_Key_Exists(SearchsArgs[0])==false)
                                        {
                                            Reg.ADD_or_CHANGE_SWELF_Reg_Key(SearchsArgs[0],"1");
                                        }
                                    }
                                    else if (SearchsArgs.Length > 1 && (String.IsNullOrEmpty(SearchsArgs[1]) == false && SearchLogType.StartsWith(Settings.CommentCharConfigs) == false && Settings.CHECK_If_EventLog_Exsits(SearchsArgs[1])))
                                    {
                                        Searchs.Add(SearchsArgs[1]);
                                        if (Reg.CHECK_SWELF_Reg_Key_Exists(SearchsArgs[1])==false)
                                        {
                                            Reg.ADD_or_CHANGE_SWELF_Reg_Key(SearchsArgs[1], "1");
                                        }
                                    }
                                    else if (SearchsArgs.Length > 2 && (String.IsNullOrEmpty(SearchsArgs[2]) == false && SearchLogType.StartsWith(Settings.CommentCharConfigs) == false && Settings.CHECK_If_EventLog_Exsits(SearchsArgs[2])))
                                    {
                                        Searchs.Add(SearchsArgs[2]);
                                        if (Reg.CHECK_SWELF_Reg_Key_Exists(SearchsArgs[2])==false)
                                        {
                                            Reg.ADD_or_CHANGE_SWELF_Reg_Key(SearchsArgs[2], "1");
                                        }
                                    }
                                }
                                catch (Exception e)
                                {
                                    Errors.Log_Error("CHECK_if_all_Search_Terms_have_Indexed_LogsSources()", e.Message.ToString() + Searchs.Count, Errors.LogSeverity.Warning);
                                }
                            }
                        }
                    }
                }
                List<string> MissingEventLogs = Searchs.Distinct().Except(EventLog_w_PlaceKeeper_List.Distinct()).ToList();

                for (int x = 0; x < MissingEventLogs.Count(); ++x)
                {
                    EventLog_w_PlaceKeeper.Add(MissingEventLogs.ElementAt(x).ToLower(), 1);
                    Reg.ADD_or_CHANGE_SWELF_Reg_Key(MissingEventLogs.ElementAt(x).ToLower(), "1");
                    EventLog_w_PlaceKeeper_List.Add(MissingEventLogs.ElementAt(x).ToLower());
                }
                EventLog_w_PlaceKeeper_List.Sort();
                EventLog_w_PlaceKeeper_Backup = EventLog_w_PlaceKeeper;
            }
            catch (Exception e)
            {
                Errors.Log_Error("CHECK_if_all_Search_Terms_have_Indexed_LogsSources() " ,e.Message.ToString() + Searchs.Count, Errors.LogSeverity.Critical);
                Stop(SWELF_CRIT_ERROR_EXIT_CODE);
            }
        }

        public static bool CHECK_If_EventLog_Exsits(string EventLog_ToFind)
        {
            return EventLogs_List_Of_Avaliable.Any(s => string.Equals(s, EventLog_ToFind, StringComparison.OrdinalIgnoreCase));
        }

        private static void SET_WindowsEventLog_Location()
        {
            try
            {
                if (!EventLog.SourceExists(SWELF_EventLog_Name))
                {
                    EventLog.CreateEventSource(SWELF_PROC_Name.ProcessName, SWELF_EventLog_Name);
                    SWELF_EvtLog_OBJ.Source = SWELF_EventLog_Name;

                    if (Reg.CHECK_Non_SWELF_Reg_Key_Exists(Reg.EventLog_Base_Key+ "\\"+SWELF_EventLog_Name))
                    {
                        Reg.SET_Event_Log_MaxSize(SWELF_EventLog_Name);
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
                Errors.Log_Error("SET_WindowsEventLog_Loc() ", e.Message.ToString(), Errors.LogSeverity.Critical);
                SWELF_EvtLog_OBJ.Source = SWELF_EventLog_Name;
            }
        }

        public static void Log_Storage_Location_Unavailable(string e)
        {
            EventLog_w_PlaceKeeper = EventLog_w_PlaceKeeper_Backup;
            //Errors.WRITE_Errors_To_Log("Log_Storage_Location_Unavailable(string e)", e + " Access to log storage location may not be available.", Errors.LogSeverity.Warning);
        }

        private static void GET_All_Files_HTTP(string Web_Config_URL)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(Web_Config_URL);
            request.AllowAutoRedirect = false;
            request.UnsafeAuthenticatedConnectionSharing = false;
            request.Timeout = 150000;

            ServicePointManager.Expect100Continue = true;
            ServicePointManager.CheckCertificateRevocationList = false;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12| SecurityProtocolType.Tls11 | SecurityProtocolType.Tls | SecurityProtocolType.Ssl3 ;

            using (CustomWebClient response = new CustomWebClient())
            {
                string WebContents = response.DownloadString(Web_Config_URL);
                Regex regex = new Regex(GET_DirectoryListingRegexForUrl(WebContents));
                MatchCollection matches = regex.Matches(WebContents);
                if (matches.Count > 0)
                {
                    if (Config_Files_on_the_Web_Server.Count > 1)
                    {
                        Config_Files_on_the_Web_Server.Clear();
                    }
                    foreach (Match match in matches)
                    {
                        if (match.Success && Web_Config_URL.Contains(".txt") == false && Web_Config_URL.Contains(".conf") == false)
                        {
                            Config_Files_on_the_Web_Server.Add(Web_Config_URL + match.Groups["name"].ToString());
                        }
                        else
                        {
                            Config_Files_on_the_Web_Server.Add(Web_Config_URL);
                        }
                    }
                }
                else
                {
                    Config_Files_on_the_Web_Server.Add(Web_Config_URL);
                }
            }
        }

        private static string GET_DirectoryListingRegexForUrl(string url)
        {
            if (url.Equals(url))
            {
                return "<a href=\".*\">(?<name>.*)</a>";
            }
            throw new NotSupportedException();
        }

        public static void SHOW_Help_Menu()
        {
            Process.Start("powershell", @"-NoExit -Command ""Write-Host 'Simmple Windows EventLog Forwarder (SWELF)

This is the SWELF Help Menu if you are using commandline operations the the binary will not be able to read a live EVTX file.
The app must be setup properly to do that and doesnt take commandline input when it does it.
Commands do not care about case. 
If your unsure of how this appeared never fear SWELF stopped itself (due to cmdline input error and only showed this help menu :) check you local eventlogs for more details.
Manual Located At:https://github.com/ceramicskate0/SWELF/wiki/CommandLine-Inputs-Args-for-local-usage
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

SWELF.exe -EVTX_File C:\Filepath\SuspiciousWindowsEvntLog.evtx -OutputCSV Findings.csv -Find detected -Dissolve
'""");
        }

        public static void Dissolve()
        {
            EventLog_SWELF.WRITE_Critical_EventLog("SWELF WAS TOLD TO SELF DELETE. After it ran.");
            Process.Start("cmd.exe", "/C choice /C Y /N /D Y /T 3 & Del /Q " + Directory.GetCurrentDirectory() + "\\"+ Settings.SWELF_PROC_Name);
            Environment.Exit(0);
        }

        public static string GET_HostName(string IP)
        { 
            try
            {
                return Dns.GetHostEntry(IPAddress.Parse(Network_Forwarder.Get_IP_from_Socket_string(IP))).HostName.ToString();
            }
            catch (Exception e)
            {
                return Network_Forwarder.Get_IP_from_Socket_string(IP);
            }
        }

        public static string GET_IP(string Hostname)
        {
            try
            {
                return Dns.GetHostEntry(Hostname).AddressList.ElementAt(0).ToString();
            }
            catch
            {
                return Hostname;
            }
        }

        public static void Stop(int error_code)
        {
            Errors.SEND_Errors_To_Central_Location();
            Environment.Exit(error_code);
        }
    }

    public class CustomWebClient : WebClient
    {
        protected override WebRequest GetWebRequest(Uri uri)
        {
            WebRequest w = base.GetWebRequest(uri);
            w.Timeout = 15000;
            return w;
        }
    }
}
