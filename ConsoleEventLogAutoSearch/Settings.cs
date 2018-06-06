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
using System.Web;
using System.Text.RegularExpressions;
using System.DirectoryServices;
using System.Security.Cryptography;
using System.Threading;
using System.Security.Principal;

namespace SWELF
{
    public class Settings
    {
        public static int Log_Forward_Location_Port = 514;
        public static long Avail_Mem_MB = 0;
        public static List<string> EventLogs_ListOfAvaliable = EventLogSession.GlobalSession.GetLogNames().ToList();
        public static Dictionary<string, long> EventLog_w_PlaceKeeper = new Dictionary<string, long>();
        public static List<string> EventLog_w_PlaceKeeper_List = new List<string>();//Tracks Eventlog reading
        public static Dictionary<string, string> AppConfig_File_Args = new Dictionary<string, string>();//program config arguements
        public static List<string> Search_Terms_Unparsed = new List<string>();//search.txt file line by lone reads
        public static List<string> WhiteList_Search_Terms_Unparsed = new List<string>();//search.txt file line by lone reads
        public static List<string> Plugin_Search_Terms_Unparsed = new List<string>();
        public static List<string> Plugin_Scripts_to_Run = new List<string>();
        public static Queue<EventLogEntry> CriticalEvents = new Queue<EventLogEntry>();//APP events that must be logged
        private static Dictionary<string, long> EventLog_w_PlaceKeeper_Backup = new Dictionary<string, long>();
        private static WebClient Wclient = new WebClient();//.net webclient to pull down central config file
        public static List<string> Config_Files_on_the_Web_Server = new List<string>();
        public static List<string> IP_List_EVT_Logs = new List<string>();
        public static List <string> Hashs_From_EVT_Logs = new List<string>();

        private static string Config_File_Location = Directory.GetCurrentDirectory() + "\\Config";
        private static string Search_File_Location = Directory.GetCurrentDirectory() + "\\Log_Searchs";
        private static string SWELF_Log_File_Location = Directory.GetCurrentDirectory() + "\\SWELF_Logs";
        private static string Plugin_Files_Location = Directory.GetCurrentDirectory() + "\\Plugins";
        private static string Plugin_Scripts_Location = Plugin_Files_Location + "\\Scripts";
        private static string Plugin_Search_Location = Plugin_Files_Location + "\\Plugin_Searchs";

        private static string ErrorFile = "Error_Log.log";
        private static string AppConfigFile = "ConsoleAppConfig.conf";
        private static string EventLogID_PlaceHolder = "Eventlog_with_PlaceKeeper.txt";
        private static string SearchTermsFileName = "Searchs.txt";
        private static string FilesToMonitor = "Files_To_Monitor.conf";
        private static string DirectoriesToMonitor = "Directories_To_Monitor.conf";
        private static string Search_WhiteList = "WhiteList_Searchs.txt";

        public static string CommentCharConfigs = "#";
        public static char[] SplitChar_Regex = { '~' };
        public static char[] SplitChar_SearchCommandSplit = { '~' };
        public static char[] SplitChar_ConfigVariableEquals = { '=' };
        public static char[] SplitChar_UNCPath = { '\\' };
        public static char[] SplitChar_Search_Command_Parsers = { ':' , '~' };

        public static string[] Search_Commands = { "count:", "eventdata_length:", "commandline_length:", "commandline_contains:", "commandline_count:", "regex:"};

        public static string ComputerName = Environment.MachineName;

        public static string SWELF_EventLog_Name = "SWELF_Events_of_Interest";
    
        private static string SWELF_Central_App_Config_Arg = "central_app_config";
        public static string SWELF_Central_Search_Arg = "central_search_config";
        public static string SWELF_Central_WhiteList_Search_Arg = "central_whitelist_config";
        private static string SWELF_Central_Plugin_Arg = "central_plugin_config";

        public static string CMDLine_EVTX_File = "";
        public static string CMDLine_Output_CSV = "SWELF_Output.csv";
        public static string CMDLine_Search_Terms = "";
        public static string CMDLine_Find_SEARCHTERM = "";
        public static bool CMDLine_Dissolve = false;
        public static bool EVTX_Override = false;

        public static EventLog EvtLog = new EventLog();

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

        public static string GET_SearchTermsFileName
        {
            get
            {
                return Search_File_Location + "\\" + SearchTermsFileName;
            }
        }

        public static string GET_WhiteList_SearchTermsFileName
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

        public static void InitializeAppSettings()
        {
            GET_ErrorLog_Ready();
            SET_WindowsEventLog_Loc();
            READ_App_Config_File();
            READ_EventLogID_Placeholders();
            READ_Search_Terms_File();
            READ_WhiteList_Search_Terms_File();

            if ((AppConfig_File_Args.ContainsKey(SWELF_Central_App_Config_Arg)))//central config for all the files in Config Dir
            {
                READ_CENTRAL_APP_Config_Folder();
                AppConfig_File_Args.Clear();//all old args are now discarded
                READ_App_Config_File();//if no match replace local files and read local file, make log of event
            }
            if ((AppConfig_File_Args.ContainsKey(SWELF_Central_Search_Arg)))
            {
                READ_CENTRAL_SEARCH_Config_File();
            }
            if ((AppConfig_File_Args.ContainsKey(SWELF_Central_WhiteList_Search_Arg)))
            {
                READ_CENTRAL_WHITELIST_SEARCH_Config_File();
            }
            //if READ_Central_Plugin_Files
            GET_Plugins_Ready();
            READ_All_Plugin_Scripts_To_Run();
            READ_Powershell_SearchTerms();

            CHECK_if_all_Search_Terms_have_Indexed_LogsSources();
        }

        private static bool VERIFY_Config_DIR()
        {
            try
            {
                if (VERIFY_if_File_Exists(GET_AppConfigFile) && VERIFY_if_File_Exists(GET_DirectoriesToMonitor) && VERIFY_if_File_Exists(GET_EventLogID_PlaceHolder) && VERIFY_if_File_Exists(GET_FilesToMonitor))
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch
            {
                return false;
            }
        }

        private static bool VERIFY_Search_DIR()
        {
            try
            {
                if (VERIFY_if_File_Exists(GET_SearchTermsFileName))
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch
            {
                return false;
            }
        }

        private static void READ_App_Config_File()
        {
            try
            {
                string[] ConfgiFilelines = File.ReadAllLines(GET_AppConfigFile);
                List<string> methods_args = new List<string>();

                foreach (string ConfigFileline in ConfgiFilelines)
                {
                    if (!ConfigFileline.Contains(Settings.CommentCharConfigs) && ConfigFileline.Contains(SplitChar_ConfigVariableEquals[0]))
                    {
                        methods_args = ConfigFileline.Split(Settings.SplitChar_ConfigVariableEquals,StringSplitOptions.RemoveEmptyEntries).ToList();
                        if (methods_args.ElementAt(0).ToLower().Contains("central") == false)
                        {
                            AppConfig_File_Args.Add(methods_args.ElementAt(0).ToLower(), methods_args.ElementAt(1).ToLower());
                        }
                        else
                        {
                            AppConfig_File_Args.Add(methods_args.ElementAt(0).ToLower(), methods_args.ElementAt(1));
                        }
                        methods_args.Clear();
                    }
                }
            }
            catch (Exception e)
            {
                Errors.WRITE_Errors_To_Log("INFO:",e.Message.ToString(),"Informational");
                CREATE_Files_And_Dirs(Config_File_Location,AppConfigFile, WRITE_Default_ConsoleAppConfig_File());
            }
        }

        private static void READ_CENTRAL_APP_Config_Folder()
        {
            try
            {
                GET_All_HTTP_Files(AppConfig_File_Args[SWELF_Central_App_Config_Arg]);//get files from web server

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
                    }
                    else if (WebFiles.ElementAt(WebFiles.Count - 1).Equals(DirectoriesToMonitor) && !VERIFY_Central_File_Config_Hash(Config_Files_on_the_Web_Server.ElementAt(x), GET_EventLogID_PlaceHolder))//check hash of file on web server to local files
                    {
                        //TODO: find which log was added and add it to exisiting file with =1
                        GET_Central_Config_File(Config_Files_on_the_Web_Server.ElementAt(x), GET_EventLogID_PlaceHolder, EventLogID_PlaceHolder);
                        READ_EventLogID_Placeholders(true);
                    }
                }
                Config_Files_on_the_Web_Server.Clear();
            }
            catch (Exception e)
            {
                READ_App_Config_File();
                Errors.Log_Error("ALERT:","READ_CENTRAL_App_Config_File: READ_CENTRAL_APP_Config_File() " + e.Message.ToString());
                HostEventLogAgent_Eventlog.WRITE_Critical_EventLog("ALERT: READ_CENTRAL_App_Config_File: READ_CENTRAL_APP_Config_File() " + e.Message.ToString());
                Errors.WRITE_Errors();
                Errors.SEND_Errors_To_Central_Location();
            }
        }

        public static void READ_CENTRAL_SEARCH_Config_File(string Central_Location="")
        {
            string Central_Loc;

            if (string.IsNullOrEmpty(Central_Location)==false)
            {
                Central_Loc = Central_Location;
            }
            else
            {
                Central_Loc=AppConfig_File_Args[SWELF_Central_Search_Arg];
            }
            try
            {
                GET_All_HTTP_Files(Central_Loc);//get files from web server

                for (int x = 0; x < Config_Files_on_the_Web_Server.Count; ++x)
                {
                    List<string> WebFiles = Config_Files_on_the_Web_Server.ElementAt(x).Split('/').ToList();//Seperate all the files out
                    //SearchConfig
                    if (WebFiles.ElementAt(WebFiles.Count - 1).Equals(SearchTermsFileName) && !VERIFY_Central_File_Config_Hash(Config_Files_on_the_Web_Server.ElementAt(x), GET_SearchTermsFileName))//check hash of file on web server to local files
                    {
                        GET_Central_Config_File(Config_Files_on_the_Web_Server.ElementAt(x), GET_SearchTermsFileName, SearchTermsFileName);
                    }
                }
                Config_Files_on_the_Web_Server.Clear();
            }
            catch (Exception e)
            {
                READ_App_Config_File();
                Errors.Log_Error("ALERT:","READ_CENTRAL_SEARCH_Config_File: READ_CENTRAL_SEARCH_Config_File() " + e.Message.ToString());
                HostEventLogAgent_Eventlog.WRITE_Critical_EventLog("ALERT: READ_CENTRAL_SEARCH_Config_File: READ_CENTRAL_SEARCH_Config_File() " + e.Message.ToString());
                Errors.WRITE_Errors();
                Errors.SEND_Errors_To_Central_Location();
            }
        }

        public static void READ_CENTRAL_WHITELIST_SEARCH_Config_File(string Central_Location = "")
        {
            //TODO VET SETTING FOR A WHITELIST
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
                GET_All_HTTP_Files(Central_Loc);//get files from web server

                for (int x = 0; x < Config_Files_on_the_Web_Server.Count; ++x)
                {
                    List<string> WebFiles = Config_Files_on_the_Web_Server.ElementAt(x).Split('/').ToList();//Seperate all the files out
                    //SearchConfig
                    if (WebFiles.ElementAt(WebFiles.Count - 1).Equals(SearchTermsFileName) && !VERIFY_Central_File_Config_Hash(Config_Files_on_the_Web_Server.ElementAt(x), GET_SearchTermsFileName))//check hash of file on web server to local files
                    {
                        GET_Central_Config_File(Config_Files_on_the_Web_Server.ElementAt(x), GET_SearchTermsFileName, SearchTermsFileName);
                    }
                }
                Config_Files_on_the_Web_Server.Clear();
            }
            catch (Exception e)
            {
                READ_App_Config_File();
                Errors.Log_Error("ALERT:", "READ_CENTRAL_SEARCH_Config_File: READ_CENTRAL_SEARCH_Config_File() " + e.Message.ToString());
                HostEventLogAgent_Eventlog.WRITE_Critical_EventLog("ALERT: READ_CENTRAL_SEARCH_Config_File: READ_CENTRAL_SEARCH_Config_File() " + e.Message.ToString());
                Errors.WRITE_Errors();
                Errors.SEND_Errors_To_Central_Location();
            }
        }

        private static void GET_Central_Config_File(string WebPath,string LocalPath,string FileName)
        {
            File.Delete(LocalPath);//remove old config file
            Wclient.DownloadFile(WebPath, LocalPath); //if match read local files
            Errors.WRITE_Errors_To_Log("INFO:","SWELF APP " + Settings.ComputerName + " updated "+ FileName +" from " + WebPath + ". It was downloaded to " + LocalPath, "Informational");//log change
        }

        public static void READ_Search_Terms_File()
        {
            try
            {
                string line;

                StreamReader file = new StreamReader(GET_SearchTermsFileName);
                while ((line = file.ReadLine()) != null)
                {
                    if (line.StartsWith("#") == false)
                    {
                        Search_Terms_Unparsed.Add(line.ToLower());
                    }
                }
                file.Close();
            }
            catch
            { 
            CREATE_Files_And_Dirs(Search_File_Location,SearchTermsFileName, WRITE_Default_Logs_Search_File());
            }
        }

        public static void READ_WhiteList_Search_Terms_File()
        {
            try
            {
                string line;

                StreamReader file = new StreamReader(GET_WhiteList_SearchTermsFileName);
                while ((line = file.ReadLine()) != null)
                {
                    if (line.StartsWith("#") == false)
                    {
                        WhiteList_Search_Terms_Unparsed.Add(line.ToLower());
                    }
                }
                file.Close();
            }
            catch
            {
                CREATE_Files_And_Dirs(Search_File_Location, Search_WhiteList, WRITE_Default_Logs_WhiteList_Search_File());
            }
        }

        private static void READ_EventLogID_Placeholders(bool Clear_PlaceKeepers_and_Restart_Log_Query= false)
        {
            if (Clear_PlaceKeepers_and_Restart_Log_Query)//do this for central config read
            {
                try
                {
                    EventLog_w_PlaceKeeper.Clear();
                    EventLog_w_PlaceKeeper_List.Clear();
                    string line;
                    StreamReader file = new StreamReader(GET_EventLogID_PlaceHolder);
                    while ((line = file.ReadLine()) != null)
                    {
                        if (!line.Contains(Settings.CommentCharConfigs))
                        {
                            string[] lines = line.Split(Settings.SplitChar_ConfigVariableEquals, StringSplitOptions.RemoveEmptyEntries).ToArray();
                            EventLog_w_PlaceKeeper.Add(lines[0].ToLower(), 1);
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
            else//reading local file not central config
            {
                try
                {
                    string line;
                    StreamReader file = new StreamReader(GET_EventLogID_PlaceHolder);
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
        }

        private static void READ_Powershell_SearchTerms()
        {
            try
            {
                string line;
                StreamReader file = new StreamReader(Plugin_Search_Location+ "\\"+SearchTermsFileName);
                while ((line = file.ReadLine()) != null)
                {
                    if (!line.Contains("#"))
                    {
                        Plugin_Search_Terms_Unparsed.Add(line.ToLower());
                    }
                }
                file.Close();
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

        public static bool VERIFY_Central_File_Config_Hash(string HTTP_File_Path,string FileConfigHash)
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
                    LocalFIle = BitConverter.ToString(sha2562.ComputeHash(Encoding.ASCII.GetBytes(Encoding.ASCII.GetString(File.ReadAllBytes(FileConfigHash)).Trim().Replace('\n', ' ').ToCharArray()))).ToLowerInvariant();
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
                Errors.WRITE_Errors_To_Log("INFO:", "Error VERIFY_Central_File_Config_Hash() "+e.Message.ToString(), "Informational");//log change
                return false;
            }
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
            /*if (!Directory.Exists(Plugin_Search_Location))
            {
                Directory.CreateDirectory(Plugin_Search_Location);
            }*/
        }

        public static string GET_FilesToMonitor_Path()
        {
            CREATE_Files_And_Dirs(Config_File_Location, FilesToMonitor);
            return GET_FilesToMonitor;
        }

        public static string GET_DirToMonitor_Path()
        {
            CREATE_Files_And_Dirs(Config_File_Location, DirectoriesToMonitor);
            return GET_DirectoriesToMonitor;
        }

        public static List<IPAddress> GET_LogCollector_Location()
        {
            List<IPAddress> IPAddr = new List<IPAddress>();

            if (AppConfig_File_Args.ContainsKey("log_collector") == true && !String.IsNullOrEmpty(AppConfig_File_Args["log_collector"]))
            {
                IPAddr.Add(IPAddress.Parse(AppConfig_File_Args["log_collector"]));
            }
            if (AppConfig_File_Args.ContainsKey("log_collector1") == true && !String.IsNullOrEmpty(AppConfig_File_Args["log_collector1"]))
            {
                IPAddr.Add(IPAddress.Parse(AppConfig_File_Args["log_collector1"]));
            }
            if (AppConfig_File_Args.ContainsKey("log_collector2") == true && !String.IsNullOrEmpty(AppConfig_File_Args["log_collector2"]))
            {
                IPAddr.Add(IPAddress.Parse(AppConfig_File_Args["log_collector2"]));
            }
            if (AppConfig_File_Args.ContainsKey("log_collector3") == true && !String.IsNullOrEmpty(AppConfig_File_Args["log_collector3"]))
            {
                IPAddr.Add(IPAddress.Parse(AppConfig_File_Args["log_collector3"]));
            }
            if (AppConfig_File_Args.ContainsKey("log_collector4") == true && !String.IsNullOrEmpty(AppConfig_File_Args["log_collector4"]))
            {
                IPAddr.Add(IPAddress.Parse(AppConfig_File_Args["log_collector4"]));
            }
            if (AppConfig_File_Args.ContainsKey("log_collector5") == true && !String.IsNullOrEmpty(AppConfig_File_Args["log_collector5"]))
            {
                IPAddr.Add(IPAddress.Parse(AppConfig_File_Args["log_collector5"]));
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
            foreach (string SearchLogType in Search_Terms_Unparsed)//search terms
            {
                string[] SearchsArgs = SearchLogType.Split(Settings.SplitChar_Search_Command_Parsers, StringSplitOptions.RemoveEmptyEntries).ToArray();
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
            DELETE_AND_CREATE_File(GET_EventLogID_PlaceHolder);
            for (int x=0; x < EventLog_w_PlaceKeeper.Count;++x)
            {
                File.AppendAllText(GET_EventLogID_PlaceHolder, EventLog_w_PlaceKeeper_List.ElementAt(x) + SplitChar_ConfigVariableEquals[0] + EventLog_w_PlaceKeeper[EventLog_w_PlaceKeeper_List.ElementAt(x)]+"\n");
            }
        }

        public static void WRITE_EventLogID_Placeholders()
        {;
            File.Delete(GET_EventLogID_PlaceHolder);
            for (int x = 0; x > EventLog_w_PlaceKeeper.Count; ++x)
            {
                File.AppendAllText(GET_EventLogID_PlaceHolder, EventLog_w_PlaceKeeper.ElementAt(x).Key + SplitChar_ConfigVariableEquals[0] + EventLog_w_PlaceKeeper.ElementAt(x).Value.ToString() + "\n");
            }
        }

        private static string WRITE_Default_ConsoleAppConfig_File()
        {
            string log = @"#Must Be IPV4 
log_collector"+ SplitChar_ConfigVariableEquals[0]+ @"127.0.0.1
#syslogxml,syslog,xml,data
output_format"+ SplitChar_ConfigVariableEquals[0] + @"syslog";
            return log;
        }

        private static string WRITE_Default_Eventlog_with_PlaceKeeper_File()
        {
            string log= @"#LOG NAME, START AT INDEX(1 if unknown)
Microsoft-Windows-PowerShell/Operational"+ SplitChar_ConfigVariableEquals[0] + @"1
Microsoft-Windows-Windows Defender/Operational" + SplitChar_ConfigVariableEquals[0] + @"1
Windows PowerShell" + SplitChar_ConfigVariableEquals[0] + @"1
Microsoft-Windows-Sysmon/Operational" + SplitChar_ConfigVariableEquals[0] + @"1
Security" + SplitChar_ConfigVariableEquals[0] + @"1
Microsoft-Windows-DeviceGuard/Operational" + SplitChar_ConfigVariableEquals[0] + @"1
Microsoft-Windows-WMI-Activity/Operational" + SplitChar_ConfigVariableEquals[0] + @"1
Microsoft-Windows-Bits-Client/Operational" + SplitChar_ConfigVariableEquals[0] + @"1
AMSI/Operational" + SplitChar_ConfigVariableEquals[0] + @"1
";
            return log;
        }

        private static string WRITE_Default_Logs_WhiteList_Search_File()
        {
            return @"#SearchTerm " + SplitChar_SearchCommandSplit[0] + @" EventLogName " + SplitChar_SearchCommandSplit[0] + @" EventID";
        }

        private static string WRITE_Default_Logs_Search_File()
        {
            string log = @"#SearchTerm " + SplitChar_SearchCommandSplit[0] + @" EventLogName " + SplitChar_SearchCommandSplit[0] + @" EventID
commandline_length:400
commandline_contains:<script>
commandline_contains:mshta
commandline_contains:sc create
commandline_contains:rundll32.exe javascript
" + SplitChar_SearchCommandSplit[0] + @"AMSI/Operational" + SplitChar_SearchCommandSplit[0] + @"
count:-split:5" + SplitChar_SearchCommandSplit[0] + @"windows powershell" + SplitChar_SearchCommandSplit[0] + @"
" + SplitChar_SearchCommandSplit[0] + @"microsoft-Windows-Windows Defender/Operational" + SplitChar_SearchCommandSplit[0] + @"detected
" + SplitChar_SearchCommandSplit[0] + @"microsoft-Windows-Windows Defender/Operational" + SplitChar_SearchCommandSplit[0] + @"detection 
" + SplitChar_SearchCommandSplit[0] + @"microsoft-Windows-Windows Defender/Operational" + SplitChar_SearchCommandSplit[0] + @"malware
" + SplitChar_SearchCommandSplit[0] + @"microsoft-Windows-Windows Defender/Operational" + SplitChar_SearchCommandSplit[0] + @"disabled
count:;:20
count:':50
count:+:12
eventdata_length:10000
iex"+ SplitChar_SearchCommandSplit[0]+@"windows powershell"+ SplitChar_SearchCommandSplit[0] + @"
webclient" + SplitChar_SearchCommandSplit[0] + @"windows powershell" + SplitChar_SearchCommandSplit[0] + @"
mshta
regsvr32.exe /s /u /i:
bitsadmin.exe  /transfer
bitsadmin.exe /download 
wscript
";
            return log;
        }

        private static string WRITE_Default_Powershell_Search_File()
        {
            string log = "#File Path to Powershell Script ~ SearchTerm ~ Powershell Script Arguments";
            return log;
        }

        public static void ADD_Eventlog_to_CriticalEvents(string Data, string EventName,string Severity)
        {
            EventLogEntry Eventlog = new EventLogEntry();
            Eventlog.LogName = SWELF_EventLog_Name;
            Eventlog.Severity = Severity;
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
            Errors.WRITE_Errors_To_Log("NETWORK ERROR: ",e + " Access to log storage location may not be available.","Warning");
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
            if (VERIFY_if_File_Exists(Dir + "\\" + FileName)==false)
            {
                File.Create(Dir + "\\" + FileName).Close();
                if (string.IsNullOrEmpty(FileData) == false)
                {
                    File.AppendAllText(Dir + "\\" + FileName, FileData);
                }
            }
        }

        private static void GET_All_HTTP_Files(string Web_Config_URL)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(Web_Config_URL);
            request.AllowAutoRedirect = false;
            request.UnsafeAuthenticatedConnectionSharing = false;
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                if (response.StatusCode == HttpStatusCode.OK)
                {
                    using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                    {
                        reader.BaseStream.ReadTimeout = 3000;
                        string html = reader.ReadToEnd();
                        Regex regex = new Regex(GetDirectoryListingRegexForUrl(Web_Config_URL));
                        MatchCollection matches = regex.Matches(html);
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
                    }
                }
                else
                {
                    READ_App_Config_File();
                    Errors.Log_Error("ALERT:", "READ_CENTRAL_App_Config_File: GET_All_HTTP_Files status code no 200. It was" + response.StatusCode.ToString());
                    HostEventLogAgent_Eventlog.WRITE_Critical_EventLog("ALERT: READ_CENTRAL_App_Config_File: GET_All_HTTP_Files status code not 200. It was" + response.StatusCode.ToString());
                    Errors.WRITE_Errors();
                }
                }        
        }

        private static string GetDirectoryListingRegexForUrl(string url)
        {
            if (url.Equals(url))
            {
                return "<a href=\".*\">(?<name>.*)</a>";
            }
            throw new NotSupportedException();
        }

        public static bool CHECK_If_Running_as_Admin()
        {
            if (new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        public static void SHOW_Help_Menu()
        {
            Process.Start("powershell", @"-NoExit -Command ""Write-Host 'Simmple Windows EventLog Forwarder (SWELF)

This is the SWELF Help Menu if you are using commandline operations the the binary will not be able to read a live EVTX file.
The app must be setup properly to do that and doesnt take commandline input when it does it.
Commands do not care about case. 
If your unsure of how this appeared never fear SWELF stopped itself (due to cmdline input error and only showed this help menu :) check you local eventlogs for more details.

-----------
|Commands:|
-----------

-EVTX_File C:\..\..\evtx.evtx
     Filepath to EVTX file

-Output_CSV C:\..\..\Fileoutput.csv
     Output Matchs as CSV
     If no file path provided it will output in CWD

-Dissolve
     Try to Disolve app when its complete

-Search_Terms C:\..\..\Search.txt
     FileMust be the same as Search.txt when app is installed

-Find SEARCHTERM
    Search EVTX file for the single SEARCHTERM

-Help
     Display this menu

Example:
SWELF.exe -EVTX_File C:\Filepath\SuspiciousWindowsEvntLog.evtx -OutputCSV Findings.csv -Search_Terms C:\Filepath\Search.txt

SWELF.exe -EVTX_File C:\Filepath\SuspiciousWindowsEvntLog.evtx -OutputCSV C:\FilePath\FleName.csv -Find SEARCHTERMTOFIND detected

SWELF.exe -EVTX_File C:\Filepath\SuspiciousWindowsEvntLog.evtx -OutputCSV Findings.csv -Find detected -Dissolve
'""");
        }

        public static void Dissolve()
        {
            Process.Start("cmd.exe", "/C choice /C Y /N /D Y /T 3 & Del /Q " + Directory.GetCurrentDirectory()+"\\SWELF.exe");
            Environment.Exit(0);
        }

        public static bool VERIFY_if_File_Exists(string FilePath)
        {
            return File.Exists(FilePath);
        }

        public static long Get_Allocated_Memory()
        {
           return Process.GetCurrentProcess().WorkingSet64/ 1000000;
        }
    }
}
