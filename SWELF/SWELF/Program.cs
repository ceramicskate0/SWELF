//Written by Ceramicskate0
//Copyright 
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;

namespace SWELF
{
    internal static class Program 
    {
        private static List<string> Program_Start_Args = new List<string>();
        private static bool RanToLongTiner = false;

        [STAThread]
        internal static void Main(string[] args)
        {
            Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.BelowNormal;
            Program_Start_Args = Environment.GetCommandLineArgs().ToList();
            string[] Program_Start_Args_Array = Environment.GetCommandLineArgs().Skip(1).ToArray();

            if (Program_Start_Args.Count > 1)
            {
                if (Program_Start_Args.Count>=3 && Program_Start_Args.ElementAt(1).ToLower()=="-c")
                {
                    if (Program_Start_Args.Count<3)
                    {
                        Program_Start_Args.Add(Settings.GET_AppConfigFile_Path);
                    }
                    //TODO make sure config file passed in is one of the correct file (by location) then update that reg key, then delete the file once read in
                    if (File_Operation.CHECK_if_File_Exists(Program_Start_Args.ElementAt(2).ToLower()))
                    {
                        if (File_Operation.CHECK_if_File_Exists(Program_Start_Args.ElementAt(2).ToLower()))
                        {
                            Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_Contents, File_Operation.READ_AllText(Program_Start_Args.ElementAt(2).ToLower()));
                            //TODO: LOG CONFIG UPDATE VIA THIS METHOD
                        }
                        else if (File_Operation.CHECK_if_File_Exists(Settings.GET_AppConfigFile_Path))
                        {
                            Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_Contents, File_Operation.READ_AllText(Settings.GET_AppConfigFile_Path));
                            //TODO: LOG CONFIG UPDATE VIA THIS METHOD
                        }

                        if (File_Operation.CHECK_if_File_Exists(Settings.GET_SearchTermsFile_Path))
                        {
                            Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.SearchTerms_File_Contents, File_Operation.READ_AllText(Settings.GET_SearchTermsFile_Path));
                            //TODO: LOG CONFIG UPDATE VIA THIS METHOD
                        }
                        if (File_Operation.CHECK_if_File_Exists(Settings.GET_WhiteList_SearchTermsFile_Path))
                        {
                            Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.WhiteList_SearchTerms_File_Contents, File_Operation.READ_AllText(Settings.GET_WhiteList_SearchTermsFile_Path));
                            //TODO: LOG CONFIG UPDATE VIA THIS METHOD
                        }
                        Start_Process_Live_Method();
                        //TODO add option for password in config file to allow updates this way
                        //if no password allow update
                        //store password in reg
                    }
                    else
                    {
                        Settings.SHOW_Help_Menu();
                        Settings.Stop(Settings.SWELF_CRIT_ERROR_EXIT_CODE, "MAIN()", "The config file path doesnt  exist for some reaosn, Also the app halted.","");
                    }
                }
                else if (Program_Start_Args.Count < 2 && Program_Start_Args.Count > 1)
                {
                    Settings.SHOW_Help_Menu();
                }
                else
                {
                    Start_EVTX_Process(); 
                }
            }
            else
            {
                try
                {
                    Start_Process_Live_Method();
                }
                catch (Exception e)
                {
                    Settings.Stop(Settings.SWELF_CRIT_ERROR_EXIT_CODE, "Start_Live_Process()", e.Message.ToString() + ", Also the app halted.", e.StackTrace.ToString());
                }
            }
            Environment.Exit(0);
        }

        internal static void Start_EVTX_Process()
        {
            try
            {
                Read_EventLog EvntLogSearch = new Read_EventLog();

                PARSE_Commandline_Input(EvntLogSearch);

                Search_EventLog search_Obj = new Search_EventLog();

                Data_Store.SWELF_Events_Of_Interest_Matching_EventLogs = search_Obj.Search(Settings.CMDLine_EVTX_File);

                if (Settings.output_csv)
                {
                    File_Operation.Write_Ouput_CSV(Settings.CMDLine_Output_CSV, Data_Store.SWELF_Events_Of_Interest_Matching_EventLogs);
                }
                else
                {
                    Start_Write_To_SWELF_EventLogs();
                }
                Error_Operation.WRITE_Stored_Errors();
            }
            catch (Exception e)
            {
                Settings.Stop(Settings.SWELF_CRIT_ERROR_EXIT_CODE, "Start_EVTX_Process() ", e.Message.ToString(), e.StackTrace.ToString());
            }
        }

        internal static void Start_Process_Live_Method()
        {
            if (System_Info.Is_SWELF_Running() == false)
            {
                Thread THREAD_APP_RUN_TIMER = new Thread(CHECK_If_App_Has_Run_To_Long);//Run thread while app runs that kills app for running to long
                THREAD_APP_RUN_TIMER.IsBackground = true;
                THREAD_APP_RUN_TIMER.Start();

                Run_Live_Process_Workflow();
            }
            else
            {
                Settings.Stop(0, "MAIN() System_Performance_Info.Is_SWELF_Running()", "SWELF tried to run but another instance was already running. Closing this instance of " + Settings.SWELF_PROC_Name.ProcessName + ".", "");
            }
        }

        private static void Run_Live_Process_Workflow()
        {
            if (Sec_Checks.Pre_Run_Sec_Checks() && Sec_Checks.CHECK_If_Running_as_Admin())
            {
                Start_Setup();

                Thread PS_Plugins_Thread = new Thread(() => Start_Run_Plugins());
                PS_Plugins_Thread.IsBackground = true;
                PS_Plugins_Thread.Priority = ThreadPriority.Lowest;
                PS_Plugins_Thread.Start();
                
                Thread READ_Local_LogFiles_Thread = new Thread(() => READ_Local_LogFiles());
                READ_Local_LogFiles_Thread.IsBackground = true;
                READ_Local_LogFiles_Thread.Priority= ThreadPriority.Lowest;
                READ_Local_LogFiles_Thread.Start();

                while (Settings.PS_PluginDone != true && !READ_Local_LogFiles_Thread.IsAlive && !READ_Local_LogFiles_Thread.IsAlive)
                {
                    Thread.Sleep(10000);
                }
                PS_Plugins_Thread.Abort();
                READ_Local_LogFiles_Thread.Abort();

                Start_Read_Search_Write_Forward_EventLogs();

                Start_Send_File_Based_Logs();

                Write_HashFile_IPsFile();
            }
            else
            {
                Settings.Stop(Settings.SWELF_CRIT_ERROR_EXIT_CODE,"Sec_Checks.Pre_Run_Sec_Checks() && Sec_Checks.CHECK_If_Running_as_Admin()", "FAILED Sec_Checks.Pre_Run_Sec_Checks() SWELF not running as local admin.","");
            }
            Error_Operation.WRITE_Stored_Errors();
        }

        private static void Start_Setup()
        {
            try
            {
                Settings.InitializeAppSettings();
            }
            catch (Exception e)
            {
                Settings.Stop(Settings.SWELF_CRIT_ERROR_EXIT_CODE, "ALERT: SWELF MAIN ERROR: Settings.InitializeAppSettings() ",e.Message.ToString() , e.StackTrace.ToString());
            }
        }

        private static void READ_Local_LogFiles()
        {
            Read_Local_Files.READ_Local_Log_Files();
            Read_Local_Files.READ_Local_Log_Dirs();
        }

        private static void Start_Run_Plugins()
        {
            try
            {
                Settings.Plugin_Search_Terms_Unparsed=Settings.Plugin_Search_Terms_Unparsed.Distinct().ToList();

                for (int x = 0; x < Settings.Plugin_Search_Terms_Unparsed.Count; ++x)
                {
                    EventLog_Entry PSLog = new EventLog_Entry();
                    PSLog.ComputerName = Settings.ComputerName;
                    PSLog.EventID = Convert.ToInt32(Error_Operation.EventID.Powershell_Plugin);
                    PSLog.LogName = "SWELF PowerShell Plugin Output";
                    PSLog.Severity = "Information";
                    PSLog.CreatedTime = DateTime.Now;
                    PSLog.TaskDisplayName = "SWELF Powershell Plugin Output";
                    PSLog.SearchRule = "SWELF_Powershell_Plugin=" + Settings.Plugin_Search_Terms_Unparsed.ElementAt(x);
                    PSLog.UserID = Environment.UserName;
                    
                    PSLog.EventData=Powershell_Plugin.Run_PS_Script(Settings.Plugin_Search_Terms_Unparsed.ElementAt(x).Split(Settings.SplitChar_SearchCommandSplit[0]).ElementAt(0), Settings.Plugin_Search_Terms_Unparsed.ElementAt(x).Split(Settings.SplitChar_SearchCommandSplit[0]).ElementAt(2));

                    if (PSLog.EventData.ToLower().Contains(Settings.Plugin_Search_Terms_Unparsed.ElementAt(x).Split(Settings.SplitChar_SearchCommandSplit[0]).ElementAt(1).ToLower()))
                    {
                        Data_Store.PS_Plugin_SWELF_Events_Of_Interest_Matching_EventLogs.Enqueue(PSLog);

                        try
                        {
                            EventLog_SWELF.WRITE_EventLog_From_SWELF_Search(Data_Store.PS_Plugin_SWELF_Events_Of_Interest_Matching_EventLogs.ElementAt(0));
                            Log_Network_Forwarder.SEND_Logs(Data_Store.PS_Plugin_SWELF_Events_Of_Interest_Matching_EventLogs);
                        }
                        catch (Exception e)
                        {
                            Error_Operation.Log_Error("Network_Forwarder.SEND_Logs(), EventLog_SWELF.WRITE_EventLog_From_SWELF_Search(), or Start_Run_Plugins()", Settings.EventLog_w_PlaceKeeper_List.ElementAt(x) + " HostEventLogAgent_Eventlog.WRITE_EventLog " + e.Message.ToString(),e.StackTrace.ToString(), Error_Operation.LogSeverity.Warning);
                        }
                    }
                }
                Settings.PS_PluginDone = true;
                GC.Collect();
            }
            catch (Exception e)
            {
                Error_Operation.Log_Error("Powershell_Plugin.Run_PS_Script() " , e.StackTrace.ToString(), e.Message.ToString(), Error_Operation.LogSeverity.Warning);
                Error_Operation.SEND_Errors_To_Central_Location();
                Settings.PS_PluginDone = true;
            }
        }

        private static void Start_Read_Search_Write_Forward_EventLogs()
        {
            if (Settings.EventLog_w_PlaceKeeper_List.Count > 0)
            {
                Sec_Checks.Pre_Live_Run_Sec_Checks();

                for (int x=0; x<Settings.EventLog_w_PlaceKeeper_List.Count;++x)
                {
                    if (RanToLongTiner == false)
                    {
                        Start_Searching_Logs(x);
                    }
                }
                if (RanToLongTiner == false)//if this is true this method is already running
                {
                    Start_Output_Post_Run();
                }
            }
            else
            {
                Error_Operation.Log_Error("Start_Read_Search_Write_Forward_EventLogs()", "Settings.EventLog_w_PlaceKeeper_List.Count is "+Settings.EventLog_w_PlaceKeeper_List.Count, "",Error_Operation.LogSeverity.Warning, Error_Operation.EventID.SWELF_Warning);
            }
        }

        private static void Start_Searching_Logs(int Index)
        {
            try
            {
                Read_EventLog EVNT_Log = new Read_EventLog();

                Sec_Checks.Live_Run_Sec_Checks(Settings.EventLog_w_PlaceKeeper_List.ElementAt(Index));

                EVNT_Log.READ_EventLog(Settings.EventLog_w_PlaceKeeper_List.ElementAt(Index), Settings.EventLog_w_PlaceKeeper[Settings.EventLog_w_PlaceKeeper_List.ElementAt(Index)]);

                if (Data_Store.contents_of_EventLog.Count>=0)
                {
                    Search_EventLog search_Obj = new Search_EventLog();

                    Data_Store.SWELF_Events_Of_Interest_Matching_EventLogs = search_Obj.Search(Settings.EventLog_w_PlaceKeeper_List.ElementAt(Index));
                }
                Data_Store.contents_of_EventLog.Clear();
            }
            catch (Exception e)
            {
                string CallStack = e.StackTrace.ToString();
                if (e.Message == "Object reference not set to an instance of an object.")
                {
                    Error_Operation.Log_Error("Start_Read_Search_Write_Forward_EventLogs()", Settings.EventLog_w_PlaceKeeper_List.ElementAt(Index) + " " + e.Message.ToString()+" This error means the EventLog was not read or searched. \n"+ CallStack, e.StackTrace.ToString(), Error_Operation.LogSeverity.Informataion);
                }
                else if (e.Message.ToString().Contains("The process cannot access the file"))
                {
                    Error_Operation.Log_Error("Start_Read_Search_Write_Forward_EventLogs()", e.Message.ToString()+" OS File lock of vital resource at runtime." + " This error means the EventLog was not read or searched.\n" + CallStack, e.StackTrace.ToString(), Error_Operation.LogSeverity.Warning);
                }
                else
                {
                    Error_Operation.Log_Error("Start_Read_Search_Write_Forward_EventLogs()", " " + Settings.EventLog_w_PlaceKeeper_List.ElementAt(Settings.Total_Threads_Run) + " x=" + (Settings.Total_Threads_Run).ToString() + " " + e.Message.ToString() + ". Check search Syntx." + " This error means the EventLog was not read or searched.\n" + CallStack, e.StackTrace.ToString(), Error_Operation.LogSeverity.Informataion);
                }
            }
            GC.Collect();
        }

        internal static void Start_Output_Post_Run()
        {
            if (Data_Store.SWELF_Events_Of_Interest_Matching_EventLogs.Count > 0)
            {
                try
                {
                    if (Settings.output_csv && Program_Start_Args.Count >= 3 && (Settings.Log_Forwarders_HostNames.Count < 1))
                    {
                        File_Operation.Write_Ouput_CSV(Settings.CMDLine_Output_CSV, Data_Store.SWELF_Events_Of_Interest_Matching_EventLogs);
                    }
                    else
                    {
                        Log_Network_Forwarder.SEND_Logs(Data_Store.SWELF_Events_Of_Interest_Matching_EventLogs);
                    }
                }
                catch (Exception e)
                {
                    Settings.Logs_Sent_to_ALL_Collectors = false;
                    Error_Operation.Log_Error("Start_Output_Post_Run()  Network_Forwarder.SEND_Logs() File_Operation.Write_Ouput_CSV()", e.Message.ToString(), e.StackTrace.ToString(), Error_Operation.LogSeverity.Warning);
                }

                if (Settings.Logs_Sent_to_ALL_Collectors)
                {
                    Start_Write_To_SWELF_EventLogs();
                }
                Sec_Checks.Post_Run_Sec_Checks();
            }
            Settings.UPDATE_EventLog_w_PlaceKeeper_RegKeys();
            Update_Eventlog_Placekeeper_Reg();
            Error_Operation.WRITE_Stored_Errors();
        }

        private static void Update_Eventlog_Placekeeper_Reg()
        {
            for (int y = 0; y < Settings.EventLog_w_PlaceKeeper_List.Count; ++y)//what reg key is eventlog
            {
                if (Settings.EventLog_w_PlaceKeeper.ContainsKey(Settings.EventLog_w_PlaceKeeper_List.ElementAt(y).ToLower()))
                {
                    Reg_Operation.ADD_or_CHANGE_Non_SWELF_Reg_Key(Settings.EventLog_w_PlaceKeeper_List.ElementAt(y).ToLower(),Settings.EventLog_w_PlaceKeeper[Settings.EventLog_w_PlaceKeeper_List.ElementAt(y).ToLower()]);
                }
            }
        }

        private static void Start_Write_To_SWELF_EventLogs()
        {
            for (int z = 0; z < Data_Store.SWELF_Events_Of_Interest_Matching_EventLogs.Count; ++z)
            {
                try
                {
                    EventLog_SWELF.WRITE_EventLog_From_SWELF_Search(Data_Store.SWELF_Events_Of_Interest_Matching_EventLogs.ElementAt(z));
                }
                catch (Exception e)
                {
                    Error_Operation.Log_Error("Start_Write_To_SWELF_EventLogs()", "An EventLog "+ Data_Store.SWELF_Events_Of_Interest_Matching_EventLogs.ElementAt(z).GET_XML_of_Log + " errored on write to SWELF Eventlog with the following error " + e.Message.ToString(), e.StackTrace.ToString(),Error_Operation.LogSeverity.Warning);
                }
            }
            
        }

        private static void Start_Send_File_Based_Logs()
        {
            bool Data_Sent = false;
            try
            {
                if (Settings.Log_Forwarders_HostNames.Any(s => string.Equals(s, "127.0.0.1", StringComparison.OrdinalIgnoreCase)) == false && Settings.Log_Forwarders_HostNames.Any(s => string.IsNullOrEmpty(s)) == false)
                {
                    for (int z = 0; z < Read_Local_Files.FileContents_From_FileReads.Count; ++z)
                    {
                        EventLog_SWELF.WRITE_EventLog_From_SWELF_Search(Read_Local_Files.FileContents_From_FileReads.ElementAt(z));
                        Data_Sent=Log_Network_Forwarder.SEND_Logs(Read_Local_Files.FileContents_From_FileReads.ElementAt(z));
                        if (Data_Sent == true && File_Operation.CHECK_if_File_Exists(Settings.GET_ErrorLog_Location) && Settings.AppConfig_File_Args.ContainsKey(Settings.SWELF_AppConfig_Args[15]))
                        {
                            File.Delete(Read_Local_Files.FileContents_From_FileReads.ElementAt(z));
                            File.Create(Read_Local_Files.FileContents_From_FileReads.ElementAt(z)).Close();
                        }
                    }
                }
            }
            catch (Exception e)//network resource unavailable. Dont send data and try again next run. No logs will be queued by app only re read
            {
                Settings.Log_Storage_Location_Unavailable(" Start_Send_File_Based_Logs() "+e.Message.ToString());
            }
        }

        private static void PARSE_Commandline_Input(Read_EventLog EvntLogSearch)
        {
            for (int x = 0; x < Program_Start_Args.Count; ++x)
            {
                switch (Program_Start_Args.ElementAt(x).ToLower())
                {
                    //ONCE YOU ADD COMMAND HERE ADD TO HELP MENU at Settings.SHOW_Help_Menu()
                    case "-help":
                        {
                            Settings.SHOW_Help_Menu();
                            break;
                        }
                    case "-h":
                        {
                            Settings.SHOW_Help_Menu();
                            break;
                        }
                    case "?":
                        {
                            Settings.SHOW_Help_Menu();
                            break;
                        }
                    case "-output_csv":
                        {
                            Settings.CMDLine_Output_CSV = Program_Start_Args.ElementAt(x + 1);
                            Settings.output_csv = true;
                            break;
                        }
                    case "-evtx_file":
                        {
                            Settings.CMDLine_EVTX_File= Program_Start_Args.ElementAt(x + 1);
                            EvntLogSearch.READ_EVTX_File(Settings.CMDLine_EVTX_File);
                            Settings.EVTX_Override = true;
                            break;
                        }
                    case "-evtx_folder":
                        {
                            Settings.CMDLine_EVTX_File = Program_Start_Args.ElementAt(x + 1);
                            EvntLogSearch.READ_EVTX_Folder(Settings.CMDLine_EVTX_File);
                            Settings.EVTX_Override = true;
                            break;
                        }
                    case "-search_terms":
                        {
                            Settings.CMDLine_Search_Terms= Program_Start_Args.ElementAt(x+1);
                            Settings.READ_Search_Terms_File(Settings.CMDLine_Search_Terms);
                            break;
                        }
                    case "-dissolve":
                        {
                            Settings.CMDLine_Dissolve = true;
                            break;
                        }
                    case "-find":
                        {
                            Settings.CMDLine_Find_SEARCHTERM = Program_Start_Args.ElementAt(x + 1);
                            break;
                        }
                    default:
                        {
                            break;
                        }
                }
            }
            }

        private static void Write_HashFile_IPsFile()
        {
            if (Settings.AppConfig_File_Args.ContainsKey(Settings.SWELF_AppConfig_Args[12]))
            {
                try
                {
                    if (File_Operation.CHECK_if_File_Exists(Settings.Hashs_File_Path))
                    {
                        File_Operation.CHECK_File_Size(Settings.Hashs_File_Path,.0002);
                        Settings.Hashs_From_EVT_Logs.AddRange(File_Operation.READ_File_In_List(Settings.Hashs_File_Path).Distinct().ToList());
                        Settings.Hashs_From_EVT_Logs = Settings.Hashs_From_EVT_Logs.Distinct().ToList();
                    }
                    File_Operation.Write_Hash_Output(Settings.Hashs_From_EVT_Logs.Distinct().ToList());
                }
                catch (Exception e)
                {
                    Error_Operation.Log_Error("Write_HashFile_IPsFile()", Settings.SWELF_AppConfig_Args[12] +" "+ e.Message.ToString(), e.StackTrace.ToString(), Error_Operation.LogSeverity.Informataion);
                }
            }
            if (Settings.AppConfig_File_Args.ContainsKey(Settings.SWELF_AppConfig_Args[11]))
            {
                try
                {
                    if (File_Operation.CHECK_if_File_Exists(Settings.IPs_File_Path))
                    {
                        File_Operation.CHECK_File_Size(Settings.IPs_File_Path, .0002);
                        Settings.IP_List_EVT_Logs.AddRange(File_Operation.READ_File_In_List(Settings.IPs_File_Path).Distinct().ToList());
                        Settings.IP_List_EVT_Logs = Settings.IP_List_EVT_Logs.Distinct().ToList();
                    }
                }
                catch (Exception e)
                {
                    Error_Operation.Log_Error("Write_HashFile_IPsFile()", Settings.SWELF_AppConfig_Args[11] + " " + e.Message.ToString(), e.StackTrace.ToString(), Error_Operation.LogSeverity.Informataion);
                }
                File_Operation.Write_IP_Output(Settings.IP_List_EVT_Logs.Distinct().ToList());
            }
        }

        private static void CHECK_If_App_Has_Run_To_Long()
        {
            var watch = System.Diagnostics.Stopwatch.StartNew();
            while (watch.Elapsed.Hours < 1)
            { Thread.Sleep(600000); }
            watch.Stop();
            var elapsedTime = watch.Elapsed;
            RanToLongTiner = true;
            Start_Output_Post_Run();
            Error_Operation.Log_Error("CHECK_If_App_Has_Run_To_Long()", "SWELF's time running on machine timer says that SWELF to long ("+elapsedTime.ToString()+") this could be for many reasons. Most likely is that there are to many log sources your trying to read into SWELF or that some of the logs files are to large to be read in with all the other searchs. Try running SWELF in sequence. ","", Error_Operation.LogSeverity.Critical);
            Error_Operation.SEND_Errors_To_Central_Location();
            Error_Operation.WRITE_Stored_Errors();
            Environment.Exit((int)Error_Operation.EventID.SWELF_MAIN_APP_ERROR);
        }
    }
}

