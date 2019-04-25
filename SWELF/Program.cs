//Written by Ceramicskate0
//Copyright 
using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Threading;

namespace SWELF
{
    internal static class Program
    {
        private static List<string> Program_Start_Args = new List<string>();

        internal static void Main(string[] args)
        {
            var watch = System.Diagnostics.Stopwatch.StartNew();

            Program_Start_Args = Environment.GetCommandLineArgs().ToList();

            if (Program_Start_Args.Count>1)
            {
                Start_EVTX_Process();
            }
            else if (Program_Start_Args.Count<2 && Program_Start_Args.Count >1)
            {
                Settings.SHOW_Help_Menu();
            }
            else
            {
                try
                {
                    if (System_Info.Is_SWELF_Running())
                    {
                        Start_Live_Process();
                    }
                    else
                    {
                       Settings.Stop(0,"MAIN() System_Performance_Info.Is_SWELF_Running()","SWELF tried to run but another instance was already running. Closing this instance of " + Settings.SWELF_PROC_Name + ".");
                    }
                }
                catch (Exception e)
                {
                    Settings.Stop(Settings.SWELF_CRIT_ERROR_EXIT_CODE, "Start_Live_Process()", e.Message.ToString() + ", Also the app halted." + "Stack=" + e.StackTrace);
                }
            }
            watch.Stop();
            var elapsedTime = watch.Elapsed;
        }

        public static void Start_EVTX_Process()
        {
            try
            {
                Read_EventLog EvntLogSearch = new Read_EventLog();

                PARSE_Commandline_Input(EvntLogSearch);

                Search_EventLog search_Obj = new Search_EventLog(EvntLogSearch.EVTX_File_Logs);

                Settings.SWELF_Events_Of_Interest_Matching_EventLogs = search_Obj.Search(Settings.CMDLine_EVTX_File);

                if (Settings.output_csv)
                {
                    File_Operation.Write_Ouput_CSV(Settings.CMDLine_Output_CSV, Settings.SWELF_Events_Of_Interest_Matching_EventLogs);
                }
                else
                {
                    Start_Write_To_SWELF_EventLogs();
                }

                if (Settings.CMDLine_Dissolve)
                {
                    Settings.Dissolve();
                }
                Error_Operation.WRITE_Stored_Errors();
            }
            catch (Exception e)
            {
                Settings.Stop(Settings.SWELF_CRIT_ERROR_EXIT_CODE, "Start_EVTX_Process() ", e.Message.ToString());
            }
        }

        private static void Start_Live_Process()
        {
            if (Sec_Checks.Pre_Run_Sec_Checks() && Sec_Checks.CHECK_If_Running_as_Admin())
            {
                if (Program_Start_Args.ElementAt(0).ToLower().Equals("-dissolve") && Settings.CHECK_If_EventLog_Exsits(Settings.SWELF_EventLog_Name) == false && File_Operation.CHECK_if_File_Exists(Settings.GET_ErrorLog_Location))
                {
                    Settings.CMDLine_Dissolve = true;
                }

                Start_Setup();

                Thread PS_Plugins_Thread = new Thread(() => Start_Run_Plugins());
                PS_Plugins_Thread.Start();

                Thread Local_Logs_Thread = new Thread(() => Start_ReadLocal_Logs());
                Local_Logs_Thread.Start();

                Start_Read_Search_Write_Forward_EventLogs();

                Start_Send_File_Based_Logs();

                Write_HashFile_IPsFile();

                int TOut = 0;
                while (Settings.PS_PluginDone != true && TOut!=5)
                {
                    Thread.Sleep(300000);
                    TOut++;
                }
            }
            else
            {
                Settings.Stop(Settings.SWELF_CRIT_ERROR_EXIT_CODE,"Sec_Checks.Pre_Run_Sec_Checks() && Sec_Checks.CHECK_If_Running_as_Admin(). APP FAILED Statement.", "FAILED Sec_Checks.Pre_Run_Sec_Checks() && Sec_Checks.CHECK_If_Running_as_Admin()");
            }
            if (Settings.CMDLine_Dissolve)
            {
                Settings.Dissolve();
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
                Settings.Stop(Settings.SWELF_CRIT_ERROR_EXIT_CODE, "ALERT: SWELF MAIN ERROR: Settings.InitializeAppSettings() ",e.Message.ToString() + " Stack=" + e.StackTrace);
            }
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
                    PSLog.SearchRule = "SWELF Powershell Plugin " + Settings.Plugin_Search_Terms_Unparsed.ElementAt(x);
                    PSLog.UserID = Environment.UserName;
                    
                    PSLog.EventData=Powershell_Plugin.Run_PS_Script(Settings.Plugin_Search_Terms_Unparsed.ElementAt(x).Split(Settings.SplitChar_SearchCommandSplit[0]).ElementAt(0), Settings.Plugin_Search_Terms_Unparsed.ElementAt(x).Split(Settings.SplitChar_SearchCommandSplit[0]).ElementAt(2));

                    if (PSLog.EventData.ToLower().Contains(Settings.Plugin_Search_Terms_Unparsed.ElementAt(x).Split(Settings.SplitChar_SearchCommandSplit[0]).ElementAt(1).ToLower()))
                    {
                        Settings.PS_Plugin_SWELF_Events_Of_Interest_Matching_EventLogs.Enqueue(PSLog);

                        try
                        {
                            EventLog_SWELF.WRITE_EventLog_From_SWELF_Search(Settings.PS_Plugin_SWELF_Events_Of_Interest_Matching_EventLogs.ElementAt(0));
                            Log_Network_Forwarder.SEND_Logs(Settings.PS_Plugin_SWELF_Events_Of_Interest_Matching_EventLogs);
                        }
                        catch (Exception e)
                        {
                            Error_Operation.Log_Error("Network_Forwarder.SEND_Logs() or EventLog_SWELF.WRITE_EventLog_From_SWELF_Search()", Settings.EventLog_w_PlaceKeeper_List.ElementAt(x) + " HostEventLogAgent_Eventlog.WRITE_EventLog " + e.Message.ToString(), Error_Operation.LogSeverity.Warning);
                        }
                    }
                }
                Settings.PS_PluginDone = true;
                GC.Collect();
            }
            catch (Exception e)
            {
                Error_Operation.Log_Error("Powershell_Plugin.Run_PS_Script() " , e.Message.ToString(), Error_Operation.LogSeverity.Warning);
                Error_Operation.SEND_Errors_To_Central_Location();
                Settings.PS_PluginDone = true;
            }
        }

        private static void Start_Read_Search_Write_Forward_EventLogs()
        {
            if (Settings.Max_Thread_Count < 1)
            {
                Settings.Max_Thread_Count = 1;
            }
            if (Settings.EventLog_w_PlaceKeeper_List.Count > 0)
            {
                Sec_Checks.Pre_Live_Run_Sec_Checks();

                while(Settings.Total_Threads_Run < Settings.EventLog_w_PlaceKeeper_List.Count)//READ and Search
                {
                    if ((Settings.Running_Thread_Count < Settings.Max_Thread_Count) || Settings.Total_Threads_Run == 0)//start threads
                    {
                       Thread Search_Thread = new Thread(() => Start_Threaded_Search(Settings.Total_Threads_Run));
                       Search_Thread.Start();
                       Thread.Sleep(1000);//wait for thread to start
                    }
                    while (Settings.Running_Thread_Count >= Settings.Max_Thread_Count)//wait for 1 thread to finish when max limit is hit. sleep becuz no work to do while threads work
                    {
                        Thread.Sleep(Settings.Thread_Sleep_Time);
                    }
                }
                while (Settings.Running_Thread_Count != 0)//wait for started threads to finish
                {
                    Thread.Sleep(Settings.Thread_Sleep_Time);
                }
                Start_Output_Post_Run();
            }
            Settings.UPDATE_EventLog_w_PlaceKeeper_File();
        }

        private static void Start_Threaded_Search(int Index)
        {
            Settings.Running_Thread_Count++;
            Settings.Total_Threads_Run++;
            try
            {
                Read_EventLog EVNT_Log = new Read_EventLog();

                Sec_Checks.Live_Run_Sec_Checks(Settings.EventLog_w_PlaceKeeper_List.ElementAt(Index));

                EVNT_Log.READ_EventLog(Settings.EventLog_w_PlaceKeeper_List.ElementAt(Index), Settings.EventLog_w_PlaceKeeper[Settings.EventLog_w_PlaceKeeper_List.ElementAt(Index)]);

                Search_EventLog search_Obj = new Search_EventLog(EVNT_Log.EventLog_Log_API.Contents_of_EventLog);

                Settings.SWELF_Events_Of_Interest_Matching_EventLogs = search_Obj.Search(Settings.EventLog_w_PlaceKeeper_List.ElementAt(Index));
            }
            catch (Exception e)
            {
                if (e.Message == "Object reference not set to an instance of an object.")
                {
                    Error_Operation.Log_Error("Start_Read_Search_Write_Forward_EventLogs()", Settings.EventLog_w_PlaceKeeper_List.ElementAt(Settings.Total_Threads_Run-1) + " " + e.Message.ToString(), Error_Operation.LogSeverity.Verbose);
                }
                else if (e.Message.ToString().Contains("The process cannot access the file"))
                {
                    Error_Operation.Log_Error("Start_Read_Search_Write_Forward_EventLogs()", e.Message.ToString()+" OS File lock of vital resource at runtime.", Error_Operation.LogSeverity.Informataion);
                }
                else
                {
                    Error_Operation.Log_Error("Start_Read_Search_Write_Forward_EventLogs()", " " + Settings.EventLog_w_PlaceKeeper_List.ElementAt(Settings.Total_Threads_Run) + " x=" + (Settings.Total_Threads_Run).ToString() + " " + e.Message.ToString() + ". Check search Syntx", Error_Operation.LogSeverity.Informataion);
                }
            }
            Settings.Running_Thread_Count--;
        }

        internal static void Start_Output_Post_Run()
        {
            if (Settings.SWELF_Events_Of_Interest_Matching_EventLogs.Count > 0)
            {
                try
                {
                    if (Settings.output_csv && Program_Start_Args.Count >= 3 && (Settings.Log_Forwarders_HostNames.Count < 1))
                    {
                        File_Operation.Write_Ouput_CSV(Settings.CMDLine_Output_CSV, Settings.SWELF_Events_Of_Interest_Matching_EventLogs);
                    }
                    else
                    {
                        Log_Network_Forwarder.SEND_Logs(Settings.SWELF_Events_Of_Interest_Matching_EventLogs);
                    }
                }
                catch (Exception e)
                {
                    Error_Operation.Log_Error("Start_Output_Post_Run()  Network_Forwarder.SEND_Logs() File_Operation.Write_Ouput_CSV()", e.Message.ToString(), Error_Operation.LogSeverity.Warning);
                }

                if (Settings.Logs_Sent_to_ALL_Collectors)
                {
                    Start_Write_To_SWELF_EventLogs();
                }
                Sec_Checks.Post_Run_Sec_Checks();
            }
        }

        private static void Start_ReadLocal_Logs()
        {
            Read_Local_Files.READ_Local_Log_Files();
            Read_Local_Files.READ_Local_Log_Dirs();
        }

        private static void Start_Write_To_SWELF_EventLogs()
        {
            for (int z = 0; z < Settings.SWELF_Events_Of_Interest_Matching_EventLogs.Count; ++z)
            {
                try
                {
                    EventLog_SWELF.WRITE_EventLog_From_SWELF_Search(Settings.SWELF_Events_Of_Interest_Matching_EventLogs.ElementAt(z));
                }
                catch (Exception e)
                {
                    Error_Operation.Log_Error("Start_Write_To_SWELF_EventLogs()", "An EventLog "+ Settings.SWELF_Events_Of_Interest_Matching_EventLogs.ElementAt(z).GET_XML_of_Log + " errored on write to SWELF Eventlog with the following error " + e.Message.ToString(),Error_Operation.LogSeverity.Warning);
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
                            Settings.READ_Search_Terms_File(false,false);
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
                    Error_Operation.Log_Error("Write_HashFile_IPsFile()", Settings.SWELF_AppConfig_Args[12] +" "+ e.Message.ToString(), Error_Operation.LogSeverity.Informataion);
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
                    Error_Operation.Log_Error("Write_HashFile_IPsFile()", Settings.SWELF_AppConfig_Args[11] + " " + e.Message.ToString(), Error_Operation.LogSeverity.Informataion);
                }
                File_Operation.Write_IP_Output(Settings.IP_List_EVT_Logs.Distinct().ToList());
            }
        }
     }
}

