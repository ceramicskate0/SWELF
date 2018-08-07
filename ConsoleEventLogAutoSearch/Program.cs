//Written by Ceramicskate0
//Copyright 2018
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ServiceProcess;
using System.Threading;
using System.Configuration.Install;
using System.ComponentModel;
using System.Net;
using System.Diagnostics;
using System.Security.Permissions;

namespace SWELF
{
    public class Program
    {
        private static ReadEventLog EvntLogSearch = new ReadEventLog();
        public static List<string> Program_Start_Args = new List<string>();

        public static void Main(string[] args)
        {
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
                    Start_Live_Process();
                }
                catch (Exception e)
                {
                    Errors.Log_Error("Start_Live_Process() ", e.Message.ToString() + ", Also the app halted.", Errors.LogSeverity.Critical);
                    Start_Write_Errors();
                    Stop(2);
                }
            }
        }

        private static void Start_EVTX_Process()
        {
            try
            {
                PARSE_Commandline_Input();

                Search_EventLogs search_Obj = new Search_EventLogs(EvntLogSearch.EVTX_File_Logs);

                Settings.SWELF_Events_Of_Interest_Matching_EventLogs = search_Obj.Search(Settings.CMDLine_EVTX_File, Settings.SWELF_Events_Of_Interest_Matching_EventLogs);

                if (Settings.output_csv)
                {
                    Output_File.Write_Ouput_CSV(Settings.CMDLine_Output_CSV, Settings.SWELF_Events_Of_Interest_Matching_EventLogs);
                }
                else
                {
                    Start_Write_To_SWELF_EventLogs();
                }

                if (Settings.CMDLine_Dissolve)
                {
                    Settings.Dissolve();
                }
            }
            catch (Exception e)
            {
                Errors.Log_Error("Start_EVTX_Process() ", e.Message.ToString(),Errors.LogSeverity.Warning);
                HostEventLogAgent_Eventlog.WRITE_Critical_EventLog("Start_EVTX_Process() " + e.Message.ToString());
                Start_Write_Errors();
                Stop(2);
            }
        }

        private static void Start_Live_Process()
        {
            if (Sec_Checks.Pre_Run_Sec_Checks() && Settings.CHECK_If_Running_as_Admin())
            {
                if (Program_Start_Args.ElementAt(0).ToLower().Equals("-dissolve") && Settings.FIND_EventLog_Exsits(Settings.SWELF_EventLog_Name) == false && Settings.VERIFY_if_File_Exists(Settings.GET_ErrorLog_Location))
                {
                    Settings.CMDLine_Dissolve = true;
                }
                Start_Setup();
                Start_Run_Plugins();
                Start_Read_Search_Write_Forward_EventLogs();
                Start_ReadLocal_Logs();
                Start_Send_File_Based_Logs();
                GC.Collect();
                Start_Write_Errors();
            }
            else
            {
                Stop(1265);
            }
            if (Settings.CMDLine_Dissolve)
            {
                Settings.Dissolve();
            }
        }

        private static void Stop(int error_code)
        {
            Environment.Exit(error_code);
        }

        private static void Start_Setup()
        {
            try
            {
                Settings.InitializeAppSettings();
            }
            catch (Exception e)
            {
                Errors.Log_Error("Settings.InitializeAppSettings()", e.Message.ToString(), Errors.LogSeverity.Warning);
                HostEventLogAgent_Eventlog.WRITE_Critical_EventLog("ALERT: SWELF MAIN ERROR: Settings.InitializeAppSettings() " + e.Message.ToString());
                Start_Write_Errors();
                Stop(2);
            }
        }

        private static void Start_Run_Plugins()
        {
            try
            {
                for (int x = 0; x < Settings.Plugin_Search_Terms_Unparsed.Count; ++x)
                {
                    EventLogEntry PSLog = new EventLogEntry();
                    PSLog.ComputerName = Settings.ComputerName;
                    PSLog.EventID = 3;
                    PSLog.LogName = "SWELF Powershell Plugin "+ Settings.Plugin_Search_Terms_Unparsed.ElementAt(x).Split(Settings.SplitChar_SearchCommandSplit)[0];
                    PSLog.Severity = "Information";
                    char spliter=Settings.SplitChar_SearchCommandSplit[0];
                    PSLog.EventData=Powershell_Plugin.Run_PS_Script(Settings.Plugin_Search_Terms_Unparsed.ElementAt(x).Split(spliter).ElementAt(0), Settings.Plugin_Search_Terms_Unparsed.ElementAt(x).Split(spliter).ElementAt(2));

                    if (PSLog.EventData.Contains(Settings.Plugin_Search_Terms_Unparsed.ElementAt(x).Split(spliter).ElementAt(1)))
                    {
                        EvntLogSearch.EventLog_Log_API.Contents_of_EventLog.Enqueue(PSLog);
                        try
                        {
                            HostEventLogAgent_Eventlog.WRITE_EventLog_From_SWELF_Search(EvntLogSearch.EventLog_Log_API.Contents_of_EventLog.ElementAt(0));
                            if (Settings.GET_LogCollector_Location().ToString().Contains("127.0.0.1") == false || String.IsNullOrWhiteSpace(Settings.GET_LogCollector_Location().ToString()) == false)//Does admin want to send off logs?
                            {
                                for (int z = 0; z < EvntLogSearch.EventLog_Log_API.Contents_of_EventLog.Count; ++z)
                                {
                                    Network_Forwarder.SEND_Logs(EvntLogSearch.EventLog_Log_API.Contents_of_EventLog.Dequeue());
                                }
                            }
                        }
                        catch (Exception e)
                        {
                            Errors.Log_Error("Start_Run_Plugins()", Settings.EventLog_w_PlaceKeeper_List.ElementAt(x) + " HostEventLogAgent_Eventlog.WRITE_EventLog " + e.Message.ToString(), Errors.LogSeverity.Verbose);
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Errors.Log_Error("Powershell_Plugin.Run_PS_Script() " , e.Message.ToString(), Errors.LogSeverity.Warning);
                Network_Forwarder.SEND_Data_from_File("Powershell_Plugin.Run_PS_Script() - " + e.Message.ToString());
                Start_Write_Errors();
            }
        }

        private static void Start_Read_Search_Write_Forward_EventLogs()
        {
            if (Settings.EventLog_w_PlaceKeeper_List.Count > 0)
            {
                Sec_Checks.Pre_Live_Run_Sec_Checks();
                for (int x = 0; x < Settings.EventLog_w_PlaceKeeper_List.Count; ++x)//READ and Search
                {
                    try
                    {
                        Sec_Checks.Live_Run_Sec_Checks(Settings.EventLog_w_PlaceKeeper_List.ElementAt(x));

                        EvntLogSearch.READ_EventLog(Settings.EventLog_w_PlaceKeeper_List.ElementAt(x), Settings.EventLog_w_PlaceKeeper[Settings.EventLog_w_PlaceKeeper_List.ElementAt(x)]);

                        Search_EventLogs search_Obj = new Search_EventLogs(EvntLogSearch.EventLog_Log_API.Contents_of_EventLog);

                        Settings.SWELF_Events_Of_Interest_Matching_EventLogs = search_Obj.Search(Settings.EventLog_w_PlaceKeeper_List.ElementAt(x), Settings.SWELF_Events_Of_Interest_Matching_EventLogs);

                        GC.Collect();

                        CHECK_Memory();
                    }
                    catch (Exception e)
                    {
                        if (e.Message == "Object reference not set to an instance of an object.")
                        {
                            Errors.Log_Error("Start_Read_Search_Write_Forward_EventLogs() ", Settings.EventLog_w_PlaceKeeper_List.ElementAt(x) + " Event Log Empty.", Errors.LogSeverity.Verbose);
                        }
                        else
                        {
                            Errors.Log_Error("Start_Read_Search_Write_Forward_EventLogs()", Settings.EventLog_w_PlaceKeeper_List.ElementAt(x) + " " + e.Message.ToString(), Errors.LogSeverity.Warning);
                        }
                    }
                    GC.Collect();
                }
                Start_Output_Post_Run();
            }
            //EvntLogSearch.EventLog_Log_API.Clear();
            //EvntLogSearch.Clear_EventLogFileName();
            GC.Collect();
            Settings.UPDATE_EventLog_w_PlaceKeeper_File();
        }

        private static void Start_Output_Post_Run()
        {
            if (Settings.SWELF_Events_Of_Interest_Matching_EventLogs.Count > 0)
            {
                Start_Write_To_SWELF_EventLogs();
                try
                {
                    if (Settings.output_csv && Program_Start_Args.Count >= 3 && (Settings.GET_LogCollector_Location().Count < 1))
                    {
                        Output_File.Write_Ouput_CSV(Settings.CMDLine_Output_CSV, Settings.SWELF_Events_Of_Interest_Matching_EventLogs);
                    }
                    else
                    {
                        Start_Send_EventLogs();
                    }
                }
                catch (Exception e)
                {
                    Errors.Log_Error("Start_Read_Search_Write_Forward_EventLogs()", e.Message.ToString(), Errors.LogSeverity.Warning);
                }
                Sec_Checks.Post_Run_Sec_Checks(Settings.SWELF_Events_Of_Interest_Matching_EventLogs.Count);
            }
            GC.Collect();
        }

        private static void Start_ReadLocal_Logs()
        {
            ReadLocalFiles.READ_Local_Log_Files();
            ReadLocalFiles.READ_Local_Log_Dirs();
        }

        private static void Start_Write_To_SWELF_EventLogs()
        {
            for (int z = 0; z < Settings.SWELF_Events_Of_Interest_Matching_EventLogs.Count; ++z)
            {
                try
                {
                    HostEventLogAgent_Eventlog.WRITE_EventLog_From_SWELF_Search(Settings.SWELF_Events_Of_Interest_Matching_EventLogs.ElementAt(z));
                }
                catch (Exception e)
                {
                    Errors.Log_Error("Start_Write_To_SWELF_EventLogs()", "An EventLog "+ Settings.SWELF_Events_Of_Interest_Matching_EventLogs.ElementAt(z) + " errored on write to SWELF Eventlog with the following error " + e.Message.ToString(),Errors.LogSeverity.Warning);
                }
            }
        }

        private static void Start_Send_EventLogs()
        {
            if (Settings.GET_LogCollector_Location().ToString().Contains("127.0.0.1") == false || String.IsNullOrWhiteSpace(Settings.GET_LogCollector_Location().ToString()) == false)//Does admin want to send off logs?
            {
                for (int x = 0; x < Settings.SWELF_Events_Of_Interest_Matching_EventLogs.Count; ++x)
                {
                    Network_Forwarder.SEND_Logs(Settings.SWELF_Events_Of_Interest_Matching_EventLogs.Dequeue());
                }
            }
        }

        private static void Start_Send_File_Based_Logs()
        {
            try
            {
                if (Settings.GET_LogCollector_Location().ToString().Contains("127.0.0.1") == false || String.IsNullOrWhiteSpace(Settings.GET_LogCollector_Location().ToString()) == false)
                {
                    for (int z = 0; z < ReadLocalFiles.FileContents_From_FileReads.Count; ++z)
                    {
                        HostEventLogAgent_Eventlog.WRITE_EventLog_From_SWELF_Search(ReadLocalFiles.FileContents_From_FileReads.ElementAt(z));
                        Network_Forwarder.SEND_Data_from_File(ReadLocalFiles.FileContents_From_FileReads.ElementAt(z));
                    }
                }
            }
            catch (Exception e)//network resource unavailable. Dont send data and try again next run. No logs will be queued by app only re read
            {
                Settings.Log_Storage_Location_Unavailable(e.Message.ToString());
            }
        }

        private static void Start_Write_Errors()
        {
            Errors.WRITE_Errors();
            Errors.SEND_Errors_To_Central_Location();
        }

        private static void PARSE_Commandline_Input()
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
                            Settings.READ_Search_Terms_File();
                            break;
                        }
                    case "-central_search_config":
                        {
                            Settings.CMDLine_Search_Terms = Program_Start_Args.ElementAt(x + 1);
                            Settings.READ_CENTRAL_SEARCH_Config_File(Program_Start_Args.ElementAt(x + 1));
                            Settings.READ_Search_Terms_File();
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

        private static void CHECK_Memory()
        {
            if (Settings.CHECK_Total_Memory_Useage() <= Settings.SWELF_Memory_MIN_Threshold)
            {
                if (Settings.Current_Memory_Dump_Retry_Number >= Settings.Max_Memory_Dump_Retry_Number)
                {
                    Errors.Log_Error("CHECK_Memory() ", "SWELF Detected MAXIMUM Memory useage and stopped after " + Settings.Max_Memory_Dump_Retry_Number.ToString() + " tries to resolve issue.", Errors.LogSeverity.Critical);
                    HostEventLogAgent_Eventlog.WRITE_Critical_EventLog("SWELF Detected MAXIMUM Memory useage and stopped after " + Settings.Max_Memory_Dump_Retry_Number.ToString() + " tries to resolve issue.");
                    Start_Write_Errors();
                    Stop(2);
                }
                else
                {
                    Settings.Current_Memory_Dump_Retry_Number++;
                    Start_Output_Post_Run();
                }
            }
        }
        }
}

