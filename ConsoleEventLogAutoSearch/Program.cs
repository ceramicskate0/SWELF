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
            else if (Program_Start_Args.Count>1 && (Program_Start_Args.Contains("-dissolve".ToLower())==false))
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
                    Errors.Log_Error("ALERT: SWELF MAIN ERROR: ", e.Message.ToString() + ", Also the app halted.");
                    Start_Write_Errors();
                    Stop(2);
                }
            }
        }

        public static void Start_EVTX_Process()
        {
            try
            {
                PARSE_Commandline_Input();

                Search_EventLogs search_Obj = new Search_EventLogs(EvntLogSearch.EVTX_File_Logs);

                Queue<EventLogEntry> Matchs_in_EVTS_File = search_Obj.Search(Settings.CMDLine_EVTX_File);

                Output_File.Write_Ouput_CSV(Settings.CMDLine_Output_CSV, Matchs_in_EVTS_File);

                if (Settings.CMDLine_Dissolve)
                {
                    Settings.Dissolve();
                }
            }
            catch (Exception e)
            {
                Errors.Log_Error("ALERT: SWELF EVTX_Process ERROR: ", "Start_EVTX_Process() " + e.Message.ToString());
                HostEventLogAgent_Eventlog.WRITE_Critical_EventLog("ALERT: SWELF EVTX_Process ERROR: Start_EVTX_Process() " + e.Message.ToString());
                Start_Write_Errors();
                Stop(2);
            }
        }

        public static void Start_Live_Process()
        {
            if (Sec_Checks.Run_Sec_Checks())
            {
                if (Program_Start_Args.ElementAt(0).ToLower().Equals("-dissolve") && Settings.FIND_EventLog_Exsits(Settings.SWELF_EventLog_Name) == false && Settings.VERIFY_if_File_Exists(Settings.GET_ErrorLog_Location))
                {
                    Settings.CMDLine_Dissolve = true;
                }
                Start_Setup();
                if (Settings.CHECK_If_Running_as_Admin())
                {
                Start_Run_Plugins();
                Start_Read_Search_Write_Forward_EventLogs();
                }
                else
                {
                   Errors.Log_Error("ERROR: If (SWELFisAdmin)", Settings.ComputerName+" SWELF MAIN ERROR: APP not running as admin and was unable to read eventlogs.");
                   Start_Write_Errors();
                }
                Start_ReadLocal_Logs();
                Start_Send_File_Based_Logs();
                Start_Write_Errors();
            }
            else
            {
                Errors.Log_Error("ALERT: SWELF:","SECURITY CHECKS FAILED ON " + Environment.MachineName +". SWELF did not run due to possible tampering.");
                Start_Write_Errors();
            }
            if (Settings.CMDLine_Dissolve)
            {
                Settings.Dissolve();
            }
        }

        public static void Stop(int error_code)
        {
            Environment.Exit(error_code);
        }

        private static void Start_Setup()
        {
            //CHECK_If_Running_as_Admin();
            try
            {
                Settings.InitializeAppSettings();
            }
            catch (Exception e)
            {
                Errors.Log_Error("ALERT: SWELF MAIN ERROR: ", "Settings.InitializeAppSettings() " + e.Message.ToString());
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
                    PSLog.Severity = "Informational";
                    PSLog.EventData=Powershell_Plugin.Run_PS_Script(Settings.Plugin_Search_Terms_Unparsed.ElementAt(x).Split(Settings.SplitChar_SearchCommandSplit)[0], Settings.Plugin_Search_Terms_Unparsed.ElementAt(x).Split(Settings.SplitChar_SearchCommandSplit)[2]);

                    if (PSLog.EventData.Contains(Settings.Plugin_Search_Terms_Unparsed.ElementAt(x).Split(Settings.SplitChar_SearchCommandSplit)[1]) || string.IsNullOrEmpty(Settings.Plugin_Search_Terms_Unparsed.ElementAt(x).Split(Settings.SplitChar_SearchCommandSplit)[1]))
                    {
                        EvntLogSearch.EventLog_Log_API.EventLogs_From_WindowsAPI.Enqueue(PSLog);
                        try
                        {
                            HostEventLogAgent_Eventlog.WRITE_EventLog_From_SWELF_Search(EvntLogSearch.EventLog_Log_API.EventLogs_From_WindowsAPI.ElementAt(0));
                            if (Settings.GET_LogCollector_Location().ToString().Contains("127.0.0.1") == false || String.IsNullOrWhiteSpace(Settings.GET_LogCollector_Location().ToString()) == false)//Does admin want to send off logs?
                            {
                                for (int z = 0; z < EvntLogSearch.EventLog_Log_API.EventLogs_From_WindowsAPI.Count; ++z)
                                {
                                    Network_Forwarder.SEND_Logs(EvntLogSearch.EventLog_Log_API.EventLogs_From_WindowsAPI.Dequeue());
                                }
                            }
                        }
                        catch (Exception e)
                        {
                            Errors.Log_Error("ALERT: SWELF WRITE/SEND EVENT LOG ERROR: ", Settings.EventLog_w_PlaceKeeper_List.ElementAt(x) + " HostEventLogAgent_Eventlog.WRITE_EventLog " + e.Message.ToString());
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Errors.Log_Error("SWELF PLUGIN ERROR: ", "Powershell_Plugin.Run_PS_Script() " + e.Message.ToString());
                Network_Forwarder.SEND_Data_from_File("SWELF PLUGIN ERROR: Powershell_Plugin.Run_PS_Script() - " + e.Message.ToString());
            }
        }

        private static void Start_Read_Search_Write_Forward_EventLogs()
        {
            if (Settings.EventLog_w_PlaceKeeper_List.Count > 0)
            {
                for (int x = 0; x < Settings.EventLog_w_PlaceKeeper_List.Count; ++x)//READ and Search
                {
                    try
                    {
                        EvntLogSearch.READ_EventLog(Settings.EventLog_w_PlaceKeeper_List.ElementAt(x), Settings.EventLog_w_PlaceKeeper[Settings.EventLog_w_PlaceKeeper_List.ElementAt(x)]);
                        Search_EventLogs search_Obj = new Search_EventLogs(EvntLogSearch.EventLog_Log_API.EventLogs_From_WindowsAPI);
                        //this is the issue with carry over list set = to new list
                        EvntLogSearch.EventLog_Log_API.EventLogs_From_WindowsAPI = search_Obj.Search(Settings.EventLog_w_PlaceKeeper_List.ElementAt(x));
                        search_Obj.Clear_Search();
                    }
                    catch (Exception e)
                    {
                        if (e.Message == "Object reference not set to an instance of an object.")
                        {
                            Errors.Log_Error("ALERT: SWELF: ", Settings.EventLog_w_PlaceKeeper_List.ElementAt(x) + " Event Log Empty.");
                        }
                        else
                        {
                            Errors.Log_Error("ALERT: SWELF APP ERROR: ", Settings.EventLog_w_PlaceKeeper_List.ElementAt(x) + " " + e.Message.ToString());
                        }
                    }
                    Start_Write_To_SWELF_EventLogs(x);
                    try
                    {
                        if (Program_Start_Args.Contains("-output_csv".ToLower()) && Program_Start_Args.Count == 3 && (Settings.GET_LogCollector_Location().Count < 1))
                        {
                            Output_File.Write_Ouput_CSV(Settings.CMDLine_Output_CSV, EvntLogSearch.EventLog_Log_API.EventLogs_From_WindowsAPI);
                        }
                        else
                        {
                            Start_Send_EventLogs();
                        }
                    }
                    catch (Exception e)
                    {
                        Errors.Log_Error("SWELF NETWORK ERROR: ", e.Message.ToString());
                    }
                    EvntLogSearch.EventLog_Log_API.Clear();
                    EvntLogSearch.Clear_EventLogFileName();
                }
                Settings.UPDATE_EventLog_w_PlaceKeeper_File();
            }
        }

        private static void Start_ReadLocal_Logs()
        {
            EvntLogSearch.READ_Local_Log_Files();
            EvntLogSearch.READ_Local_Log_Dirs();
        }

        private static void Start_Write_To_SWELF_EventLogs(int x)
        {
            for (int z = 0; z < EvntLogSearch.EventLog_Log_API.EventLogs_From_WindowsAPI.Count; ++z)
            {
                try
                {
                    HostEventLogAgent_Eventlog.WRITE_EventLog_From_SWELF_Search(EvntLogSearch.EventLog_Log_API.EventLogs_From_WindowsAPI.ElementAt(z));
                }
                catch (Exception e)
                {
                    Errors.Log_Error("ALERT: SWELF WRITE EVENT LOG ERROR: ", Settings.EventLog_w_PlaceKeeper_List.ElementAt(x) + " HostEventLogAgent_Eventlog.WRITE_EventLog " + e.Message.ToString());
                }
            }
        }

        private static void Start_Send_EventLogs()
        {
            if (Settings.GET_LogCollector_Location().ToString().Contains("127.0.0.1") == false || String.IsNullOrWhiteSpace(Settings.GET_LogCollector_Location().ToString()) == false)//Does admin want to send off logs?
            {
                for (int x = 0; x < EvntLogSearch.EventLog_Log_API.EventLogs_From_WindowsAPI.Count; ++x)
                {
                    Network_Forwarder.SEND_Logs(EvntLogSearch.EventLog_Log_API.EventLogs_From_WindowsAPI.Dequeue());
                }
            }
        }

        private static void Start_Send_File_Based_Logs()
        {
            try
            {
                if (Settings.GET_LogCollector_Location().ToString().Contains("127.0.0.1") == false || String.IsNullOrWhiteSpace(Settings.GET_LogCollector_Location().ToString()) == false)
                {
                    for (int z = 0; z < EvntLogSearch.FileContents_From_FileReads.Count; ++z)
                    {
                        HostEventLogAgent_Eventlog.WRITE_EventLog_From_SWELF_Search(EvntLogSearch.FileContents_From_FileReads.ElementAt(z));
                        Network_Forwarder.SEND_Data_from_File(EvntLogSearch.FileContents_From_FileReads.ElementAt(z));
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
                    case "-help":
                        {
                            Settings.SHOW_Help_Menu();
                            break;
                        }
                    case "-output_csv":
                        {
                            Settings.CMDLine_Output_CSV = Program_Start_Args.ElementAt(x + 1);
                            break;
                        }
                    case "-evtx_file":
                        {
                            Settings.CMDLine_EVTX_File= Program_Start_Args.ElementAt(x + 1);
                            EvntLogSearch.READ_EVTX_File(Settings.CMDLine_EVTX_File);
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
        }
}

