//Written by Ceramicskate0
//Copyright 2018
using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;

namespace SWELF
{
    public class Program
    {
        private static Read_EventLog EvntLogSearch = new Read_EventLog();
        private static List<string> Program_Start_Args = new List<string>();

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
                    Settings.Stop(1265);
                }
            }
        }

        private static void Start_EVTX_Process()
        {
            try
            {
                PARSE_Commandline_Input();

                Search_EventLogs search_Obj = new Search_EventLogs(EvntLogSearch.EVTX_File_Logs);

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
            }
            catch (Exception e)
            {
                Errors.Log_Error("Start_EVTX_Process() ", e.Message.ToString(),Errors.LogSeverity.Warning);
                EventLog_SWELF.WRITE_Critical_EventLog("Start_EVTX_Process() " + e.Message.ToString());
                Settings.Stop(1265);
            }
        }

        private static void Start_Live_Process()
        {
            if (Sec_Checks.Pre_Run_Sec_Checks() && Sec_Checks.CHECK_If_Running_as_Admin())
            {
                if (Program_Start_Args.ElementAt(0).ToLower().Equals("-dissolve") && Settings.FIND_EventLog_Exsits(Settings.SWELF_EventLog_Name) == false && File_Operation.VERIFY_if_File_Exists(Settings.GET_ErrorLog_Location))
                {
                    Settings.CMDLine_Dissolve = true;
                }
                Start_Setup();
                Start_Run_Plugins();
                Start_Read_Search_Write_Forward_EventLogs();
                Start_ReadLocal_Logs();
                Start_Send_File_Based_Logs();
                GC.Collect();
                Settings.Start_Write_Errors();
                Write_HashFile_IPsFile();
                Encryptions.Lock_File(Settings.GET_EventLogID_PlaceHolder);
            }
            else
            {
                EventLog_SWELF.WRITE_Critical_EventLog("Sec_Checks.Pre_Run_Sec_Checks() && Sec_Checks.CHECK_If_Running_as_Admin(). APP FAILED Statement.");
                Settings.Stop(1265);
            }
            if (Settings.CMDLine_Dissolve)
            {
                Settings.Dissolve();
            }
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
                EventLog_SWELF.WRITE_Critical_EventLog("ALERT: SWELF MAIN ERROR: Settings.InitializeAppSettings() " + e.Message.ToString());
                Settings.Stop(1265);
            }
        }

        private static void Start_Run_Plugins()
        {
            try
            {
                for (int x = 0; x < Settings.Plugin_Search_Terms_Unparsed.Count; ++x)
                {
                    EventLog_Entry PSLog = new EventLog_Entry();
                    PSLog.ComputerName = Settings.ComputerName;
                    PSLog.EventID = 3;
                    PSLog.LogName = "SWELF Powershell Plugin Output";
                    PSLog.Severity = "Information";
                    PSLog.CreatedTime = DateTime.Now;
                    PSLog.TaskDisplayName = "SWELF Powershell Plugin Output";
                    PSLog.UserID = Environment.UserName;
                    char spliter=Settings.SplitChar_SearchCommandSplit[0];
                    PSLog.EventData=Powershell_Plugin.Run_PS_Script(Settings.Plugin_Search_Terms_Unparsed.ElementAt(x).Split(spliter).ElementAt(0), Settings.Plugin_Search_Terms_Unparsed.ElementAt(x).Split(spliter).ElementAt(2));

                    if (PSLog.EventData.ToLower().Contains(Settings.Plugin_Search_Terms_Unparsed.ElementAt(x).Split(spliter).ElementAt(1).ToLower()))
                    {
                        Settings.SWELF_Events_Of_Interest_Matching_EventLogs.Enqueue(PSLog);
                        try
                        {
                            EventLog_SWELF.WRITE_EventLog_From_SWELF_Search(Settings.SWELF_Events_Of_Interest_Matching_EventLogs.ElementAt(0));
                            if (Settings.GET_LogCollector_Location().ToString().Contains("127.0.0.1") == false || String.IsNullOrWhiteSpace(Settings.GET_LogCollector_Location().ToString()) == false)//Does admin want to send off logs?
                            {
                                for (int z = 0; z < Settings.SWELF_Events_Of_Interest_Matching_EventLogs.Count; ++z)
                                {
                                    Network_Forwarder.SEND_Logs(Settings.SWELF_Events_Of_Interest_Matching_EventLogs.Dequeue());
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
                Settings.Start_Write_Errors();
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

                        Settings.SWELF_Events_Of_Interest_Matching_EventLogs = search_Obj.Search(Settings.EventLog_w_PlaceKeeper_List.ElementAt(x));

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
                }
                Start_Output_Post_Run();
            }
            GC.Collect();
            File_Operation.UPDATE_EventLog_w_PlaceKeeper_File();
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
                        File_Operation.Write_Ouput_CSV(Settings.CMDLine_Output_CSV, Settings.SWELF_Events_Of_Interest_Matching_EventLogs);
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
            Read_LocalFiles.READ_Local_Log_Files();
            Read_LocalFiles.READ_Local_Log_Dirs();
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
                    for (int z = 0; z < Read_LocalFiles.FileContents_From_FileReads.Count; ++z)
                    {
                        EventLog_SWELF.WRITE_EventLog_From_SWELF_Search(Read_LocalFiles.FileContents_From_FileReads.ElementAt(z));
                        Network_Forwarder.SEND_Data_from_File(Read_LocalFiles.FileContents_From_FileReads.ElementAt(z));
                    }
                }
            }
            catch (Exception e)//network resource unavailable. Dont send data and try again next run. No logs will be queued by app only re read
            {
                Settings.Log_Storage_Location_Unavailable(e.Message.ToString());
            }
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
            if (System_Performance_Info.CHECK_Total_Memory_Useage() <= System_Performance_Info.SWELF_Memory_MIN_Threshold)
            {
                if (System_Performance_Info.Current_Memory_Dump_Retry_Number >= System_Performance_Info.Max_Memory_Dump_Retry_Number)
                {
                    Errors.Log_Error("CHECK_Memory() ", "SWELF Detected MAXIMUM Memory useage and stopped after " + System_Performance_Info.Max_Memory_Dump_Retry_Number.ToString() + " tries to resolve issue.", Errors.LogSeverity.Critical);
                    EventLog_SWELF.WRITE_Critical_EventLog("SWELF Detected MAXIMUM Memory useage and stopped after " + System_Performance_Info.Max_Memory_Dump_Retry_Number.ToString() + " tries to resolve issue.");
                    Settings.Stop(1265);
                }
                else
                {
                    System_Performance_Info.Current_Memory_Dump_Retry_Number++;
                    Start_Output_Post_Run();
                }
            }
        }

        private static void Write_HashFile_IPsFile()
        {
            //TODO Do file size limit check if over size delete old data and replace with only new
            if (Settings.AppConfig_File_Args.ContainsKey("output_hashs"))
            {
                try
                {
                    if (File.Exists(Settings.Hashs_File))
                    {
                        Settings.Hashs_From_EVT_Logs.AddRange(File_Operation.READ_File_In(Settings.Hashs_File).Distinct().ToList());
                        Settings.Hashs_From_EVT_Logs = Settings.Hashs_From_EVT_Logs.Distinct().ToList();
                    }
                    File_Operation.Write_Hash_Output(Settings.Hashs_From_EVT_Logs.Distinct().ToList());
                }
                catch
                {

                }
            }
            if (Settings.AppConfig_File_Args.ContainsKey("output_ips"))
            {
                try
                {
                    if (File.Exists(Settings.IPs_File))
                    {
                        Settings.IP_List_EVT_Logs.AddRange(File_Operation.READ_File_In(Settings.IPs_File).Distinct().ToList());
                        Settings.IP_List_EVT_Logs = Settings.IP_List_EVT_Logs.Distinct().ToList();
                    }
                }
                catch
                {

                }
                File_Operation.Write_IP_Output(Settings.IP_List_EVT_Logs.Distinct().ToList());
            }
        }
     }
}

