//Written by Ceramicskate0
//Copyright 2018
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Principal;
using System.Diagnostics.Eventing.Reader;
using System.Diagnostics.Eventing;
using System.Diagnostics;


namespace SWELF
{
    class Program
    {
        private static ReadEventLog EvntLogSearch = new ReadEventLog();

        public static void Main(string[] args)
        {
            
            try
            {
                Start_Setup();

                Start_Read_Search_Write_Forward_EventLogs();

                Start_ReadLocal_Logs();

                Start_Send_File_Based_Logs();

                Start_Write_Errors();
            }
            catch (Exception e)
            {
                Errors.Log_Error("ALERT: SWELF MAIN ERROR: ", e.Message.ToString() + ", Also the app died");
                Start_Write_Errors();
                Environment.Exit(2);
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
                Errors.Log_Error("ALERT: SWELF MAIN ERROR: ", "Settings.InitializeAppSettings() " + e.Message.ToString());
                HostEventLogAgent_Eventlog.WRITE_All_App_EventLog(Settings.CriticalEvents);
                Start_Write_Errors();
                Environment.Exit(2);
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
                        Search_EventLogs search_Obj = new Search_EventLogs(EvntLogSearch.EventLog_Log_File.EventLogs_From_WindowsAPI);
                        EvntLogSearch.EventLog_Log_File.EventLogs_From_WindowsAPI = search_Obj.Search(Settings.EventLog_w_PlaceKeeper_List.ElementAt(x));
                    }
                    catch (Exception e)
                    {
                        Errors.Log_Error("ALERT: SWELF APP ERROR: ", Settings.EventLog_w_PlaceKeeper_List.ElementAt(x) + " " + e.Message.ToString());
                    }
                    Start_Write_To_SWELF_EventLogs(x);
                }
                try
                {
                    Start_Send_EventLogs();
                }
                catch (Exception e)
                {
                    Errors.Log_Error("SWELF NETWORK ERROR: ", e.Message.ToString());
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
            for (int z = 0; z < EvntLogSearch.EventLog_Log_File.EventLogs_From_WindowsAPI.Count; ++z)
            {
                try
                {
                    HostEventLogAgent_Eventlog.WRITE_EventLog(EvntLogSearch.EventLog_Log_File.EventLogs_From_WindowsAPI.ElementAt(z).EventData);
                }
                catch (Exception e)
                {
                    Errors.Log_Error("ALERT: SWELF WRITE EVENT LOG ERROR: ", Settings.EventLog_w_PlaceKeeper_List.ElementAt(x) + " HostEventLogAgent_Eventlog.WRITE_EventLog " + e.Message.ToString());
                }
            }
        }

        private static void Start_Send_EventLogs()
        {
            if (Settings.GET_LogCollector_Location().ToString().Contains("127.0.0.1") == false && String.IsNullOrWhiteSpace(Settings.GET_LogCollector_Location().ToString()) == false)//Does admin want to send off logs?
            {
                for (int x = 0; x < EvntLogSearch.EventLog_Log_File.EventLogs_From_WindowsAPI.Count; ++x)
                {
                    Network_Forwarder.SEND_Eventlogs(EvntLogSearch.EventLog_Log_File.EventLogs_From_WindowsAPI.Dequeue());
                }
            }
        }

        private static void Start_Send_File_Based_Logs()
        {
            try
            {
                if (Settings.GET_LogCollector_Location().ToString().Contains("127.0.0.1") == false && String.IsNullOrWhiteSpace(Settings.GET_LogCollector_Location().ToString()) == false)
                {
                    for (int z = 0; z < EvntLogSearch.FileContents_From_FileReads.Count; ++z)
                    {
                        HostEventLogAgent_Eventlog.WRITE_EventLog(EvntLogSearch.FileContents_From_FileReads.ElementAt(z));
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

        private static bool CHECK_If_Running_as_Admin()
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
    }
}
