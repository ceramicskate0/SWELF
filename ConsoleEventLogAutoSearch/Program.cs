//Written by Ceramicskate0
//Copyright 2017
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics.Eventing.Reader;
using System.Diagnostics.Eventing;
using System.Diagnostics;

namespace ConsoleEventLogAutoSearch
{
    class Program
    {
        private static ReadEventLog EvntLogSearch = new ReadEventLog();

        public static void Main(string[] args)
        {
            try
            {
                try
                {
                    Settings.InitializeAppSettings();
                }
                catch (Exception e)
                {
                    Errors.Log_Error("SWELF MAIN ERROR: ", "Settings.InitializeAppSettings() "+e.Message.ToString());
                    HostEventLogAgent_Eventlog.WRITE_All_App_EventLog(Settings.CriticalEvents);
                    GC.Collect();
                    Environment.Exit(2);
                }
                if (Settings.EventLog_w_PlaceKeeper_List.Count > 0)
                {
                    for (int x = 0; x < Settings.EventLog_w_PlaceKeeper_List.Count; ++x)//READ and Search
                    {
                        try
                        {
                            EvntLogSearch.READ_EventLog(Settings.EventLog_w_PlaceKeeper_List.ElementAt(x), Settings.EventLog_w_PlaceKeeper[Settings.EventLog_w_PlaceKeeper_List.ElementAt(x)]);
                            Search_EventLogs search_Obj = new Search_EventLogs(EvntLogSearch.EventLog_Log_File.EventLogs_From_WindowsAPI);
                            EvntLogSearch.EventLog_Log_File.EventLogs_From_WindowsAPI = search_Obj.Search();
                        }
                        catch (Exception e)
                        {
                            Errors.Log_Error("SWELF ERROR: ", Settings.EventLog_w_PlaceKeeper_List.ElementAt(x)+ " "+e.Message.ToString());
                        }

                        for (int z = 0; z < EvntLogSearch.EventLog_Log_File.EventLogs_From_WindowsAPI.Count; ++z)
                        {
                            try
                            {
                                HostEventLogAgent_Eventlog.WRITE_EventLog(EvntLogSearch.EventLog_Log_File.EventLogs_From_WindowsAPI.ElementAt(z).EventData);
                            }
                            catch (Exception e)
                            {
                                Errors.Log_Error("SWELF ERROR: ", Settings.EventLog_w_PlaceKeeper_List.ElementAt(x) + " " + e.Message.ToString());
                            }
                        }
                    }
                    try
                    {
                        if (Settings.GET_LogCollector_Location().ToString().Contains("127.0.0.1") == true||String.IsNullOrWhiteSpace(Settings.GET_LogCollector_Location().ToString()) == false)//Does admin want to send off logs?
                        {
                            for (int x = 0; x < EvntLogSearch.EventLog_Log_File.EventLogs_From_WindowsAPI.Count; ++x)
                            {
                                Network_Forwarder.SEND_Data_from_Eventlogs(EvntLogSearch.EventLog_Log_File.EventLogs_From_WindowsAPI.Dequeue());
                            }
                        }
                    }
                    catch (Exception e)//network resource unavailable. Dont send data and try again next run. No logs will be queued by app only re read
                    {
                        Errors.Log_Error("NETWORK ERROR: ", e.Message.ToString());
                    }
                    Settings.UPDATE_EventLog_w_PlaceKeeper_File();
                }
                //Read all log files admin wants
                EvntLogSearch.READ_Local_Log_Files();
                EvntLogSearch.READ_Local_Log_Dirs();
                try
                {
                    if (Settings.GET_LogCollector_Location().ToString().Contains("127.0.0.1") == true || String.IsNullOrWhiteSpace(Settings.GET_LogCollector_Location().ToString()) == false)//Does admin want to send off logs?
                    {
                        for (int z = 0; z < EvntLogSearch.FileContents_From_FileReads.Count; ++z)//send data from local log files to network resource
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
            catch (Exception e)//WTF HAPPENED??!?!?!?!
            {
                Errors.Log_Error("MAIN() ERROR: ", e.Message.ToString() + ", Also the app died");
            }
            GC.Collect();
            Environment.Exit(0);
        }
    }
}
