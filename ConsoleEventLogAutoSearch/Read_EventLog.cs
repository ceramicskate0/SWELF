//Written by Ceramicskate0
//Copyright 2018
using System;
using System.Collections.Generic;
using System.Linq;
using System.Diagnostics.Eventing.Reader;
using System.IO;


namespace SWELF
{
    class Read_EventLog
    {
        private static EventRecord Windows_EventLog_from_API { get; set; }

        private string EvntLog_Name;
        public EventLog_File EventLog_Log_API;//windows live api read
        private static bool MissingLogInFileDueToException = false;
        public Queue<EventLog_Entry> EVTX_File_Logs = new Queue<EventLog_Entry>();
        private static EventLog_File EventLogFileName;

        public Read_EventLog()
        {
            EvntLog_Name = "";
        }

        public void Clear_EventLogFileName()
        {
            EventLogFileName.Clear();
        }

        public void READ_EventLog(string Eventlog_FullName,long PlaceKeeper_EventRecordID=1)
        {
            long EVTlog_PlaceHolder = PlaceKeeper_EventRecordID;
            try
            {
                if (EVTlog_PlaceHolder <= 1)
                {
                    EVTlog_PlaceHolder = Settings.EventLog_w_PlaceKeeper[Eventlog_FullName.ToLower()];
                }
            }
            catch
            {
                EVTlog_PlaceHolder = 1;
            }

            if (Settings.FIND_EventLog_Exsits(Eventlog_FullName))
            {
                EventLogFileName = new EventLog_File(Eventlog_FullName, PlaceKeeper_EventRecordID);
                long First_EventID = EventLogFileName.First_EventLogID_From_Check;
                long Last_EventID = EventLogFileName.Last_EventLogID_From_Check;

                if (PlaceKeeper_EventRecordID > First_EventID && PlaceKeeper_EventRecordID < Last_EventID)//Normal operation placekkeeper in middle of log file
                {
                    EVTlog_PlaceHolder = PlaceKeeper_EventRecordID;
                    READ_WindowsEventLog_API(Eventlog_FullName, EVTlog_PlaceHolder, EventLogFileName);
                    Settings.EventLog_w_PlaceKeeper[Eventlog_FullName.ToLower()] = Last_EventID;
                }
                else if (Last_EventID == PlaceKeeper_EventRecordID)//no logs added
                {
                    EVTlog_PlaceHolder = PlaceKeeper_EventRecordID;
                }
                else if (PlaceKeeper_EventRecordID==1)
                {
                    EVTlog_PlaceHolder = First_EventID;
                    READ_WindowsEventLog_API(Eventlog_FullName, EVTlog_PlaceHolder, EventLogFileName);
                    EventLog_SWELF.WRITE_Warning_EventLog("Logging as app or EventLog Source 1st run for "+ Eventlog_FullName +" "+ Settings.ComputerName);
                    Settings.EventLog_w_PlaceKeeper[Eventlog_FullName] = Last_EventID;
                }
                else if (First_EventID > PlaceKeeper_EventRecordID)//missed all logs and missing log files send alert for missing log files
                {
                    EVTlog_PlaceHolder = First_EventID;
                    READ_WindowsEventLog_API(Eventlog_FullName, EVTlog_PlaceHolder, EventLogFileName);
                    EventLog_SWELF.WRITE_Critical_EventLog("Missed all logs from "+ Eventlog_FullName+" on machine "+Settings.ComputerName +" the first eventlog id was older than where app left off.");
                    Settings.EventLog_w_PlaceKeeper[Eventlog_FullName.ToLower()] = Last_EventID;
                }
                else//unknown/catch condition assume 1st run
                {
                    EVTlog_PlaceHolder = First_EventID;
                    READ_WindowsEventLog_API(Eventlog_FullName, EVTlog_PlaceHolder, EventLogFileName);
                    EventLog_SWELF.WRITE_Warning_EventLog("ERROR: App unable to determine app reading state in event log. App starting over. App not told to reset. "+Eventlog_FullName +" "+ Settings.ComputerName);
                    Settings.EventLog_w_PlaceKeeper[Eventlog_FullName] = Last_EventID;
                }
                EventLog_Log_API = EventLogFileName;
            }
            else
            {
                Errors.Log_Error("if (Settings.FIND_EventLog_Exsits(Eventlog_FullName))", Eventlog_FullName+" EventLog does not exist.",Errors.LogSeverity.Verbose);
            }
        }

        public void READ_EVTX_File(string Path)
        {
            using (var reader = new EventLogReader(Path, PathType.FilePath))
            {
                while ((Windows_EventLog_from_API = reader.ReadEvent()) != null)
                {
                    try
                    {
                        EventLog_Entry Eventlog = new EventLog_Entry();
                        using (Windows_EventLog_from_API)
                        {
                            Eventlog.EventLog_Seq_num = Windows_EventLog_from_API.RecordId.Value;
                            Eventlog.LogName = Windows_EventLog_from_API.LogName;
                            Eventlog.ComputerName = Windows_EventLog_from_API.MachineName;
                            Eventlog.EventID = Windows_EventLog_from_API.Id;
                            Eventlog.CreatedTime = Windows_EventLog_from_API.TimeCreated.Value;
                            try
                            {
                                Eventlog.Severity = Windows_EventLog_from_API.OpcodeDisplayName;
                            }
                            catch
                            {
                                Eventlog.Severity = Windows_EventLog_from_API.Level.Value.ToString();
                            }
                            try
                            {
                                Eventlog.TaskDisplayName = Windows_EventLog_from_API.TaskDisplayName;
                            }
                            catch
                            {
                                Eventlog.TaskDisplayName = Windows_EventLog_from_API.ProviderName;
                            }
                            try
                            {
                                Eventlog.EventData = Windows_EventLog_from_API.FormatDescription().ToLower().ToString();
                                Eventlog.GET_FileHash();
                                Eventlog.GET_IP_FromLogFile();
                            }
                            catch
                            {
                                Eventlog.GET_XML_of_Log = Windows_EventLog_from_API.ToXml();
                                Eventlog.EventData = Windows_EventLog_from_API.ToXml();
                            }

                        }
                        EVTX_File_Logs.Enqueue(Eventlog);
                    }
                    catch (Exception e)
                    {
                        Errors.Log_Error("READ_EVTX_File(string Path)", e.Message.ToString(), Errors.LogSeverity.Informataion);
                    }
                }
            }
        }

        public void READ_EVTX_Folder(string Folder_Path)
        {
            Settings.Evtx_Files = Directory.GetFiles(Folder_Path, "*.evtx").ToList();
            for (int x=0;x< Settings.Evtx_Files.Count;++x)
            {
                READ_EVTX_File(Settings.Evtx_Files.ElementAt(x));
            }
        }

        private static void READ_WindowsEventLog_API(string Eventlog_FullName, long EventRecordID, EventLog_File EventLogFileName)
        {
            EventLogQuery eventsQuery = new EventLogQuery(Eventlog_FullName, PathType.LogName);
            EventLogReader EventLogtoReader = new EventLogReader(eventsQuery);
           
            while (GET_EventLogEntry_From_API(EventLogtoReader) != null)
            {
                EventLog_Entry Eventlog = new EventLog_Entry();
                try
                {
                    if (Windows_EventLog_from_API.RecordId.Value >= EventRecordID)
                    {
                        EventLogFileName.ID_EVENTLOG = Windows_EventLog_from_API.RecordId.Value;
                        EventLogFileName.EventlogMissing = Sec_Checks.CHECK_If_EventLog_Missing(EventLogFileName, Eventlog);

                        Eventlog.EventLog_Seq_num = Windows_EventLog_from_API.RecordId.Value;
                        Eventlog.LogName = Windows_EventLog_from_API.LogName;
                        Eventlog.ComputerName = Windows_EventLog_from_API.MachineName;
                        Eventlog.EventID = Windows_EventLog_from_API.Id;
                        Eventlog.CreatedTime = Windows_EventLog_from_API.TimeCreated.Value;

                        try
                        {
                            Eventlog.Severity = Windows_EventLog_from_API.OpcodeDisplayName;
                        }
                        catch
                        {
                            Eventlog.Severity = Windows_EventLog_from_API.Level.Value.ToString();
                        }
                        try
                        {
                            Eventlog.TaskDisplayName = Windows_EventLog_from_API.TaskDisplayName;
                        }
                        catch
                        {
                            Eventlog.TaskDisplayName = Windows_EventLog_from_API.ProviderName;
                        }
                        try
                        {
                            Eventlog.EventData = Windows_EventLog_from_API.FormatDescription().ToLower().ToString();
                            Eventlog.GET_FileHash();
                            Eventlog.GET_IP_FromLogFile();
                        }
                        catch
                        {
                            Eventlog.GET_XML_of_Log = Windows_EventLog_from_API.ToXml();
                            Eventlog.EventData = Windows_EventLog_from_API.ToXml(); 
                        }
                        EventLogFileName.Enqueue_Log(Eventlog);
                    }
                }
                catch (Exception e)
                {
                   Errors.Log_Error("INDEX_Record_FROM_API()" +Eventlog_FullName +" removed", e.Message.ToString(), Errors.LogSeverity.Verbose);
                    if (!MissingLogInFileDueToException)
                    {
                        File_Operation.GET_ErrorLog_Ready();
                        Errors.Log_Error("INDEX_Record_FROM_API() MissingLogInFileDueToException ", e.Message.ToString(), Errors.LogSeverity.Warning);
                    }
                    MissingLogInFileDueToException = true;
                }
            }
            Settings.IP_List_EVT_Logs.AddRange(Settings.IP_List_EVT_Logs.Distinct().ToList());
            Settings.Hashs_From_EVT_Logs.AddRange(Settings.Hashs_From_EVT_Logs.Distinct().ToList());
            MissingLogInFileDueToException = false;
        }

        private static EventRecord GET_EventLogEntry_From_API(EventLogReader EventLogtoReader)
        {
            return Windows_EventLog_from_API = EventLogtoReader.ReadEvent();
        }


    }
}
