//Written by Ceramicskate0
//Copyright 2018
using System;
using System.Collections.Generic;
using System.Linq;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Collections.Concurrent;

namespace SWELF
{
    class Read_EventLog
    {
        private static EventRecord Windows_EventLog_from_API { get; set; }
        public EventLog_File EventLog_Log_API;//windows live api read
        private static bool MissingLogInFileDueToException = false;
        public Queue<EventLog_Entry> EVTX_File_Logs = new Queue<EventLog_Entry>();



        public Read_EventLog()
        {

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

            if (Settings.CHECK_If_EventLog_Exsits(Eventlog_FullName))
            {
                EventLog_Log_API = new EventLog_File(Eventlog_FullName, PlaceKeeper_EventRecordID);

                long First_EventID = EventLog_Log_API.First_EventLogID_From_Check;
                long Last_EventID = EventLog_Log_API.Last_EventLogID_From_Check;

                if (PlaceKeeper_EventRecordID > First_EventID && PlaceKeeper_EventRecordID < Last_EventID)//Normal operation placekkeeper in middle of log file
                {
                    EVTlog_PlaceHolder = PlaceKeeper_EventRecordID;
                    READ_WindowsEventLog_API(Eventlog_FullName, EVTlog_PlaceHolder, EventLog_Log_API);
                    Settings.EventLog_w_PlaceKeeper[Eventlog_FullName.ToLower()] = Last_EventID;
                }
                else if (Last_EventID == PlaceKeeper_EventRecordID)//no logs added
                {
                    EVTlog_PlaceHolder = PlaceKeeper_EventRecordID;
                }
                else if (PlaceKeeper_EventRecordID<=1)
                {
                    EVTlog_PlaceHolder = First_EventID;
                    READ_WindowsEventLog_API(Eventlog_FullName, EVTlog_PlaceHolder, EventLog_Log_API);
                    EventLog_SWELF.WRITE_Warning_EventLog("Logging as EventLog Source 1st run for Eventlog named '"+ Eventlog_FullName +"' on machine named '"+ Settings.ComputerName+ "' due to PlaceKeeper_EventRecordID<=1");
                    Settings.EventLog_w_PlaceKeeper[Eventlog_FullName] = Last_EventID;
                }
                else if (First_EventID > PlaceKeeper_EventRecordID)//missed all logs and missing log files send alert for missing log files
                {
                    EVTlog_PlaceHolder = First_EventID;
                    READ_WindowsEventLog_API(Eventlog_FullName, EVTlog_PlaceHolder, EventLog_Log_API);
                    EventLog_SWELF.WRITE_Critical_EventLog("Missed all logs from '"+ Eventlog_FullName+"' on machine '"+Settings.ComputerName +"' the first eventlog id was older than where app left off. Possible log file cycle/overwrite between runs. "+ First_EventID+" > "+PlaceKeeper_EventRecordID);
                    Settings.EventLog_w_PlaceKeeper[Eventlog_FullName.ToLower()] = Last_EventID;
                }
                else//unknown/catch condition assume 1st run
                {
                    EVTlog_PlaceHolder = First_EventID;
                    READ_WindowsEventLog_API(Eventlog_FullName, EVTlog_PlaceHolder, EventLog_Log_API);
                    EventLog_SWELF.WRITE_Warning_EventLog("ERROR: App unable to determine app reading state in event log. App starting over. App not told to reset. '"+Eventlog_FullName +"' '"+ Settings.ComputerName+ "'. unknown/catch condition assume 1st run");
                    Settings.EventLog_w_PlaceKeeper[Eventlog_FullName] = Last_EventID;
                }
                //EventLog_Log_API = EventLogName;
            }
            else
            {
                Errors.Log_Error("if (Settings.FIND_EventLog_Exsits(Eventlog_FullName)) '", Eventlog_FullName+"' EventLog does not exist.",Errors.LogSeverity.Informataion);
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
                            Eventlog.ComputerName = Windows_EventLog_from_API.MachineName;
                            Eventlog.EventID = Windows_EventLog_from_API.Id;
                            Eventlog.CreatedTime = Windows_EventLog_from_API.TimeCreated.Value;
                            try
                            {
                                Eventlog.LogName = Windows_EventLog_from_API.LogName;
                            }
                            catch
                            {
                                Eventlog.LogName = Path;
                            }
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
                                Eventlog.GET_XML_of_Log = Windows_EventLog_from_API.ToXml();
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
                        Errors.Log_Error("READ_EVTX_File()", e.Message.ToString() +"Event Log Missing due to improper format. Possible tampering or invalid format.", Errors.LogSeverity.FailureAudit);
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

        private static void READ_WindowsEventLog_API(string Eventlog_FullName, long EventRecordID, EventLog_File EventLogName)
        {
            try
            {
                EventLogQuery eventsQuery = new EventLogQuery(Eventlog_FullName, PathType.LogName);
                EventLogReader EventLogtoReader = new EventLogReader(eventsQuery);

                while (GET_EventLogEntry_From_API(EventLogtoReader) != null)
                {
                    EventLog_Entry SWELF_Eventlog = new EventLog_Entry();
                    try
                    {
                        SWELF_Eventlog = new EventLog_Entry();

                        if (Windows_EventLog_from_API.RecordId.Value >= EventRecordID)
                        {
                            SWELF_Eventlog.CreatedTime = Windows_EventLog_from_API.TimeCreated.Value;//if this doesnt work we have issues that we cant fix
                            SWELF_Eventlog.EventLog_Seq_num = Windows_EventLog_from_API.RecordId.Value; ;//if this doesnt work we have issues that we cant fix
                            SWELF_Eventlog.EventID = Windows_EventLog_from_API.Id; ;//if this doesnt work we have issues that we cant fix
                            SWELF_Eventlog.LogName = Windows_EventLog_from_API.LogName;
                            try
                            {
                                SWELF_Eventlog.ComputerName = Windows_EventLog_from_API.MachineName;
                            }
                            catch (Exception e)
                            {
                                SWELF_Eventlog.ComputerName = Settings.ComputerName;
                            }

                            try
                            {
                                SWELF_Eventlog.Severity = Windows_EventLog_from_API.OpcodeDisplayName;
                            }
                            catch (Exception e)
                            {
                                SWELF_Eventlog.Severity = Windows_EventLog_from_API.Level.Value.ToString();//if this doesnt work we have issues that we cant fix
                            }

                            try
                            {
                                SWELF_Eventlog.TaskDisplayName = Windows_EventLog_from_API.TaskDisplayName;
                            }
                            catch (Exception e)
                            {
                                SWELF_Eventlog.TaskDisplayName = Windows_EventLog_from_API.ProviderName;//if this doesnt work we have issues that we cant fix
                            }

                            try
                            {
                                if (Settings.AppConfig_File_Args.ContainsKey("debug"))
                                {
                                    SWELF_Eventlog.EventData = "CreationDate="+SWELF_Eventlog.CreatedTime + "\r\nEventLog_Seq_Number=" + SWELF_Eventlog.EventLog_Seq_num + "\r\nEventID=" + SWELF_Eventlog.EventID + "\r\nSeverity=" + SWELF_Eventlog.Severity + "\r\nEventLogName=" + SWELF_Eventlog.LogName + "\r\n\r\n" + Windows_EventLog_from_API.FormatDescription().ToLower();
                                }
                                else
                                {
                                    SWELF_Eventlog.EventData = Windows_EventLog_from_API.FormatDescription().ToLower();
                                }
                            }
                            catch (Exception e)
                            {
                                if (Settings.AppConfig_File_Args.ContainsKey("debug"))
                                {
                                    SWELF_Eventlog.EventData = "CreationDate=" + SWELF_Eventlog.CreatedTime + "\r\nEventLog_Seq_Number=" + SWELF_Eventlog.EventLog_Seq_num + "\r\nEventID=" + SWELF_Eventlog.EventID + "\r\nSeverity=" + SWELF_Eventlog.Severity + "\r\nEventLogName=" + SWELF_Eventlog.LogName + "\r\n\r\n" + Windows_EventLog_from_API.ToXml(); ;
                                }
                                else
                                {
                                    SWELF_Eventlog.EventData = Windows_EventLog_from_API.ToXml();//if this doesnt work we have issues that we cant fix
                                }
                            }

                            try
                            {
                                SWELF_Eventlog.GET_XML_of_Log = Windows_EventLog_from_API.ToXml();
                                if (string.IsNullOrEmpty(SWELF_Eventlog.GET_XML_of_Log) == false)
                                {
                                    SWELF_Eventlog.GET_XML_of_Log = Windows_EventLog_from_API.ToXml();
                                }
                                else
                                {
                                    SWELF_Eventlog.GET_XML_of_Log = "";
                                }
                            }
                            catch (Exception e)
                            {
                                SWELF_Eventlog.GET_XML_of_Log = "ERROR READING";
                            }

                            try
                            {
                                SWELF_Eventlog.GET_FileHash();
                            }
                            catch (Exception e)
                            {

                            }

                            try
                            {
                                SWELF_Eventlog.GET_IP_FromLogFile();
                            }
                            catch (Exception e)
                            {

                            }

                            try
                            {
                                EventLogName.EventlogMissing = Sec_Checks.CHECK_If_EventLog_Missing(EventLogName, SWELF_Eventlog);
                            }
                            catch (Exception e)
                            {
                                EventLogName.EventlogMissing = true;
                            }

                            try
                            {
                                EventLogName.ID_EVENTLOG = Windows_EventLog_from_API.RecordId.Value;
                            }
                            catch (Exception e)
                            {
                                EventLogName.ID_EVENTLOG = EventLogName.ID_EVENTLOG++;
                            }
                            EventLogName.Enqueue_Log(SWELF_Eventlog);
                        }
                    }
                    catch (Exception e)
                    {
                        Errors.Log_Error("INDEX_Record_FROM_API() Missing Event Log(s) Due To Exception with log format while reading in eventlogs.", "EventLog='" + Eventlog_FullName + "' " + e.Message.ToString(), Errors.LogSeverity.Warning);
                        MissingLogInFileDueToException = true;
                        GC.Collect();
                    }
                }
                try
                {
                    Settings.IP_List_EVT_Logs.AddRange(Settings.IP_List_EVT_Logs.Distinct().ToList());
                    Settings.Hashs_From_EVT_Logs.AddRange(Settings.Hashs_From_EVT_Logs.Distinct().ToList());
                }
                catch (Exception e)
                {
                    Errors.Log_Error("Settings.IP_List_EVT_Logs.AddRange() OR Settings.Hashs_From_EVT_Logs.AddRange()", e.Message.ToString(), Errors.LogSeverity.Warning);
                }
                MissingLogInFileDueToException = false;
                GC.Collect();
            }
            catch (Exception e)
            {
                Errors.Log_Error("READ_WindowsEventLog_API() Missing All Event Log(s) Due To Exception. ", "EventLog='" + Eventlog_FullName + "' " + e.Message.ToString() + " " + Eventlog_FullName + " " + EventRecordID + " " + EventLogName.First_EventLogID_From_Check + " " +EventLogName.Last_EventLogID_From_Check + " " + EventLogName.Contents_of_EventLog.Count, Errors.LogSeverity.FailureAudit);
                MissingLogInFileDueToException = true;
                GC.Collect();
            }
        }

        private static EventRecord GET_EventLogEntry_From_API(EventLogReader EventLogtoReader)
        {
            try
            {
                return Windows_EventLog_from_API = EventLogtoReader.ReadEvent();
            }
            catch
            {
                return Windows_EventLog_from_API;
            }
        }
    }
}
