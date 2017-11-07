//Written by Ceramicskate0
//Copyright 2017
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics.Eventing.Reader;
using System.Diagnostics;
using System.IO;

namespace ConsoleEventLogAutoSearch
{
    class ReadEventLog
    {
        private static EventRecord Windows_EventLog_API { get; set; }
        public string EvntLog_Name;
        public EventLogFile EventLog_Log_File;
        public List<string> FileContents_From_FileReads;
        public static bool MissingLogInFileDueToException = false;

        public ReadEventLog()
        {
            EvntLog_Name = "";
            FileContents_From_FileReads = new List<string>();
        }

        public void READ_EventLog(string Eventlog_FullName,long eventRecordID=1)
        {
            long EVTlog_PlaceHolder = eventRecordID;
            try
            {
                if (EVTlog_PlaceHolder == 1)
                {
                    EVTlog_PlaceHolder = Settings.EventLog_w_PlaceKeeper[Eventlog_FullName.ToLower()];
                }
            }
            catch
            {
                EVTlog_PlaceHolder = 1;
            }

            if (FIND_EventLogExsits(Eventlog_FullName))
            {
                EventLogFile EventLogFileName = new EventLogFile(Eventlog_FullName, eventRecordID);
                long First_EventID = EventLogFileName.First_EventLogID_From_Check;
                long Last_EventID = EventLogFileName.Last_EventLogID_From_Check;
                if (First_EventID < eventRecordID)//more logs added to event log since last read
                {
                    EVTlog_PlaceHolder = eventRecordID;
                    READ_WindowsEventLog_API(Eventlog_FullName, EVTlog_PlaceHolder, EventLogFileName);
                    Settings.EventLog_w_PlaceKeeper[Eventlog_FullName.ToLower()] = Last_EventID;
                }
                else if (Last_EventID == eventRecordID)//no logs added
                {
                    EVTlog_PlaceHolder = eventRecordID;
                }
                else if (First_EventID > eventRecordID)//missed all logs and missing log files send alert for missing log files
                {
                    EVTlog_PlaceHolder = First_EventID;
                    READ_WindowsEventLog_API(Eventlog_FullName, EVTlog_PlaceHolder, EventLogFileName);
                    HostEventLogAgent_Eventlog.WRITE_Warning_EventLog("Missed all logs from "+ Eventlog_FullName+"possible first run or no search items to find.");
                    Settings.EventLog_w_PlaceKeeper[Eventlog_FullName.ToLower()] = Last_EventID;
                }
                else//unknown condition assume 1st run
                {
                    EVTlog_PlaceHolder = First_EventID;
                    READ_WindowsEventLog_API(Eventlog_FullName, EVTlog_PlaceHolder, EventLogFileName);
                    //TODO write event log /error and prepare to send event log of error in read state for unknown condition.
                    HostEventLogAgent_Eventlog.WRITE_EventLog("Logging as app or EventLog Source 1st run");
                    Settings.EventLog_w_PlaceKeeper[Eventlog_FullName] = Last_EventID;
                }
                EventLog_Log_File = EventLogFileName;
            }
            else
            {
                Errors.Log_Error("ReadEventLog->Read_EventLog()", "EventLog does not exist.");
            }
        }

        public void READ_Local_Log_Files()
        {
            try
            {
                List<string> FilePaths = File.ReadAllLines(Settings.GET_FilesToMonitor_Path()).ToList();

                for (int z = 0; z < FilePaths.Count; ++z)
                {
                    if (File.Exists(FilePaths.ElementAt(z)))
                    {
                        string[] FileContent = File.ReadAllLines(FilePaths.ElementAt(z));
                        FileContents_From_FileReads.AddRange(FileContent.ToList());
                    }
                }
            }
            catch (Exception e)
            {
                Errors.Log_Error("READ_Local_Log_Files() ERROR: ", e.Message.ToString());
            }
        }

        public void READ_Local_Log_Dirs()
        {
            try
            {
                List<string> DirPaths = File.ReadAllLines(Settings.GET_DirToMonitor_Path()).ToList();

                for (int z = 0; z < DirPaths.Count; ++z)
                {
                    if (Directory.Exists(DirPaths.ElementAt(z)))
                    {
                        string[] FilePaths = Directory.GetFiles(DirPaths.ElementAt(z));

                        for (int x = 0; x < FilePaths.Length-1; ++x)
                        {
                            if (File.Exists(FilePaths.ElementAt(x)) && (FilePaths.ElementAt(x).Contains(".txt") || FilePaths.ElementAt(x).Contains(".log")))
                            {
                                string[] FileContent = File.ReadAllLines(FilePaths.ElementAt(x));
                                FileContents_From_FileReads.AddRange(FileContent.ToList());
                            }
                        }
                    }
                }

            }
            catch (Exception e)
            {
                Errors.Log_Error("READ_Local_Log_Dirs() ERROR: ", e.Message.ToString());
            }
        }

        private static void READ_WindowsEventLog_API(string Eventlog_FullName, long EventRecordID, EventLogFile EventLogFileName)
        {
            EventLogQuery eventsQuery = new EventLogQuery(Eventlog_FullName, PathType.LogName);
            EventLogReader EventLogtoReader = new EventLogReader(eventsQuery);
            while (GET_EventLogEntry_From_API(EventLogtoReader) != null)
            {
                    INDEX_Record_FROM_API(EventLogFileName, Windows_EventLog_API, EventRecordID);
            }
            MissingLogInFileDueToException = false;
        }

        private static EventRecord GET_EventLogEntry_From_API(EventLogReader EventLogtoReader)
        {
            return Windows_EventLog_API = EventLogtoReader.ReadEvent();
        }

        private static void INDEX_Record_FROM_API(EventLogFile EventLogFileName, EventRecord Windows_EventLog_API, long EventRecordID)
        {
            EventLogEntry Eventlog = new EventLogEntry();
            try
            {
                if (Windows_EventLog_API.RecordId.Value >= EventRecordID)
                {
                    Eventlog.EventLog_Seq_num = Windows_EventLog_API.RecordId.Value;
                    Eventlog.LogName = Windows_EventLog_API.LogName;
                    Eventlog.Severity = Windows_EventLog_API.OpcodeDisplayName;
                    Eventlog.TaskDisplayName = Windows_EventLog_API.TaskDisplayName;
                    Eventlog.PID = Windows_EventLog_API.ProcessId.Value;
                    Eventlog.ComputerName = Windows_EventLog_API.MachineName;
                    Eventlog.UserID = Windows_EventLog_API.UserId.ToString();
                    Eventlog.EventData = Windows_EventLog_API.FormatDescription().ToLower().ToString();
                    Eventlog.EventID = Windows_EventLog_API.Id;
                    Eventlog.GET_XML_of_Log = Windows_EventLog_API.ToXml();
                    Eventlog.CreatedTime = Windows_EventLog_API.TimeCreated.Value;

                    EventLogFileName.EventlogMissing = CHECK_IfEventLogMissing(EventLogFileName, Eventlog);
                    EventLogFileName.ID_EVENTLOG = Windows_EventLog_API.RecordId.Value;
                    EventLogFileName.Hashes_From_EventLog.Add(Eventlog.GET_Hash_FromLogFile);//will check in class if sysmon or not, only check hash for sysmon
                    EventLogFileName.Add_IP(Eventlog.GET_IP_FromLogFile);//will check all logs BUT high false positive

                    EventLogFileName.Enqueue_Log(Eventlog);
                }
            }
            catch (Exception e)
            {
                if (!MissingLogInFileDueToException)
                {
                    Settings.GET_ErrorLog_Ready();
                    string ALert = "Logs on " + Eventlog.ComputerName + " under Event Log name " + Eventlog.LogName + " near event id " + EventRecordID.ToString() + " found eventlogs missing.";
                    Errors.WriteErrorsToLog(ALert);
                    Errors.Log_Error("INDEX_Record_FROM_API()", e.Message.ToString());
                }
                MissingLogInFileDueToException = true;
            }
        }

        private static bool CHECK_IfEventLogMissing(EventLogFile ELF, EventLogEntry EVE)
        {
            if (EVE.EventLog_Seq_num != ELF.ID_EVENTLOG + 1 && ELF.EventlogMissing == false && ELF.ID_EVENTLOG != 0)
            {
                ELF.EventlogMissing = true;
                string ALert = "Logs on " + EVE.ComputerName + " under Event Log name " + EVE.LogName + " near event id " + EVE.EventRecordID.ToString() + " found eventlogs missing.";
                Errors.WriteErrorsToLog(ALert);
                Settings.ADD_Eventlog_to_CriticalEvents(ALert, "Missing Event Log");
                return true;
            }
            else
            {
                return false;
            }
        }

        private static bool FIND_EventLogExsits(string EventLog_ToFind)
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
    }

}
