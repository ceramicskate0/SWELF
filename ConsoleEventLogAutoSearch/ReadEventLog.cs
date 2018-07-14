//Written by Ceramicskate0
//Copyright 2018
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics.Eventing.Reader;
using System.Diagnostics;
using System.IO;
using System.Collections.Concurrent;

namespace SWELF
{
    class ReadEventLog
    {
        private static EventRecord Windows_EventLog_API { get; set; }
        public string EvntLog_Name;
        public EventLogFile EventLog_Log_API;//windows live api read
        public List<string> FileContents_From_FileReads;
        public static bool MissingLogInFileDueToException = false;
        public Queue<EventLogEntry> EVTX_File_Logs = new Queue<EventLogEntry>();
        private static EventLogFile EventLogFileName;

        public ReadEventLog()
        {
            EvntLog_Name = "";
            FileContents_From_FileReads = new List<string>();
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
                if (EVTlog_PlaceHolder == 1)
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
                EventLogFileName = new EventLogFile(Eventlog_FullName, PlaceKeeper_EventRecordID);
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
                    HostEventLogAgent_Eventlog.WRITE_Warning_EventLog("Logging as app or EventLog Source 1st run for "+ Eventlog_FullName +" "+ Settings.ComputerName);
                    Settings.EventLog_w_PlaceKeeper[Eventlog_FullName] = Last_EventID;
                }
                else if (First_EventID > PlaceKeeper_EventRecordID)//missed all logs and missing log files send alert for missing log files
                {
                    EVTlog_PlaceHolder = First_EventID;
                    READ_WindowsEventLog_API(Eventlog_FullName, EVTlog_PlaceHolder, EventLogFileName);
                    HostEventLogAgent_Eventlog.WRITE_Critical_EventLog("Missed all logs from "+ Eventlog_FullName+" on machine "+Settings.ComputerName +" the first eventlog id was older than where app left off.");
                    Settings.EventLog_w_PlaceKeeper[Eventlog_FullName.ToLower()] = Last_EventID;
                }
                else//unknown/catch condition assume 1st run
                {
                    EVTlog_PlaceHolder = First_EventID;
                    READ_WindowsEventLog_API(Eventlog_FullName, EVTlog_PlaceHolder, EventLogFileName);
                    HostEventLogAgent_Eventlog.WRITE_Warning_EventLog("ERROR: App unable to determine app reading state in event log. App starting over. App not told to reset. "+Eventlog_FullName +" "+ Settings.ComputerName);
                    Settings.EventLog_w_PlaceKeeper[Eventlog_FullName] = Last_EventID;
                }
                EventLog_Log_API = EventLogFileName;
            }
            else
            {
                Errors.Log_Error("if (Settings.FIND_EventLog_Exsits(Eventlog_FullName))", Eventlog_FullName+" EventLog does not exist.",Errors.LogSeverity.Verbose);
            }
        }

        public void READ_Local_Log_Files()
        {
            try
            {
                List<string> FilePaths = File.ReadAllLines(Settings.GET_FilesToMonitor_Path()).ToList();

                for (int z = 0; z < FilePaths.Count; ++z)
                {
                    string FileContent = File.ReadAllText(FilePaths.ElementAt(z));
                    File.Delete(FilePaths.ElementAt(z));
                    FileContents_From_FileReads.Add(FileContent);
                }
            }
            catch (Exception e)
            {
                Errors.Log_Error("READ_Local_Log_Files() ", e.Message.ToString(),Errors.LogSeverity.Warning);
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
                        if (DirPaths.ElementAt(z).ToLower().Contains("powershell") || DirPaths.ElementAt(z).ToLower().Contains("iis"))
                        {
                            READ_Local_Log_Dirs_for_Powershell_or_IIS(DirPaths.ElementAt(z));
                        }
                        else
                        {
                            string[] FilePaths = Directory.GetFiles(DirPaths.ElementAt(z));

                            for (int x = 0; x < FilePaths.Length - 1; ++x)
                            {
                                if (Settings.VERIFY_if_File_Exists(FilePaths.ElementAt(x)) && (FilePaths.ElementAt(x).Contains(".txt") || FilePaths.ElementAt(x).Contains(".log")))
                                {
                                    string FileContent = File.ReadAllText(FilePaths.ElementAt(x));
                                    File.Delete(FilePaths.ElementAt(x));
                                    FileContents_From_FileReads.Add(FileContent);
                                }
                            }
                        }
                    }
                }

            }
            catch (Exception e)
            {
                Errors.Log_Error("READ_Local_Log_Dirs() ", e.Message.ToString(),Errors.LogSeverity.Warning);
            }
        }

        public void READ_EVTX_File(string Path)
        {
            using (var reader = new EventLogReader(Path, PathType.FilePath))
            {
                while ((Windows_EventLog_API = reader.ReadEvent()) != null)
                {
                    EventLogEntry Eventlog = new EventLogEntry();
                    using (Windows_EventLog_API)
                    {
                        Eventlog.EventLog_Seq_num = Windows_EventLog_API.RecordId.Value;
                        Eventlog.LogName = Windows_EventLog_API.LogName;
                        Eventlog.Severity = Windows_EventLog_API.OpcodeDisplayName;
                        Eventlog.TaskDisplayName = Windows_EventLog_API.TaskDisplayName;
                        Eventlog.ComputerName = Windows_EventLog_API.MachineName;
                        Eventlog.EventID = Windows_EventLog_API.Id;
                        Eventlog.GET_XML_of_Log = Windows_EventLog_API.ToXml();
                        Eventlog.CreatedTime = Windows_EventLog_API.TimeCreated.Value;
                        Eventlog.EventData = Windows_EventLog_API.FormatDescription().ToLower().ToString();
                    }
                    EVTX_File_Logs.Enqueue(Eventlog);
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

        private void READ_Local_Log_Dirs_for_Powershell_or_IIS(string directory)
        {
            try
            {
                    if (Directory.Exists(directory))
                    {
                        string[] SubDirs = Directory.GetDirectories(directory);

                        for (int x = 0; x < SubDirs.Length; ++x)
                        {
                            string[] FilePaths = Directory.GetFiles(SubDirs[x]);

                            for (int c = 0; c < FilePaths.Length; ++c)
                            {
                                if (FilePaths[c].Contains(".txt") && (FilePaths[c].ToLower().Contains("powershell_transcript.")|| FilePaths[c].ToLower().Contains("iis")))
                                {
                                    string FileContent = File.ReadAllText(FilePaths.ElementAt(c));
                                    File.Delete(FilePaths.ElementAt(c));
                                    FileContents_From_FileReads.Add(FileContent);
                                }
                            }
                        }
                    }
            }
            catch (Exception e)
            {
                Errors.Log_Error("READ_Local_Log_Dirs() ", e.Message.ToString(),Errors.LogSeverity.Warning);
            }
        }

        private static void READ_WindowsEventLog_API(string Eventlog_FullName, long EventRecordID, EventLogFile EventLogFileName)
        {
            EventLogQuery eventsQuery = new EventLogQuery(Eventlog_FullName, PathType.LogName);
            EventLogReader EventLogtoReader = new EventLogReader(eventsQuery);
           
            while (GET_EventLogEntry_From_API(EventLogtoReader) != null)
            {
                EventLogEntry Eventlog = new EventLogEntry();
                try
                {
                    if (Windows_EventLog_API.RecordId.Value >= EventRecordID)
                    {
                        EventLogFileName.ID_EVENTLOG = Windows_EventLog_API.RecordId.Value;
                        EventLogFileName.EventlogMissing = CHECK_If_EventLog_Missing(EventLogFileName, Eventlog);

                        Eventlog.EventLog_Seq_num = Windows_EventLog_API.RecordId.Value;
                        Eventlog.LogName = Windows_EventLog_API.LogName;
                        Eventlog.ComputerName = Windows_EventLog_API.MachineName;
                        Eventlog.EventID = Windows_EventLog_API.Id;
                        Eventlog.CreatedTime = Windows_EventLog_API.TimeCreated.Value;
                        try
                        {
                            Eventlog.Severity = Windows_EventLog_API.OpcodeDisplayName;
                        }
                        catch
                        {
                            Eventlog.Severity = Windows_EventLog_API.Level.Value.ToString();
                        }
                        try
                        {
                            Eventlog.TaskDisplayName = Windows_EventLog_API.TaskDisplayName;
                        }
                        catch
                        {
                            Eventlog.TaskDisplayName = Windows_EventLog_API.ProviderName;
                        }
                        try
                        {
                            Eventlog.EventData = Windows_EventLog_API.FormatDescription().ToLower().ToString();
                            Eventlog.GET_FileHash();
                            Eventlog.GET_IP_FromLogFile();
                        }
                        catch
                        {
                            Eventlog.GET_XML_of_Log = Windows_EventLog_API.ToXml();
                            Eventlog.EventData = Windows_EventLog_API.ToXml(); 
                        }
                        EventLogFileName.Enqueue_Log(Eventlog);
                    }
                }
                catch (Exception e)
                {
                   Errors.Log_Error("INDEX_Record_FROM_API()" +Eventlog_FullName +" removed", e.Message.ToString(), Errors.LogSeverity.Verbose);
                    if (!MissingLogInFileDueToException)
                    {
                        Settings.GET_ErrorLog_Ready();
                        //string Alert = "ALERT: Logs on " + Settings.ComputerName + " under Event Log name " + Eventlog.LogName + " near event id " + EventRecordID.ToString() + " found Eventlogs missing.";
                        Errors.Log_Error("INDEX_Record_FROM_API() MissingLogInFileDueToException ", e.Message.ToString(), Errors.LogSeverity.Warning);
                    }
                    MissingLogInFileDueToException = true;
                }
            }
            Settings.IP_List_EVT_Logs = Settings.Hashs_From_EVT_Logs.Distinct().ToList();
            Settings.Hashs_From_EVT_Logs = Settings.Hashs_From_EVT_Logs.Distinct().ToList();
            MissingLogInFileDueToException = false;
        }

        private static EventRecord GET_EventLogEntry_From_API(EventLogReader EventLogtoReader)
        {
            return Windows_EventLog_API = EventLogtoReader.ReadEvent();
        }

        private static bool CHECK_If_EventLog_Missing(EventLogFile ELF, EventLogEntry EVE)
        {
            if ((EVE.EventLog_Seq_num != ELF.ID_EVENTLOG + 1) && ELF.EventlogMissing == false && (ELF.ID_EVENTLOG != 0 && EVE.EventRecordID!=0))
            {
                ELF.EventlogMissing = true;
                Errors.WRITE_Errors_To_Log("CHECK_If_EventLog_Missing(EventLogFile ELF, EventLogEntry EVE)", "Logs on " + Settings.ComputerName + " under Event Log name " + EVE.LogName + " near or around Event ID " + EVE.EventRecordID.ToString() + " found Eventlogs missing.",Errors.LogSeverity.Critical);
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}
