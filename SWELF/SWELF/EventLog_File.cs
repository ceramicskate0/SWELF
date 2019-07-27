//Written by Ceramicskate0
//Copyright 
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;

namespace SWELF
{
    internal class EventLog_File
    {
        internal Queue<EventLog_Entry> contents_of_EventLog;

        internal string EventLogFileName = "";
        private long iD_EVENTLOG = 0;
        internal bool EventlogMissing = false;
        internal long Last_EventLogID_From_Check { get; set; }
        internal long First_EventLogID_From_Check { get; set; }
        internal int ThreadsDone_Setup = 0;

        internal EventLog_File(string LogName, long ID_EVENTLOGRecordID = 0)
        {
            EventLogFileName = LogName;
            contents_of_EventLog = new Queue<EventLog_Entry>();
            iD_EVENTLOG = ID_EVENTLOGRecordID;

            ThreadsDone_Setup = 0;

            GET_Last_EventRecordID_InLogFile(LogName);
            GET_First_EventRecordID_InLogFile(LogName);
        }

        internal Queue<EventLog_Entry> Contents_of_EventLog
        {
            get
            {
            return contents_of_EventLog;
            }
        }

        internal long ID_Number_Of_Individual_log_Entry_EVENTLOG
        {
            get
            {
                return iD_EVENTLOG;
            }
            set
            {
                iD_EVENTLOG = value;
            }
        }

        internal bool Check_if_EventLog_Empty()
        {
            if (iD_EVENTLOG <= 1 || Contents_of_EventLog.Count == 0)
            {
                return true;
            }
            else
                return false;
        } 

        internal void Enqueue_Log(EventLog_Entry Eventlog)
        {
            Contents_of_EventLog.Enqueue(Eventlog);
        }

        internal EventLog_Entry Dequeue_Log()
        {
            return Contents_of_EventLog.Dequeue();
        }

        private void GET_Last_EventRecordID_InLogFile(string Eventlog_FullName)
        {
            TimeSpan Timeout = new TimeSpan(0, 30, 0);
            EventLogReader EventLogtoReader = new EventLogReader(Eventlog_FullName, PathType.LogName);
            EventLogtoReader.BatchSize = 100;
            EventRecord Windows_EventLog_API = EventLogtoReader.ReadEvent();
            EventLog_Entry Eventlog = new EventLog_Entry();

            First_EventLogID_From_Check = Windows_EventLog_API.RecordId.Value;

            while ((Windows_EventLog_API = EventLogtoReader.ReadEvent(Timeout)) != null)
            {
                Last_EventLogID_From_Check = Windows_EventLog_API.RecordId.Value;
            }
            ThreadsDone_Setup++;
        }

        private long GET_First_EventRecordID_InLogFile(string Eventlog_FullName)
        {
            EventLogReader EventLogtoReader = new EventLogReader(Eventlog_FullName, PathType.LogName);
            EventLogtoReader.BatchSize = 100;
            EventRecord Windows_EventLog_API = EventLogtoReader.ReadEvent();
            EventLog_Entry Eventlog = new EventLog_Entry();
            First_EventLogID_From_Check = Windows_EventLog_API.RecordId.Value;
            ThreadsDone_Setup++;
            return First_EventLogID_From_Check = Windows_EventLog_API.RecordId.Value;
        }
    }
}
