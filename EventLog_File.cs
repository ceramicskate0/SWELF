//Written by Ceramicskate0
//Copyright 2018
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;

namespace SWELF
{
    class EventLog_File
    {
        private Queue<EventLog_Entry> contents_of_EventLog;

        public string EventLogFileName = "";
        private long iD_EVENTLOG = 0;
        public bool EventlogMissing = false;
        public long Last_EventLogID_From_Check { get; set; }
        public long First_EventLogID_From_Check { get; set; }

        public EventLog_File(string LogName, long ID_EVENTLOGRecordID = 0)
        {
            EventLogFileName = LogName;
            contents_of_EventLog = new Queue<EventLog_Entry>();
            iD_EVENTLOG = ID_EVENTLOGRecordID;
            GET_Last_EventRecordID_InLogFile(LogName);
            GET_First_EventRecordID_InLogFile(LogName);
        }

        public Queue<EventLog_Entry> Contents_of_EventLog
        {
            get
            {
            return contents_of_EventLog;
            }
        }

        public long ID_EVENTLOG
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

        public bool Check_if_EventLog_Empty()
        {
            if (iD_EVENTLOG <= 1 || Contents_of_EventLog.Count == 0)
            {
                return true;
            }
            else
                return false;
        } 

        public void Enqueue_Log(EventLog_Entry Eventlog)
        {
            Contents_of_EventLog.Enqueue(Eventlog);
        }

        public EventLog_Entry Dequeue_Log()
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
        }

        private long GET_First_EventRecordID_InLogFile(string Eventlog_FullName)
        {
            EventLogReader EventLogtoReader = new EventLogReader(Eventlog_FullName, PathType.LogName);
            EventLogtoReader.BatchSize = 100;
            EventRecord Windows_EventLog_API = EventLogtoReader.ReadEvent();
            EventLog_Entry Eventlog = new EventLog_Entry();
            First_EventLogID_From_Check = Windows_EventLog_API.RecordId.Value;
            return First_EventLogID_From_Check = Windows_EventLog_API.RecordId.Value;
        }
    }
}
