//Written by Ceramicskate0
//Copyright 2018
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics.Eventing.Reader;

namespace SWELF
{
    class EventLogFile
    {
        public Queue<EventLogEntry> Contents_of_EventLog= new Queue<EventLogEntry> ();

        public string EventLogFileName = "";
        private long iD_EVENTLOG=0;
        public bool EventlogMissing = false;
        public long Last_EventLogID_From_Check { get; set; }
        public long First_EventLogID_From_Check { get; set; }

        public EventLogFile(string Name,long ID_EVENTLOGRecordID=0)
        {
            EventLogFileName = Name;
            Contents_of_EventLog = new Queue<EventLogEntry>();
            iD_EVENTLOG = ID_EVENTLOGRecordID;
            GET_Last_EventRecordID_InLogFile(Name);
            GET_First_EventRecordID_InLogFile(Name);
        }

        public void Clear()
        {
            Contents_of_EventLog.Clear();
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

        public void Enqueue_Log(EventLogEntry Eventlog)
        {
            Contents_of_EventLog.Enqueue(Eventlog);
        }

        public EventLogEntry Dequeue_Log()
        {
            return Contents_of_EventLog.Dequeue();
        }

        private void GET_Last_EventRecordID_InLogFile(string Eventlog_FullName)
        {
            TimeSpan Timeout = new TimeSpan(0, 30, 0);
            EventLogReader EventLogtoReader = new EventLogReader(Eventlog_FullName, PathType.LogName);
            EventLogtoReader.BatchSize = 100;
            EventRecord Windows_EventLog_API = EventLogtoReader.ReadEvent();
            EventLogEntry Eventlog = new EventLogEntry();

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
            EventLogEntry Eventlog = new EventLogEntry();
            First_EventLogID_From_Check = Windows_EventLog_API.RecordId.Value;
            return First_EventLogID_From_Check = Windows_EventLog_API.RecordId.Value;
        }
    }
}
