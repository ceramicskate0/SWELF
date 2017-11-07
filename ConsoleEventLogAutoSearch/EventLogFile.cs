//Written by Ceramicskate0
//Copyright 2017
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics.Eventing.Reader;

namespace ConsoleEventLogAutoSearch
{
    class EventLogFile: APP_API
    {
        public Queue<EventLogEntry> EventLogs_From_WindowsAPI;
        public string EventLogFileName = "";
        private long iD_EVENTLOG=0;
        public bool EventlogMissing = false;
        public long Last_EventLogID_From_Check { get; set; }
        public long First_EventLogID_From_Check { get; set; }

        public EventLogFile(string Name,long ID_EVENTLOGRecordID=0)
        {
            EventLogFileName = Name;
            EventLogs_From_WindowsAPI = new Queue<EventLogEntry>();
            iD_EVENTLOG = ID_EVENTLOGRecordID;
            GET_Last_EventRecordID_InLogFile(Name);
            GET_First_EventRecordID_InLogFile(Name);
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
            if (iD_EVENTLOG <= 1 || EventLogs_From_WindowsAPI.Count == 0)
            {
                return true;
            }
            else
                return false;
        } 

        public void Enqueue_Log(EventLogEntry Eventlog)
        {
            EventLogs_From_WindowsAPI.Enqueue(Eventlog);
        }

        public EventLogEntry Dequeue_Log()
        {
            return EventLogs_From_WindowsAPI.Dequeue();
        }

        public void Dedup_IP_List()
        {
            IP_From_EventLog=IP_From_EventLog.Distinct().ToList();
        }

        public void Dedup_Hash_List()
        {
            Hashes_From_EventLog=Hashes_From_EventLog.Distinct().ToList();
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
