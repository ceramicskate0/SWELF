//Written by Ceramicskate0
//Copyright 2017
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Diagnostics;

namespace ConsoleEventLogAutoSearch
{
    class HostEventLogAgent_Eventlog
    {
        public static void WRITE_EventLog(string log)
        {
            using (EventLog myLogger = new EventLog(Settings.EvtLog.Source, ".", Settings.EvtLog.Source))
            {
                myLogger.WriteEntry(log, EventLogEntryType.Information);
            }
        }

        public static void WRITE_Critical_EventLog(string log)
        {
            using (EventLog myLogger = new EventLog(Settings.EvtLog.Source, ".", Settings.EvtLog.Source))
            {
                myLogger.WriteEntry(log, EventLogEntryType.Error);
            }
        }

        public static void WRITE_Warning_EventLog(string log)
        {
            using (EventLog myLogger = new EventLog(Settings.EvtLog.Source, ".", Settings.EvtLog.Source))
            {
                myLogger.WriteEntry(log, EventLogEntryType.Warning);
            }
        }

        public static void WRITE_All_App_EventLog(Queue<EventLogEntry> Logs)
        {
            while (Logs.Count>0)
            {
                WRITE_Critical_EventLog(Logs.Dequeue().EventData);
            }
        }
    }
}

