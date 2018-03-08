//Written by Ceramicskate0
//Copyright 2018
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Diagnostics;

namespace SWELF
{
    class HostEventLogAgent_Eventlog
    {
        public static void WRITE_EventLog_From_SWELF_Search(string log)
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

        public static void WRITE_All_App_EventLog(Queue<EventLogEntry> Logs, string Severity)
        {
            while (Logs.Count>0)
            {
                if (Severity.ToLower() == "critical")
                {
                    WRITE_Critical_EventLog(Logs.Dequeue().EventData);
                }
                else if (Severity.ToLower() == "warning")
                {
                    WRITE_Warning_EventLog(Logs.Dequeue().EventData);
                }
                else if (Severity.ToLower() == "informational")
                {
                    WRITE_EventLog_From_SWELF_Search(Logs.Dequeue().EventData);
                }
            }
        }
    }
}

