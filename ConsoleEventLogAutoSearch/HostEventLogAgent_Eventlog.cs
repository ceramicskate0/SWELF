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
            using (EventLog myLogger = new EventLog(Settings.EvtLog.Source, Environment.MachineName, Settings.EvtLog.Source))
            {
                myLogger.WriteEntry(log, EventLogEntryType.Information);
            }
        }
        public static void WRITE_EventLog_From_SWELF_Search(EventLogEntry EvntLog)
        {
            using (EventLog myLogger = new EventLog(Settings.EvtLog.Source, Environment.MachineName, EvntLog.LogName))
            {
                myLogger.WriteEntry(EvntLog.EventData, EventLogEntryType.Information, EvntLog.EventID);
            }
        }
        public static void WRITE_Critical_EventLog(string log)
        {
            using (EventLog myLogger = new EventLog(Settings.EvtLog.Source, Environment.MachineName, Settings.EvtLog.Source))
            {
                myLogger.WriteEntry(log, EventLogEntryType.Error, 2);
            }
        }
        public static void WRITE_Critical_EventLog(EventLogEntry EvntLog)
        {
            using (EventLog myLogger = new EventLog(Settings.EvtLog.Source, Environment.MachineName, EvntLog.LogName))
            {
                myLogger.WriteEntry(EvntLog.EventData, EventLogEntryType.Error, EvntLog.EventID);
            }
        }
        public static void WRITE_Warning_EventLog(string log)
        {
            using (EventLog myLogger = new EventLog(Settings.EvtLog.Source, Environment.MachineName, Settings.EvtLog.Source))
            {
                myLogger.WriteEntry(log, EventLogEntryType.Warning, 1);
            }
        }
        public static void WRITE_Warning_EventLog(EventLogEntry EvntLog)
        {
            using (EventLog myLogger = new EventLog(Settings.EvtLog.Source, Environment.MachineName, EvntLog.LogName))
            {
                myLogger.WriteEntry(EvntLog.EventData, EventLogEntryType.Warning, EvntLog.EventID);
            }
        }
    }
}

