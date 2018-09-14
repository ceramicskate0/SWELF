//Written by Ceramicskate0
//Copyright 2018
using System;
using System.Linq;
using System.Diagnostics;

namespace SWELF
{
    class EventLog_SWELF
    {

        private static string[] Protected_Event_Log_Names = { "application", "security", "system" };

        public static void WRITE_EventLog_From_SWELF_Search(string log)
        {
            using (EventLog myLogger = new EventLog(Settings.EvtLog.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(Settings.EvtLog.Source)))
            {
                myLogger.WriteEntry(log, EventLogEntryType.Information);
            }
        }

        public static void WRITE_EventLog_From_SWELF_Search(EventLog_Entry EvntLog)
        {
            using (EventLog myLogger = new EventLog(Settings.EvtLog.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(EvntLog.LogName)))
            {
                myLogger.WriteEntry(EvntLog.EventData, EventLogEntryType.Information, EvntLog.EventID);
            }
        }

        public static void WRITE_Critical_EventLog(string Msg)
        {
            using (EventLog myLogger = new EventLog(Settings.EvtLog.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(Settings.EvtLog.Source)))
            {
                myLogger.WriteEntry(Msg, EventLogEntryType.FailureAudit, 16);
            }
        }

        public static void WRITE_Critical_EventLog(EventLog_Entry EvntLog)
        {
            using (EventLog myLogger = new EventLog(Settings.EvtLog.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(EvntLog.LogName)))
            {
                myLogger.WriteEntry(EvntLog.EventData, EventLogEntryType.FailureAudit, EvntLog.EventID);
            }
        }

        public static void WRITE_Warning_EventLog(string log)
        {
            using (EventLog myLogger = new EventLog(Settings.EvtLog.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(Settings.EvtLog.Source)))
            {
                myLogger.WriteEntry(log, EventLogEntryType.Warning, 1);
            }
        }

        public static void WRITE_Warning_EventLog(EventLog_Entry EvntLog)
        {
            using (EventLog myLogger = new EventLog(Settings.EvtLog.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(EvntLog.LogName)))
            {
                myLogger.WriteEntry(EvntLog.EventData, EventLogEntryType.Warning, EvntLog.EventID);
            }
        }

        private static string CHECK_If_Protected_Log_Name (string EvntLog_LogName)
        {
            if (Protected_Event_Log_Names.Any(s => EvntLog_LogName.ToLower().IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0))
            {
                return EvntLog_LogName + " on "+Settings.ComputerName;
            }
            else
            {
                return EvntLog_LogName;
            }
        }
    }
}

