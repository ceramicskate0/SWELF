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
        
        //SWELF EVENT LOG ERRORS LIST
        private static int SWELF_Information = 996;
        private static int SWELF_SuccessAudit = 995;
        private static int SWELF_Error = 998;
        private static int SWELF_FailureAudit = 999;
        private static int SWELF_WARNING = 997;

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
            {//TODO Have eventlog log as same as original
                myLogger.WriteEntry("SearchRule="+ EvntLog.SearchRule + "\r\n\r\n" + EvntLog.EventData, EventLogEntryType.Information, EvntLog.EventID);
            }
        }

        public static void WRITE_Critical_EventLog(string Msg)
        {
            using (EventLog myLogger = new EventLog(Settings.EvtLog.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(Settings.EvtLog.Source)))
            {
                myLogger.WriteEntry(Msg, EventLogEntryType.FailureAudit, SWELF_FailureAudit);
            }
        }
        public static void WRITE_ERROR_EventLog(string Msg)
        {
            using (EventLog myLogger = new EventLog(Settings.EvtLog.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(Settings.EvtLog.Source)))
            {
                myLogger.WriteEntry(Msg, EventLogEntryType.Error, SWELF_Error);
            }
        }
        public static void WRITE_Verbose_EventLog(string Msg)
        {
            using (EventLog myLogger = new EventLog(Settings.EvtLog.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(Settings.EvtLog.Source)))
            {
                myLogger.WriteEntry(Msg, EventLogEntryType.SuccessAudit, SWELF_SuccessAudit);
            }
        }
        public static void WRITE_Info_EventLog(string Msg)
        {
            using (EventLog myLogger = new EventLog(Settings.EvtLog.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(Settings.EvtLog.Source)))
            {
                myLogger.WriteEntry(Msg, EventLogEntryType.Information, SWELF_Information);
            }
        }
        public static void WRITE_Warning_EventLog(string log)
        {
            using (EventLog myLogger = new EventLog(Settings.EvtLog.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(Settings.EvtLog.Source)))
            {
                myLogger.WriteEntry(log, EventLogEntryType.Warning, SWELF_WARNING);
            }
        }


        public static void WRITE_Critical_EventLog(EventLog_Entry EvntLog)
        {
            using (EventLog myLogger = new EventLog(Settings.EvtLog.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(EvntLog.LogName)))
            {
                myLogger.WriteEntry(EvntLog.EventData, EventLogEntryType.FailureAudit, EvntLog.EventID);
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
                return EvntLog_LogName + " on " + Settings.ComputerName;
            }
            else
            {
                return EvntLog_LogName;
            }
        }
    }
}

