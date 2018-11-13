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
        public static int SWELF_MAIN_APP_ERROR_EVTID = 990;
        public static int SWELF_Central_Config_Changed_EVTID = 994;
        private static int SWELF_SuccessAudit_EVTID = 995;
        private static int SWELF_Information_EVTID = 996;
        private static int SWELF_Warning_EVTID = 997;
        private static int SWELF_Error_EVTID = 998;
        private static int SWELF_FailureAudit_EVTID = 999;

        public static void WRITE_EventLog_From_SWELF_Search(string log)
        {
            using (EventLog myLogger = new EventLog(Settings.SWELF_EvtLog_OBJ.Source, Environment.MachineName,CHECK_If_Protected_Log_Name(Settings.SWELF_EvtLog_OBJ.Source)))
            {
                myLogger.WriteEntry(log, EventLogEntryType.Information);
            }
        }

        public static void WRITE_EventLog_From_SWELF_Search(EventLog_Entry EvntLog)
        {
            using (EventLog myLogger = new EventLog(Settings.SWELF_EventLog_Name, Environment.MachineName, CHECK_If_Protected_Log_Name(EvntLog.LogName)))
            {
                //TODO Have eventlog log EventLogEntryType same as original
                //THIS is where SWELF eventlog get the severity BTW. along with alot of others
                myLogger.WriteEntry("SearchRule="+ EvntLog.SearchRule + "\r\n\r\n" + EvntLog.EventData, EventLogEntryType.Information, EvntLog.EventID);
            }
        }

        public static void WRITE_Critical_EventLog(string Msg, int EventID = 0)
        {
            if (EventID == 0)
            {
                using (EventLog myLogger = new EventLog(Settings.SWELF_EvtLog_OBJ.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(Settings.SWELF_EvtLog_OBJ.Source)))
                {
                    myLogger.WriteEntry(Msg, EventLogEntryType.FailureAudit, SWELF_FailureAudit_EVTID);
                }
            }
            else
            {
                using (EventLog myLogger = new EventLog(Settings.SWELF_EvtLog_OBJ.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(Settings.SWELF_EvtLog_OBJ.Source)))
                {
                    myLogger.WriteEntry(Msg, EventLogEntryType.FailureAudit, EventID);
                }
            }
        }
        public static void WRITE_ERROR_EventLog(string Msg, int EventID = 0)
        {
            if (EventID == 0)
            {
                using (EventLog myLogger = new EventLog(Settings.SWELF_EvtLog_OBJ.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(Settings.SWELF_EvtLog_OBJ.Source)))
                {
                    myLogger.WriteEntry(Msg, EventLogEntryType.Error, SWELF_Error_EVTID);
                }
            }
            else
            {
                using (EventLog myLogger = new EventLog(Settings.SWELF_EvtLog_OBJ.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(Settings.SWELF_EvtLog_OBJ.Source)))
                {
                    myLogger.WriteEntry(Msg, EventLogEntryType.FailureAudit, EventID);
                }
            }
        }
        public static void WRITE_Verbose_EventLog(string Msg, int EventID = 0)
        {
            if (EventID == 0)
            {
                using (EventLog myLogger = new EventLog(Settings.SWELF_EvtLog_OBJ.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(Settings.SWELF_EvtLog_OBJ.Source)))
                {
                    myLogger.WriteEntry(Msg, EventLogEntryType.SuccessAudit, SWELF_SuccessAudit_EVTID);
                }
            }
            else
            {
                using (EventLog myLogger = new EventLog(Settings.SWELF_EvtLog_OBJ.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(Settings.SWELF_EvtLog_OBJ.Source)))
                {
                    myLogger.WriteEntry(Msg, EventLogEntryType.FailureAudit, EventID);
                }
            }
        }
        public static void WRITE_Info_EventLog(string Msg, int EventID = 0)
        {
            if (EventID == 0)
            {
                using (EventLog myLogger = new EventLog(Settings.SWELF_EvtLog_OBJ.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(Settings.SWELF_EvtLog_OBJ.Source)))
                {
                    myLogger.WriteEntry(Msg, EventLogEntryType.Information, SWELF_Information_EVTID);
                }
            }
            else
            {
                using (EventLog myLogger = new EventLog(Settings.SWELF_EvtLog_OBJ.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(Settings.SWELF_EvtLog_OBJ.Source)))
                {
                    myLogger.WriteEntry(Msg, EventLogEntryType.FailureAudit, EventID);
                }
            }
        }
        public static void WRITE_Warning_EventLog(string Msg, int EventID=0)
        {
            if (EventID == 0)
            {
                using (EventLog myLogger = new EventLog(Settings.SWELF_EvtLog_OBJ.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(Settings.SWELF_EvtLog_OBJ.Source)))
                {
                    myLogger.WriteEntry(Msg, EventLogEntryType.Warning, SWELF_Warning_EVTID);
                }
            }
            else
            {
                using (EventLog myLogger = new EventLog(Settings.SWELF_EvtLog_OBJ.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(Settings.SWELF_EvtLog_OBJ.Source)))
                {
                    myLogger.WriteEntry(Msg, EventLogEntryType.FailureAudit, EventID);
                }
            }
        }


        public static void WRITE_Critical_EventLog(EventLog_Entry EvntLog)
        {
            using (EventLog myLogger = new EventLog(Settings.SWELF_EvtLog_OBJ.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(EvntLog.LogName)))
            {
                myLogger.WriteEntry(EvntLog.EventData, EventLogEntryType.FailureAudit, EvntLog.EventID);
            }
        }

        public static void WRITE_Warning_EventLog(EventLog_Entry EvntLog)
        {
            using (EventLog myLogger = new EventLog(Settings.SWELF_EvtLog_OBJ.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(EvntLog.LogName)))
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

