//Written by Ceramicskate0
//Copyright 
using System;
using System.Linq;
using System.Diagnostics;

namespace SWELF
{
    internal class EventLog_SWELF
    {

        private static string[] Protected_Event_Log_Names = { "application", "security", "system" };

        internal static void WRITE_EventLog_From_SWELF_Search(string log)
        {
            using (EventLog myLogger = new EventLog(Settings.SWELF_EventLog_Name, Environment.MachineName, Settings.SWELF_EvtLog_OBJ.Source))
            {
                myLogger.WriteEntry(log, EventLogEntryType.Information);
            }
        }

        internal static void WRITE_EventLog_From_SWELF_Search(EventLog_Entry EvntLog)
        {                
            //TODO Have eventlog log EventLogEntryType same as original

            using (EventLog myLogger = new EventLog(Settings.SWELF_EvtLog_OBJ.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(EvntLog.LogName)))
            {
                //THIS is where SWELF eventlog get the severity BTW.
                myLogger.WriteEntry("Search_Rule=" + EvntLog.SearchRule + "\r\n\r\n" + EvntLog.EventData, EventLogEntryType.Information, EvntLog.EventID);
                //IF ERROR For eventlog source occures it because in reg the 'source' is a sub folder uner a eventlog reg key with same name. Might want to do renaming to avoid issues.
            }
        }

        internal static void WRITE_FailureAudit_Error_To_EventLog(string Msg, Error_Operation.EventID eventID = 0)
        {
            Settings.SWELF_EvtLog_OBJ.Source = Settings.SWELF_EventLog_Name;
            if (eventID == 0)
            {
                using (EventLog myLogger = new EventLog(Settings.SWELF_EvtLog_OBJ.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(Settings.SWELF_EvtLog_OBJ.Source)))
                {
                    myLogger.WriteEntry(Msg, EventLogEntryType.FailureAudit, Convert.ToInt32(Error_Operation.EventID.SWELF_Error));
                }
            }
            else
            {
                using (EventLog myLogger = new EventLog(Settings.SWELF_EvtLog_OBJ.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(Settings.SWELF_EvtLog_OBJ.Source)))
                {
                    myLogger.WriteEntry(Msg, EventLogEntryType.FailureAudit, Convert.ToInt32(eventID));
                }
            }
        }

        internal static void WRITE_ERROR_EventLog(string Msg, Error_Operation.EventID eventID = 0)
        {
            Settings.SWELF_EvtLog_OBJ.Source = Settings.SWELF_EventLog_Name;

            if (Convert.ToInt32(eventID) == 0)
            {
                using (EventLog myLogger = new EventLog(Settings.SWELF_EvtLog_OBJ.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(Settings.SWELF_EvtLog_OBJ.Source)))
                {
                    myLogger.WriteEntry(Msg, EventLogEntryType.Error, Convert.ToInt32(Error_Operation.EventID.SWELF_Error));
                }
            }
            else
            {
                using (EventLog myLogger = new EventLog(Settings.SWELF_EvtLog_OBJ.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(Settings.SWELF_EvtLog_OBJ.Source)))
                {
                    myLogger.WriteEntry(Msg, EventLogEntryType.FailureAudit, Convert.ToInt32(eventID));
                }
            }
        }

        internal static void WRITE_Verbose_EventLog(string Msg, Error_Operation.EventID eventID = 0)
        {
            Settings.SWELF_EvtLog_OBJ.Source = Settings.SWELF_EventLog_Name;

            if (Convert.ToInt32(eventID) == 0)
            {
                using (EventLog myLogger = new EventLog(Settings.SWELF_EvtLog_OBJ.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(Settings.SWELF_EvtLog_OBJ.Source)))
                {
                    myLogger.WriteEntry(Msg, EventLogEntryType.SuccessAudit, Convert.ToInt32(Error_Operation.EventID.SWELF_SuccessAudit));
                }
            }
            else
            {
                using (EventLog myLogger = new EventLog(Settings.SWELF_EvtLog_OBJ.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(Settings.SWELF_EvtLog_OBJ.Source)))
                {
                    myLogger.WriteEntry(Msg, EventLogEntryType.FailureAudit, Convert.ToInt32(eventID));
                }
            }
        }

        internal static void WRITE_Info_EventLog(string Msg,Error_Operation.EventID eventID= 0)
        {
            Settings.SWELF_EvtLog_OBJ.Source = Settings.SWELF_EventLog_Name;

            if (Convert.ToInt32(eventID) == 0)
            {
                using (EventLog myLogger = new EventLog(Settings.SWELF_EvtLog_OBJ.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(Settings.SWELF_EvtLog_OBJ.Source)))
                {
                    myLogger.WriteEntry(Msg, EventLogEntryType.Information, Convert.ToInt32(Error_Operation.EventID.SWELF_Information));
                }
            }
            else
            {
                using (EventLog myLogger = new EventLog(Settings.SWELF_EvtLog_OBJ.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(Settings.SWELF_EvtLog_OBJ.Source)))
                {
                    myLogger.WriteEntry(Msg, EventLogEntryType.FailureAudit, Convert.ToInt32(eventID));
                }
            }
        }

        internal static void WRITE_Warning_EventLog(string Msg, Error_Operation.EventID eventID = 0)
        {
            Settings.SWELF_EvtLog_OBJ.Source = Settings.SWELF_EventLog_Name;
            if (Convert.ToInt32(eventID) == 0)
            {
                using (EventLog myLogger = new EventLog(Settings.SWELF_EvtLog_OBJ.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(Settings.SWELF_EvtLog_OBJ.Source)))
                {
                    myLogger.WriteEntry(Msg, EventLogEntryType.Warning, Convert.ToInt32(Error_Operation.EventID.SWELF_Warning));
                }
            }
            else
            {
                using (EventLog myLogger = new EventLog(Settings.SWELF_EvtLog_OBJ.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(Settings.SWELF_EvtLog_OBJ.Source)))
                {
                    myLogger.WriteEntry(Msg, EventLogEntryType.FailureAudit, Convert.ToInt32(eventID));
                }
            }
        }

        internal static void WRITE_Critical_EventLog_DataType(EventLog_Entry EvntLog)
        {
            Settings.SWELF_EvtLog_OBJ.Source = Settings.SWELF_EventLog_Name;

            using (EventLog myLogger = new EventLog(Settings.SWELF_EvtLog_OBJ.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(EvntLog.LogName)))
            {
                myLogger.WriteEntry(EvntLog.EventData, EventLogEntryType.FailureAudit, EvntLog.EventID);
            }
        }

        internal static void WRITE_Warning_EventLog_DataType(EventLog_Entry EvntLog)
        {
            Settings.SWELF_EvtLog_OBJ.Source = Settings.SWELF_EventLog_Name;

            using (EventLog myLogger = new EventLog(Settings.SWELF_EvtLog_OBJ.Source, Environment.MachineName, CHECK_If_Protected_Log_Name(EvntLog.LogName)))
            {
                myLogger.WriteEntry(EvntLog.EventData, EventLogEntryType.Warning, EvntLog.EventID);
            }
        }

        internal static string CHECK_If_Protected_Log_Name (string EvntLog_LogName)
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

