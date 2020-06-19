//Written by Ceramicskate0
//Copyright 2020
using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;

namespace SWELF
{
    internal class Error_Operation
    {
        internal readonly static string[] Severity_Levels = { "verbose", "informataion", "warning", "critical", "", "", "", "", "", "", "", "", "", "", "", "", "failureaudit" };

        internal static int Logging_Level_To_Report = 3;

        internal enum EventID
        {
            NO_Value = 0,
            SWELF_MAIN_APP_ERROR = 990,
            Powershell_Plugin = 993,
            SWELF_Central_Config_Changed = 994,
            SWELF_SuccessAudit = 995,
            SWELF_Information = 996,
            SWELF_Warning = 997,
            SWELF_Error = 998,
            SWELF_FailureAudit = 999

        }

        internal enum LogSeverity
        {
            Verbose = 0,
            Informataion = 1,
            Warning = 2,
            Critical = 3,
            FailureAudit = 16
        };

        internal static void ErrorLogging_Level()
        {
            try
            {
                if (Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.logging_level) == false)
                {
                    Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.logging_level, Settings.AppConfig_File_Args[Settings.SWELF_AppConfig_Args[17]]);
                }
                else
                {
                    Settings.Logging_Level_To_Report = Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.logging_level);
                }
                int index = Array.FindIndex(Severity_Levels, row => row == Settings.Logging_Level_To_Report);
                Logging_Level_To_Report = Convert.ToInt32(index);
            }
            catch (Exception e)
            {
                if (Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.logging_level))
                {
                    Settings.Logging_Level_To_Report = Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.logging_level);
                }
                else
                {
                    Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.logging_level, "warning");
                    Settings.Logging_Level_To_Report = "warning";
                    Logging_Level_To_Report = 3;
                }
            }
        }

        internal static void Log_Error(string MethodNameInCode, string Message, string StackDetails, LogSeverity LogSeverity, EventID eventID = 0)
        {
            if (Settings.Logging_Level_To_Report.ToLower() == "verbose")
            {
                Message = Message + " Stack_Info=" + StackDetails;
            }

            string msg = "DateTime=" + DateTime.Now.ToString(Settings.SWELF_Date_Time_Format) + "   SourceComputer=" + Settings.ComputerName + "   Severity=" + Severity_Levels[(int)LogSeverity] + "   Error_MethodInCode=" + MethodNameInCode + "   Error_Message=" + Message + "\n";

            try//write ALL to local error log 1st
            {
                File_Operation.CHECK_File_Size(Settings.GET_ErrorLog_Location);
                File_Operation.APPEND_AllTXT(Settings.GET_ErrorLog_Location, msg);
            }
            catch (Exception e)
            {
                try
                {
                    File_Operation.APPEND_AllTXT(Settings.SWELF_Log_File_Location + "\\" + Path.GetRandomFileName() + "_" + Settings.ErrorFile_FileName, msg);
                }
                catch (Exception ex)
                {
                    msg += "\nAdditional_ERROR: " + ex.Message.ToString() + " " + Settings.SWELF_PROC_Name + " was unable to write this error to a local file on this system at " + Settings.GET_ErrorLog_Location;
                }
            }
            if (Logging_Level_To_Report <= (int)LogSeverity)
            {
                try//write to eventlog
                {
                    WRITE_Errors_To_EventLog(MethodNameInCode, Message, LogSeverity, eventID);
                }
                catch (Exception exc)
                {
                    msg += "\nAdditional_ERROR: " + exc.Message.ToString() + " " + Settings.SWELF_PROC_Name + " was unable to write this error to the event log on this system";
                    try
                    {
                        File_Operation.APPEND_AllTXT(Settings.SWELF_Log_File_Location + "\\" + Path.GetRandomFileName() + "_" + Settings.ErrorFile_FileName, msg);
                    }
                    catch (Exception execp)
                    {
                        msg += "\nAdditional_ERROR: " + execp.Message.ToString() + " " + Settings.SWELF_PROC_Name + " was unable to write this error to a local file on this system at " + Settings.GET_ErrorLog_Location;
                    }
                }
                try// send eventlog to collector
                {
                    Log_Network_Forwarder.SEND_SINGLE_LOG(msg);
                }
                catch (Exception p)
                {
                    msg += "\nAdditional_ERROR: " + p.Message.ToString() + " " + Settings.SWELF_PROC_Name + " was unable to write error to Event Log";
                    try//write to eventlog
                    {
                        WRITE_Errors_To_EventLog(MethodNameInCode, Message, LogSeverity, eventID);
                    }
                    catch (Exception exc)
                    {
                        msg += "\nAdditional_ERROR: " + exc.Message.ToString() + " " + Settings.SWELF_PROC_Name + " was unable to write this error to the event log on this system";
                        try
                        {
                            File_Operation.APPEND_AllTXT(Settings.SWELF_Log_File_Location + "\\" + Path.GetRandomFileName() + "_" + Settings.ErrorFile_FileName, msg);
                        }
                        catch (Exception execp)
                        {
                            msg += "\nAdditional_ERROR: " + execp.Message.ToString() + " " + Settings.SWELF_PROC_Name + " was unable to write this error to a local file on this system at " + Settings.GET_ErrorLog_Location;
                        }
                    }
                }
            }
            Data_Store.ErrorsLog.Add(msg);
        }

        private static void WRITE_Errors_To_EventLog(string MethodInCode, string msg, LogSeverity LogSeverity, EventID eventID = 0)
        {
            ErrorLogging_Level();

                string err_msg = "DateTime=" + DateTime.Now.ToString(Settings.SWELF_Date_Time_Format) + "   SourceComputer=" + Settings.ComputerName + "   Severity=" + Severity_Levels[(int)LogSeverity] + "   MethodInCode=" + MethodInCode + "   Message=" + msg + "\n";

                if (LogSeverity == LogSeverity.Informataion)
                {
                    EventLog_SWELF.WRITE_Info_EventLog("DateTime=" + DateTime.Now.ToString(Settings.SWELF_Date_Time_Format) + " SWELF Immediate" + "   Severity=" + Severity_Levels[(int)LogSeverity] + "   Message=" + err_msg + "\n", eventID);
                }
                else if (LogSeverity == LogSeverity.Verbose)
                {
                    EventLog_SWELF.WRITE_Verbose_EventLog("DateTime=" + DateTime.Now.ToString(Settings.SWELF_Date_Time_Format) + " SWELF Immediate" + "   Severity=" + Severity_Levels[(int)LogSeverity] + "   Message=" + err_msg + "\n", eventID);
                }
                else if (LogSeverity == LogSeverity.Warning)
                {
                    EventLog_SWELF.WRITE_Warning_EventLog("DateTime=" + DateTime.Now.ToString(Settings.SWELF_Date_Time_Format) + " SWELF Immediate" + "   Severity=" + Severity_Levels[(int)LogSeverity] + "   Message=" + err_msg + "\n", eventID);
                }
                else if (LogSeverity == LogSeverity.FailureAudit)
                {
                    EventLog_SWELF.WRITE_FailureAudit_Error_To_EventLog("DateTime=" + DateTime.Now.ToString(Settings.SWELF_Date_Time_Format) + " SWELF Immediate" + "   Severity=" + Severity_Levels[(int)LogSeverity] + "   Message=" + err_msg + "\n", eventID);
                }
                else if (LogSeverity == LogSeverity.Critical)
                {
                    EventLog_SWELF.WRITE_ERROR_EventLog("DateTime=" + DateTime.Now.ToString(Settings.SWELF_Date_Time_Format) + " SWELF Immediate" + "   Severity=" + Severity_Levels[(int)LogSeverity] + "   Message=" + err_msg + "\n", eventID);
                }
                else
                {
                    EventLog_SWELF.WRITE_Verbose_EventLog("DateTime=" + DateTime.Now.ToString(Settings.SWELF_Date_Time_Format) + " SWELF Immediate" + "   Severity=" + Severity_Levels[(int)LogSeverity] + "   Message=" + err_msg + "\n", eventID);
                }
        }
    }
}
