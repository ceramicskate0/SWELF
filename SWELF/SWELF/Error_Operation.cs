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
        internal readonly static string[] Severity_Levels = { "verbose", "informataion", "warning", "critical", "","","","","","","","","","","","", "failureaudit" };
        internal static int Logging_Level_To_Report = 3;

        internal enum EventID 
        {
            NO_Value=0,
            SWELF_MAIN_APP_ERROR = 990,
            Powershell_Plugin = 993,
            SWELF_Central_Config_Changed = 994,
            SWELF_SuccessAudit= 995,
            SWELF_Information = 996,
            SWELF_Warning = 997,
            SWELF_Error = 998,
            SWELF_FailureAudit = 999

        }

        internal enum  LogSeverity
        {
            Verbose=0,
            Informataion=1,
            Warning=2,
            Critical=3,
            FailureAudit=16
        };

        internal static void ErrorLogging_Level()
        {
            try
            {
                if (Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.logging_level)==false)
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
                    Settings.Logging_Level_To_Report = Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.logging_level);
                    Logging_Level_To_Report = 1;
                }
            }
        }

        internal static void Log_Error(string MethodNameInCode, string Message,string StackDetails, LogSeverity LogSeverity, EventID eventID = 0)
        {
            if (Settings.Logging_Level_To_Report.ToLower() == "verbose")
            {
                Message = Message + " Stack_Info=" + StackDetails; 
            }
            string msg = "DateTime=" + DateTime.Now.ToString(Settings.SWELF_Date_Time_Format) + "   SourceComputer=" + Settings.ComputerName + "   Severity=" + Severity_Levels[(int)LogSeverity] + "   MethodInCode=" + MethodNameInCode + "   Message=" + Message + "\n";
            ErrorLogging_Level();
            try
            {
                if (Logging_Level_To_Report <= (int)LogSeverity)
                {
                    WRITE_Errors_To_Log(msg, LogSeverity, eventID);
                    Log_Network_Forwarder.SEND_SINGLE_LOG(msg);
                }
            }
            catch (Exception e)
            {
                Data_Store.ErrorsLog.Add(msg);
            }
        }

        internal static void WRITE_Errors_To_Log(string MethodInCode, string msg, LogSeverity LogSeverity, EventID eventID=0)
        {
            ErrorLogging_Level();

            if (Logging_Level_To_Report >= (int)LogSeverity)
            {
                string err_msg = "DateTime=" + DateTime.Now.ToString(Settings.SWELF_Date_Time_Format) + "   SourceComputer=" + Settings.ComputerName + "   Severity=" + Severity_Levels[(int)LogSeverity] + "   MethodInCode=" + MethodInCode + "   Message=" + msg + "\n";

                if (File_Operation.CHECK_if_File_Exists(Settings.GET_ErrorLog_Location))
                {
                    File.AppendAllText(Settings.GET_ErrorLog_Location, err_msg);
                }
                else
                {
                    File.Create(Settings.GET_ErrorLog_Location).Close();
                    File.AppendAllText(Settings.GET_ErrorLog_Location, err_msg);
                }

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

                File_Operation.CHECK_File_Size(Settings.GET_ErrorLog_Location);
            }
        }

        private  static void WRITE_Errors_To_Log(string msg, LogSeverity LogSeverity, EventID eventID=0)
        {
            if (File_Operation.CHECK_if_File_Exists(Settings.GET_ErrorLog_Location))
            {
                File.AppendAllText(Settings.GET_ErrorLog_Location, msg);
            }
            else
            {
                File.Create(Settings.GET_ErrorLog_Location).Close();
                File.AppendAllText(Settings.GET_ErrorLog_Location, msg);
            }
            File_Operation.CHECK_File_Size(Settings.GET_ErrorLog_Location);

            if (LogSeverity== LogSeverity.Informataion)
            {
                EventLog_SWELF.WRITE_Info_EventLog(msg, eventID);
            }
            else if (LogSeverity == LogSeverity.Verbose)
            {
                EventLog_SWELF.WRITE_Verbose_EventLog(msg, eventID);
            }
            else if (LogSeverity == LogSeverity.Warning)
            {
                EventLog_SWELF.WRITE_Warning_EventLog(msg, eventID);
            }
            else if (LogSeverity == LogSeverity.FailureAudit)
            {
                EventLog_SWELF.WRITE_FailureAudit_Error_To_EventLog(msg, eventID);
            }
            else if (LogSeverity == LogSeverity.Critical)
            {
                EventLog_SWELF.WRITE_ERROR_EventLog(msg, eventID);
            }
            else
            {
                EventLog_SWELF.WRITE_Verbose_EventLog(msg, eventID);
            }
        }

        internal static void SEND_Errors_To_Central_Location()
        {
            try
            {
                string[] Errors = File.ReadAllLines(Settings.GET_ErrorLog_Location);

                if (Settings.Log_Forwarders_HostNames.Any(s => string.Equals(s, "127.0.0.1", StringComparison.OrdinalIgnoreCase)) == false && Settings.Log_Forwarders_HostNames.Any(s => string.IsNullOrEmpty(s)) == false)
                {
                    for (int x = 0; x < Errors.Length; ++x)
                    {
                        Settings.Logs_Sent_to_ALL_Collectors = Log_Network_Forwarder.SEND_Logs(Errors[x], Settings.GET_ErrorLog_Location,true);
                    }
                    if (Settings.Logs_Sent_to_ALL_Collectors && File_Operation.CHECK_if_File_Exists(Settings.GET_ErrorLog_Location) || Settings.AppConfig_File_Args.ContainsKey(Settings.SWELF_AppConfig_Args[15]))
                    {
                        File_Operation.DELETE_File(Settings.GET_ErrorLog_Location);
                        File.Create(Settings.GET_ErrorLog_Location).Close();
                    }
                }

            }
            catch(Exception e)
            {
                Settings.Log_Storage_Location_Unavailable("SEND_Errors_To_Central_Location() "+e.Message.ToString());
            }
        }

        internal static void WRITE_Stored_Errors()
        {
            if (Data_Store.ErrorsLog.Count > 0)
            {
                for (int x = 0; x < Data_Store.ErrorsLog.Count; ++x)
                {
                    File.AppendAllText(Settings.SWELF_Log_File_Location + "\\" + Path.GetRandomFileName() + "_SWELF_HAD_IO_ERROR.log", Data_Store.ErrorsLog.ElementAt(x));
                }
            }
        }
    }
}
