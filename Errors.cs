//Written by Ceramicskate0
//Copyright 2018
using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;

namespace SWELF
{
    class Errors
    {
        private static List<string> ErrorsLog = new List<string>();
        private static string[] Severity_Levels = { "Verbose", "Informataion", "Warning", "Critical", "","","","","","","","","","","","", "FailureAudit" };
        private static int Logging_Level_To_Report = 1;

        public enum  LogSeverity : int
        {
            Verbose=0,
            Informataion=1,
            Warning=2,
            Critical=3,
            FailureAudit=16
        };

        public static void ErrorLogging_Level()
        {
            try
            {
                Settings.Logging_Level_To_Report = Settings.AppConfig_File_Args["logging_level"];
                int index = Array.FindIndex(Severity_Levels, row => row == Settings.Logging_Level_To_Report);
                Logging_Level_To_Report = Convert.ToInt32(index);
            }
            catch
            {
                Logging_Level_To_Report = 1;
            }
        }

        public static void Log_Error(string MethodNameInCode, string Message, LogSeverity LogSeverity,int EventID=0)
        {
            try
            {
                ErrorLogging_Level();
                if (Logging_Level_To_Report <= (int)LogSeverity)
                {
                    WRITE_Errors_To_Log("Date=" + DateTime.Now.ToShortDateString() + "   SourceComputer=" + Settings.ComputerName + "   LogSeverity=" + Severity_Levels[(int)LogSeverity] + "   MethodInCode=" + MethodNameInCode + "   Message=" + Message + "\n", LogSeverity, EventID);
                }
            }
            catch (Exception e)
            {
                ErrorsLog.Add("Date=" + DateTime.Now.ToShortDateString() + "   SourceComputer=" + Settings.ComputerName + "   LogSeverity=" + Severity_Levels[(int)LogSeverity] + "   MethodInCode=" + MethodNameInCode + "   Message=" + Message + "\n");
            }
        }

        public static void WRITE_Errors_To_Log(string MethodInCode, string msg, LogSeverity LogSeverity, int EventID = 0)
        {
            ErrorLogging_Level();
            if (Logging_Level_To_Report >= (int)LogSeverity)
            {
                string err = "Date="+DateTime.Now + "   SourceComputer=" + Settings.ComputerName + "   LogSeverity=" + Severity_Levels[(int)LogSeverity] + "   MethodInCode=" + MethodInCode + "   Message=" + msg + "\n";
                if (File_Operation.VERIFY_if_File_Exists(Settings.GET_ErrorLog_Location))
                {
                    File.AppendAllText(Settings.GET_ErrorLog_Location, err);
                }
                else
                {
                    File.Create(Settings.GET_ErrorLog_Location).Close();
                    File.AppendAllText(Settings.GET_ErrorLog_Location, err);
                }
                EventLog_SWELF.WRITE_Critical_EventLog("SWELF Immediate" + "   LogSeverity=" + Severity_Levels[(int)LogSeverity] + "   Message=" + err + "\n", EventID);
                File_Operation.CHECK_File_Size(Settings.GET_ErrorLog_Location);
            }
        }


        private  static void WRITE_Errors_To_Log(string msg, LogSeverity LogSeverity,int EventID=0)
        {
            if (File_Operation.VERIFY_if_File_Exists(Settings.GET_ErrorLog_Location))
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
                EventLog_SWELF.WRITE_Warning_EventLog(msg, EventID);
            }
            else if (LogSeverity == LogSeverity.Verbose)
            {
                EventLog_SWELF.WRITE_Verbose_EventLog(msg, EventID);
            }
            else if (LogSeverity == LogSeverity.Warning)
            {
                EventLog_SWELF.WRITE_Warning_EventLog(msg, EventID);
            }
            else if (LogSeverity == LogSeverity.FailureAudit)
            {
                EventLog_SWELF.WRITE_ERROR_EventLog(msg, EventID);
            }
            else if (LogSeverity == LogSeverity.Critical)
            {
                EventLog_SWELF.WRITE_Critical_EventLog(msg, EventID);
            }
            else
            {
                EventLog_SWELF.WRITE_Verbose_EventLog(msg, EventID);
            }
        }

        public static void SEND_Errors_To_Central_Location()
        {
            string[]  Errors = File.ReadAllLines(Settings.GET_ErrorLog_Location);
            if (Settings.GET_LogCollector_Location().ToString().Contains("127.0.0.1") == false && String.IsNullOrWhiteSpace(Settings.GET_LogCollector_Location().ToString()) == false)
            {
                for (int x = 0; x < Errors.Length; ++x)
                {
                    Network_Forwarder.SEND_Data_from_File(Errors[x]);
                }
            }
        }

        public static void WRITE_Stored_Errors()
        {
            if (ErrorsLog.Count > 0)
            {
                for (int x = 0; x < ErrorsLog.Count; ++x)
                {
                    File.AppendAllText(Settings.SWELF_Log_File_Location + "\\" + Path.GetRandomFileName() + "_SWELF_HAD_IO_ERROR.log", ErrorsLog.ElementAt(x));
                }
            }
        }
    }
}
