//Written by Ceramicskate0
//Copyright 2018
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace SWELF
{
    class Errors
    {
        private static List<string> ErrorsLog = new List<string>();
        private static DriveInfo Disk = new DriveInfo("C");
        private static long Drives_Available_Space = Disk.AvailableFreeSpace;
        private static string[] Severity_Levels = { "verbose","informataion","warning","critical","failureaudit"};
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
                Settings.Logging_Level_To_Report = Settings.AppConfig_File_Args["logging_level"].ToLower();
                var index = Array.FindIndex(Severity_Levels, row => row == Settings.Logging_Level_To_Report);
                Logging_Level_To_Report = Convert.ToInt32(index);
            }
            catch
            {
                Logging_Level_To_Report = 1;
            }
        }

        public static void Log_Error(string MethodNameInCode, string Message, LogSeverity LogSeverity,bool LastLog=false)
        {
            ErrorLogging_Level();
            if (Logging_Level_To_Report <= (int)LogSeverity)
            {
                ErrorsLog.Add("Date=" + DateTime.Now.ToShortDateString() + "   SourceComputer=" + Settings.ComputerName + "   LogSeverity=" + Severity_Levels[(int)LogSeverity] + "   MethodInCode=" + MethodNameInCode + "   Message=" + Message + "\n");
                ErrorsLog = ErrorsLog.Distinct().ToList();
                if (ErrorsLog.Count > 6 || LastLog)
                {
                    WRITE_Errors();
                }
            }
        }

        public static void WRITE_Errors_To_Log(string MethodInCode, string msg, LogSeverity LogSeverity)
        {
            ErrorLogging_Level();
            if (Logging_Level_To_Report >= (int)LogSeverity)
            {
                string err = "Date="+DateTime.Now + "   SourceComputer=" + Settings.ComputerName + "   LogSeverity=" + Severity_Levels[(int)LogSeverity] + "   MethodInCode=" + MethodInCode + "   Message=" + msg + "\n";
                if (Settings.VERIFY_if_File_Exists(Settings.GET_ErrorLog_Location))
                {
                    File.AppendAllText(Settings.GET_ErrorLog_Location, err);
                }
                else
                {
                    File.Create(Settings.GET_ErrorLog_Location).Close();
                    File.AppendAllText(Settings.GET_ErrorLog_Location, err);
                }
                HostEventLogAgent_Eventlog.WRITE_Critical_EventLog("SWELF Immediate" + "   LogSeverity=" + Severity_Levels[(int)LogSeverity] + "   Message=" + err + "\n");
                CHECK_Error_Log_Size();
            }
        }

        private static void CHECK_Error_Log_Size()
        {
            FileInfo Log_App_Log_File = new FileInfo(Settings.GET_ErrorLog_Location);

            if (Log_App_Log_File.Length > Drives_Available_Space * .0001)
            {
                Settings.DELETE_AND_CREATE_File(Settings.GET_ErrorLog_Location);
            }
        }

        public static void WRITE_Errors()
        {
            for (int x = 0; x < ErrorsLog.Count; ++x)
            {
                WRITE_Errors_To_Log_BATCH(ErrorsLog.ElementAt(x));
            }
            ErrorsLog.Clear();
        }

        private  static void WRITE_Errors_To_Log_BATCH(string msg)
        {
            if (Settings.VERIFY_if_File_Exists(Settings.GET_ErrorLog_Location))
            {
                File.AppendAllText(Settings.GET_ErrorLog_Location, msg);
            }
            else
            {
                File.Create(Settings.GET_ErrorLog_Location).Close();
                File.AppendAllText(Settings.GET_ErrorLog_Location, msg);
            }
            HostEventLogAgent_Eventlog.WRITE_Warning_EventLog(msg);
            CHECK_Error_Log_Size();
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
    }
}
