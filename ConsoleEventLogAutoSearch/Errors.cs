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

        public static void Log_Error(string CodeInfo, string msg)
        {
            string err = DateTime.Now + " : " + CodeInfo + " : " + msg + "\n";
            ErrorsLog.Add(err);

            if (ErrorsLog.Count>5)
            {
                WRITE_Errors();
            }
        }

        public static void WRITE_Errors_To_Log(string CodeInfo, string msg, string Severity)
        {
            if (!CodeInfo.Contains(':'))
            {
                CodeInfo += ':';
            }
            string err = DateTime.Now + " : " + CodeInfo +  msg + '\n';
            if (Settings.VERIFY_if_File_Exists(Settings.GET_ErrorLog_Location))
            {
              File.AppendAllText(Settings.GET_ErrorLog_Location, err);
            }
            else
            {
                File.Create(Settings.GET_ErrorLog_Location).Close();
                File.AppendAllText(Settings.GET_ErrorLog_Location, err);
            }
            Settings.ADD_Eventlog_to_CriticalEvents(err, "SWELF App Error", Severity);
            HostEventLogAgent_Eventlog.WRITE_All_App_EventLog(Settings.CriticalEvents,"critical");

            CHECK_Error_Log_Size();
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
            for (int x = 0; x > ErrorsLog.Count; ++x)
            {
                WRITE_Errors_To_Log_BATCH(ErrorsLog.ElementAt(x) + '\n');
            }
            ErrorsLog.Clear();
        }

        private  static void WRITE_Errors_To_Log_BATCH(string msg)
        {
            if (Settings.VERIFY_if_File_Exists(Settings.GET_ErrorLog_Location))
            {
                File.AppendAllText(Settings.GET_ErrorLog_Location, msg + '\n');
            }
            else
            {
                File.Create(Settings.GET_ErrorLog_Location).Close();
                File.AppendAllText(Settings.GET_ErrorLog_Location, msg + '\n');
            }
            Settings.ADD_Eventlog_to_CriticalEvents(msg, "SWELF App Error","Warning");
            HostEventLogAgent_Eventlog.WRITE_All_App_EventLog(Settings.CriticalEvents, "warning");

            CHECK_Error_Log_Size();
        }

        public static void SEND_Errors_To_Central_Location()
        {
            string[]  Errors = File.ReadAllLines(Settings.GET_ErrorLog_Location);
            if (Settings.GET_LogCollector_Location().ToString().Contains("127.0.0.1") == false && String.IsNullOrWhiteSpace(Settings.GET_LogCollector_Location().ToString()) == false)
            {
                for (int x = 0; x > Errors.Length; ++x)
                {
                    Network_Forwarder.SEND_Data_from_File(Errors[x]);
                }
            }
        }
    }
}
