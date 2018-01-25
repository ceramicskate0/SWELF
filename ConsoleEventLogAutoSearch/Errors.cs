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
        private static string ErrorLogFile = Settings.GET_ErrorLog_Location;
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

        public static void WRITE_Errors_To_Log(string msg)
        {
            if (!File.Exists(ErrorLogFile))
            {
                using (StreamWriter filewriter = new StreamWriter(ErrorLogFile))
                {
                    filewriter.WriteLine(msg);
                }
                
            }
            else
            {
                File.Create(ErrorLogFile).Close();
                using (StreamWriter filewriter = new StreamWriter(ErrorLogFile))
                {
                    filewriter.WriteLine(msg);
                }
            }
            Settings.ADD_Eventlog_to_CriticalEvents(msg, "SWELF App Error");
            HostEventLogAgent_Eventlog.WRITE_All_App_EventLog(Settings.CriticalEvents);

            CHECK_Error_Log_Size();
        }

        private static void CHECK_Error_Log_Size()
        {
            FileInfo Log_App_Log_File = new FileInfo(ErrorLogFile);

            if (Log_App_Log_File.Length > Drives_Available_Space * .0001)
            {
                Settings.DELETE_AND_CREATE_File(ErrorLogFile);
            }
        }

        public static void WRITE_Errors()
        {
            for (int x = 0; x > ErrorsLog.Count; ++x)
            {
                WRITE_Errors_To_Log(ErrorsLog.ElementAt(x));
            }
            ErrorsLog.Clear();
        }

        public static void SEND_Errors_To_Central_Location()
        {
            string[]  Errors = File.ReadAllLines(ErrorLogFile);
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
