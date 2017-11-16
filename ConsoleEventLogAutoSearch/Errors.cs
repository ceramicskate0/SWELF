//Written by Ceramicskate0
//Copyright 2017
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace ConsoleEventLogAutoSearch
{
    class Errors
    {
        private static List<string> ErrorsLog = new List<string>();
        private static string ErrorLogFile = Settings.GET_ErrorLog_Location;

        /// <summary>
        /// Writes errors to console and log to file in batch at end of program
        /// </summary>
        /// <param name="CodeInfo"></param>
        /// <param name="msg"></param>
        public static void Log_Error(string CodeInfo, string msg)
        {
            string err = DateTime.Now + " : " + CodeInfo + " : " + msg + "\n";
            ErrorsLog.Add(err);
            if (ErrorsLog.Count>100)
            {
                for ( int x = 0; x > ErrorsLog.Count; ++x)
                {
                    WriteErrorsToLog(ErrorsLog.ElementAt(x));
                }
            }
        }

        /// <summary>
        /// Writes errors to logs ASAP
        /// </summary>
        /// <param name="msg"></param>
        public static void WriteErrorsToLog(string msg)
        {
            if (!File.Exists(ErrorLogFile))
            {
                using (StreamWriter file = new StreamWriter(ErrorLogFile))
                {
                   file.WriteLine(msg);
                }
            }
            else
            {
                File.Create(ErrorLogFile).Close();
                using (StreamWriter file = new StreamWriter(ErrorLogFile))
                {
                    file.WriteLine(msg);
                }
            }
            Settings.ADD_Eventlog_to_CriticalEvents(msg, "SWELF App Error");
            HostEventLogAgent_Eventlog.WRITE_All_App_EventLog(Settings.CriticalEvents);
        }

        private static void DO_If_Log_File()
        {
            Settings.GET_ErrorLog_Ready();
        }
    }
}
