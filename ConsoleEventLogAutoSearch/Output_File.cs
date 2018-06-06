using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace SWELF
{
    class Output_File
    {
        private static List<string> OutputFileContents = new List<string>();

        public static void Write_Ouput_CSV(string FilePath,Queue<EventLogEntry> FileContents)
        {
            if (Settings.VERIFY_if_File_Exists(FilePath))
             {
                Write_Contents(FilePath,FileContents);
             }
            else
            {
                File.Create(FilePath).Close();
                File.AppendAllText(FilePath, "LogName" + "," + "EventRecordID" + "," + "EventID" + "," + "CreatedTime" + "," + "ComputerName" + "," + "UserID" + "," + "Severity" + "," + "TaskDisplayName" + "," + "EventData" + '\n');
                Write_Contents(FilePath,FileContents);
            }

        }

        private static void Write_Contents(string FilePath, Queue<EventLogEntry> FileContents)
        {
            for (int x=0; x<FileContents.Count;++x)
            {
               File.AppendAllText(FilePath,FORMAT_Output(FileContents.ElementAt(x)));
            }
        }

        private static string FORMAT_Output(EventLogEntry EventLog)
        {
            string EventData;
            EventData=EventLog.EventData;
            EventData=EventData.Replace('\n', ' ');
            EventData=EventData.Replace('\r', ' ');
            EventData=EventData.Replace("\n\r", " ");
            EventData=EventData.Replace("\r\n", " ");

            return EventLog.LogName + "," + EventLog.EventRecordID + "," + EventLog.EventID + "," + EventLog.CreatedTime + "," + EventLog.ComputerName + "," + EventLog.UserID + ","  + EventLog.Severity + "," + EventLog.TaskDisplayName + ",\"" + EventData +"\""+ '\n';
        }
    }
}
