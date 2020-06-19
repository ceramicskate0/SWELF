using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SWELF
{
    class Data_Store
    {
        internal static Queue<EventLog_Entry> contents_of_EventLog = new Queue<EventLog_Entry>();//The contents of a eventlog read into SWELF
        internal static Queue<EventLog_Entry> EVTX_File_Logs = new Queue<EventLog_Entry>();//contents of evtx file read into swelf
        internal static Queue<EventLog_Entry> SWELF_Events_Of_Interest_Matching_EventLogs = new Queue<EventLog_Entry>();//The event logs that matched a search
        internal static Queue<EventLog_Entry> PS_Plugin_SWELF_Events_Of_Interest_Matching_EventLogs = new Queue<EventLog_Entry>();//the contents of a event log that a plugin found
        
        internal static Queue<EventLog_Entry> CriticalEvents = new Queue<EventLog_Entry>();//APP error events that must be logged
        internal static List<string> ErrorsLog = new List<string>();
    }
}
