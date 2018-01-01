//Written by Ceramicskate0
//Copyright 2017
using System;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using System.Collections;
using System.Text.RegularExpressions;

namespace ConsoleEventLogAutoSearch
{
    class Search_EventLogs
    {
        private Dictionary<int, List<EventLogEntry>> EVENTLOG_SEARCH_DATA_MODEL = new Dictionary<int, List<EventLogEntry>>();
        private Queue<EventLogEntry> EventLogs_From_WindowsAPI = new Queue<EventLogEntry>();
        private static List<EventLogEntry> Matchs = new List<EventLogEntry>();

        public Search_EventLogs(Queue<EventLogEntry> eventLogs_From_WindowsAPI)
        {
            EventLogs_From_WindowsAPI = eventLogs_From_WindowsAPI;
        }

        public Queue<EventLogEntry> Search()
        {
            try
            {
                for (int x = 0; x < Settings.Logs_Search_Terms_Unparsed.Count; ++x)
                {
                    if (Settings.Logs_Search_Terms_Unparsed.ElementAt(x).Contains('#') == false)
                    {
                        if (Settings.Logs_Search_Terms_Unparsed.ElementAt(x).Contains("count:") || Settings.Logs_Search_Terms_Unparsed.ElementAt(x).Contains("eventdata_length:") || Settings.Logs_Search_Terms_Unparsed.ElementAt(x).Contains("commandline_length:"))
                        {
                            SEARCH_Run_Commands(Settings.Logs_Search_Terms_Unparsed.ElementAt(x));
                        }
                        else
                        {
                            SEARCH_FindTerms(x);
                        }
                    }
                }
                Matchs = Matchs.Distinct().ToList();
                IEnumerable<EventLogEntry> noduplicates = Matchs.Distinct();
                var queue = new Queue<EventLogEntry>(Matchs);
                return queue;
            }
            catch (Exception e)
            {
                Errors.Log_Error("Search()", e.Message.ToString());
                return null;
            }
        }

        private List<EventLogEntry> SEARCH_EventID_and_Data(int EventID, string SearchTerm)
        {
            List<EventLogEntry> EventsThatMatchSearch = new List<EventLogEntry>();
            for (int x = 0; x > EVENTLOG_SEARCH_DATA_MODEL[EventID].Count; ++x)
            {
                if (EVENTLOG_SEARCH_DATA_MODEL[EventID].ElementAt(x).EventData.Contains(SearchTerm))
                {
                    EventsThatMatchSearch.Add(EVENTLOG_SEARCH_DATA_MODEL[EventID].ElementAt(x));
                }
            }
            return EventsThatMatchSearch;
        }

        private List<EventLogEntry> SEARCH_EventID(int EventID)
        {
            List<EventLogEntry> EventsThatMatchSearch = new List<EventLogEntry>();
            IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(s => s.EventID.Equals(EventID)==true).ToList();
            EventsThatMatchSearch = results.ToList();
            return EventsThatMatchSearch;
        }

        private List<EventLogEntry> SEARCH_Everything(string SearchTerm)
        {
            List<EventLogEntry> EventsThatMatchSearch = new List<EventLogEntry>();
            IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(s => s.GET_XML_of_Log.Contains(SearchTerm)).ToList();
            EventsThatMatchSearch = results.ToList();
            return EventsThatMatchSearch;
        }

        private List<EventLogEntry> SEARCH_EventLog_For_EventID(int EventID ,string EventLogName)
        {
            List<EventLogEntry> EventsThatMatchSearch = new List<EventLogEntry>();
            IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(s => s.EventID.Equals(EventID) == true && s.LogName.ToLower() == EventLogName.ToLower()).ToList();
            EventsThatMatchSearch = results.ToList();
            return EventsThatMatchSearch;
        }

        private List<EventLogEntry> SEARCH_Counts_in_Log (string SearchTerm,int numofoccur)
        {
            List<EventLogEntry> EventsThatMatchSearch = new List<EventLogEntry>();
            for (int x=0;x< EventLogs_From_WindowsAPI.Count;++x)
            {
                int Count = Regex.Matches(EventLogs_From_WindowsAPI.ElementAt(x).GET_XML_of_Log, SearchTerm, RegexOptions.IgnoreCase).Count;
                if (Count>=numofoccur)
                {
                    EventsThatMatchSearch.Add(EventLogs_From_WindowsAPI.ElementAt(x));
                }
            }
             return EventsThatMatchSearch;
        }

        private List<EventLogEntry> SEARCH_Length_of_LogEntry(int length)
        {
            List<EventLogEntry> EventsThatMatchSearch = new List<EventLogEntry>();
            IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(s => s.EventData.ToCharArray().Length >= length).ToList();
            EventsThatMatchSearch = results.ToList();
            return EventsThatMatchSearch;
        }

        private List<EventLogEntry> SEARCH_Length_Sysmon_CMDLine_Args(int length)
        {
            List<EventLogEntry> EventsThatMatchSearch = new List<EventLogEntry>();
            IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(s => s.GET_Sysmon_CommandLineArgs.ToCharArray().Length >= length).ToList();
            EventsThatMatchSearch = results.ToList();
            return EventsThatMatchSearch;
        }

        private void SEARCH_Run_Commands(string xSearch)
        {
            try
            {
                string[] Searchs = xSearch.Split(':').ToArray();
                switch (Searchs[0].ToLower())
                {
                    case "count":
                        {
                            Matchs.AddRange(SEARCH_Counts_in_Log(Searchs[1].ToString(), Convert.ToInt32(Searchs[2])));
                            break;
                        }
                    case "eventdata_length":
                        {
                            Matchs.AddRange(SEARCH_Length_of_LogEntry(Convert.ToInt32(Searchs[1])));
                            break;
                        }
                    case "commandline_length":
                        {
                            if (Convert.ToInt32(Searchs[1]) != -1)
                            {
                                Matchs.AddRange(SEARCH_Length_Sysmon_CMDLine_Args(Convert.ToInt32(Searchs[1])));
                            }
                            break;
                        }
                }
            }
            catch (Exception e)
            {
                Errors.Log_Error("SEARCH_Run_Commands()", e.Message.ToString());
            }
        }

        private void SEARCH_FindTerms(int x)
        {
                string[] SearchsArgs = Settings.Logs_Search_Terms_Unparsed.ElementAt(x).Split(',').ToArray();
                switch (SearchsArgs.Length)
                {
                    case 1://search term only
                        {
                            Matchs.AddRange(SEARCH_Everything(SearchsArgs[0]));
                            break;
                        }
                    case 2://search log and term
                        {
                            if (SearchsArgs[1].ToLower() == EventLogs_From_WindowsAPI.Peek().LogName.ToLower())
                            {
                                Matchs.AddRange(SEARCH_Everything(SearchsArgs[0]));
                            }
                            break;
                        }
                    case 3://search log term and or id
                        {
                            if (String.IsNullOrEmpty(SearchsArgs[0])==true && String.IsNullOrEmpty(SearchsArgs[1]) == true && String.IsNullOrEmpty(SearchsArgs[2]) == false)//Search only event id all others blank
                            {
                            Matchs.AddRange(SEARCH_EventID(Convert.ToInt32(SearchsArgs[2])));
                            }
                            else if (String.IsNullOrEmpty(SearchsArgs[0]) == true && String.IsNullOrEmpty(SearchsArgs[1]) == false && String.IsNullOrEmpty(SearchsArgs[2]) == false)//search event log for only ID
                            {
                            Matchs.AddRange(SEARCH_EventLog_For_EventID(Convert.ToInt32(SearchsArgs[2]), SearchsArgs[1]));
                            }
                            else //Gave 3 step search and somehow got here
                            {
                                Matchs.AddRange(SEARCH_EventID_and_Data(Convert.ToInt32(SearchsArgs[2]), SearchsArgs[0]));
                            }
                        break;
                        }
                    default:
                        {
                            foreach (string Search in SearchsArgs)
                            {
                                Matchs.AddRange(SEARCH_Everything(Search));
                            }
                            break;
                        }
                }
        }
    }
}
