//Written by Ceramicskate0
//Copyright 2018
using System;
using System.Linq;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace SWELF
{
    class Search_EventLogs
    {
        private Queue<EventLog_Entry> Read_In_EventLogs_From_WindowsAPI = new Queue<EventLog_Entry>();
        private static List<EventLog_Entry> ALL_Logs_That_Matched_Search_This_Event_Log = new List<EventLog_Entry>();//The logs that matched this run,this log
        private List<EventLog_Entry> Filtered_Matched_Logs_This_SWELF_Run = new List<EventLog_Entry>();//All the logs found that matched

        private static string CurrentEventLogBeingSearched = "";

        public Search_EventLogs(Queue<EventLog_Entry> Contents_of_EventLog)
        {
            Read_In_EventLogs_From_WindowsAPI = Contents_of_EventLog;
        }

        public void Clear_Search()
        {
            Read_In_EventLogs_From_WindowsAPI.Clear();
            ALL_Logs_That_Matched_Search_This_Event_Log.Clear();
        }

        public Queue<EventLog_Entry> Search(string Current_EventLog)
        {
            int temp_int_stor_for_Errors = 0;
            for (int x = 0; x < Settings.Search_Terms_Unparsed.Count; ++x)
            {
                try
                {
                    string[] Search_String_Parsed = Settings.Search_Terms_Unparsed.ElementAt(x).Split(Settings.SplitChar_SearchCommandSplit, StringSplitOptions.None).ToArray();

                    if (Search_String_Parsed.Length > 3)
                    {
                        Errors.Log_Error("Search()", "Value=" + Settings.Search_Terms_Unparsed.ElementAt(x) + ". Check syntax and data input names. Command to Long for input Format see docs.", Errors.LogSeverity.Warning);
                    }
                    else
                    {
                        if (Settings.Search_Commands.Any(s => Settings.Search_Terms_Unparsed.ElementAt(x).ToLower().IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0))
                        {
                            if ((Search_String_Parsed.Length > 1 && (string.IsNullOrEmpty(Search_String_Parsed[1]) == false) && Search_String_Parsed[1] == Current_EventLog) || Search_String_Parsed.Length == 1)
                            {
                                SEARCH_Run_Commands(Settings.Search_Terms_Unparsed.ElementAt(x), Search_String_Parsed, Settings.Search_Terms_Unparsed.ElementAt(x));
                            }
                        }
                        else
                        {
                            if (Search_String_Parsed.Length >= 1)
                            {
                                SEARCH_FindTerms(x, Search_String_Parsed);
                            }
                        }
                    }
                }
                catch (Exception e)
                {
                    Errors.Log_Error("Search() Value=" + Settings.Search_Terms_Unparsed.ElementAt(temp_int_stor_for_Errors), e.Message.ToString() + ". Check syntax and data input names.", Errors.LogSeverity.Informataion);
                }
            }
            Filtered_Matched_Logs_This_SWELF_Run.AddRange(ALL_Logs_That_Matched_Search_This_Event_Log.Distinct().OrderBy(x => x.CreatedTime).ToList());
            if (ALL_Logs_That_Matched_Search_This_Event_Log.Count > 0)
            {
                Remove_Whitelisted_Logs();
            }

            var queue = new Queue<EventLog_Entry>(Filtered_Matched_Logs_This_SWELF_Run);
            Filtered_Matched_Logs_This_SWELF_Run.Clear();
            return queue;
        }

        private void Remove_Whitelisted_Logs()
        {
            for (int x = 0; x < Settings.WhiteList_Search_Terms_Unparsed.Count; ++x)
            {
                try
                {
                    string[] WhiteListSearchsArgs = Settings.WhiteList_Search_Terms_Unparsed.ElementAt(x).Split(Settings.SplitChar_SearchCommandSplit, StringSplitOptions.RemoveEmptyEntries).ToArray();

                    switch (WhiteListSearchsArgs.Length)
                    {
                        case 1:
                            {
                                SEARCH_REMOVE_WhiteList(WhiteListSearchsArgs[0]);
                                break;
                            }
                        case 2:
                            {
                                SEARCH_REMOVE_WhiteList(WhiteListSearchsArgs[0], WhiteListSearchsArgs[1]);
                                break;
                            }
                        case 3:
                            {
                                SEARCH_REMOVE_WhiteList(WhiteListSearchsArgs[0], WhiteListSearchsArgs[1], Convert.ToInt32(WhiteListSearchsArgs[2]));
                                break;
                            }
                    }
                }
                catch (Exception e)
                {
                    Errors.Log_Error("Remove_Whitelisted_Logs() Value=" + Settings.WhiteList_Search_Terms_Unparsed.ElementAt(x), e.Message.ToString(), Errors.LogSeverity.Warning);
                }
            }
        }

        private void SEARCH_REMOVE_WhiteList(string SearchTerm, string EventLogName="", int EventID=-1)
        {
            if (EventID > 0)
            {
                Filtered_Matched_Logs_This_SWELF_Run.RemoveAll(s => s.EventData.Contains(SearchTerm) && s.LogName.ToLower().Equals(EventLogName.ToLower()) && s.EventID.Equals(EventID));
            }
            else if (!string.IsNullOrEmpty(SearchTerm) && !string.IsNullOrEmpty(EventLogName))
            {
                Filtered_Matched_Logs_This_SWELF_Run.RemoveAll(s => s.EventData.Contains(SearchTerm) && s.LogName.ToLower().Equals(EventLogName.ToLower()));
            }
            else
            {
                Filtered_Matched_Logs_This_SWELF_Run.RemoveAll(s => s.EventData.Contains(SearchTerm));
            }
        }

        private void SEARCH_FindTerms(int x,string[] Search_String_Parsed)
        {
            string[] SearchsArgs = Settings.Search_Terms_Unparsed.ElementAt(x).Split(Settings.SplitChar_SearchCommandSplit, StringSplitOptions.RemoveEmptyEntries).ToArray();

            switch (SearchsArgs.Length)
            {
                case 1://search term and event id
                    {
                        if (Read_In_EventLogs_From_WindowsAPI.Count > 0)
                        {
                            if (string.IsNullOrEmpty(Search_String_Parsed[0]) && string.IsNullOrEmpty(Search_String_Parsed[1]) == false)
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_EventLog_Return_All(Search_String_Parsed[1]));
                            }
                            else if (string.IsNullOrEmpty(Search_String_Parsed[0])==true && string.IsNullOrEmpty(Search_String_Parsed[1]) == true)
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_EventID(Convert.ToInt32(Search_String_Parsed[2])));
                            }
                            else if (string.IsNullOrEmpty(Search_String_Parsed[0]) == true && string.IsNullOrEmpty(Search_String_Parsed[2]) == true)
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_EventLog_Return_All(Search_String_Parsed[1]));
                            }
                            else
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_Everything(SearchsArgs[0]));
                            }
                        }
                        break;
                    }
                case 2://search log and term
                    {
                        if (Read_In_EventLogs_From_WindowsAPI.Count > 0)
                        {
                            if (string.IsNullOrEmpty(Search_String_Parsed[0]) == true && string.IsNullOrEmpty(Search_String_Parsed[1]) == false && string.IsNullOrEmpty(Search_String_Parsed[2]) == true)
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_EventLog_Return_All(SearchsArgs[0]));
                            }
                            else if (string.IsNullOrEmpty(Search_String_Parsed[0]) == true && string.IsNullOrEmpty(Search_String_Parsed[1]) == true && string.IsNullOrEmpty(Search_String_Parsed[2]) == false)
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_EventLog_For_EventID(Convert.ToInt32(SearchsArgs[2]), SearchsArgs[1]));
                            }
                            else if (string.IsNullOrEmpty(Search_String_Parsed[0]) == false && string.IsNullOrEmpty(Search_String_Parsed[1]) == true && string.IsNullOrEmpty(Search_String_Parsed[2]) == true)
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_Everything(SearchsArgs[0]));
                            }
                            else if (string.IsNullOrEmpty(Search_String_Parsed[0]) == false && string.IsNullOrEmpty(Search_String_Parsed[1]) == false && string.IsNullOrEmpty(Search_String_Parsed[2]) == true)
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_Eventlog_For_SearchTerm(SearchsArgs[0], SearchsArgs[1]));
                            }
                            else if (string.IsNullOrEmpty(Search_String_Parsed[0]) == true && string.IsNullOrEmpty(Search_String_Parsed[1]) == false && string.IsNullOrEmpty(Search_String_Parsed[2]) == false)
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_EventLog_For_EventID(Convert.ToInt32(SearchsArgs[1]), SearchsArgs[0]));
                            }
                            else
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_Everything(SearchsArgs[0]));
                            }
                        }
                        break;
                    }
                case 3://search either term,and/or log, and/or eventid
                    {
                        if (Read_In_EventLogs_From_WindowsAPI.Count > 0)
                        {
                            if (String.IsNullOrEmpty(SearchsArgs[0]) == true && String.IsNullOrEmpty(SearchsArgs[1]) == true && String.IsNullOrEmpty(SearchsArgs[2]) == false)//Search only event id all others blank
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_EventID(Convert.ToInt32(SearchsArgs[2])));
                            }
                            else if (String.IsNullOrEmpty(SearchsArgs[0]) == true && String.IsNullOrEmpty(SearchsArgs[1]) == false && String.IsNullOrEmpty(SearchsArgs[2]) == false)//search event log for only ID
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_EventLog_For_EventID(Convert.ToInt32(SearchsArgs[2]), SearchsArgs[1]));
                            }
                            else if ((String.IsNullOrEmpty(SearchsArgs[0]) == false && String.IsNullOrEmpty(SearchsArgs[1]) == false && String.IsNullOrEmpty(SearchsArgs[2]) == true) && SearchsArgs[1].ToLower() == CurrentEventLogBeingSearched.ToLower())
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_Everything(SearchsArgs[0]));
                            }
                            else if ((String.IsNullOrEmpty(SearchsArgs[0]) == false && String.IsNullOrEmpty(SearchsArgs[1]) == false && String.IsNullOrEmpty(SearchsArgs[2]) == true) && SearchsArgs[1].ToLower() != CurrentEventLogBeingSearched.ToLower())
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_Eventlog_For_SearchTerm(SearchsArgs[0], SearchsArgs[1]));
                            }
                            else if ((String.IsNullOrEmpty(SearchsArgs[0]) == false && String.IsNullOrEmpty(SearchsArgs[1]) == false && String.IsNullOrWhiteSpace(SearchsArgs[2]) == true) && SearchsArgs[1].ToLower() != CurrentEventLogBeingSearched.ToLower())
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_Eventlog_For_SearchTerm(SearchsArgs[0], SearchsArgs[1]));
                            }
                            else if ((String.IsNullOrEmpty(SearchsArgs[0]) == false && String.IsNullOrEmpty(SearchsArgs[1]) == false && String.IsNullOrWhiteSpace(SearchsArgs[2]) == false) && SearchsArgs[1].ToLower() != CurrentEventLogBeingSearched.ToLower())
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_EventLog_For_SearchTerm_LogName_EventID(SearchsArgs[0], SearchsArgs[1], Convert.ToInt32(SearchsArgs[2])));
                            }
                            else //Gave 3 step search and somehow got here
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_Everything(SearchsArgs[0]));
                            }
                        }
                        break;
                    }
                default:
                    {
                        foreach (string Search in SearchsArgs)
                        {
                            ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_Everything(Search));
                        }
                        break;
                    }
            }
        }

        private void SEARCH_Run_Commands(string SearchCommand,string[] Search_String_Parsed,string Search_Terms_Unparsed)
        {
                if (SearchCommand.Contains(Settings.SplitChar_Search_Command_Parsers[0]))
                {
                    string[] Search_Command_Values = SearchCommand.Split(Settings.SplitChar_Search_Command_Parsers, StringSplitOptions.RemoveEmptyEntries).ToArray();

                    switch (Search_Command_Values[0].ToLower())
                    {
                        case "count":
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_CMD_Counts_in_Log(Search_Command_Values[1].ToString(), Convert.ToInt32(Search_Command_Values[2]), Search_Command_Values));
                                break;
                            }
                        case "log_level":
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_CMD_For_Severity_EVTX_Level(Search_Command_Values[1].ToString().ToLower(), Search_Command_Values, SearchCommand));
                                break;
                            }
                        case "eventdata_length":
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_CMD_Length_of_LogData(Convert.ToInt32(Search_Command_Values[1]), Search_Command_Values, SearchCommand));
                                break;
                            }
                        case "regex":
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_CMD_For_Regex_in_Log(Search_Command_Values[1].ToString().ToLower(), Search_Command_Values, SearchCommand));
                                break;
                            }
                        case "not_in_log":
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_CMD_NOT_IN_EVENT(Search_Command_Values[1].ToString(), Search_Command_Values[2], Convert.ToInt32(Search_Command_Values[3])));
                                break;
                            }
                        case "commandline_count"://sysmon/powershell only
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_Counts_in_CMDLine(Search_Command_Values[1].ToString(), Convert.ToInt32(Search_Command_Values[2])));
                                break;
                            }
                        case "commandline_contains"://sysmon/powershell only
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_Length_Sysmon_CMDLine_Args_Contains(Search_Command_Values[1]));
                                break;
                            }
                        case "network_connect"://sysmon only
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_CMD_Process_Port_Match(SearchCommand));
                                break;
                            }
                        case "search_multiple":
                            {
                                string[] Search_Command_Values2 = SearchCommand.Split(Settings.SplitChar_SearchCommandSplit, StringSplitOptions.None).ToArray();
                                SEARCH_CMD_Search_Multiple_SearchTerms(Search_Command_Values2[0], Search_Command_Values2[1], Search_Command_Values2[2]);
                                break;
                            }
                        case "commandline_length"://sysmon/powershell only
                            {
                                try
                                {
                                    int Max_Length = -1;
                                    if (int.TryParse(Search_Command_Values[1], out Max_Length) && Max_Length != -1)
                                    {
                                        ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_Length_Sysmon_CMDLine_Args_Length(Max_Length));
                                    }
                                }
                                catch (Exception e)
                                {
                                    Errors.Log_Error("SEARCH_Run_Commands() commandline_length", e.Message.ToString(), Errors.LogSeverity.Warning);
                                }
                                break;
                            }
                    default:
                        {
                            break;
                        }
                    }
                }
        }



        private List<EventLog_Entry> SEARCH_EventID_and_Data(int EventID , string SearchTerm)
        {
            IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(s => s.EventID.Equals(EventID) == true && s.EventData.Contains(SearchTerm)).ToList();
            return results.ToList();
        }

        private List<EventLog_Entry> SEARCH_EventID(int EventID)
        {
            IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(s => s.EventID.Equals(EventID)==true).ToList();
            return results.ToList();
        }

        private List<EventLog_Entry> SEARCH_Everything(string SearchTerm)
        {
           IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(s => s.EventData.Contains(SearchTerm) || s.EventID.ToString().Equals(SearchTerm)).ToList();
           return results.ToList();
        }

        private List<EventLog_Entry> SEARCH_EventLog_Return_All(string LogName)
        {
            IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(s => s.LogName.ToLower().Equals(LogName.ToLower())).ToList();
            return results.ToList();
        }

        private List<EventLog_Entry> SEARCH_Eventlog_For_SearchTerm(string SearchTerm, string EventLogName)
        {
            IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(s => s.EventData.Contains(SearchTerm) && s.LogName.ToLower().Equals(EventLogName.ToLower())).ToList();
            return results.ToList();
        }

        private List<EventLog_Entry> SEARCH_EventLog_For_EventID(int EventID , string EventLogName)
        {
            IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(s => s.EventID.Equals(EventID) && s.LogName.ToLower().Equals(EventLogName.ToLower())).ToList();
            return results.ToList();
        }

        private List<EventLog_Entry> SEARCH_EventLog_For_SearchTerm_LogName_EventID(string SearchTerm,string EventLogName, int EventID)
        {
            IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(s => s.EventID.Equals(EventID) == true && s.LogName.ToLower() == EventLogName.ToLower() && s.EventData.Contains(SearchTerm)).ToList();
            return results.ToList();
        }



        private List<EventLog_Entry> SEARCH_Length_Sysmon_CMDLine_Args_Length(int Max_Length)
        {
            IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(s => s.GET_Sysmon_CommandLine_Args.ToCharArray().Length >= Max_Length).ToList();
            return results.ToList();
        }

        private List<EventLog_Entry> SEARCH_Length_Sysmon_CMDLine_Args_Contains(string SearchTerm)
        {
            IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(s => s.GET_Sysmon_CommandLine_Args.Contains(SearchTerm)).ToList();
            return results.ToList();
        }

        private List<EventLog_Entry> SEARCH_Counts_in_CMDLine(string SearchTerm, int Max_Num_Of_Occurances)
        {
            IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(s => s.GET_Sysmon_CommandLine_Args.Count(f => f == Convert.ToChar(SearchTerm)) >= Max_Num_Of_Occurances).ToList();
            return results.ToList();
        }

        private List<EventLog_Entry> SEARCH_CMD_NOT_IN_EVENT(string SearchTerm, string EventLogName, int EventID=-1)
        {
            if (EventID!=-1)
            {
                IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(s => !s.EventData.Contains(SearchTerm) || s.GET_XML_of_Log.Contains(SearchTerm) && s.LogName.ToLower() == EventLogName.ToLower()).ToList();
                return results.ToList();
            }
            else
            {
                IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(s => !s.EventData.Contains(SearchTerm) || s.GET_XML_of_Log.Contains(SearchTerm) && s.LogName.ToLower() == EventLogName.ToLower() && s.EventID== EventID).ToList();
                return results.ToList();
            }
        }

        private List<EventLog_Entry> SEARCH_CMD_Counts_in_Log(string SearchTerm , int Min_Num_Of_Occurances, string[] Search_Command)
        {
            string[] Split_Search_Command = { SearchTerm };

            if (Min_Num_Of_Occurances > 0)
            {
                try
                {
                    if ((Search_Command.Length == 3) || (Settings.EVTX_Override && Search_Command.Length == 3))
                    {
                        IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(s => s.EventData.Split(Split_Search_Command, StringSplitOptions.RemoveEmptyEntries).ToList().Count - 1 >= Min_Num_Of_Occurances).ToList();
                        return results.ToList();
                    }
                    else if ((Settings.EVTX_Override && Search_Command.Length == 4) || (Search_Command.Length == 4 && (Settings.FIND_EventLog_Exsits(Search_Command[3]))))
                    {
                        IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(s => s.EventData.Split(Split_Search_Command, StringSplitOptions.RemoveEmptyEntries).ToList().Count - 1 >= Min_Num_Of_Occurances && s.LogName.ToLower() == Search_Command[3].ToLower()).ToList();
                        return results.ToList();
                    }
                    else if ((Settings.EVTX_Override && Search_Command.Length == 5) || (Search_Command.Length == 5 && (Settings.FIND_EventLog_Exsits(Search_Command[3]))))
                    {
                        if (int.TryParse(Search_Command[4], out int EventID))
                        {
                            IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(s => s.EventData.Split(Split_Search_Command, StringSplitOptions.RemoveEmptyEntries).ToList().Count - 1 >= Min_Num_Of_Occurances && s.LogName.ToLower() == Search_Command[3].ToLower() && s.EventID == EventID).ToList();
                            return results.ToList();
                        }
                        else
                        {
                            Errors.Log_Error("SEARCH_CMD_Counts_in_Log()", "The search term had bad input. Event ID not a number. Check search config format.", Errors.LogSeverity.Warning);
                            List<EventLog_Entry> results = new List<EventLog_Entry>();
                            return results.ToList();
                        }
                    }
                    else
                    {
                        if ((Settings.FIND_EventLog_Exsits(Search_Command[2])) || Settings.EVTX_Override)
                        {
                            Errors.Log_Error("SEARCH_CMD_Counts_in_Log()", "The search term had bad input it was to long " + Settings.SplitChar_Search_Command_Parsers[0] + ". Check search config format.", Errors.LogSeverity.Warning);
                            IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(s => s.EventData.Split(Split_Search_Command, StringSplitOptions.RemoveEmptyEntries).ToList().Count - 1 >= Min_Num_Of_Occurances).ToList();
                            return results.ToList();
                        }
                        else
                        {
                            Errors.Log_Error("SEARCH_CMD_Counts_in_Log()", "The search term had bad input Eventlog did not exist " + Settings.SplitChar_Search_Command_Parsers[0] + ". Check search config format.", Errors.LogSeverity.Warning);
                            List<EventLog_Entry> results = new List<EventLog_Entry>();
                            return results.ToList();

                        }
                    }
                }
                catch (Exception e)
                {
                    Errors.Log_Error("SEARCH_CMD_Counts_in_Log()", "The search term had bad input. Check search config format. " + e.Message.ToString(), Errors.LogSeverity.Warning);
                    List<EventLog_Entry> results = new List<EventLog_Entry>();
                    return results.ToList();
                }
            }
            return new List<EventLog_Entry>();
        }

        private List<EventLog_Entry> SEARCH_CMD_Length_of_LogData(int Max_Length, string[] SearchResults, string SearchCommand)
        {
            try
            {
                if (SearchResults.Length == 2 || (Settings.EVTX_Override && SearchResults.Length == 2))
                {
                    IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(f => f.EventData.ToCharArray().Length >= Max_Length).ToList();
                    return results.ToList();
                }
                else if ((Settings.EVTX_Override && SearchResults.Length == 3) || (SearchResults.Length == 3 && (Settings.FIND_EventLog_Exsits(SearchResults[2]))))
                {
                    IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(f => f.EventData.ToCharArray().Length >= Max_Length && f.LogName.ToLower() == SearchResults[2].ToLower()).ToList();
                    return results.ToList();
                }
                else if ((Settings.EVTX_Override && SearchResults.Length == 4) || (SearchResults.Length == 4 && (Settings.FIND_EventLog_Exsits(SearchResults[2])) && SearchResults.Length == 3))
                {
                    IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(f => f.EventData.ToCharArray().Length >= Max_Length && f.LogName.ToLower().Equals(SearchResults[2].ToLower())).ToList();
                    return results.ToList();
                }
                else if ((Settings.EVTX_Override && SearchResults.Length == 4) || (SearchResults.Length == 4 && (Settings.FIND_EventLog_Exsits(SearchResults[2])) && SearchResults.Length == 4))
                {
                    if (int.TryParse(SearchResults[3], out int EventID))
                    {
                        IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(f => f.EventData.ToCharArray().Length >= Max_Length && f.LogName.ToLower() == SearchResults[2].ToLower() && f.EventID == EventID).ToList();
                        return results.ToList();
                    }
                    else
                    {
                        Errors.Log_Error("SEARCH_CMD_Length_of_LogData()", "The search term had bad input. Event ID not a number. Check search config format.", Errors.LogSeverity.Warning);
                        List<EventLog_Entry> results = new List<EventLog_Entry>();
                        return results.ToList();
                    }
                }
                else
                {
                    Errors.Log_Error("SEARCH_CMD_Length_of_LogData()", "The search term had bad input it was to long " + Settings.SplitChar_Search_Command_Parsers[0] + ". Check search config format.", Errors.LogSeverity.Warning);
                    IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(f => f.EventData.ToCharArray().Length >= Max_Length).ToList();
                    return results.ToList();
                }
            }
            catch
            {
                Errors.Log_Error("SEARCH_CMD_Length_of_LogData()", "The search term had bad input. Check search config format.", Errors.LogSeverity.Warning);
                List<EventLog_Entry> results = new List<EventLog_Entry>();
                return results.ToList();
            }
        }

        private List<EventLog_Entry> SEARCH_CMD_For_Regex_in_Log(string Regex_SearchString, string[] SearchResults,string SearchCommand)
        {
            try
            {
                var RegX = new Regex(Regex_SearchString, RegexOptions.IgnoreCase);
                int Number_of_Parsers = SearchCommand.Count(f => f == Convert.ToChar(Settings.SplitChar_Search_Command_Parsers[0]));

                if (Number_of_Parsers == 1)
                {
                    IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(f => RegX.IsMatch(f.EventData)).ToList();
                    return results.ToList();
                }
                else if (Number_of_Parsers == 2 && (Settings.FIND_EventLog_Exsits(SearchResults[2])))
                {
                    IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(f => RegX.IsMatch(f.EventData) && f.LogName.ToLower() == SearchResults[2].ToLower()).ToList();
                    return results.ToList();
                }
                else if (Number_of_Parsers == 3 && (Settings.FIND_EventLog_Exsits(SearchResults[2])) && SearchResults.Length==3)
                {
                    IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(f => RegX.IsMatch(f.EventData) && f.LogName.ToLower() == SearchResults[2].ToLower()).ToList();
                    return results.ToList();
                }
                else if (Number_of_Parsers == 3 && (Settings.FIND_EventLog_Exsits(SearchResults[2])) && SearchResults.Length == 4)
                {
                    bool testEventID = int.TryParse(SearchResults[3], out int EventID);
                    if (testEventID)
                    {
                        IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(f => RegX.IsMatch(f.EventData) && f.LogName.ToLower() == SearchResults[2].ToLower() && f.EventID == EventID).ToList();
                        return results.ToList();
                    }
                    else
                    {
                        Errors.Log_Error("SEARCH_CMD_For_Regex_in_Log()", "The search term had bad input. Event ID not a number. Check search config format.", Errors.LogSeverity.Warning);
                        List<EventLog_Entry> results = new List<EventLog_Entry>();
                        return results.ToList();
                    }
                }
                else
                {
                    Errors.Log_Error("SEARCH_CMD_For_Regex_in_Log()", "The search term had bad input it was to long " + Settings.SplitChar_Search_Command_Parsers[0] + ". Check search config format.", Errors.LogSeverity.Warning);

                    IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(f => RegX.IsMatch(f.EventData)).ToList();
                    return results.ToList();
                }
            }
            catch
            {
                Errors.Log_Error("SEARCH_CMD_For_Regex_in_Log()", "The search term had bad input. Check search config format.", Errors.LogSeverity.Warning);
                List<EventLog_Entry> results = new List<EventLog_Entry>();
                return results.ToList();
            }
        }

        private List<EventLog_Entry> SEARCH_CMD_For_Severity_EVTX_Level(string Severity_level, string[] SearchResults, string SearchCommand)
        {
            if (Severity_level.ToLower() == "critical")
            {
                Severity_level = "1";
            }
            else if (Severity_level.ToLower() == "error")
            {
                Severity_level = "2";
            }
            else if (Severity_level.ToLower() == "warning")
            {
                Severity_level = "3";
            }
            else if (Severity_level.ToLower() == "information")
            {
                Severity_level = "4";
            }
            try
            {
                int Number_of_Parsers = SearchCommand.Count(f => f == Convert.ToChar(Settings.SplitChar_Search_Command_Parsers[0]));

                if (Number_of_Parsers == 1)
                {
                    IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(f => f.Severity.Equals(Severity_level)).ToList();
                    return results.ToList();
                }
                else if (Number_of_Parsers == 2 && (Settings.FIND_EventLog_Exsits(SearchResults[2])))
                {
                    IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(f => f.Severity.Equals(Severity_level) && f.LogName.ToLower() == SearchResults[2].ToLower()).ToList();
                    return results.ToList();
                }
                else if (Number_of_Parsers == 3 && (Settings.FIND_EventLog_Exsits(SearchResults[2])) && SearchResults.Length == 3)
                {
                    IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(f => f.Severity.Equals(Severity_level) && f.LogName.ToLower() == SearchResults[2].ToLower()).ToList();
                    return results.ToList();
                }
                else if (Number_of_Parsers == 3 && (Settings.FIND_EventLog_Exsits(SearchResults[2])) && SearchResults.Length == 4)
                {
                    bool testEventID = int.TryParse(SearchResults[3], out int EventID);
                    if (testEventID)
                    {
                        IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(f => f.Severity.Equals(Severity_level) && f.LogName.ToLower() == SearchResults[2].ToLower() && f.EventID == EventID).ToList();
                        return results.ToList();
                    }
                    else
                    {
                        Errors.Log_Error("SEARCH_CMD_For_Level()", "The search term had bad input. Event ID not a number. Check search config format.", Errors.LogSeverity.Warning);
                        List<EventLog_Entry> results = new List<EventLog_Entry>();
                        return results.ToList();
                    }
                }
                else
                {
                    Errors.Log_Error("SEARCH_CMD_For_Level()", "The search term had bad input it was to long " + Settings.SplitChar_Search_Command_Parsers[0] + ". Check search config format.", Errors.LogSeverity.Warning);
                    IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(f => f.Severity.Equals(Severity_level)).ToList();
                    return results.ToList();
                }
            }
            catch (Exception e)
            {
                Errors.Log_Error("SEARCH_CMD_For_Level()", e.Message.ToString()+" The search term had bad input. Check search config format.", Errors.LogSeverity.Warning);
                List<EventLog_Entry> results = new List<EventLog_Entry>();
                return results.ToList();
            }
        }

        private List<EventLog_Entry> SEARCH_CMD_Search_Multiple_SearchTerms(string SearchTerm, string EventLogName="", string EventID="")
        {
            List<EventLog_Entry> MultSearchList = new List<EventLog_Entry>();
            List<EventLog_Entry> Read_In_EventLogs_From_WindowsAPI_Temp = Read_In_EventLogs_From_WindowsAPI.ToList(); 
            List<EventLog_Entry> results = new List<EventLog_Entry>();
            List<EventLog_Entry> results_1 = new List<EventLog_Entry>();

            string[] SearchTerms = SearchTerm.Split(Settings.SplitChar_Search_Command_Parser_Multi_Search, StringSplitOptions.RemoveEmptyEntries).ToArray();
            if (SearchTerms.Length < 20)
            {

                if (SearchTerms.Length > 1)
                {
                    for (int x = 0; x < SearchTerms.Length; ++x)
                    {

                        if (x == 0)
                        {
                            results_1 = SEARCH_Everything(SearchTerms[x]);
                            Read_In_EventLogs_From_WindowsAPI_Temp = results_1;
                            MultSearchList.AddRange(results_1);
                        }
                        else if (results_1.Count < 1)
                        {
                            return MultSearchList = new List<EventLog_Entry>();
                        }
                        else
                        {
                            if (String.IsNullOrEmpty(SearchTerms[x]) == true && String.IsNullOrEmpty(EventLogName) == true && String.IsNullOrEmpty(EventID) == false)
                            {
                                results = Read_In_EventLogs_From_WindowsAPI_Temp.Where(s => s.EventID.ToString().Equals(EventID) == true).ToList();
                            }
                            else if (String.IsNullOrEmpty(SearchTerms[x]) == true && String.IsNullOrEmpty(EventLogName) == false && String.IsNullOrEmpty(EventID) == false)
                            {
                                results = Read_In_EventLogs_From_WindowsAPI_Temp.Where(s => s.EventID.ToString().Equals(EventID) == true && s.LogName.ToLower().Equals(EventLogName.ToLower())).ToList();
                            }
                            else if (String.IsNullOrEmpty(SearchTerms[x]) == false && String.IsNullOrEmpty(EventLogName) == false && String.IsNullOrEmpty(EventID) == true)
                            {
                                results = Read_In_EventLogs_From_WindowsAPI_Temp.Where(s => s.EventData.Contains(SearchTerms[x]) && s.LogName.ToLower().Equals(EventLogName.ToLower())).ToList();
                            }
                            else if (String.IsNullOrEmpty(SearchTerms[x]) == false && String.IsNullOrEmpty(EventLogName) == false && String.IsNullOrEmpty(EventID) == true)
                            {
                                results = Read_In_EventLogs_From_WindowsAPI_Temp.Where(s => s.EventData.Contains(SearchTerms[x]) && s.LogName.ToLower().Equals(EventLogName.ToLower())).ToList();
                            }
                            else if (String.IsNullOrEmpty(SearchTerms[x]) == false && String.IsNullOrEmpty(EventLogName) == false && String.IsNullOrEmpty(EventID) == true)
                            {
                                results = Read_In_EventLogs_From_WindowsAPI_Temp.Where(s => s.EventData.Contains(SearchTerms[x]) && s.LogName.ToLower().Equals(EventLogName.ToLower())).ToList();
                            }
                            else if (String.IsNullOrEmpty(SearchTerms[x]) == false && String.IsNullOrEmpty(EventLogName) == false && String.IsNullOrEmpty(EventID) == false)
                            {
                                results = Read_In_EventLogs_From_WindowsAPI_Temp.Where(s => s.EventID.ToString().Equals(EventID) == true && s.LogName.ToLower().Equals(EventLogName.ToLower()) && s.EventData.Contains(SearchTerms[x])).ToList();
                            }
                            else
                            {
                                results = Read_In_EventLogs_From_WindowsAPI_Temp.Where(s => s.EventData.Contains(SearchTerms[x]) || s.EventID.ToString().Equals(SearchTerms[x])).ToList();
                            }

                            if (results.Count > 0)
                            {
                                MultSearchList = results;
                            }
                            else
                            {
                                return MultSearchList = new List<EventLog_Entry>();
                            }
                            results.Clear();
                        }
                        GC.Collect();
                    }
                }
                else
                {
                    if (SearchTerms.Length > 0)
                    {
                        MultSearchList = SEARCH_Everything(SearchTerms[0]);
                    }
                }

                if (MultSearchList.Count > 1)
                {
                    return MultSearchList;
                }
                else
                {
                    return MultSearchList = new List<EventLog_Entry>();
                }
            }
            else
            {
                Errors.Log_Error("SEARCH_CMD_Search_Multiple_SearchTerms()", SearchTerm + " has to many things to search for per log. Limit is less than 20.", Errors.LogSeverity.Warning);
                return MultSearchList;
            }
        }

        private List<EventLog_Entry> SEARCH_CMD_Process_Port_Match(string SearchTerm, string EventLogName = "microsoft-windows-sysmon/operational", string EventID = "3")
        {
            string[] SearchTerms = SearchTerm.Split(Settings.SplitChar_Search_Command_Parsers, StringSplitOptions.RemoveEmptyEntries).ToArray();
            //[1]=port
            //[2]=app
            if (SearchTerms.Length == 3)
            {
                IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(s => s.LogName.ToLower().Equals(EventLogName.ToLower()) && s.EventID.ToString().Equals(EventID) && s.GET_Sysmon_Network_Calling_Process_Name.ToLower().Contains(SearchTerms[2].ToLower()) && s.GET_Sysmon_Netwrok_Calling_Process_Name_Dest_Port.Equals(SearchTerms[1])).ToList();
                return results.ToList();
            }
            else if (SearchTerms.Length == 2)
            {
                try
                {
                    Convert.ToInt32(SearchTerms[1]);
                    IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(s => s.LogName.ToLower().Equals(EventLogName.ToLower()) && s.EventID.ToString().Equals(EventID) && s.GET_Sysmon_Netwrok_Calling_Process_Name_Dest_Port.Equals(SearchTerms[1])).ToList();
                    return results.ToList();
                }
                catch
                {
                    IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(s => s.LogName.ToLower().Equals(EventLogName.ToLower()) && s.EventID.ToString().Equals(EventID) && s.GET_Sysmon_Network_Calling_Process_Name.ToLower().Contains(SearchTerms[2].ToLower())).ToList();
                    return results.ToList();
                }
            }
            else
            {
                IList<EventLog_Entry> results = Read_In_EventLogs_From_WindowsAPI.Where(s => s.LogName.ToLower().Equals(EventLogName.ToLower()) && s.EventID.ToString().Equals(EventID)).ToList();
                return results.ToList();
            }
        }
    }
}
