//Written by Ceramicskate0
//Copyright 2018
using System;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using System.Collections;
using System.Text.RegularExpressions;

namespace SWELF
{
    class Search_EventLogs
    {
        private Queue<EventLogEntry> EventLogs_From_WindowsAPI = new Queue<EventLogEntry>();
        private static List<EventLogEntry> Logs_That_Matched_Search = new List<EventLogEntry>();
        private static string CurrentEventLogBeingSearched = "";

        public Search_EventLogs(Queue<EventLogEntry> eventLogs_From_WindowsAPI)
        {
            EventLogs_From_WindowsAPI = eventLogs_From_WindowsAPI;
        }

        public void Clear_Search()
        {
            EventLogs_From_WindowsAPI.Clear();
            Logs_That_Matched_Search.Clear();
        }

        private void SEARCH_Run_Commands(string SearchCommand)
        {
            try
            {
                if (SearchCommand.Contains(Settings.SplitChar_Search_Command_Parsers[0]))
                {
                    string[] Search_Command_Values = SearchCommand.Split(Settings.SplitChar_Search_Command_Parsers, StringSplitOptions.RemoveEmptyEntries).ToArray();

                    switch (Search_Command_Values[0].ToLower())
                    {
                        case "count":
                            {
                               Logs_That_Matched_Search.AddRange(SEARCH_CMD_Counts_in_Log(Search_Command_Values[1].ToString(), Convert.ToInt32(Search_Command_Values[2]), Search_Command_Values));
                                break;
                            }
                        case "log_level":
                            {
                                Logs_That_Matched_Search.AddRange(SEARCH_CMD_For_Severity_EVTX_Level(Search_Command_Values[1].ToString().ToLower(), Search_Command_Values, SearchCommand));
                                break;
                            }
                        case "eventdata_length":
                            {
                              Logs_That_Matched_Search.AddRange(SEARCH_CMD_Length_of_LogData(Convert.ToInt32(Search_Command_Values[1]), Search_Command_Values, SearchCommand));
                                break;
                            }
                        case "regex":
                            {
                                Logs_That_Matched_Search.AddRange(SEARCH_CMD_For_Regex_in_Log(Search_Command_Values[1].ToString().ToLower(), Search_Command_Values, SearchCommand));
                                break;
                            }
                        case "not_in_log":
                            {
                                Logs_That_Matched_Search.AddRange(SEARCH_CMD_NOT_IN_EVENT(Search_Command_Values[1].ToString(), Search_Command_Values[2], Convert.ToInt32(Search_Command_Values[3])));
                                break;
                            }
                        case "commandline_count"://sysmon/powershell only
                            {
                                Logs_That_Matched_Search.AddRange(SEARCH_Counts_in_CMDLine(Search_Command_Values[1].ToString(), Convert.ToInt32(Search_Command_Values[2])));
                                break;
                            }
                        case "commandline_contains"://sysmon/powershell only
                            {
                                Logs_That_Matched_Search.AddRange(SEARCH_Length_Sysmon_CMDLine_Args_Contains(Search_Command_Values[1]));
                                break;
                            }
                        case "commandline_length"://sysmon/powershell only
                            {
                                try
                                {
                                    int Max_Length = -1;
                                    if (int.TryParse(Search_Command_Values[1], out Max_Length) && Max_Length != -1)
                                    {
                                        Logs_That_Matched_Search.AddRange(SEARCH_Length_Sysmon_CMDLine_Args_Length(Max_Length));
                                    }
                                }
                                catch (Exception e)
                                {
                                    Errors.Log_Error("SEARCH_Run_Commands() commandline_length", e.Message.ToString(),Errors.LogSeverity.Warning);
                                }
                                break;
                            }
                    }
                }
            }
            catch (Exception e)
            {
                Errors.Log_Error("SEARCH_Run_Commands()", e.Message.ToString(), Errors.LogSeverity.Warning);
            }
        }

        public Queue<EventLogEntry> Search(string Current_EventLog)
        {
            //Search LOGS
            int temp_int_stor = 0;
                for (int x = 0; x < Settings.Search_Terms_Unparsed.Count; ++x)
                {
                    temp_int_stor = x;
                    try
                    {
                        if (Settings.Search_Terms_Unparsed.ElementAt(x).Substring(0).Equals(Settings.CommentCharConfigs)==false)
                        {
                            if (Settings.Search_Commands.Any(s => Settings.Search_Terms_Unparsed.ElementAt(x).ToLower().IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0))
                            {
                                SEARCH_Run_Commands(Settings.Search_Terms_Unparsed.ElementAt(x));
                            }
                            else
                            {
                                SEARCH_FindTerms(x);
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        Errors.Log_Error("Search() Value=" + Settings.Search_Terms_Unparsed.ElementAt(temp_int_stor), e.Message.ToString()+". Check syntax and data input names.", Errors.LogSeverity.Infomrtaion);
                    }
                }
                if (Logs_That_Matched_Search.Count > 0)
                {
                    Remove_Whitelisted_Logs();
                    Logs_That_Matched_Search = Logs_That_Matched_Search.Distinct().OrderBy(x => x.CreatedTime).ToList();
                    IEnumerable<EventLogEntry> noduplicates = Logs_That_Matched_Search.Distinct();
                }
                var queue = new Queue<EventLogEntry>(Logs_That_Matched_Search);
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
                Logs_That_Matched_Search.RemoveAll(s => s.EventData.Contains(SearchTerm) && s.LogName.ToLower().Equals(EventLogName.ToLower()) && s.EventID.Equals(EventID));
            }
            else if (!string.IsNullOrEmpty(SearchTerm) && !string.IsNullOrEmpty(EventLogName))
            {
                Logs_That_Matched_Search.RemoveAll(s => s.EventData.Contains(SearchTerm) && s.LogName.ToLower().Equals(EventLogName.ToLower()));
            }
            else
            {
                Logs_That_Matched_Search.RemoveAll(s => s.EventData.Contains(SearchTerm));
            }
        }

        private void SEARCH_FindTerms(int x)
        {
            string[] SearchsArgs = Settings.Search_Terms_Unparsed.ElementAt(x).Split(Settings.SplitChar_SearchCommandSplit, StringSplitOptions.RemoveEmptyEntries).ToArray();

            switch (SearchsArgs.Length)
            {
                case 1://search term only
                    {
                        Logs_That_Matched_Search.AddRange(SEARCH_Everything(SearchsArgs[0]));
                        break;
                    }
                case 2://search log and term
                    {
                        if (EventLogs_From_WindowsAPI.Count > 0)
                        {
                            if (SearchsArgs[1].ToLower() == EventLogs_From_WindowsAPI.Peek().LogName.ToLower())
                            {
                                Logs_That_Matched_Search.AddRange(SEARCH_Everything(SearchsArgs[0]));
                            }
                        }
                        break;
                    }
                case 3://search either term,and/or log, and/or eventid
                    {
                        if (String.IsNullOrEmpty(SearchsArgs[0]) == true && String.IsNullOrEmpty(SearchsArgs[1]) == true && String.IsNullOrEmpty(SearchsArgs[2]) == false)//Search only event id all others blank
                        {
                            Logs_That_Matched_Search.AddRange(SEARCH_EventID(Convert.ToInt32(SearchsArgs[2])));
                        }
                        else if (String.IsNullOrEmpty(SearchsArgs[0]) == true && String.IsNullOrEmpty(SearchsArgs[1]) == false && String.IsNullOrEmpty(SearchsArgs[2]) == false)//search event log for only ID
                        {
                            Logs_That_Matched_Search.AddRange(SEARCH_EventLog_For_EventID(Convert.ToInt32(SearchsArgs[2]), SearchsArgs[1]));
                        }
                        else if ((String.IsNullOrEmpty(SearchsArgs[0]) == false && String.IsNullOrEmpty(SearchsArgs[1]) == false && String.IsNullOrEmpty(SearchsArgs[2]) == true) && SearchsArgs[1].ToLower() == CurrentEventLogBeingSearched.ToLower())
                        {
                            Logs_That_Matched_Search.AddRange(SEARCH_Everything(SearchsArgs[0]));
                        }
                        else if ((String.IsNullOrEmpty(SearchsArgs[0]) == false && String.IsNullOrEmpty(SearchsArgs[1]) == false && String.IsNullOrEmpty(SearchsArgs[2]) == true) && SearchsArgs[1].ToLower() != CurrentEventLogBeingSearched.ToLower())
                        {
                            Logs_That_Matched_Search.AddRange(SEARCH_Eventlog_For_SearchTerm(SearchsArgs[0], SearchsArgs[1]));
                        }
                        else if ((String.IsNullOrEmpty(SearchsArgs[0]) == false && String.IsNullOrEmpty(SearchsArgs[1]) == false && String.IsNullOrWhiteSpace(SearchsArgs[2]) == true) && SearchsArgs[1].ToLower() != CurrentEventLogBeingSearched.ToLower())
                        {
                            Logs_That_Matched_Search.AddRange(SEARCH_Eventlog_For_SearchTerm(SearchsArgs[0], SearchsArgs[1]));
                        }
                        else //Gave 3 step search and somehow got here
                        {
                            Logs_That_Matched_Search.AddRange(SEARCH_EventID_and_Data(Convert.ToInt32(SearchsArgs[2]), SearchsArgs[0]));
                        }
                        break;
                    }
                default:
                    {
                        foreach (string Search in SearchsArgs)
                        {
                            Logs_That_Matched_Search.AddRange(SEARCH_Everything(Search));
                        }
                        break;
                    }
            }
        }

        private List<EventLogEntry> SEARCH_EventID_and_Data(int EventID , string SearchTerm)
        {
            IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(s => s.EventID.Equals(EventID) == true && s.EventData.Contains(SearchTerm)).ToList();
            return results.ToList();
        }

        private List<EventLogEntry> SEARCH_EventID(int EventID)
        {
            IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(s => s.EventID.Equals(EventID)==true).ToList();
            return results.ToList();
        }

        private List<EventLogEntry> SEARCH_Everything(string SearchTerm)
        {
           IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(s => s.EventData.Contains(SearchTerm) || s.GET_XML_of_Log.Contains(SearchTerm) || s.EventID.ToString().Equals(SearchTerm)).ToList();
           return results.ToList();
        }

        private List<EventLogEntry> SEARCH_Eventlog_For_SearchTerm(string SearchTerm, string EventLogName)
        {
            IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(s => s.EventData.Contains(SearchTerm) || s.GET_XML_of_Log.Contains(SearchTerm) || s.EventID.ToString().Equals(SearchTerm) && s.LogName.ToLower() == EventLogName.ToLower()).ToList();
            return results.ToList();
        }

        private List<EventLogEntry> SEARCH_EventLog_For_EventID(int EventID , string EventLogName)
        {
            IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(s => s.EventID.Equals(EventID) == true && s.LogName.ToLower() == EventLogName.ToLower()).ToList();
            return results.ToList();
        }

        private List<EventLogEntry> SEARCH_Length_Sysmon_CMDLine_Args_Length(int Max_Length)
        {
            IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(s => s.GET_Sysmon_CommandLine_Args.ToCharArray().Length >= Max_Length).ToList();
            return results.ToList();
        }

        private List<EventLogEntry> SEARCH_Length_Sysmon_CMDLine_Args_Contains(string SearchTerm)
        {
            IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(s => s.GET_Sysmon_CommandLine_Args.Contains(SearchTerm)).ToList();
            return results.ToList();
        }

        private List<EventLogEntry> SEARCH_Counts_in_CMDLine(string SearchTerm, int Max_Num_Of_Occurances)
        {
            IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(s => s.GET_Sysmon_CommandLine_Args.Count(f => f == Convert.ToChar(SearchTerm)) >= Max_Num_Of_Occurances).ToList();
            return results.ToList();
        }

        private List<EventLogEntry> SEARCH_CMD_NOT_IN_EVENT(string SearchTerm, string EventLogName, int EventID=-1)
        {
            if (EventID!=-1)
            {
                IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(s => !s.EventData.Contains(SearchTerm) || s.GET_XML_of_Log.Contains(SearchTerm) && s.LogName.ToLower() == EventLogName.ToLower()).ToList();
                return results.ToList();
            }
            else
            {
                IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(s => !s.EventData.Contains(SearchTerm) || s.GET_XML_of_Log.Contains(SearchTerm) && s.LogName.ToLower() == EventLogName.ToLower() && s.EventID== EventID).ToList();
                return results.ToList();
            }
        }

        private List<EventLogEntry> SEARCH_CMD_Counts_in_Log(string SearchTerm , int Min_Num_Of_Occurances, string[] SearchResults)
        {
            string[] SplitArray = { SearchTerm };
            try
            {
                if ((SearchResults.Length == 3 )|| (Settings.EVTX_Override && SearchResults.Length == 3))
                {
                    IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(s => s.EventData.Split(SplitArray,StringSplitOptions.RemoveEmptyEntries).ToList().Count-1 >= Min_Num_Of_Occurances).ToList();
                    return results.ToList();
                }
                else if ((Settings.EVTX_Override && SearchResults.Length == 4) || (SearchResults.Length == 4 && (Settings.FIND_EventLog_Exsits(SearchResults[3]))))
                {
                    IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(s => s.EventData.Split(SplitArray, StringSplitOptions.RemoveEmptyEntries).ToList().Count - 1 >= Min_Num_Of_Occurances && s.LogName.ToLower() == SearchResults[3].ToLower()).ToList();
                    return results.ToList();
                }
                else if ((Settings.EVTX_Override && SearchResults.Length == 5) || (SearchResults.Length == 5 && (Settings.FIND_EventLog_Exsits(SearchResults[3]))) )
                {
                    bool testEventID = int.TryParse(SearchResults[4], out int EventID);
                    if (testEventID)
                    {
                        IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(s => s.EventData.Split(SplitArray, StringSplitOptions.RemoveEmptyEntries).ToList().Count - 1 >= Min_Num_Of_Occurances && s.LogName.ToLower() == SearchResults[3].ToLower() && s.EventID == EventID).ToList();
                        return results.ToList();
                    }
                    else
                    {
                        Errors.Log_Error("SEARCH_CMD_Counts_in_Log()", "The search term had bad input. Event ID not a number. Check search config format.", Errors.LogSeverity.Warning);
                        List<EventLogEntry> results = new List<EventLogEntry>();
                        return results.ToList();
                    }
                }
                else
                {
                    if ((Settings.FIND_EventLog_Exsits(SearchResults[2])) || Settings.EVTX_Override)
                    {
                        Errors.Log_Error("SEARCH_CMD_Counts_in_Log()", "The search term had bad input it was to long " + Settings.SplitChar_Search_Command_Parsers[0] + ". Check search config format.", Errors.LogSeverity.Warning);
                        IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(s => s.EventData.Split(SplitArray, StringSplitOptions.RemoveEmptyEntries).ToList().Count - 1 >= Min_Num_Of_Occurances).ToList();
                        return results.ToList();
                    }
                    else
                    {
                        Errors.Log_Error("SEARCH_CMD_Counts_in_Log()", "The search term had bad input Eventlog did not exist " + Settings.SplitChar_Search_Command_Parsers[0] + ". Check search config format.", Errors.LogSeverity.Warning);
                        List<EventLogEntry> results = new List<EventLogEntry>();
                        return results.ToList();

                    }
                }
            }
            catch (Exception e)
            {
                Errors.Log_Error("SEARCH_CMD_Counts_in_Log()", "The search term had bad input. Check search config format. "+e.Message.ToString(), Errors.LogSeverity.Warning);
                List<EventLogEntry> results = new List<EventLogEntry>();
                return results.ToList();
            }
        }

        private List<EventLogEntry> SEARCH_CMD_Length_of_LogData(int Max_Length, string[] SearchResults, string SearchCommand)
        {
            try
            {
                if (SearchResults.Length == 2 || (Settings.EVTX_Override && SearchResults.Length == 2))
                {
                    IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(f => f.EventData.ToCharArray().Length >= Max_Length).ToList();
                    return results.ToList();
                }
                else if ((Settings.EVTX_Override && SearchResults.Length == 3) || (SearchResults.Length == 3 && (Settings.FIND_EventLog_Exsits(SearchResults[2]))))
                {
                    IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(f => f.EventData.ToCharArray().Length >= Max_Length && f.LogName.ToLower() == SearchResults[2].ToLower()).ToList();
                    return results.ToList();
                }
                else if ((Settings.EVTX_Override && SearchResults.Length == 4) || (SearchResults.Length == 4 && (Settings.FIND_EventLog_Exsits(SearchResults[2])) && SearchResults.Length == 3))
                {
                    IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(f => f.EventData.ToCharArray().Length >= Max_Length && f.LogName.ToLower().Equals(SearchResults[2].ToLower())).ToList();
                    return results.ToList();
                }
                else if ((Settings.EVTX_Override && SearchResults.Length == 4) || (SearchResults.Length == 4 && (Settings.FIND_EventLog_Exsits(SearchResults[2])) && SearchResults.Length == 4))
                {
                    bool testEventID = int.TryParse(SearchResults[3], out int EventID);
                    if (testEventID)
                    {
                        IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(f => f.EventData.ToCharArray().Length >= Max_Length && f.LogName.ToLower() == SearchResults[2].ToLower() && f.EventID == EventID).ToList();
                        return results.ToList();
                    }
                    else
                    {
                        Errors.Log_Error("SEARCH_CMD_Length_of_LogData()", "The search term had bad input. Event ID not a number. Check search config format.", Errors.LogSeverity.Warning);
                        List<EventLogEntry> results = new List<EventLogEntry>();
                        return results.ToList();
                    }
                }
                else
                {
                    Errors.Log_Error("SEARCH_CMD_Length_of_LogData()", "The search term had bad input it was to long " + Settings.SplitChar_Search_Command_Parsers[0] + ". Check search config format.", Errors.LogSeverity.Warning);
                    IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(f => f.EventData.ToCharArray().Length >= Max_Length).ToList();
                    return results.ToList();
                }
            }
            catch
            {
                Errors.Log_Error("SEARCH_CMD_Length_of_LogData()", "The search term had bad input. Check search config format.", Errors.LogSeverity.Warning);
                List<EventLogEntry> results = new List<EventLogEntry>();
                return results.ToList();
            }
        }

        private List<EventLogEntry> SEARCH_CMD_For_Regex_in_Log(string Regex_SearchString, string[] SearchResults,string SearchCommand)
        {
            try
            {
                var RegX = new Regex(Regex_SearchString, RegexOptions.IgnoreCase);
                int Number_of_Parsers = SearchCommand.Count(f => f == Convert.ToChar(Settings.SplitChar_Search_Command_Parsers[0]));

                if (Number_of_Parsers == 1)
                {
                    IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(f => RegX.IsMatch(f.EventData)).ToList();
                    return results.ToList();
                }
                else if (Number_of_Parsers == 2 && (Settings.FIND_EventLog_Exsits(SearchResults[2])))
                {
                    IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(f => RegX.IsMatch(f.EventData) && f.LogName.ToLower() == SearchResults[2].ToLower()).ToList();
                    return results.ToList();
                }
                else if (Number_of_Parsers == 3 && (Settings.FIND_EventLog_Exsits(SearchResults[2])) && SearchResults.Length==3)
                {
                    IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(f => RegX.IsMatch(f.EventData) && f.LogName.ToLower() == SearchResults[2].ToLower()).ToList();
                    return results.ToList();
                }
                else if (Number_of_Parsers == 3 && (Settings.FIND_EventLog_Exsits(SearchResults[2])) && SearchResults.Length == 4)
                {
                    bool testEventID = int.TryParse(SearchResults[3], out int EventID);
                    if (testEventID)
                    {
                        IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(f => RegX.IsMatch(f.EventData) && f.LogName.ToLower() == SearchResults[2].ToLower() && f.EventID == EventID).ToList();
                        return results.ToList();
                    }
                    else
                    {
                        Errors.Log_Error("SEARCH_CMD_For_Regex_in_Log()", "The search term had bad input. Event ID not a number. Check search config format.", Errors.LogSeverity.Warning);
                        List<EventLogEntry> results = new List<EventLogEntry>();
                        return results.ToList();
                    }
                }
                else
                {
                    Errors.Log_Error("SEARCH_CMD_For_Regex_in_Log()", "The search term had bad input it was to long " + Settings.SplitChar_Search_Command_Parsers[0] + ". Check search config format.", Errors.LogSeverity.Warning);

                    IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(f => RegX.IsMatch(f.EventData)).ToList();
                    return results.ToList();
                }
            }
            catch
            {
                Errors.Log_Error("SEARCH_CMD_For_Regex_in_Log()", "The search term had bad input. Check search config format.", Errors.LogSeverity.Warning);
                List<EventLogEntry> results = new List<EventLogEntry>();
                return results.ToList();
            }
        }

        private List<EventLogEntry> SEARCH_CMD_For_Severity_EVTX_Level(string Severity_level, string[] SearchResults, string SearchCommand)
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
                    IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(f => f.Severity.Equals(Severity_level)).ToList();
                    return results.ToList();
                }
                else if (Number_of_Parsers == 2 && (Settings.FIND_EventLog_Exsits(SearchResults[2])))
                {
                    IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(f => f.Severity.Equals(Severity_level) && f.LogName.ToLower() == SearchResults[2].ToLower()).ToList();
                    return results.ToList();
                }
                else if (Number_of_Parsers == 3 && (Settings.FIND_EventLog_Exsits(SearchResults[2])) && SearchResults.Length == 3)
                {
                    IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(f => f.Severity.Equals(Severity_level) && f.LogName.ToLower() == SearchResults[2].ToLower()).ToList();
                    return results.ToList();
                }
                else if (Number_of_Parsers == 3 && (Settings.FIND_EventLog_Exsits(SearchResults[2])) && SearchResults.Length == 4)
                {
                    bool testEventID = int.TryParse(SearchResults[3], out int EventID);
                    if (testEventID)
                    {
                        IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(f => f.Severity.Equals(Severity_level) && f.LogName.ToLower() == SearchResults[2].ToLower() && f.EventID == EventID).ToList();
                        return results.ToList();
                    }
                    else
                    {
                        Errors.Log_Error("SEARCH_CMD_For_Level()", "The search term had bad input. Event ID not a number. Check search config format.", Errors.LogSeverity.Warning);
                        List<EventLogEntry> results = new List<EventLogEntry>();
                        return results.ToList();
                    }
                }
                else
                {
                    Errors.Log_Error("SEARCH_CMD_For_Level()", "The search term had bad input it was to long " + Settings.SplitChar_Search_Command_Parsers[0] + ". Check search config format.", Errors.LogSeverity.Warning);
                    IList<EventLogEntry> results = EventLogs_From_WindowsAPI.Where(f => f.Severity.Equals(Severity_level)).ToList();
                    return results.ToList();
                }
            }
            catch (Exception e)
            {
                Errors.Log_Error("SEARCH_CMD_For_Level()", e.Message.ToString()+" The search term had bad input. Check search config format.", Errors.LogSeverity.Warning);
                List<EventLogEntry> results = new List<EventLogEntry>();
                return results.ToList();
            }
        }
    }
}
