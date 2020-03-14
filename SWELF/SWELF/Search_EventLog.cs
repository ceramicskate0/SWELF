//Written by Ceramicskate0
//Copyright
using System;
using System.Linq;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Collections.Concurrent;

namespace SWELF
{
    internal class Search_EventLog
    {
        private List<EventLog_Entry> ALL_Logs_That_Matched_Search_This_Event_Log = new List<EventLog_Entry>();//The logs that matched this run,this log
        private static List<EventLog_Entry> Filtered_Matched_Logs_This_SWELF_Run;//All the logs found that matched
        private static List<EventLog_Entry> Read_In_EventLogs_From_WindowsAPI_Temp = new List<EventLog_Entry>();
        internal static Queue<EventLog_Entry> Read_In_EventLogs_From_WindowsAPI = Data_Store.contents_of_EventLog;

        internal Search_EventLog()
        {

        }

        internal Queue<EventLog_Entry> Search(string Current_EventLog)
        {
            int temp_int_stor_for_Errors = 0;
            Filtered_Matched_Logs_This_SWELF_Run = new List<EventLog_Entry>();
            ALL_Logs_That_Matched_Search_This_Event_Log = new List<EventLog_Entry>();
            Read_In_EventLogs_From_WindowsAPI_Temp = new List<EventLog_Entry>();

            for (int x = 0; x < Settings.Search_Rules_Unparsed.Count; ++x)
            {
                try
                {
                    string[] Search_String_Parsed = Settings.Search_Rules_Unparsed.ElementAt(x).Split(Settings.SplitChar_SearchCommandSplit, StringSplitOptions.None).ToArray();
                    temp_int_stor_for_Errors = x;
                    Read_In_EventLogs_From_WindowsAPI = Data_Store.contents_of_EventLog;

                    if (Search_String_Parsed.Length > 3)
                    {
                        Error_Operation.Log_Error("Search()", "Value = " + Settings.Search_Rules_Unparsed.ElementAt(x) + ". Check syntax and data input names. Command has something wrong with it, syntax,too long, invalid chars, etc.","", Error_Operation.LogSeverity.Warning);
                    }
                    else
                    {
                        if (Settings.Search_Commands.Any(s => Settings.Search_Rules_Unparsed.ElementAt(x).IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0))
                        {
                            if ((Search_String_Parsed.Length > 1 && (string.IsNullOrEmpty(Search_String_Parsed[1]) == false) && Search_String_Parsed[1] == Current_EventLog) || Search_String_Parsed.Length == 1)
                            {
                                SEARCH_Run_Commands(Settings.Search_Rules_Unparsed.ElementAt(x), Settings.Search_Rules_Unparsed.ElementAt(x));
                            }
                        }
                        else
                        {
                            if (Search_String_Parsed.Length >= 1)
                            {
                                PARSE_Search_String_Prep_For_Searching(x, Search_String_Parsed, Current_EventLog);
                            }
                        }
                    }
                }
                catch (Exception e)
                {
                    Error_Operation.Log_Error("Search() Value=" + Settings.Search_Rules_Unparsed.ElementAt(temp_int_stor_for_Errors), e.Message.ToString() + ". Check syntax and data input names.", e.StackTrace.ToString(), Error_Operation.LogSeverity.Informataion);
                    Settings.Search_Rules_Unparsed.RemoveAt(temp_int_stor_for_Errors);
                }
                System_Info.CHECK_Memory();
            }

            Filtered_Matched_Logs_This_SWELF_Run.AddRange(ALL_Logs_That_Matched_Search_This_Event_Log.Distinct().ToList());

            if (ALL_Logs_That_Matched_Search_This_Event_Log.Count > 0)
            {
                Remove_Whitelisted_Logs();
            }

            Filtered_Matched_Logs_This_SWELF_Run.AddRange(Data_Store.SWELF_Events_Of_Interest_Matching_EventLogs);//add what we already found with new findings
            Filtered_Matched_Logs_This_SWELF_Run=Filtered_Matched_Logs_This_SWELF_Run.Distinct(new ItemEqualityComparer()).OrderBy(x => x.CreatedTime).ToList();//remove duplicates order list
            var queue = new Queue<EventLog_Entry>(Filtered_Matched_Logs_This_SWELF_Run);//set total findings list to the new total findings
            Filtered_Matched_Logs_This_SWELF_Run.Clear();
            ALL_Logs_That_Matched_Search_This_Event_Log.Clear();
            GC.Collect();
            return queue;
        }

        private void Remove_Whitelisted_Logs()
        {
            for (int x = 0; x < Settings.WhiteList_Search_Terms_Unparsed.Count; ++x)
            {
                try
                {
                    string[] WhiteListSearchsArgs = Settings.WhiteList_Search_Terms_Unparsed.ElementAt(x).Split(Settings.SplitChar_SearchCommandSplit).ToArray();

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
                                try
                                {
                                    SEARCH_REMOVE_WhiteList(WhiteListSearchsArgs[0], WhiteListSearchsArgs[1], Convert.ToInt32(WhiteListSearchsArgs[2]));
                                }
                                catch (Exception e)
                                {
                                    try
                                    {
                                        SEARCH_REMOVE_WhiteList(WhiteListSearchsArgs[0], WhiteListSearchsArgs[1], -1);
                                    }
                                    catch
                                    {
                                        try
                                        {
                                            SEARCH_REMOVE_WhiteList(WhiteListSearchsArgs[0], "", -1);
                                        }
                                        catch
                                        {
                                            SEARCH_REMOVE_WhiteList("", WhiteListSearchsArgs[1], -1);
                                        }
                                    }
                                }
                                break;
                            }
                    }
                }
                catch (Exception e)
                {
                    Error_Operation.Log_Error("Remove_Whitelisted_Logs() Value=" + Settings.WhiteList_Search_Terms_Unparsed.ElementAt(x), e.Message.ToString(), e.StackTrace.ToString(), Error_Operation.LogSeverity.Warning);
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

        private List<EventLog_Entry> SWITCH_to_Parse_SearchRule(string[] Search_String_Parsed, string Current_EventLog, string SearchRule,int SearchTermsElementIndex)
        {
            try
            {
                List <string> Search_String_Parsed_Empty_Removed = SearchRule.Split(Settings.SplitChar_SearchCommandSplit, StringSplitOptions.None).ToList();
                List<string> Search_String_Parsed_Empty_Removed_TEMP = new List<string>();

                for (int x=0;x< Search_String_Parsed_Empty_Removed.Count;++x)
                {
                    if((Search_String_Parsed_Empty_Removed.ElementAt(x)==" "|| Search_String_Parsed_Empty_Removed.ElementAt(x)=="    "|| Search_String_Parsed_Empty_Removed.ElementAt(x) == " ")&&x>=2)
                    {
                        Search_String_Parsed_Empty_Removed_TEMP.Add("");
                    }
                    else
                    {
                        Search_String_Parsed_Empty_Removed_TEMP.Add(Search_String_Parsed_Empty_Removed.ElementAt(x));
                    }
                }
                Search_String_Parsed = Search_String_Parsed_Empty_Removed_TEMP.ToArray();

                switch (Search_String_Parsed_Empty_Removed.Count)
                {
                    case 1://search term and event id
                        {//Term,log,id
                            if (Data_Store.contents_of_EventLog.Count > 0)
                            {
                                if (string.IsNullOrEmpty(Search_String_Parsed[0]) == false)//searchterm
                                {
                                   return SEARCH_Everything(Search_String_Parsed[0], Read_In_EventLogs_From_WindowsAPI);
                                }
                                else if (string.IsNullOrEmpty(Search_String_Parsed[1]) == false && Search_String_Parsed[1].ToLower() == Current_EventLog.ToLower())//search event log
                                {
                                    return SEARCH_EventLog_Return_All(Search_String_Parsed[1], SearchRule);
                                }
                                else if (string.IsNullOrEmpty(Search_String_Parsed[2]) == false)//search event id
                                {
                                    return SEARCH_EventID(Convert.ToInt32(Search_String_Parsed[2]), SearchRule);
                                }
                                else
                                {
                                    try
                                    {
                                        if (Search_String_Parsed[1].ToLower() == Current_EventLog.ToLower())
                                        {
                                            string UnparsedTerm = "";
                                            foreach (string Search_String_Parseddata in Search_String_Parsed)
                                            {
                                                UnparsedTerm += Search_String_Parseddata;
                                            }
                                            Error_Operation.Log_Error("SEARCH_FindTerms(case1)", "The Search term syntax for " + UnparsedTerm + "  has an error. Correct syntax is SearchTerm~EventLogName(Optinal)~EventID(Optinal).\nSearchTerm ~ ~ is min required syntax.\nAn attempt to search all currenlty searched logs was still performed using the exact search term " + UnparsedTerm, "", Error_Operation.LogSeverity.Warning);
                                            return SEARCH_Everything(UnparsedTerm, Read_In_EventLogs_From_WindowsAPI);
                                        }
                                        else//eventlog name not the one we are looking for
                                        {
                                            return new List<EventLog_Entry>();
                                        }
                                    }
                                    catch
                                    {
                                        return new List<EventLog_Entry>();
                                    }
                                }
                            }
                            break;
                        }
                    case 2://search log and term
                        {//Term,log,id 
                            if (Data_Store.contents_of_EventLog.Count > 0)
                            {
                                if (string.IsNullOrEmpty(Search_String_Parsed[0]) == false && string.IsNullOrEmpty(Search_String_Parsed[1]) == false && Search_String_Parsed[1].ToLower() == Current_EventLog.ToLower())
                                {
                                    return SEARCH_Eventlog_For_SearchTerm(Search_String_Parsed[0], Search_String_Parsed[1], SearchRule);
                                }
                                else if (string.IsNullOrEmpty(Search_String_Parsed[1]) == false && string.IsNullOrEmpty(Search_String_Parsed[2]) == false && Search_String_Parsed[1].ToLower() == Current_EventLog.ToLower())
                                {
                                    return SEARCH_EventLog_For_EventID(Convert.ToInt32(Search_String_Parsed[2]), Search_String_Parsed[1], SearchRule);
                                }
                                else if (string.IsNullOrEmpty(Search_String_Parsed[0]) == false && string.IsNullOrEmpty(Search_String_Parsed[2]) == false)
                                {
                                    return SEARCH_EventID(Convert.ToInt32(Search_String_Parsed[2]), SearchRule);
                                }
                                else
                                {
                                    try
                                    {
                                        if (Search_String_Parsed[1].ToLower() == Current_EventLog.ToLower())
                                        {
                                            string UnparsedTerm = "";
                                            foreach (string Search_String_Parseddata in Search_String_Parsed)
                                            {
                                                UnparsedTerm += Search_String_Parseddata;
                                            }
                                            Error_Operation.Log_Error("SEARCH_FindTerms(case2)", "The Search term syntax for " + UnparsedTerm + "  has an error. Correct syntax is SearchTerm~EventLogName(Optinal)~EventID(Optinal).\nSearchTerm ~ ~ is min required syntax.\nAn attempt to search all currenlty searched logs was still performed using the exact search term " + UnparsedTerm, "", Error_Operation.LogSeverity.Warning);
                                            return SEARCH_Everything(UnparsedTerm, Read_In_EventLogs_From_WindowsAPI);
                                        }
                                        else//eventlog name not the one we are looking for
                                        {
                                            return new List<EventLog_Entry>();
                                        }
                                    }
                                    catch
                                    {
                                        return new List<EventLog_Entry>();
                                    }
                                    //ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_Everything(Search_String_Parsed[0]));
                                    //is above sonething you wanted????
                                }
                            }
                            break;
                        }
                    case 3://search either term,and/or log, and/or eventid
                        {//Term,log,id
                            if (Data_Store.contents_of_EventLog.Count > 0)
                            {
                                if ((String.IsNullOrEmpty(Search_String_Parsed[0]) == false && String.IsNullOrEmpty(Search_String_Parsed[1]) == false && String.IsNullOrWhiteSpace(Search_String_Parsed[2]) == false) && Search_String_Parsed[1].ToLower() == Current_EventLog.ToLower())
                                {
                                    return SEARCH_EventLog_For_SearchTerm_LogName_EventID(Search_String_Parsed[0], Search_String_Parsed[1], Convert.ToInt32(Search_String_Parsed[2]));
                                }
                                else if (String.IsNullOrEmpty(Search_String_Parsed[0]) == true && String.IsNullOrEmpty(Search_String_Parsed[1]) == true && String.IsNullOrEmpty(Search_String_Parsed[2]) == false)//Search only event id all others blank
                                {
                                    return SEARCH_EventID(Convert.ToInt32(Search_String_Parsed[2]), SearchRule);
                                }
                                else if (String.IsNullOrEmpty(Search_String_Parsed[0]) == true && String.IsNullOrEmpty(Search_String_Parsed[1]) == false && String.IsNullOrEmpty(Search_String_Parsed[2]) == true && Search_String_Parsed[1].ToLower() == Current_EventLog.ToLower())//search event log for only ID
                                {
                                    return SEARCH_EventLog_Return_All(Search_String_Parsed[1], "");
                                }
                                else if ((String.IsNullOrEmpty(Search_String_Parsed[0]) == false && String.IsNullOrEmpty(Search_String_Parsed[1]) == false && String.IsNullOrEmpty(Search_String_Parsed[2]) == true) && Search_String_Parsed[1].ToLower() == Current_EventLog.ToLower())
                                {
                                    return SEARCH_Eventlog_For_SearchTerm(Search_String_Parsed[0], Search_String_Parsed[1], Current_EventLog);
                                }
                                else if ((String.IsNullOrEmpty(Search_String_Parsed[0]) == true && String.IsNullOrEmpty(Search_String_Parsed[1]) == false && String.IsNullOrEmpty(Search_String_Parsed[2]) == false) && Search_String_Parsed[1].ToLower() == Current_EventLog.ToLower())
                                {
                                    return SEARCH_EventLog_For_EventID(Convert.ToInt32(Search_String_Parsed[2]), Search_String_Parsed[1], SearchRule);
                                }
                                else if (Search_String_Parsed[1].ToLower() != Current_EventLog.ToLower())//not eventlog we are looking for
                                {
                                    return new List<EventLog_Entry>();
                                }
                                else //Gave 3 step search and somehow got here
                                {
                                    return new List<EventLog_Entry>();
                                }
                            }
                            break;
                        }
                    default:
                        {
                            string UnparsedTerm = "";
                            foreach (string Search_String_Parseddata in Search_String_Parsed)
                            {
                                UnparsedTerm += Search_String_Parseddata;
                            }
                            Error_Operation.Log_Error("SEARCH_FindTerms(case Default)", "The Search term syntax for " + UnparsedTerm + "  has an error.\nIn that the ~ char is used to many times or not enough. Correct syntax is SearchTerm~EventLogName(Optinal)~EventID(Optinal).\nSearchTErm ~ ~ is min required syntax.\nAn attempt to search all currenlty searched logs was still performed using the exact search term " + UnparsedTerm, "", Error_Operation.LogSeverity.Warning);
                            return SEARCH_Everything(UnparsedTerm, Read_In_EventLogs_From_WindowsAPI);
                            break;
                        }
                }
                return new List<EventLog_Entry>();
            }
            catch (Exception e)
            {
                string Data = "";
                foreach (string Search_String_Parseddata in Search_String_Parsed)
                {
                    Data+= Search_String_Parseddata;
                }
                Error_Operation.Log_Error("SEARCH_FindTerms(case Exception)", "Unable to finish search and index of logs for event log named '" + SearchRule + "' with Current_EventLog '"+Current_EventLog +"' "+"Search term was '"+ Data+"' error message is '"+ e.Message.ToString()+"'", e.StackTrace.ToString(), Error_Operation.LogSeverity.Critical);
                Settings.Search_Rules_Unparsed.RemoveAt(SearchTermsElementIndex);
                return new List<EventLog_Entry>();
            }
        }

        private void PARSE_Search_String_Prep_For_Searching(int x, string[] Search_String_Parsed, string Current_EventLog)
        {
            /*
        * possibilities for this
        1~1~1
        1~1~0
        1~0~0
        0~0~1
        0~1~1
        1~0~1
        0~1~0
        0~0~0 Settings.Search_Rules_Unparsed.ElementAt(x)
        */
            ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SWITCH_to_Parse_SearchRule(Search_String_Parsed, Current_EventLog, Settings.Search_Rules_Unparsed.ElementAt(x),x));
        }

        private void SEARCH_Run_Commands(string SearchCommand,string Search_Terms_Unparsed)
        {
                if (SearchCommand.Contains(Settings.SplitChar_Search_Command_Parsers[0]))
                {
                    string[] Search_Command_Values = SearchCommand.Split(Settings.SplitChar_Search_Command_Parsers, StringSplitOptions.RemoveEmptyEntries).ToArray();

                    switch (Search_Command_Values[0].ToLower())
                    {
                        case "count":
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_CMD_Counts_in_Log(Search_Command_Values[1].ToString(), Convert.ToInt32(Search_Command_Values[2]), Search_Command_Values, Search_Terms_Unparsed));
                                break;
                            }
                        case "logging_level":
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_CMD_For_Severity_EVTX_Level(Search_Command_Values[1].ToString().ToLower(), Search_Command_Values, Search_Terms_Unparsed));
                                break;
                            }
                        case "log_level":
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_CMD_For_Severity_EVTX_Level(Search_Command_Values[1].ToString().ToLower(), Search_Command_Values, Search_Terms_Unparsed));
                                break;
                            }
                        case "eventdata_length":
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_CMD_Length_of_LogData(Convert.ToInt32(Search_Command_Values[1]), Search_Command_Values, Search_Terms_Unparsed));
                                break;
                            }
                        case "regex":
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_CMD_For_Regex_in_Log(Search_Command_Values[1].ToString().ToLower(), Search_Command_Values, Search_Terms_Unparsed));
                                break;
                            }
                        case "not_in_log":
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_CMD_NOT_IN_EVENT(Search_Command_Values[1].ToString(), Search_Command_Values[2], Search_Command_Values[3]));
                                break;
                            }
                        case "commandline_count"://sysmon/powershell only commandline has X this # times
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_CMD_Counts_in_CMDLine(Search_Command_Values[1].ToString(), Convert.ToInt32(Search_Command_Values[2]), Search_Terms_Unparsed));
                                break;
                            }
                        case "commandline_contains"://sysmon/powershell only. commandline contains x 1 or more times
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_CMD_Length_Sysmon_CMDLine_Args_Contains(Search_Command_Values[1], Search_Terms_Unparsed));
                                break;
                            }
                        case "commandline_length"://sysmon/powershell only. the length of the commandline is x chars
                            {
                                try
                                {
                                    int Max_Length = -1;
                                    if (int.TryParse(Search_Command_Values[1], out Max_Length) && Max_Length != -1)
                                    {
                                        ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_CMD_Length_Sysmon_CMDLine_Args_Length(Max_Length, SearchCommand));
                                    }
                                }
                                catch (Exception e)
                                {
                                    Error_Operation.Log_Error("SEARCH_Run_Commands() commandline_length", e.Message.ToString(), e.StackTrace.ToString(), Error_Operation.LogSeverity.Warning);
                                }
                                break;
                            }
                        case "network_connect"://sysmon only
                            {
                                ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_CMD_Process_Port_Match(SearchCommand, Search_Terms_Unparsed));
                                break;
                            }
                        case "search_multiple":
                            {
                                string[] Search_Command_Values2 = SearchCommand.Split(Settings.SplitChar_SearchCommandSplit, StringSplitOptions.None).ToArray();

                                if (Search_Command_Values2.Length == 1)
                                {
                                    ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_CMD_Search_Multiple_SearchTerms(Search_Command_Values2[0], Search_Terms_Unparsed));
                                }
                                else if (Search_Command_Values2.Length == 2)
                                {
                                    ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_CMD_Search_Multiple_SearchTerms(Search_Command_Values2[0], Search_Terms_Unparsed, Search_Command_Values2[1]));
                                }
                                else if (Search_Command_Values2.Length == 3)
                                {
                                    ALL_Logs_That_Matched_Search_This_Event_Log.AddRange(SEARCH_CMD_Search_Multiple_SearchTerms(Search_Command_Values2[0], Search_Terms_Unparsed, Search_Command_Values2[1], Search_Command_Values2[2]));
                                }
                                else
                                {

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

        private List<EventLog_Entry> ADD_Search_Tagging(List<EventLog_Entry> MacthedList, string SearchTerm_Or_Command)//SEARCHRULE ADDED HERE
        {
            try
            {
                for (int x = 0; x < MacthedList.Count; ++x)
                {
                    if (string.IsNullOrEmpty(MacthedList.ElementAt(x).SearchRule)==true || string.IsNullOrWhiteSpace(MacthedList.ElementAt(x).SearchRule)==true)
                    {
                        MacthedList.ElementAt(x).SearchRule = SearchTerm_Or_Command;
                    }
                }
                return MacthedList;
            }
            catch (Exception e)
            {
                return MacthedList;
            }
        }



        private List<EventLog_Entry> SEARCH_Everything(string SearchRule, Queue<EventLog_Entry> EventLogs)
        {
            IList<EventLog_Entry> results = EventLogs.Where(s => s.EventData.Contains(SearchRule) || s.EventID.ToString().Equals(SearchRule)).ToList();
            return ADD_Search_Tagging(results.ToList(), SearchRule);
        }

        private List<EventLog_Entry> SEARCH_EventID_and_Data(int EventID , string SearchTerm)
        {
            IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(s => s.EventID.Equals(EventID) == true && s.EventData.Contains(SearchTerm)).ToList();
            return ADD_Search_Tagging(results.ToList(), SearchTerm);
        }

        private List<EventLog_Entry> SEARCH_EventID(int EventID,string SearchRule)
        {
            IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(s => s.EventID.Equals(EventID)==true).ToList();
            return ADD_Search_Tagging(results.ToList(), SearchRule);
        }

        private List<EventLog_Entry> SEARCH_EventLog_Return_All(string LogName,string SearchRule)
        {
            IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(s => s.LogName.ToLower().Equals(LogName.ToLower())).ToList();
            return ADD_Search_Tagging(results.ToList(), SearchRule);
        }

        private List<EventLog_Entry> SEARCH_Eventlog_For_SearchTerm(string SearchTerm, string EventLogName, string SearchRule)
        {
            IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(s => s.EventData.Contains(SearchTerm) && s.LogName.ToLower().Equals(EventLogName.ToLower())).ToList();
            return ADD_Search_Tagging(results.ToList(), SearchRule);
        }

        private List<EventLog_Entry> SEARCH_EventLog_For_EventID(int EventID , string EventLogName,string SearchRule)
        {
            IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(s => s.EventID.Equals(EventID) && s.LogName.ToLower().Equals(EventLogName.ToLower())).ToList();
            return ADD_Search_Tagging(results.ToList(), SearchRule);
        }

        private List<EventLog_Entry> SEARCH_EventLog_For_SearchTerm_LogName_EventID(string SearchTerm,string EventLogName, int EventID)
        {
            IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(s => s.EventID.Equals(EventID) == true && s.LogName.ToLower() == EventLogName.ToLower() && s.EventData.Contains(SearchTerm)).ToList();
            return ADD_Search_Tagging(results.ToList(), SearchTerm);
        }



        private List<EventLog_Entry> SEARCH_CMD_Length_Sysmon_CMDLine_Args_Length(int Max_Length,string SearchRule)
        {
            IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(s => s.GET_Sysmon_CommandLine_Args.ToCharArray().Length >= Max_Length).ToList();
            return ADD_Search_Tagging(results.ToList(), SearchRule);
        }

        private List<EventLog_Entry> SEARCH_CMD_Length_Sysmon_CMDLine_Args_Contains(string SearchTerm,string SearchRule)
        {
            IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(s => s.GET_Sysmon_CommandLine_Args.Contains(SearchTerm)).ToList();
            return ADD_Search_Tagging(results.ToList(), SearchRule);
        }

        private List<EventLog_Entry> SEARCH_CMD_Counts_in_CMDLine(string SearchTerm, int Max_Num_Of_Occurances,string SearchRule)
        {
            IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(s => s.GET_Sysmon_CommandLine_Args.Count(f => f == Convert.ToChar(SearchTerm)) >= Max_Num_Of_Occurances).ToList();
            return ADD_Search_Tagging(results.ToList(), SearchRule);
        }

        private List<EventLog_Entry> SEARCH_CMD_NOT_IN_EVENT(string SearchRule, string EventLogName, string EventID="-1")
        {
            if (EventLogName.ToLower() == Data_Store.contents_of_EventLog.Peek().LogName.ToLower())
            {
                int Limit = 10;

                Read_In_EventLogs_From_WindowsAPI_Temp = Data_Store.contents_of_EventLog.ToList();

                string[] SearchTerms = SearchRule.Split(Settings.SplitChar_Search_Command_Parser_Multi_Search, StringSplitOptions.RemoveEmptyEntries).ToArray();

                if (SearchTerms.Length < Limit && SearchTerms.Length > 0)
                {
                    for (int x = 0; x < SearchTerms.Length; ++x)
                    {

                        Read_In_EventLogs_From_WindowsAPI_Temp = Read_In_EventLogs_From_WindowsAPI_Temp.Where(s => !s.EventData.Contains(SearchTerms[x]) && s.LogName.ToLower().Equals(EventLogName.ToLower())).ToList();
                    }
                }
                else
                {
                    Error_Operation.Log_Error("SEARCH_CMD_NOT_IN_EVENT()", "Search Term '" + SearchRule + "'" + " has to many or not enough (limit "+Limit+" and more than 0 terms) things to search for per log. Limit is less than " + Limit, "", Error_Operation.LogSeverity.Warning);
                    return ADD_Search_Tagging(Read_In_EventLogs_From_WindowsAPI_Temp, SearchRule);
                }
                return ADD_Search_Tagging(Read_In_EventLogs_From_WindowsAPI_Temp, SearchRule);
            }
            return new List<EventLog_Entry>();
        }

        private List<EventLog_Entry> SEARCH_CMD_Counts_in_Log(string SearchTerm , int Min_Num_Of_Occurances, string[] Search_Command,string SearchRule)
        {
            string[] Split_Search_Command = { SearchTerm };

            if (Min_Num_Of_Occurances > 0)
            {
                try
                {
                    if ((Search_Command.Length == 3) || (Settings.EVTX_Override && Search_Command.Length == 3))
                    {
                        IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(s => s.EventData.Split(Split_Search_Command, StringSplitOptions.RemoveEmptyEntries).ToList().Count - 1 >= Min_Num_Of_Occurances).ToList();
                        return ADD_Search_Tagging(results.ToList(), SearchRule);
                    }
                    else if ((Settings.EVTX_Override && Search_Command.Length == 4) || (Search_Command.Length == 4 && (Settings.CHECK_If_EventLog_Exsits(Search_Command[3]))))
                    {
                        IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(s => s.EventData.Split(Split_Search_Command, StringSplitOptions.RemoveEmptyEntries).ToList().Count - 1 >= Min_Num_Of_Occurances && s.LogName.ToLower() == Search_Command[3].ToLower()).ToList();
                        return ADD_Search_Tagging(results.ToList(), SearchRule);
                    }
                    else if ((Settings.EVTX_Override && Search_Command.Length == 5) || (Search_Command.Length == 5 && (Settings.CHECK_If_EventLog_Exsits(Search_Command[3]))))
                    {
                        if (int.TryParse(Search_Command[4], out int EventID))
                        {
                            IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(s => s.EventData.Split(Split_Search_Command, StringSplitOptions.RemoveEmptyEntries).ToList().Count - 1 >= Min_Num_Of_Occurances && s.LogName.ToLower() == Search_Command[3].ToLower() && s.EventID == EventID).ToList();
                            return ADD_Search_Tagging(results.ToList(), SearchRule);
                        }
                        else
                        {
                            Error_Operation.Log_Error("SEARCH_CMD_Counts_in_Log()", "The search term had bad input. Event ID not a number. Check search config format.","", Error_Operation.LogSeverity.Warning);
                            List<EventLog_Entry> results = new List<EventLog_Entry>();
                            return ADD_Search_Tagging(results.ToList(), SearchRule);
                        }
                    }
                    else
                    {
                        if ((Settings.CHECK_If_EventLog_Exsits(Search_Command[2])) || Settings.EVTX_Override)
                        {
                            Error_Operation.Log_Error("SEARCH_CMD_Counts_in_Log()", "The search term had bad input it was to long " + Settings.SplitChar_Search_Command_Parsers[0] + ". Check search config format.","", Error_Operation.LogSeverity.Warning);
                            IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(s => s.EventData.Split(Split_Search_Command, StringSplitOptions.RemoveEmptyEntries).ToList().Count - 1 >= Min_Num_Of_Occurances).ToList();
                            return ADD_Search_Tagging(results.ToList(), SearchRule);
                        }
                        else
                        {
                            Error_Operation.Log_Error("SEARCH_CMD_Counts_in_Log()", "The search term had bad input Eventlog did not exist " + Settings.SplitChar_Search_Command_Parsers[0] + ". Check search config format.","", Error_Operation.LogSeverity.Warning);
                            List<EventLog_Entry> results = new List<EventLog_Entry>();
                            return ADD_Search_Tagging(results.ToList(), SearchRule);

                        }
                    }
                }
                catch (Exception e)
                {
                    Error_Operation.Log_Error("SEARCH_CMD_Counts_in_Log()", "The search term had bad input. Check search config format. " + e.Message.ToString(), e.StackTrace.ToString(), Error_Operation.LogSeverity.Warning);
                    List<EventLog_Entry> results = new List<EventLog_Entry>();
                    return ADD_Search_Tagging(results.ToList(), SearchRule);
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
                    IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(f => f.EventData.ToCharArray().Length >= Max_Length).ToList();
                    return ADD_Search_Tagging(results.ToList(), SearchCommand);
                }
                else if ((Settings.EVTX_Override && SearchResults.Length == 3) || (SearchResults.Length == 3 && (Settings.CHECK_If_EventLog_Exsits(SearchResults[2]))))
                {
                    IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(f => f.EventData.ToCharArray().Length >= Max_Length && f.LogName.ToLower() == SearchResults[2].ToLower()).ToList();
                    return ADD_Search_Tagging(results.ToList(), SearchCommand);
                }
                else if ((Settings.EVTX_Override && SearchResults.Length == 4) || (SearchResults.Length == 4 && (Settings.CHECK_If_EventLog_Exsits(SearchResults[2])) && SearchResults.Length == 3))
                {
                    IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(f => f.EventData.ToCharArray().Length >= Max_Length && f.LogName.ToLower().Equals(SearchResults[2].ToLower())).ToList();
                    return ADD_Search_Tagging(results.ToList(), SearchCommand);
                }
                else if ((Settings.EVTX_Override && SearchResults.Length == 4) || (SearchResults.Length == 4 && (Settings.CHECK_If_EventLog_Exsits(SearchResults[2])) && SearchResults.Length == 4))
                {
                    if (int.TryParse(SearchResults[3], out int EventID))
                    {
                        IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(f => f.EventData.ToCharArray().Length >= Max_Length && f.LogName.ToLower() == SearchResults[2].ToLower() && f.EventID == EventID).ToList();
                        return ADD_Search_Tagging(results.ToList(), SearchCommand);
                    }
                    else
                    {
                        Error_Operation.Log_Error("SEARCH_CMD_Length_of_LogData()", "The search term had bad input. Event ID not a number. Check search config format.","", Error_Operation.LogSeverity.Warning);
                        List<EventLog_Entry> results = new List<EventLog_Entry>();
                        return ADD_Search_Tagging(results.ToList(), SearchCommand);
                    }
                }
                else
                {
                    Error_Operation.Log_Error("SEARCH_CMD_Length_of_LogData()", "The search term had bad input it was to long " + Settings.SplitChar_Search_Command_Parsers[0] + ". Check search config format.","", Error_Operation.LogSeverity.Warning);
                    IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(f => f.EventData.ToCharArray().Length >= Max_Length).ToList();
                    return ADD_Search_Tagging(results.ToList(), SearchCommand);
                }
            }
            catch (Exception e)
            {
                Error_Operation.Log_Error("SEARCH_CMD_Length_of_LogData()", "The search term had bad input. Check search config format."+e.Message.ToString(), e.StackTrace.ToString(), Error_Operation.LogSeverity.Warning);
                List<EventLog_Entry> results = new List<EventLog_Entry>();
                return ADD_Search_Tagging(results.ToList(), SearchCommand);
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
                    IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(f => RegX.IsMatch(f.EventData)).ToList();
                    return ADD_Search_Tagging(results.ToList(), SearchCommand);
                }
                else if (Number_of_Parsers == 2 && (Settings.CHECK_If_EventLog_Exsits(SearchResults[2])))
                {
                    IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(f => RegX.IsMatch(f.EventData) && f.LogName.ToLower() == SearchResults[2].ToLower()).ToList();
                    return ADD_Search_Tagging(results.ToList(), SearchCommand);
                }
                else if (Number_of_Parsers == 3 && (Settings.CHECK_If_EventLog_Exsits(SearchResults[2])) && SearchResults.Length==3)
                {
                    IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(f => RegX.IsMatch(f.EventData) && f.LogName.ToLower() == SearchResults[2].ToLower()).ToList();
                    return ADD_Search_Tagging(results.ToList(), SearchCommand);
                }
                else if (Number_of_Parsers == 3 && (Settings.CHECK_If_EventLog_Exsits(SearchResults[2])) && SearchResults.Length == 4)
                {
                    bool testEventID = int.TryParse(SearchResults[3], out int EventID);
                    if (testEventID)
                    {
                        IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(f => RegX.IsMatch(f.EventData) && f.LogName.ToLower() == SearchResults[2].ToLower() && f.EventID == EventID).ToList();
                        return ADD_Search_Tagging(results.ToList(), SearchCommand);
                    }
                    else
                    {
                        Error_Operation.Log_Error("SEARCH_CMD_For_Regex_in_Log()", "The search term had bad input. Event ID not a number. Check search config format.","", Error_Operation.LogSeverity.Warning);
                        List<EventLog_Entry> results = new List<EventLog_Entry>();
                        return ADD_Search_Tagging(results.ToList(), SearchCommand);
                    }
                }
                else
                {
                    Error_Operation.Log_Error("SEARCH_CMD_For_Regex_in_Log()", "The search term had bad input it was to long " + Settings.SplitChar_Search_Command_Parsers[0] + ". Check search config format.","", Error_Operation.LogSeverity.Warning);

                    IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(f => RegX.IsMatch(f.EventData)).ToList();
                    return ADD_Search_Tagging(results.ToList(), SearchCommand);
                }
            }
            catch (Exception e)
            {
                Error_Operation.Log_Error("SEARCH_CMD_For_Regex_in_Log()", "The search term had bad input. Check search config format."+e.Message.ToString(), e.StackTrace.ToString(), Error_Operation.LogSeverity.Warning);
                List<EventLog_Entry> results = new List<EventLog_Entry>();
                return ADD_Search_Tagging(results.ToList(), SearchCommand);
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
                    IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(f => f.Severity.Contains(Severity_level)).ToList();
                    return ADD_Search_Tagging(results.ToList(), SearchCommand);
                }
                else if (Number_of_Parsers == 2 && (Settings.CHECK_If_EventLog_Exsits(SearchResults[2])))
                {
                    IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(f => f.Severity.Contains(Severity_level) && f.LogName.ToLower() == SearchResults[2].ToLower()).ToList();
                    return ADD_Search_Tagging(results.ToList(), SearchCommand);
                }
                else if (Number_of_Parsers == 3 && (Settings.CHECK_If_EventLog_Exsits(SearchResults[2])) && SearchResults.Length == 3)
                {
                    IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(f => f.Severity.Contains(Severity_level) && f.LogName.ToLower() == SearchResults[2].ToLower()).ToList();
                    return ADD_Search_Tagging(results.ToList(), SearchCommand);
                }
                else if (Number_of_Parsers == 3 && (Settings.CHECK_If_EventLog_Exsits(SearchResults[2])) && SearchResults.Length == 4)
                {
                    bool testEventID = int.TryParse(SearchResults[3], out int EventID);
                    if (testEventID)
                    {
                        IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(f => f.Severity.Contains(Severity_level) && f.LogName.ToLower() == SearchResults[2].ToLower() && f.EventID == EventID).ToList();
                        return ADD_Search_Tagging(results.ToList(), SearchCommand);
                    }
                    else
                    {
                        Error_Operation.Log_Error("SEARCH_CMD_For_Level()", "The search term had bad input. Event ID not a number. Check search config format.","", Error_Operation.LogSeverity.Warning);
                        List<EventLog_Entry> results = new List<EventLog_Entry>();
                        return ADD_Search_Tagging(results.ToList(), SearchCommand);
                    }
                }
                else
                {
                    Error_Operation.Log_Error("SEARCH_CMD_For_Level()", "The search term had bad input it was to long " + Settings.SplitChar_Search_Command_Parsers[0] + ". Check search config format.","", Error_Operation.LogSeverity.Warning);
                    IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(f => f.Severity.Contains(Severity_level)).ToList();
                    return ADD_Search_Tagging(results.ToList(), SearchCommand);
                }
            }
            catch (Exception e)
            {
                Error_Operation.Log_Error("SEARCH_CMD_For_Level()", e.Message.ToString()+" The search term had bad input. Check search config format.", e.StackTrace.ToString(), Error_Operation.LogSeverity.Warning);
                List<EventLog_Entry> results = new List<EventLog_Entry>();
                return ADD_Search_Tagging(results.ToList(), SearchCommand);
            }
        }

        private List<EventLog_Entry> SEARCH_CMD_Search_Multiple_SearchTerms(string SearchTerm, string SearchRule,string EventLogName="", string EventID="")
        {
            int Limit = 10;

            List<EventLog_Entry> MultSearchList = new List<EventLog_Entry>();
            Queue<EventLog_Entry> Temp_Storage = Read_In_EventLogs_From_WindowsAPI;//backup eventlog read in 
            Read_In_EventLogs_From_WindowsAPI_Temp = Read_In_EventLogs_From_WindowsAPI.ToList();
            List<EventLog_Entry> Completed_Search = new List<EventLog_Entry>();
            List<EventLog_Entry> results_1 = new List<EventLog_Entry>();

            string[] SearchTerms = SearchTerm.Split(Settings.SplitChar_Search_Command_Parser_Multi_Search, StringSplitOptions.RemoveEmptyEntries).ToArray();

            if (SearchTerms.Length < Limit)
            {
                if (SearchTerms.Length > 1)
                {
                    for (int x = 0; x < SearchTerms.Length; ++x)
                    {
                        if (x == 0)
                        {
                            results_1 = SEARCH_Everything(SearchTerms[0], Read_In_EventLogs_From_WindowsAPI);
                            Read_In_EventLogs_From_WindowsAPI_Temp = results_1;
                            MultSearchList.AddRange(results_1);

                            if (results_1.Count < 1)
                            {
                                return new List<EventLog_Entry>();
                            }
                        }
                        else if (results_1.Count < 1)
                        {
                            return new List<EventLog_Entry>();
                        }
                        else
                        {
                            Read_In_EventLogs_From_WindowsAPI = new Queue<EventLog_Entry>(MultSearchList);

                            int MultSearchList_PreCount = MultSearchList.Count;//count b4 searching

                            string[] searchthis = { SearchTerms.ElementAt(x), EventLogName, EventID };

                            Read_In_EventLogs_From_WindowsAPI = new Queue<EventLog_Entry>(SWITCH_to_Parse_SearchRule(searchthis, EventLogName, SearchRule,x));

                            if (MultSearchList_PreCount < Read_In_EventLogs_From_WindowsAPI.Count)//didi the first thing searched have any logs with the n'th thing in them to return. if 0 answer is no.
                            {
                                return new List<EventLog_Entry>();
                            }
                            else
                            {
                                Completed_Search.AddRange(Read_In_EventLogs_From_WindowsAPI);
                            }
                        }
                    }
                    Read_In_EventLogs_From_WindowsAPI = Temp_Storage;//return the list of all the things to original state
                }
                else
                {
                    if (SearchTerms.Length > 0)
                    {
                        return SEARCH_Everything(SearchTerms[0], Read_In_EventLogs_From_WindowsAPI);
                    }
                }

                if (Completed_Search.Count > 1)//something was found to return
                {
                    return ADD_Search_Tagging(Completed_Search, SearchRule);
                }
                else
                {
                    return new List<EventLog_Entry>();
                }
            }
            else
            {
                Error_Operation.Log_Error("SEARCH_CMD_Search_Multiple_SearchTerms()", SearchTerm + " has to many things to search for per log. Limit is less than " + Limit, "", Error_Operation.LogSeverity.Warning);
                return ADD_Search_Tagging(MultSearchList, SearchRule);
            }
        }

        private List<EventLog_Entry> SEARCH_CMD_Process_Port_Match(string SearchTerm,string SearchRule, string EventLogName = "microsoft-windows-sysmon/operational", string EventID = "3")
        {
            string[] SearchTerms = SearchTerm.Split(Settings.SplitChar_Search_Command_Parsers, StringSplitOptions.RemoveEmptyEntries).ToArray();
            //[1]=port
            //[2]=app
            if (SearchTerms.Length == 3)
            {
                IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(s => s.LogName.ToLower().Equals(EventLogName.ToLower()) && s.EventID.ToString().Equals(EventID) && s.GET_Sysmon_Network_Calling_Process_Name.ToLower().Contains(SearchTerms[2].ToLower()) && s.GET_Sysmon_Netwrok_Calling_Process_Name_Dest_Port.Equals(SearchTerms[1])).ToList();
                return ADD_Search_Tagging(results.ToList(), SearchRule);
            }
            else if (SearchTerms.Length == 2)
            {
                try
                {
                    Convert.ToInt32(SearchTerms[1]);
                    IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(s => s.LogName.ToLower().Equals(EventLogName.ToLower()) && s.EventID.ToString().Equals(EventID) && s.GET_Sysmon_Netwrok_Calling_Process_Name_Dest_Port.Equals(SearchTerms[1])).ToList();
                    return ADD_Search_Tagging(results.ToList(), SearchRule);
                }
                catch
                {
                    IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(s => s.LogName.ToLower().Equals(EventLogName.ToLower()) && s.EventID.ToString().Equals(EventID) && s.GET_Sysmon_Network_Calling_Process_Name.ToLower().Contains(SearchTerms[2].ToLower())).ToList();
                    return ADD_Search_Tagging(results.ToList(), SearchRule);
                }
            }
            else
            {
                IList<EventLog_Entry> results = Data_Store.contents_of_EventLog.Where(s => s.LogName.ToLower().Equals(EventLogName.ToLower()) && s.EventID.ToString().Equals(EventID)).ToList();
                return ADD_Search_Tagging(results.ToList(), SearchRule);
            }
        }
    }

    class ItemEqualityComparer : IEqualityComparer<EventLog_Entry>
    {
        public bool Equals(EventLog_Entry x, EventLog_Entry y)
        {
            // Two items are equal if their keys are equal.
            return x.EventLog_Seq_num == y.EventLog_Seq_num;
        }

        public int GetHashCode(EventLog_Entry obj)
        {
            return obj.EventLog_Seq_num.GetHashCode();
        }
    }
}
