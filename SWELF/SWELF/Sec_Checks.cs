//Written by Ceramicskate0
//Copyright
using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceProcess;
using Microsoft.Win32;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Security.Principal;

namespace SWELF
{
    internal static class Sec_Checks
    {
        private static long Default_Min_EventLogSize = 64000;

        internal static int UpTime
        {
            get
            {
                using (var uptime = new PerformanceCounter("System", "System Up Time"))
                {
                    uptime.NextValue();
                    return TimeSpan.FromSeconds(uptime.NextValue()).Days;
                }
            }
        }

        private static long Eventlog_Count_Before_Write = 0;


        internal static bool Pre_Run_Sec_Checks()
        {
            if (Check_Service_Running("EventLog") && Check_EventLog_Service_Reg_Keys())//Event logs requirements in place
            {
                return true;
            }
            else
            {
                LOG_SEC_CHECK_Fail("Check_EventLog_Service() && Check_Reg_Keys() Windows Event Log Regkey or Service Missing or off. SWELF did not run due to possible tampering.");
                return false;
            }
        }

        internal static void Pre_Live_Run_Sec_Checks()
        {
            Settings.Services_To_Check_Up = Settings.Services_To_Check_Up.Distinct().ToList();

            if (Settings.Services_To_Check_Up.Count > 0)//CHECK logging thrid party eventlog services are running
            {
                for (int x = 0; x < Settings.Services_To_Check_Up.Count; ++x)
                {
                    if (Check_Service_Running(Settings.Services_To_Check_Up.ElementAt(x)) == false)
                    {
                        LOG_SEC_CHECK_Fail("Pre_Live_Run_Sec_Checks() && Check_Service_Running() The windows service " + Settings.Services_To_Check_Up.ElementAt(x) + " is not running or not a service on " + Settings.ComputerName);
                    }
                }
            }
        }

        internal static bool Live_Run_Sec_Checks(string EVT_Log_Name)
        {
            try
            {
                if (Settings.CHECK_If_EventLog_Exsits(EVT_Log_Name))
                {
                    if (Check_Event_Log_Is_Blank(EVT_Log_Name) && Check_Event_Log_Is_Blank(Settings.SWELF_EventLog_Name) && Check_Windows_Event_Log_Size(EVT_Log_Name) && Check_Windows_Event_Log_Retention_Policy() && Check_Event_Log_Has_Not_Recorded_Logs_In_X_Days(EVT_Log_Name))
                    {
                        GET_EventLog_Count_Before_Write(EVT_Log_Name);
                        return true;
                    }
                    else
                    {
                        GET_EventLog_Count_Before_Write(EVT_Log_Name);
                        return false;//FAILED
                    }
                }
                else
                {
                    return false;
                }
            }
            catch (Exception e)
            {
                return false;//FAILED
            }
        }

        internal static bool Post_Run_Sec_Checks()
        {
            if (Settings.Logs_Sent_to_ALL_Collectors==true)//if no logs sent, none to write
            {
                if (Check_If_SWELF_Event_Logs_Written(Convert.ToInt32(Eventlog_Count_Before_Write), Settings.SWELF_Events_Of_Interest_Matching_EventLogs.Count))//check samde number of logs written to eventlog
                {
                    return true;//the same number was written
                }
                else
                {
                    return false;
                }
            }
            else
            {
                return true;//got to rerun, so ignore
            }
        }



        internal static bool CHECK_If_EventLog_Missing(EventLog_File ELF, EventLog_Entry EVE)
        {
            if ((EVE.EventLog_Seq_num != ELF.ID_Number_Of_Individual_log_Entry_EVENTLOG + 1) && ELF.EventlogMissing == false && (ELF.ID_Number_Of_Individual_log_Entry_EVENTLOG != 0 && EVE.EventRecordID != 0))
            {
                ELF.EventlogMissing = true;
                LOG_SEC_CHECK_Fail("CHECK_If_EventLog_Missing() Logs on " + Settings.ComputerName + " under Event Log name " + EVE.LogName + " near or around Event ID " + EVE.EventRecordID.ToString() + " found Eventlogs missing.");
                return true;
            }
            else
            {
                return false;
            }
        }

        internal static void GET_EventLog_Count_Before_Write(string EVT_Log_Name)
        {
            Eventlog_Count_Before_Write = EventLogSession.GlobalSession.GetLogInformation(Settings.SWELF_EventLog_Name, PathType.LogName).RecordCount.Value;
        }

        internal static bool CHECK_If_Running_as_Admin()
        {
            if (new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
            {
                return true;
            }
            else
            {
                LOG_SEC_CHECK_Fail("Settings.CHECK_If_Running_as_Admin() " +Settings.ComputerName + " SWELF not running as admin and was unable to read eventlogs.");
                Error_Operation.SEND_Errors_To_Central_Location();
                return false;
            }
        }

        private static bool Check_EventLog_Service_Reg_Keys()
        {
            List<string> RegKeys = new List<string>
            {
                @"System\CurrentControlSet\Services\Eventlog",
                @"SYSTEM\CurrentControlSet\Control\WMI\Autologger"
            };
            for (int x = 0; x < RegKeys.Count; ++x)
            {
                try
                {
                    RegistryKey reg = Registry.LocalMachine.OpenSubKey(RegKeys.ElementAt(x));
                    if (reg == null)
                    {
                        return false;
                    }
                }
                catch (Exception e)
                {
                    LOG_SEC_CHECK_Fail("FAILED Security Check Registry " + e.Message.ToString());
                    return false;
                }
            }
            return true;
        }

        private static bool Check_Service_Running(string ServiceName)
        {
            try
            {
                using (ServiceController sc = new ServiceController(ServiceName))
                {
                    if (sc.Status == ServiceControllerStatus.Running)
                        return true;//service up
                    else
                        return false;//service down
                }
            }
            catch (Exception E)
            {
                LOG_SEC_CHECK_Fail(E.Message.ToString());
                return false;
            }
        }

        private static bool Check_If_SWELF_Event_Logs_Written(int NumberOfRecordsWritten_Before, int NumberOfRecordsWritten_After)
        {
            if ((NumberOfRecordsWritten_Before + NumberOfRecordsWritten_After) >= NumberOfRecordsWritten_Before)
            {
                return true;
            }
            else
            {
                LOG_SEC_CHECK_Fail(Settings.SWELF_EventLog_Name + " Eventlog is empty and logs did not write to event log.");
                return false;//FAILED
            }
        }

        private static bool Check_Windows_Event_Log_Size(string EVT_Log_Name)
        {
            long EVT_Log_Namez_FileSize = EventLogSession.GlobalSession.GetLogInformation(EVT_Log_Name, PathType.LogName).FileSize.Value;
            if (EVT_Log_Namez_FileSize < Default_Min_EventLogSize)
            {
                LOG_SEC_CHECK_Fail("The " + EVT_Log_Name + " eventlog is smaller that the system log. This could be unintended modification");
                return false;
            }
            return true;
        }

        private static bool Check_Windows_Event_Log_Retention_Policy()
        {
            List<EventLog> eventLogs = EventLog.GetEventLogs().ToList();

            for (int x = 0; x < eventLogs.Count; ++x)
            {
                if (eventLogs.Any(s => eventLogs.ElementAt(x).Log.ToLower().IndexOf(s.Log.ToLower(), StringComparison.OrdinalIgnoreCase) > 0))
                {
                    RegistryKey regEventLog = Registry.LocalMachine.OpenSubKey("System\\CurrentControlSet\\Services\\EventLog\\" + eventLogs.ElementAt(x).Log);
                    if (regEventLog != null)
                    {
                        Object RegKeyFileAttrib = regEventLog.GetValue("File");
                        if (RegKeyFileAttrib != null)
                        {
                            switch (eventLogs.ElementAt(x).OverflowAction)
                            {
                                case OverflowAction.OverwriteOlder:
                                    LOG_SEC_CHECK_Fail("Check_Windows_Event_Log_Retention_Policy() " + eventLogs.ElementAt(x).LogDisplayName + " is set to not overwire only logs older than " + eventLogs.ElementAt(x).MinimumRetentionDays.ToString());
                                    return true;
                                case OverflowAction.DoNotOverwrite:
                                    LOG_SEC_CHECK_Fail("Check_Windows_Event_Log_Retention_Policy() " + eventLogs.ElementAt(x).LogDisplayName + " is set to not overwire the oldest event log");
                                    return true;
                            }
                        }
                        else
                        {
                            LOG_SEC_CHECK_Fail("Check_Windows_Event_Log_Retention_Policy() "+ eventLogs.ElementAt(x).LogDisplayName + " \"File\" reg attrib does not exist and it should");
                            return false;
                        }
                    }
                }
            }
            return true;
        }

        private static bool Check_Event_Log_Has_Not_Recorded_Logs_In_X_Days(string EVT_Log_Name)
        {
            TimeSpan diff;

            DateTime Today = DateTime.Now;

            DateTime CreationTime = EventLogSession.GlobalSession.GetLogInformation(EVT_Log_Name, PathType.LogName).CreationTime.Value;

            DateTime LastWriteTime = EventLogSession.GlobalSession.GetLogInformation(EVT_Log_Name, PathType.LogName).LastWriteTime.Value;
            //For a given eventlog when was the last time it was written to. Based on today - last time X. Alert yes or no.

            diff = Today.Subtract(LastWriteTime);

            if (diff.Days < 0 && UpTime < 1)
            {
                LOG_SEC_CHECK_Fail("Check_Windows_Event_Log_Has_Not_Recorded_Logs_In_X_Days() The Event Log " + EVT_Log_Name + " has not been written to in 24 hours."+ diff.Days +"<"+ 0 +"&&"+ UpTime +"<"+ 1);
                return false;//FAILED
            }

            diff = Today.Subtract(CreationTime);
            if (diff.Days <= 0)
            {
                LOG_SEC_CHECK_Fail("Check_Windows_Event_Log_Has_Not_Recorded_Logs_In_X_Days() The Event Log " + EVT_Log_Name + " was created in the last 24 hours."+ diff.Days +"<="+ 0);
                return false;//FAILED
            }

            if (EventLogSession.GlobalSession.GetLogInformation(EVT_Log_Name, PathType.LogName).IsLogFull.Value && EventLogSession.GlobalSession.GetLogInformation(EVT_Log_Name, PathType.LogName).RecordCount < 10)
            {
                LOG_SEC_CHECK_Fail("Check_Windows_Event_Log_Has_Not_Recorded_Logs_In_X_Days() The Event Log " + EVT_Log_Name + " is full amd has less than 10 records.");
                return false;//FAILED
            }
            return true;
        }

        private static bool Check_Event_Log_Is_Blank(string EVT_Log_Name) 
        {
            try
            {
                if (Settings.CHECK_If_EventLog_Exsits(EVT_Log_Name))
                {
                    if (EventLogSession.GlobalSession.GetLogInformation(EVT_Log_Name, PathType.LogName).RecordCount.Value > 1)
                    {
                        return true;
                    }
                    else
                    {
                        if (EventLogSession.GlobalSession.GetLogInformation(Settings.SWELF_EventLog_Name, PathType.LogName).RecordCount.Value > 0)
                        {
                            return true;
                        }
                        else if (EVT_Log_Name == Settings.SWELF_EventLog_Name)
                        {
                            LOG_SEC_CHECK_Fail("Check_Event_Log_Is_Blank() "+EVT_Log_Name + " Eventlog is empty.");
                            return false;//FAILED
                        }
                        else
                        {
                            LOG_SEC_CHECK_Fail("Check_Event_Log_Is_Blank() "+ EVT_Log_Name + " Eventlog is empty.");
                            return false;//FAILED
                        }
                    }
                }
                else
                {
                    return false;//FAILED
                }
            }
            catch (Exception e)
            {
                LOG_SEC_CHECK_Fail("Check_Event_Log_Is_Blank() EventLogSession.GlobalSession.GetLogInformation("+ EVT_Log_Name+", PathType.LogName). EventLog Name was " + EVT_Log_Name + ". Error message was "+e.Message.ToString());
                return false;//FAILED
            }
        }

        internal static void CHECK_Reg_vs_File_Config(string Settings_FilePath)
        {
            if (Settings.GET_AppConfigFile_Path == Settings_FilePath)//Appconfig
            {
                if (CHECK_File_vs_Reg_Contents(Settings_FilePath, Reg_Operation.REG_KEY.ConsoleAppConfig_Contents)==false)
                {
                    EventLog_SWELF.WRITE_FailureAudit_Error_To_EventLog("CHECK_Reg_vs_File_Config() The app config file(ConsoleAppConfig.conf) did not match what was stored in the registry on this machine. Config File was " + Settings_FilePath);
                    if (Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.ConsoleAppConfig_Contents))
                    {
                        File_Operation.DELETE_AND_CREATE_File(Settings.GET_AppConfigFile_Path);
                        File_Operation.CREATE_NEW_Files_And_Dirs(Settings.Config_File_Location, Settings.AppConfigFile_FileName, File_Operation.GET_Default_ConsoleAppConfig_File_Contents);
                    }
                    else
                    {
                        File_Operation.DELETE_AND_CREATE_File(Settings.GET_AppConfigFile_Path);
                        File_Operation.CREATE_NEW_Files_And_Dirs(Settings.Config_File_Location, Settings.AppConfigFile_FileName, Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_Contents));
                        Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_Contents, Crypto_Operation.Decrypt_File_Contents(Settings.GET_AppConfigFile_Path));
                    }
                }
            }
            else if (Settings.GET_EventLogID_PlaceHolder_Path == Settings_FilePath)//EventLog ID
            {
                EventLog_SWELF.WRITE_FailureAudit_Error_To_EventLog("CHECK_Reg_vs_File_Config() The file that tracks the event id of an eventlog config file (Eventlog_with_PlaceKeeper.txt) did not match what was stored in the registry on this machine. Config File was " + Settings_FilePath);
                File_Operation.DELETE_AND_CREATE_File(Settings.GET_EventLogID_PlaceHolder_Path);
                File_Operation.CREATE_NEW_Files_And_Dirs(Settings.Config_File_Location, Settings.AppConfigFile_FileName, File_Operation.GET_Default_ConsoleAppConfig_File_Contents);
            }
            else if (Settings.GET_SearchTermsFile_Path == Settings_FilePath)//Search SearchFile
            {
                if (CHECK_File_vs_Reg_Contents(Settings_FilePath, Reg_Operation.REG_KEY.SearchTerms_File_Contents) ==false)
                {
                    EventLog_SWELF.WRITE_FailureAudit_Error_To_EventLog("CHECK_Reg_vs_File_Config() The Search term file (Searchs.txt) config file did not match what was stored in the registry on this machine. Config File was " + Settings_FilePath);
                    File_Operation.DELETE_AND_CREATE_File(Settings.GET_SearchTermsFile_Path);
                    File_Operation.CREATE_NEW_Files_And_Dirs(Settings.Search_File_Location, Settings.SearchTermsFileName_FileName, File_Operation.GET_Default_Eventlog_with_PlaceKeeper_File_Contents);
                }
            }
            else if (Settings.GET_WhiteList_SearchTermsFile_Path == Settings_FilePath)//Search WHitelist
            {
                EventLog_SWELF.WRITE_FailureAudit_Error_To_EventLog("CHECK_Reg_vs_File_Config() The white list search terms file (WhiteList_Searchs.txt) did not match what was stored in the registry on this machine. Config File was " + Settings_FilePath);
                File_Operation.DELETE_AND_CREATE_File(Settings.GET_WhiteList_SearchTermsFile_Path);
                File_Operation.CREATE_NEW_Files_And_Dirs(Settings.Search_File_Location, Settings.Search_WhiteList_FileName, File_Operation.GET_Default_Whitelist_File_Contents);
            }
            else if (Settings.GET_SearchTermsFile_PLUGIN_Path == Settings_FilePath)//PLUGIN Search
            {
                EventLog_SWELF.WRITE_FailureAudit_Error_To_EventLog("CHECK_Reg_vs_File_Config() The Plugin config file (Search.txt in the Plugins Folder) did not match what was stored in the registry on this machine. Config File was " + Settings_FilePath);
                File_Operation.DELETE_AND_CREATE_File(Settings.GET_SearchTermsFile_PLUGIN_Path);
                File_Operation.CREATE_NEW_Files_And_Dirs(Settings.Plugin_Files_Location, Settings.SearchTermsFileName_FileName, File_Operation.GET_Default_Powershell_Plugins_File_Contents);
            }
            else if (Settings.GET_WhiteList_SearchTermsFile_PLUGIN_Path == Settings_FilePath)//PLugin WHitelist
            {
                EventLog_SWELF.WRITE_FailureAudit_Error_To_EventLog("CHECK_Reg_vs_File_Config() The Plugin config file (WhiteList_Searchs.txt in the Plugins Folder) did not match what was stored in the registry on this machine. Config File was " + Settings_FilePath);
                File_Operation.DELETE_AND_CREATE_File(Settings.GET_WhiteList_SearchTermsFile_PLUGIN_Path);
                File_Operation.CREATE_NEW_Files_And_Dirs(Settings.Plugin_Files_Location, Settings.Search_WhiteList_FileName, File_Operation.GET_Default_Whitelist_File_Contents);
            }
            else
            {
                LOG_SEC_CHECK_Fail("CHECK_Reg_vs_File_Config() File Path:" + Settings_FilePath + " did not match encrypted config file path");
            }
        }

        internal static bool CHECK_File_vs_Reg_Contents(string SettingsConfigFilePath,Reg_Operation.REG_KEY RegKey)
        {
            if (Crypto_Operation.Decrypt_File_Contents(SettingsConfigFilePath).ToLower()==Reg_Operation.READ_SWELF_Reg_Key(RegKey).ToLower())
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        /// <summary>
        /// Used for SEC_CHeck Fail logging outside of SEC_Check Class
        /// </summary>
        /// <param name="Msg"></param>
        internal static void LOG_SEC_CHECK_Fail(string Msg)
        {
            Error_Operation.Log_Error("SEC_Check_Failed()", Msg,"", Error_Operation.LogSeverity.Critical, Error_Operation.EventID.SWELF_FailureAudit);
        }
    }
}
