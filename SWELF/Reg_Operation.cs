//Written by Ceramicskate0
//Copyright
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Text;
using Microsoft.Win32;

namespace SWELF
{
    //SWELF KEYS SYSTEM:
    //HKLM/Software/SWELF
    //Persist Sub Key,Value
    internal class Reg_Operation
    {
        private static RegistryKey BASE_SWELF_KEY = Registry.LocalMachine.CreateSubKey("Software\\SWELF");
        internal static RegistryKey EventLog_Base_Key = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\Eventlog\\");

        private static long Default_Size = EventLogSession.GlobalSession.GetLogInformation("security", PathType.LogName).FileSize.Value;

        private static string[] SWELF_Keys =
        {"First_Run", "Encryption",Settings.SWELF_AppConfig_Args[17], Settings.SWELF_AppConfig_Args[10],
            "SWELF_Current_Version","SWELF_CWD","SWELF_FAILED_SEC_CHECK",
             Settings.SWELF_AppConfig_Args[7],Settings.SWELF_AppConfig_Args[8],Settings.SWELF_AppConfig_Args[6], Settings.SWELF_AppConfig_Args[9],
            Settings.SWELF_AppConfig_Args[1],Settings.SWELF_AppConfig_Args[2],Settings.SWELF_AppConfig_Args[3],Settings.SWELF_AppConfig_Args[4],Settings.SWELF_AppConfig_Args[5],Settings.SWELF_AppConfig_Args[0],
            "ConsoleAppConfig_CreationDate","ConsoleAppConfig_Contents","SearchTerms_File_Contents","Logs_Last_Sent"};

        internal enum REG_KEY : int
        {
            First_Run = 0,
            Encryption = 1,
            logging_level = 2,
            output_format = 3,
            SWELF_Current_Version = 4,
            SWELF_CWD = 5,
            SWELF_FAILED_SEC_CHECK = 6,
            central_app_config = 7,
            central_plugin_search_config = 8,
            central_search_config = 9,
            central_whitelist_search_config = 10,
            LogCollecter_1 = 11,
            LogCollecter_2 = 12,
            LogCollecter_3 = 13,
            LogCollecter_4 = 14,
            LogCollecter_5 = 15,
            LogCollecter = 16,
            ConsoleAppConfig_CreationDate = 17,
            ConsoleAppConfig_Contents = 18,
            SearchTerms_File_Contents = 19,
            Logs_Last_Sent=20
        };

        internal static bool CHECK_Eventlog_SWELF_Reg_Key_Exists(string Key)
        {
            try
            {
                if (BASE_SWELF_KEY.GetValue(Key)!=null)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch (Exception e)
            {
                return false;
            }
        }

        internal static bool CHECK_SWELF_Reg_Key_Exists(REG_KEY Key)
        {
            try
            {
                if (Settings.REG_Keys.Count > 1)
                {
                    if (Settings.REG_Keys.ContainsKey(SWELF_Keys[(int)Key].ToString()))
                    {
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }
                else
                {
                    if (String.IsNullOrEmpty(BASE_SWELF_KEY.GetValue(SWELF_Keys[(int)Key]).ToString()) == false)
                    {
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }
            }
            catch (Exception e)
            {
                return false;
            }
        }

        internal static bool CHECK_SWELF_Reg_Key_Exists(string Key)
        {
            try
            {
                if (Settings.REG_Keys.Count > 1)
                {
                    if (Settings.REG_Keys.ContainsKey(Key))
                    {
                        return true;
                    }
                    else
                    {
                        if (String.IsNullOrEmpty(BASE_SWELF_KEY.GetValue(Key).ToString()) == false)
                        {
                            return true;
                        }
                        else
                        {
                            return false;
                        }
                    }
                }
                else
                {
                    if (String.IsNullOrEmpty(BASE_SWELF_KEY.GetValue(Key).ToString()) == false)
                    {
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }
            }
            catch (Exception e)
            {
                try
                {
                    if (String.IsNullOrEmpty(BASE_SWELF_KEY.GetValue(Key).ToString()) == false)
                    {
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }
                catch
                {
                    return false;
                }
            }
        }

        internal static void ADD_or_CHANGE_SWELF_Reg_Key(REG_KEY Key, string Value)
        {
           BASE_SWELF_KEY.SetValue(SWELF_Keys[(int)Key], Crypto_Operation.Protect_Data_Value(Value));
        }

        internal static void ADD_or_CHANGE_SWELF_Reg_Key(string Key, string Value)
        {
           BASE_SWELF_KEY.SetValue(Key, Crypto_Operation.Protect_Data_Value(Value));
        }

        internal static void ADD_or_CHANGE_Non_SWELF_Reg_Key(string Key, object Value)
        {
            BASE_SWELF_KEY.SetValue(Key, Value);
        }

        private static string READ_SWELF_Reg_Key(string Key)
        {
            try
            {
                if (CHECK_SWELF_Reg_Key_Exists(Key))
                {
                    if (Crypto_Operation.CHECK_Value_Encrypted(Crypto_Operation.ObjectToByteArray(BASE_SWELF_KEY.GetValue(Key))))
                    {
                        try
                        {
                            string thing = Crypto_Operation.UnProtect_Data_Value((byte[])BASE_SWELF_KEY.GetValue(Key));
                            return thing;
                        }
                        catch (Exception e)
                        {
                            if (e.Message.Contains("Unable to cast object of type 'System.String' to type 'System.Byte[]'."))
                            {
                                ADD_or_CHANGE_SWELF_Reg_Key(Key, (string)BASE_SWELF_KEY.GetValue(Key));
                            }
                            try
                            {
                                string thing = Crypto_Operation.UnProtect_Data_Value((byte[])BASE_SWELF_KEY.GetValue(Key));
                                return thing;
                            }
                            catch (Exception ex)
                            {
                                return "";
                            }
                        }
                    }
                    else
                    {
                        string thing2 = Crypto_Operation.UnProtect_Data_Value((byte[])BASE_SWELF_KEY.GetValue(Key));
                        return thing2;
                    }
                }
                else
                {
                    return "";
                }
            }
            catch (Exception e)
            {
                return "";
            }
        }

        internal static string READ_SWELF_Reg_Key(REG_KEY Key, bool Log_Error = true)
        {
            try
            {
                if (Settings.REG_Keys.Count > 1)
                {
                    if (Settings.REG_Keys.ContainsKey(SWELF_Keys[(int)Key].ToString()))
                    {
                        return Settings.REG_Keys[SWELF_Keys[(int)Key]].ToString();
                    }
                    else
                    {
                        return "";
                    }
                }
                else
                {
                    if (CHECK_SWELF_Reg_Key_Exists(Key))
                    {
                        if (Crypto_Operation.CHECK_Value_Encrypted(Crypto_Operation.ObjectToByteArray(BASE_SWELF_KEY.GetValue(SWELF_Keys[(int)Key]))))
                        {
                            try
                            {
                                string thing = Crypto_Operation.UnProtect_Data_Value((byte[])BASE_SWELF_KEY.GetValue(SWELF_Keys[(int)Key]));
                                return thing;
                            }
                            catch (Exception e)
                            {
                                ADD_or_CHANGE_SWELF_Reg_Key(Key, SWELF_Keys[(int)Key]);
                                string thing = Crypto_Operation.UnProtect_Data_Value((byte[])BASE_SWELF_KEY.GetValue(SWELF_Keys[(int)Key]));
                                return thing;
                            }
                        }
                        else
                        {
                            ADD_or_CHANGE_SWELF_Reg_Key(Key, Crypto_Operation.CONVERT_To_String_From_Bytes(Crypto_Operation.Protect_Data_Value(SWELF_Keys[(int)Key].ToString()), 1));
                            string thing = Crypto_Operation.UnProtect_Data_Value((byte[])BASE_SWELF_KEY.GetValue(SWELF_Keys[(int)Key]));
                            return thing;
                        }
                    }
                    else
                    {
                        return "";
                    }
                }
            }
            catch
            {
                try
                {
                    if (CHECK_SWELF_Reg_Key_Exists(Key))
                    {
                        if (Crypto_Operation.CHECK_Value_Encrypted(Crypto_Operation.ObjectToByteArray(BASE_SWELF_KEY.GetValue(SWELF_Keys[(int)Key]))))
                        {
                            try
                            {
                                string thing = Crypto_Operation.UnProtect_Data_Value((byte[])BASE_SWELF_KEY.GetValue(SWELF_Keys[(int)Key]));
                                return thing;
                            }
                            catch (Exception e)
                            {
                                ADD_or_CHANGE_SWELF_Reg_Key(Key, SWELF_Keys[(int)Key]);
                                string thing = Crypto_Operation.UnProtect_Data_Value((byte[])BASE_SWELF_KEY.GetValue(SWELF_Keys[(int)Key]));
                                return thing;
                            }
                        }
                        else
                        {
                            ADD_or_CHANGE_SWELF_Reg_Key(Key, Crypto_Operation.CONVERT_To_String_From_Bytes(Crypto_Operation.Protect_Data_Value(SWELF_Keys[(int)Key].ToString()), 1));
                            string thing = Crypto_Operation.UnProtect_Data_Value((byte[])BASE_SWELF_KEY.GetValue(SWELF_Keys[(int)Key]));
                            return thing;
                        }
                    }
                    else
                    {
                        if (Log_Error)
                        {
                            Error_Operation.Log_Error("CHANGE_Reg_Key()", "Reg Key does not exist. RegKey=" + Key, Error_Operation.LogSeverity.Warning);
                        }
                        return "";
                    }
                }
                catch (Exception e)
                {
                    if (Log_Error)
                    {
                        Error_Operation.Log_Error("CHANGE_Reg_Key()", "Reg Key does not exist. RegKey=" + Key + ". " + e.Message.ToString(), Error_Operation.LogSeverity.Warning);
                    }
                    return "";
                }
            }
        }

        internal static object READ_Eventlog_SWELF_Reg_Key(string Key)
        {
            if (Settings.REG_Keys.Count > 1)
            {
                if (Settings.REG_Keys.ContainsKey(Key))
                {
                    return Settings.REG_Keys[Key];
                }
            }
            else
            {
                if (CHECK_Eventlog_SWELF_Reg_Key_Exists(Key))
                {
                    if (Crypto_Operation.CHECK_Value_Encrypted(Crypto_Operation.ObjectToByteArray(BASE_SWELF_KEY.GetValue(Key))))
                    {
                        return Crypto_Operation.UnProtect_Data_Value(Crypto_Operation.ObjectToByteArray(BASE_SWELF_KEY.GetValue(Key)));
                    }
                    else
                    {
                        ADD_or_CHANGE_SWELF_Reg_Key(Key, Crypto_Operation.CONVERT_To_String_From_Bytes(Crypto_Operation.Protect_Data_Value(Crypto_Operation.ObjectToByteArray(BASE_SWELF_KEY.GetValue(Key))), 1));
                        return Crypto_Operation.UnProtect_Data_Value(Crypto_Operation.ObjectToByteArray(BASE_SWELF_KEY.GetValue(Key)));
                    }
                }
                else
                {
                    Error_Operation.Log_Error("CHANGE_Reg_Key()", "Reg Key does not exist. RegKey=" + Key, Error_Operation.LogSeverity.Warning);
                    return "";
                }
            }
            return "";
        }

        internal static void READ_ALL_SWELF_Reg_Keys()
        {
            foreach (string sub in BASE_SWELF_KEY.GetValueNames())
            {
                try
                {
                    if (String.IsNullOrEmpty(BASE_SWELF_KEY.GetValue(sub).ToString()) == false)
                    {
                        Settings.REG_Keys.Add(sub, READ_SWELF_Reg_Key(sub));
                    }
                }
                catch (Exception e)
                {
                    //catch error
                }
            }

            if (CHECK_SWELF_Reg_Key_Exists(REG_KEY.Logs_Last_Sent)==false)
            {
                string Date = DateTime.Now.ToString();
                BASE_SWELF_KEY.SetValue(SWELF_Keys[(int)REG_KEY.Logs_Last_Sent], Crypto_Operation.Protect_Data_Value(Date));
                Settings.REG_Keys.Add(SWELF_Keys[20], Date);
            }
        }

        internal static void DELETE_SWELF_Reg_Key(REG_KEY Key)
        {
            BASE_SWELF_KEY.DeleteValue(SWELF_Keys[(int)Key]);
        }

        internal static void WRITE_Default_SWELF_Reg_Keys()
        {
            Microsoft.Win32.RegistryKey key;
            key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey("Software\\SWELF");
            BASE_SWELF_KEY.SetValue(SWELF_Keys[(int)REG_KEY.First_Run].ToString(), Crypto_Operation.Protect_Data_Value("true"));
            BASE_SWELF_KEY.SetValue(SWELF_Keys[(int)REG_KEY.LogCollecter].ToString(), Crypto_Operation.Protect_Data_Value("127.0.0.1"));
            //BASE_SWELF_KEY.SetValue(SWELF_Keys[(int)REG_KEY.LogCollecter_1].ToString(), Encryptions.Protect_Data_Value("127.0.0.1"));
            //BASE_SWELF_KEY.SetValue(SWELF_Keys[(int)REG_KEY.LogCollecter_2].ToString(), Encryptions.Protect_Data_Value("127.0.0.1"));
            //BASE_SWELF_KEY.SetValue(SWELF_Keys[(int)REG_KEY.LogCollecter_3].ToString(), Encryptions.Protect_Data_Value("127.0.0.1"));
            //BASE_SWELF_KEY.SetValue(SWELF_Keys[(int)REG_KEY.LogCollecter_4].ToString(), Encryptions.Protect_Data_Value("127.0.0.1"));
            //BASE_SWELF_KEY.SetValue(SWELF_Keys[(int)REG_KEY.LogCollecter_5].ToString(), Encryptions.Protect_Data_Value("127.0.0.1"));
            BASE_SWELF_KEY.SetValue(SWELF_Keys[(int)REG_KEY.Encryption].ToString(), Crypto_Operation.Protect_Data_Value(Crypto_Operation.Generate_Decrypt()));
            BASE_SWELF_KEY.SetValue(SWELF_Keys[(int)REG_KEY.logging_level].ToString(), Crypto_Operation.Protect_Data_Value(Settings.Logging_Level_To_Report));
            BASE_SWELF_KEY.SetValue(SWELF_Keys[(int)REG_KEY.output_format].ToString(), Crypto_Operation.Protect_Data_Value("keyvalue"));
            BASE_SWELF_KEY.SetValue(SWELF_Keys[(int)REG_KEY.SWELF_Current_Version].ToString(), Crypto_Operation.Protect_Data_Value(Settings.SWELF_Version));
            BASE_SWELF_KEY.SetValue(SWELF_Keys[(int)REG_KEY.SWELF_CWD].ToString(), Crypto_Operation.Protect_Data_Value(Settings.SWELF_CWD));
            BASE_SWELF_KEY.SetValue(SWELF_Keys[(int)REG_KEY.SWELF_FAILED_SEC_CHECK].ToString(), Crypto_Operation.Protect_Data_Value("false"));
            BASE_SWELF_KEY.SetValue(SWELF_Keys[(int)REG_KEY.central_app_config].ToString(), Crypto_Operation.Protect_Data_Value(""));
            BASE_SWELF_KEY.SetValue(SWELF_Keys[(int)REG_KEY.central_plugin_search_config].ToString(), Crypto_Operation.Protect_Data_Value(""));
            BASE_SWELF_KEY.SetValue(SWELF_Keys[(int)REG_KEY.central_search_config].ToString(), Crypto_Operation.Protect_Data_Value(""));
            BASE_SWELF_KEY.SetValue(SWELF_Keys[(int)REG_KEY.central_whitelist_search_config].ToString(),Crypto_Operation.Protect_Data_Value(""));
            BASE_SWELF_KEY.SetValue(SWELF_Keys[(int)REG_KEY.ConsoleAppConfig_CreationDate].ToString(), Crypto_Operation.Protect_Data_Value(File_Operation.GET_CreationTime(Settings.GET_AppConfigFile_Path)));
            BASE_SWELF_KEY.SetValue(SWELF_Keys[(int)REG_KEY.ConsoleAppConfig_Contents], Crypto_Operation.Protect_Data_Value(File_Operation.READ_AllText(Settings.GET_AppConfigFile_Path)));
            BASE_SWELF_KEY.SetValue(SWELF_Keys[(int)REG_KEY.SearchTerms_File_Contents], Crypto_Operation.Protect_Data_Value(File_Operation.READ_AllText(Settings.GET_SearchTermsFile_Path)));
            BASE_SWELF_KEY.SetValue(SWELF_Keys[(int)REG_KEY.Logs_Last_Sent], Crypto_Operation.Protect_Data_Value(DateTime.Now.ToString()));
        }

        internal static void SET_Event_Log_MaxSize(string LogName, long Size = 0)
        {
            if (Size == 0)
            {
                Size = Default_Size;
            }
            RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Eventlog\" + LogName, true);
            if (key == null)
            {
                Error_Operation.Log_Error("SET_Event_Log_MaxSize(string LogName)", "Registry key for this Event Log does not exist.", Error_Operation.LogSeverity.Warning);
            }
            else
            {
                key.SetValue("MaxSize", Convert.ToInt32(Size));
                Registry.LocalMachine.Close();
            }
        }

        internal static bool Compare_Values(REG_KEY Key, string File_Contents)
        {
            if (READ_SWELF_Reg_Key(Key,false).ToLower()== File_Contents.ToLower())
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        internal static bool Compare_Central_Config_To_File(REG_KEY Key, string Local_Config_File_Path)
        {
            if (Web_Operation.VERIFY_Central_File_Config_Hash(READ_SWELF_Reg_Key(Key, false), Local_Config_File_Path))
            {
                return true;
            }
            else
            {
                return false;
            }

        }
    }
    }
