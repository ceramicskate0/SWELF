using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace SWELF
{
    //SWELF KEYS SYSTEM:
    //HKLM/Software/SWELF
    //             Persist Sub Key,Value
    class Reg
    {
        private static RegistryKey SWELF_KEY = Microsoft.Win32.Registry.LocalMachine.CreateSubKey("Software\\SWELF");
        public static string Windows_Reg_For_EventLogs = @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\";

        public static Dictionary<string, string> Reg_Keys_and_Values = new Dictionary<string, string>();

        private static string[] SWELF_Keys =
        {"First_Run", "Encryption", "logging_level", "output_format",
            "SWELF_Current_Version","SWELF_CWD","SWELF_FAILED_SEC_CHECK",
            "central_app_config","central_plugin_search_config","central_search_config","central_whitelist_search_config",
            "LogCollecter_1","LogCollecter_2","LogCollecter_3","LogCollecter_4","LogCollecter_5","LogCollecter" };

        //REG Entrys
        //Keys,Values
        //location:Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\SWELF
        //-------------------
        //First_Run,(Bool) {Has app run before}
        //LogCollecter_(#), Hostname {Where SWELF was told to send logs from config file. If diffrent log and send to both}
        //Central_Config_(name), url {Where SWELF was told to get central config from config file.}
        //Encryption,numbers {SWELF Local config decrypt numbers}
        //logging_level,value {SWELF Error logging levels}
        //output_format,value 
        //SWELF_Current_Version,value {Current SWELF.exe file version}(to be used in update process)
        //SWELF_CWD,File Path {SWELF Current working dir}
        //SWELF_FAILED_SEC_CHECK,(bool) {Log if SWELF failed last sec check}

        public enum REG_KEY : int
        {
            First_Run =0,
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
            LogCollecter = 16
        };

        public Reg()
        {

        }

        public static void ADD_or_CHANGE_Non_SWELF_Reg_Key(string Key, string Value)
        {
            SWELF_KEY.SetValue(Key, Value);
        }

        public static bool CHECK_Non_SWELF_Reg_Key_Exists(string Key)
        {
            try
            {
                if (String.IsNullOrEmpty(Key) == false)
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

        public static string READ_Non_SWELF_Reg_Key(string Key)
        {
            if (CHECK_Non_SWELF_Reg_Key_Exists(Key))
            {
                return SWELF_KEY.GetValue(Key).ToString();
            }
            else
            {
                Errors.Log_Error("CHANGE_Reg_Key()", "Reg Key does not exist. RegKey=" + Key, Errors.LogSeverity.Warning);
                return "";
            }
        }

        //Below are SWELF App Reg entries
        public static bool CHECK_SWELF_Reg_Key_Exists(REG_KEY Key)
        {
            try
            {
                if (String.IsNullOrEmpty(SWELF_KEY.GetValue(SWELF_Keys[(int)Key]).ToString())==false)
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

        public static bool CHECK_SWELF_Reg_Key_Exists(string Key)
        {
            try
            {
                if (String.IsNullOrEmpty(SWELF_KEY.GetValue(Key).ToString()) == false)
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

        public static void ADD_or_CHANGE_SWELF_Reg_Key(REG_KEY Key, string Value)
        {
           SWELF_KEY.SetValue(SWELF_Keys[(int)Key], Value);
        }

        public static void ADD_or_CHANGE_SWELF_Reg_Key(string Key, string Value)
        {
           SWELF_KEY.SetValue(Key, Value);
        }

        public static void CHANGE_SWELF_Reg_Key(REG_KEY Key, string Value)
        {
            if (CHECK_SWELF_Reg_Key_Exists(Key))
            {
                SWELF_KEY.SetValue(SWELF_Keys[(int)Key], Value);
            }
            else
            {
                Errors.Log_Error("CHANGE_Reg_Key()", "Reg Key does not exist. RegKey=" + Key + "," + Value, Errors.LogSeverity.Warning);
            }
        }

        public static string READ_SWELF_Reg_Key(REG_KEY Key)
        {
            if (CHECK_SWELF_Reg_Key_Exists(Key))
            {
                return SWELF_KEY.GetValue(SWELF_Keys[(int)Key]).ToString();
            }
            else
            {
                Errors.Log_Error("CHANGE_Reg_Key()", "Reg Key does not exist. RegKey=" + Key, Errors.LogSeverity.Warning);
                return "";
            }
        }

        public static string READ_SWELF_Reg_Key(string Key)
        {
            if (CHECK_SWELF_Reg_Key_Exists(Key))
            {
                return SWELF_KEY.GetValue(Key).ToString();
            }
            else
            {
                Errors.Log_Error("CHANGE_Reg_Key()", "Reg Key does not exist. RegKey=" + Key, Errors.LogSeverity.Warning);
                return "";
            }
        }

        public static void WRITE_Default_SWELF_Reg_Keys()
        {
            Microsoft.Win32.RegistryKey key;
            key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey("Software\\SWELF");
            SWELF_KEY.SetValue("first_run", false);
            SWELF_KEY.SetValue("log_collecter", "127.0.0.1");
            SWELF_KEY.SetValue("encryption", Encryptions.Generate_Decrypt());
            SWELF_KEY.SetValue("logging_level", Settings.Logging_Level_To_Report);
            SWELF_KEY.SetValue("output_format", Settings.AppConfig_File_Args["output_format"]);
            SWELF_KEY.SetValue("SWELF_Current_Version", Settings.SWELF_Version);
            SWELF_KEY.SetValue("SWELF_CWD", Settings.SWELF_CWD);
            SWELF_KEY.SetValue("SWELF_FAILED_SEC_CHECK", false);

            SWELF_KEY.SetValue("central_app_config", "");
            SWELF_KEY.SetValue("central_plugin_search_config", "");
            SWELF_KEY.SetValue("central_search_config", "");
            SWELF_KEY.SetValue("central_whitelist_search_config", "");

        }

        public static void READ_All_SWELF_Reg_Keys()
        {
            string[] KeyName = SWELF_KEY.GetValueNames();

            for (int x = 0; x < SWELF_KEY.ValueCount; ++x)
            {
                Reg_Keys_and_Values.Add(KeyName[x], SWELF_KEY.GetValue(KeyName[x]).ToString());
            }
        }
    }
}
