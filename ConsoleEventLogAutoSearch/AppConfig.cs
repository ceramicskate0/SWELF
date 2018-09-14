using System;
using System.Configuration;


namespace SWELF
{
    class AppConfig
    {
        public static void Read_All_App_Config_Settings()
        {
            try
            {
                var appSettings = ConfigurationManager.AppSettings;

                if (appSettings.Count == 0)
                {
                    Errors.Log_Error("Read_All_App_Config_Settings() appSettings.Count == 0", "Appconfig had not keys. This means bad things.", Errors.LogSeverity.FailureAudit);
                    EventLog_SWELF.WRITE_Critical_EventLog("Read_All_App_Config_Settings() appSettings.Count == 0 : " + "Appconfig had not keys. This means bad things.");
                }
                else
                {
                    foreach (var key in appSettings.AllKeys)
                    {
                        Settings.AppConfig_App_Args.Add(key, appSettings[key]);
                    }
                }
            }
            catch (ConfigurationErrorsException e)
            {
                Errors.Log_Error("Read_All_App_Config_Settings() ConfigurationErrorsException", e.Message.ToString(), Errors.LogSeverity.Warning);
            }
        }

        public static string GET_App_Config_Setting(string key)
        {
            try
            {
                var appSettings = ConfigurationManager.AppSettings;
                return appSettings[key] ?? "Not Found";
            }
            catch (ConfigurationErrorsException)
            {
                return "Not Found";
            }
        }

        public static void ADD_UPDATE_App_Config_Setting(string key, string value)
        {
            try
            {
                var configFile = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
                var settings = configFile.AppSettings.Settings;
                if (settings[key] == null)
                {
                    settings.Add(key, value);
                }
                else
                {
                    settings[key].Value = value;
                }
                configFile.Save(ConfigurationSaveMode.Modified);
                ConfigurationManager.RefreshSection(configFile.AppSettings.SectionInformation.Name);
            }
            catch (ConfigurationErrorsException e)
            {
                Errors.Log_Error("ADD_UPDATE_App_Config_Setting() ConfigurationErrorsException", e.Message.ToString(), Errors.LogSeverity.Warning);
            }
        }
    }
}
