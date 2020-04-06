//Written by Ceramicskate0
//Copyright 2020
using System;
using System.Collections.Generic;
using System.IO;
using System.Diagnostics;
using System.Security.Cryptography;


namespace SWELF
{
    internal static class Powershell_Plugin
    {
        internal static List<string> HistoryOfCommandsRun = new List<string>();
        private static string powershellSciptLocation = "";
        private static string powershellSciptArgs = "";
        internal static string ScriptContents = "";

        internal static string Run_PS_Script(String PowershellSciptLocation, string PowershellSciptArgs = "")
        {
            if (File_Operation.CHECK_if_File_Exists(PowershellSciptLocation))
            {
                ScriptContents = File_Operation.READ_AllText(PowershellSciptLocation);

                if (CallAntimalwareScanInterface(Get_SHA256(PowershellSciptLocation), ScriptContents) < 32768)
                {
                    powershellSciptLocation = PowershellSciptLocation;
                    powershellSciptArgs = PowershellSciptArgs;

                    ProcessStartInfo startInfo = new ProcessStartInfo("powershell", "-ExecutionPolicy Bypass .\\" + Path.GetFileName(PowershellSciptLocation));
                    startInfo.WorkingDirectory = Path.GetDirectoryName(PowershellSciptLocation);
                    startInfo.RedirectStandardOutput = true;
                    startInfo.RedirectStandardError = true;
                    startInfo.LoadUserProfile = true;
                    startInfo.UseShellExecute = false;
                    startInfo.CreateNoWindow = true;
                    Process process = new Process();
                    process.StartInfo = startInfo;
                    process.Start();
                    string output = process.StandardOutput.ReadToEnd();
                    if (string.IsNullOrEmpty(output))
                    {
                        output += "\nPS Plugin ERROR: " + process.StandardError.ReadToEnd();
                    }
                    if (string.IsNullOrEmpty(ScriptContents) == false || string.IsNullOrWhiteSpace(ScriptContents) == false)
                    {
                        Settings.WhiteList_Search_Terms_Unparsed.Add(ScriptContents + "~" + "microsoft-windows-powershell/operational" + "~");
                        Settings.WhiteList_Search_Terms_Unparsed.Add(ScriptContents + "~" + "windows powershell" + "~");
                    }
                    return output;
                }
                else
                {
                    Error_Operation.Log_Error("Run_PS_Script() POSSIBLE MALWARE DETECTED", "Script located at " + powershellSciptLocation + " SHA256=" + Get_SHA256(PowershellSciptLocation) + ". Script is Malware according to AMSI. SWELF converted the contents to Base64 1 time for the purpose of the log size. Malware Script Contents = " + Base64Encode(ScriptContents),"", Error_Operation.LogSeverity.Critical);
                    return ("POSSIBLE MALWARE DETECTED - Script located at " + powershellSciptLocation + " SHA256=" + Get_SHA256(PowershellSciptLocation) + ". Script is Malware according to AMSI. SWELF converted the contents to Base64 1 time for the purpose of the log size. Malware Script Contents = " + Base64Encode(ScriptContents));
                }
            }
            else
            {
                Error_Operation.Log_Error("Run_PS_Script()",PowershellSciptLocation + " is not a valid file on " + Settings.ComputerName, "", Error_Operation.LogSeverity.Warning);
                return (PowershellSciptLocation + " is not a valid file on " + Settings.ComputerName);
            }
        }

        private static string Get_SHA256(string PowershellSciptLocation)
        {
            using (var sha256 = SHA256.Create())
            {
                using (var stream = File.OpenRead(PowershellSciptLocation))
                {
                    return sha256.ComputeHash(stream).ToString();
                }
            }
        }

        private static int CallAntimalwareScanInterface(string PluginName, string PluginContents)
        {
            IntPtr amsiContext;
            IntPtr session;
            AMSI_RESULT result = 0;
            int returnValue;
            //AMSI_RESULT_CLEAN = 0,
            //AMSI_RESULT_NOT_DETECTED = 1,
            //AMSI_RESULT_MALWARE_DETECTED = 32768
            returnValue = AMSI.AmsiInitialize(PluginName, out amsiContext);
            returnValue = AMSI.AmsiOpenSession(amsiContext, out session);
            returnValue = AMSI.AmsiScanString(amsiContext, PluginContents, PluginName, session, out result);
            AMSI.AmsiCloseSession(amsiContext, session);
            AMSI.AmsiUninitialize(amsiContext);
            return returnValue;
        }

        internal static string Base64Encode(string plainText)
        {
            byte[] plainTextBytes = Crypto_Operation.CONVERT_To_ASCII_Bytes(plainText.ToCharArray().ToString());
            return System.Convert.ToBase64String(plainTextBytes, Base64FormattingOptions.None);
        }
    }
}
