using System;
using System.Collections.Generic;
using System.IO;
using System.Diagnostics;
using System.Security.Cryptography;


namespace SWELF
{
    class Powershell_Plugin
    {
        public static List<string> HistoryOfCommandsRun = new List<string>();
        private static string powershellSciptLocation = "";
        private static string powershellSciptArgs = "";
        private static string CurrentWorkingDir = Directory.GetCurrentDirectory() + "\\";
        public static string ScriptContents = "";

        public static string Run_PS_Script(String PowershellSciptLocation, string PowershellSciptArgs = "")
        {
            ScriptContents = File.ReadAllText(PowershellSciptLocation);
            
            if (CallAntimalwareScanInterface(Get_SHA256(PowershellSciptLocation), ScriptContents) <= 32768)
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
                    output += "\nERROR: " + process.StandardError.ReadToEnd();
                }
                Settings.WhiteList_Search_Terms_Unparsed.Add(ScriptContents+"~"+ "microsoft-windows-powershell/operational"+"~");
                Settings.WhiteList_Search_Terms_Unparsed.Add(ScriptContents + "~" + "windows powershell" + "~");
                return output;
            }
            else
            {
                Errors.Log_Error("POSSIBLE MALWARE DETECTED", "Script located at " + powershellSciptLocation + " SHA256=" + Get_SHA256(PowershellSciptLocation) + ". Script is Malware according to AMSI. Script Base64 Contents = " + Base64Encode(ScriptContents),Errors.LogSeverity.Critical);
                return ("POSSIBLE MALWARE DETECTED - Script located at " + powershellSciptLocation + " SHA256=" + Get_SHA256(PowershellSciptLocation) + ". Script is Malware according to AMSI. Script Base64 Contents = " + Base64Encode(ScriptContents));
            }
        }

        //public static string Run_PSless_Script(string PowershellSciptLocation, string PowershellSciptArgs = "")
        //{
        //    string output;
        //    ScriptContents = File.ReadAllText(PowershellSciptLocation);
        //    RunspaceConfiguration rspacecfg = RunspaceConfiguration.Create();
        //    Runspace rspace = RunspaceFactory.CreateRunspace(rspacecfg);
        //    rspace.Open();
        //    Pipeline pipeline = rspace.CreatePipeline();
        //    pipeline.Commands.AddScript(ScriptContents);
        //    Collection<PSObject> results = pipeline.Invoke();
        //    using (StringWriter sw = new StringWriter())
        //    {
        //        foreach (PSObject invoke in results)
        //            sw.WriteLine(invoke.ToString());

        //        output = sw.ToString();
        //    }
        //    return output;
        //}

        private static string PSScript1LinerArg()
        {
            if (!string.IsNullOrEmpty(powershellSciptArgs))
            {
                return "'" + powershellSciptLocation + "' " + ""+powershellSciptArgs+"";
            }
            else
            {
                return "" + powershellSciptLocation + "";
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
           // AMSI_RESULT_MALWARE_DETECTED = 32768
            returnValue = AMSI.AmsiInitialize(PluginName, out amsiContext);
            returnValue = AMSI.AmsiOpenSession(amsiContext, out session);
            returnValue = AMSI.AmsiScanString(amsiContext, PluginContents, PluginName, session, out result);
            AMSI.AmsiCloseSession(amsiContext, session);
            AMSI.AmsiUninitialize(amsiContext);
            return returnValue;
        }

        public static string Base64Encode(string plainText)
        {
            byte[] plainTextBytes = System.Text.Encoding.ASCII.GetBytes(plainText.ToCharArray());
            return System.Convert.ToBase64String(plainTextBytes, Base64FormattingOptions.None);
        }
    }
}
