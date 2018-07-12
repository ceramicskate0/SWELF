using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.IO;
using System.Diagnostics;
using System.Security;
using System.Management.Automation;
using System.Management.Automation.Host;
using System.Management.Automation.Runspaces;
using System.Globalization;
using System.Collections.ObjectModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SWELF
{
    class Powershell_Plugin
    {
        public static List<string> HistoryOfCommandsRun = new List<string>();
        private static string powershellSciptLocation = "";
        private static string powershellSciptArgs = "";
        private static string CurrentWorkingDir = Directory.GetCurrentDirectory() + "\\";
        private static string Run_Plugin_BatchFile = CurrentWorkingDir + "SWELF_PS_Plugin.bat";
        public static string ScriptContents = "";

        [DllImport("amsi.dll", EntryPoint = "AmsiInitialize", CallingConvention = CallingConvention.StdCall)]
        public static extern int AmsiInitialize([MarshalAs(UnmanagedType.LPWStr)]string appName, out IntPtr amsiContext);

        [DllImport("amsi.dll", EntryPoint = "AmsiUninitialize", CallingConvention = CallingConvention.StdCall)]
        public static extern void AmsiUninitialize(IntPtr amsiContext);

        [DllImport("amsi.dll", EntryPoint = "AmsiOpenSession", CallingConvention = CallingConvention.StdCall)]
        public static extern int AmsiOpenSession(IntPtr amsiContext, out IntPtr session);

        [DllImport("amsi.dll", EntryPoint = "AmsiCloseSession", CallingConvention = CallingConvention.StdCall)]
        public static extern void AmsiCloseSession(IntPtr amsiContext, IntPtr session);

        [DllImport("amsi.dll", EntryPoint = "AmsiScanString", CallingConvention = CallingConvention.StdCall)]
        public static extern int AmsiScanString(IntPtr amsiContext, [InAttribute()] [MarshalAsAttribute(UnmanagedType.LPWStr)]string @string, [InAttribute()] [MarshalAsAttribute(UnmanagedType.LPWStr)]string contentName, IntPtr session, out AMSI_RESULT result);

        [DllImport("amsi.dll", EntryPoint = "AmsiScanBuffer", CallingConvention = CallingConvention.StdCall)]
        public static extern int AmsiScanBuffer(IntPtr amsiContext, [In] [MarshalAs(UnmanagedType.LPArray)] byte[] buffer, ulong length, [In()] [MarshalAs(UnmanagedType.LPWStr)] string contentName, IntPtr session, out AMSI_RESULT result);

        [DllImport("amsi.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        public static extern bool AmsiResultIsMalware(AMSI_RESULT result);

        public enum AMSI_RESULT
        {
            AMSI_RESULT_CLEAN = 0,
            AMSI_RESULT_NOT_DETECTED = 1,
            AMSI_RESULT_DETECTED = 32768
        }

        public static string Run_PS_Script(String PowershellSciptLocation, string PowershellSciptArgs = "")
        {
            if (CallAntimalwareScanInterface(GetMD5(PowershellSciptLocation), ScriptContents) != 32768)
            {
                powershellSciptLocation = PowershellSciptLocation;
                powershellSciptArgs = PowershellSciptArgs;

                WriteBatchFile(PSScript1LinerArg());
                ProcessStartInfo startInfo = new ProcessStartInfo("powershell", ".\\"+ Path.GetFileName(PowershellSciptLocation));
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
                Errors.Log_Error("MALWARE DETECTED", "Script located at " + powershellSciptLocation + " MD5=" + GetMD5(PowershellSciptLocation) + ". Script is Malware according to AMSI. Script Base64 Contents = " + Base64Encode(ScriptContents),Errors.LogSeverity.Critical);
                return ("MALWARE DETECTED - Script located at " + powershellSciptLocation + " MD5=" + GetMD5(PowershellSciptLocation) + ". Script is Malware according to AMSI. Script Base64 Contents = " + Base64Encode(ScriptContents));
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

        private static string GetMD5(string PowershellSciptLocation)
        {
            using (var md5 = MD5.Create())
            {
                using (var stream = File.OpenRead(PowershellSciptLocation))
                {
                    return md5.ComputeHash(stream).ToString();
                }
            }
        }

        private static int CallAntimalwareScanInterface(string PluginName, string PluginContents)
        {
            IntPtr amsiContext;
            IntPtr session;
            AMSI_RESULT result = 0;
            int returnValue;

            returnValue = AmsiInitialize(PluginName, out amsiContext);
            returnValue = AmsiOpenSession(amsiContext, out session);
            returnValue = AmsiScanString(amsiContext, PluginContents, PluginName, session, out result);
            AmsiCloseSession(amsiContext, session);
            AmsiUninitialize(amsiContext);
            return returnValue;
        }

        public static string Base64Encode(string plainText)
        {
            byte[] plainTextBytes = System.Text.Encoding.ASCII.GetBytes(plainText.ToCharArray());
            return System.Convert.ToBase64String(plainTextBytes, Base64FormattingOptions.None);
        }

        private static void WriteBatchFile(string cmdToWrite)
        {
            try
            {
                if (Settings.VERIFY_if_File_Exists(Run_Plugin_BatchFile))
                {
                    File.Delete(Run_Plugin_BatchFile);
                }
                File.Create(Run_Plugin_BatchFile).Close();
                File.WriteAllText(Run_Plugin_BatchFile, cmdToWrite);
            }
            catch (Exception e)
            {
                Errors.Log_Error("WriteBatchFile()", e.Message.ToString(),Errors.LogSeverity.Warning);
            }
        }
    }
}
