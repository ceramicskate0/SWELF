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

namespace SWELF
{
    internal class Powershell_Plugin
    {
        public static List<string> HistoryOfCommandsRun = new List<string>();
        private static string powershellSciptLocation = "";
        private static string powershellSciptArgs = "";
        private static string CurrentWorkingDir = Directory.GetCurrentDirectory()+"\\";
        private static string Run_Plugin_BatchFile = CurrentWorkingDir + "SWELF_PS_Plugin.bat";

        public static string RunTimeError = "";

        //[DllImport("Amsi.dll", EntryPoint = "AmsiInitialize", CallingConvention = CallingConvention.StdCall)]
        //public static extern int AmsiInitialize([MarshalAs(UnmanagedType.LPWStr)]string appName, out IntPtr amsiContext);

        //[DllImport("Amsi.dll", EntryPoint = "AmsiUninitialize", CallingConvention = CallingConvention.StdCall)]
        //public static extern void AmsiUninitialize(IntPtr amsiContext);

        //[DllImport("Amsi.dll", EntryPoint = "AmsiOpenSession", CallingConvention = CallingConvention.StdCall)]
        //public static extern int AmsiOpenSession(IntPtr amsiContext, out IntPtr session);

        //[DllImport("Amsi.dll", EntryPoint = "AmsiCloseSession", CallingConvention = CallingConvention.StdCall)]
        //public static extern void AmsiCloseSession(IntPtr amsiContext, IntPtr session);

        //[DllImport("Amsi.dll", EntryPoint = "AmsiScanString", CallingConvention = CallingConvention.StdCall)]
        //public static extern int AmsiScanString(IntPtr amsiContext, [InAttribute()] [MarshalAsAttribute(UnmanagedType.LPWStr)]string @string, [InAttribute()] [MarshalAsAttribute(UnmanagedType.LPWStr)]string contentName, IntPtr session, out AMSI_RESULT result);

        //[DllImport("Amsi.dll", EntryPoint = "AmsiScanBuffer", CallingConvention = CallingConvention.StdCall)]
        //public static extern int AmsiScanBuffer(IntPtr amsiContext, byte[] buffer, ulong length, string contentName, IntPtr session, out AMSI_RESULT result);

        ////This method apparently exists on MSDN but not in AMSI.dll (version 4.9.10586.0)
        //[DllImport("Amsi.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        //public static extern bool AmsiResultIsMalware(AMSI_RESULT result);

        public enum AMSI_RESULT
        {
            AMSI_RESULT_CLEAN = 0,
            AMSI_RESULT_NOT_DETECTED = 1,
            AMSI_RESULT_DETECTED = 32768
        }

        public static string Run_PS_Script(string PowershellSciptLocation, string PowershellSciptArgs)
        {
            powershellSciptLocation = PowershellSciptLocation;
            powershellSciptArgs = PowershellSciptArgs;
            WriteBatchFile(PSScript1LinerArginScript());
            ProcessStartInfo startInfo = new ProcessStartInfo("Powershell", Run_Plugin_BatchFile);
            startInfo.WorkingDirectory = CurrentWorkingDir;
            startInfo.RedirectStandardOutput = true;
            startInfo.RedirectStandardError = true;
            startInfo.LoadUserProfile = true;
            startInfo.UseShellExecute = false;
            startInfo.CreateNoWindow = true;
            Process process = new Process();
            process.StartInfo = startInfo;
            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            RunTimeError += process.StandardError.ReadToEnd();
            return output;
        }

        public static Task RunProcessAsync(string processPath)
        {
            var tcs = new TaskCompletionSource<object>();
            var process = new Process
            {
                EnableRaisingEvents = true,
                StartInfo = new ProcessStartInfo(processPath)
                {
                    RedirectStandardError = true,
                    UseShellExecute = false
                }
            };
            process.Exited += (sender, args) =>
            {
                if (process.ExitCode != 0)
                {
                    var errorMessage = process.StandardError.ReadToEnd();
                    tcs.SetException(new InvalidOperationException("The process did not exit correctly. " +"The corresponding error message was: " + errorMessage));
                }
                else
                {
                    tcs.SetResult(null);
                }
                process.Dispose();
            };
            process.Start();
            return tcs.Task;
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
                Errors.Log_Error("WriteBatchFile()", e.Message.ToString());
            }
        }

        private static string PSScript1LinerArginScript()
        {
            if (!string.IsNullOrEmpty(powershellSciptArgs))
            {
                return "Powershell -NoProfile -NoLogo -ExecutionPolicy Bypass \"& \"" + powershellSciptLocation + "\" '" + powershellSciptArgs + "'\" | Out-File -filepath \"" + CurrentWorkingDir + "Plugin_Output.txt\"";
            }
            else
            {
                return "Powershell -NoProfile -NoLogo -ExecutionPolicy Bypass \"& \"" + powershellSciptLocation + "\"\" | Out-File -filepath \"" + CurrentWorkingDir + "Plugin_Output.txt\"";

            }
        }
    }
}
