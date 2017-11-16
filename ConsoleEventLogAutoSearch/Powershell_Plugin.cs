using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading.Tasks;
using System.IO;
using System.Diagnostics;
using System.Security;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace ConsoleEventLogAutoSearch
{
    class Powershell_Plugin
    {

        public static int Start_Process_PS(string arguements)
        {
            try
            {
                bool started = false;
                var process = new System.Diagnostics.Process();
                System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
                startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
                startInfo.WorkingDirectory = Directory.GetCurrentDirectory();
                startInfo.FileName = "powershell.exe";
                startInfo.Arguments = arguements;
                startInfo.RedirectStandardOutput = true;
                startInfo.UseShellExecute = false;
                startInfo.CreateNoWindow = true;
                process.StartInfo = startInfo;
                started = process.Start();
                var procId = process.Id;
                StreamReader reader = process.StandardOutput;
                string output = reader.ReadToEnd();
                return 0;
            }
            catch
            {
                return 1;
            }
        }

        public static void Start_Powershell(string arguements)
        {
            using (var runspace = RunspaceFactory.CreateRunspace())
            {
                using (var powerShell = PowerShell.Create())
                {
                    powerShell.Runspace = runspace;
                    powerShell.AddScript(arguements);
                    powerShell.Streams.Progress.DataAdded += myProgressEventHandler;
                    var results = powerShell.Invoke();
                }
            }
        }
        static void myProgressEventHandler(object sender, DataAddedEventArgs e)
        {
            ProgressRecord newRecord = ((PSDataCollection<ProgressRecord>)sender)[e.Index];
        }
    }
}
