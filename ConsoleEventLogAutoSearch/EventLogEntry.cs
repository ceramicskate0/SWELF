//Written by Ceramicskate0
//Copyright 2018
using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.IO;

namespace SWELF
{
    public class EventLogEntry
    {
        public long EventLog_Seq_num = 0;

        public int EventRecordID { get; set; }
        public string GET_XML_of_Log { get; set; }
        public int EventID { get; set; }
        public string ComputerName { get; set; }
        public string UserID { get; set; }
        public string EventData { get; set; }
        public string LogName { get; set; }
        public string Severity { get; set; }
        public string TaskDisplayName { get; set; }
        public DateTime CreatedTime { get; set; }

        public static int CommandLineArgLength { get; set; }
        public static string CommandLineArgs { get; set; }

        public static string Sysmon_DST_Port { get; set; }
        public static string Sysmon_Src_Process { get; set; }

        public string GET_Sysmon_CommandLine_Args
        {
            get
            {
                return GET_CMDLineArgs();
            }
        }

        public string GET_Sysmon_Netwrok_Calling_Process_Name_Dest_Port
        {
            get
            {
                return GET_Sysmon_Netwrok_Calling_Process_Name_Dst_Port();
            }
        }

        public string GET_Sysmon_Network_Calling_Process_Name
        {
            get
            {
                return GET_Sysmon_Network_Process_Name();
            }
        }

        public void GET_IP_FromLogFile()
        {
            List<string> EventlogDataSegment = EventData.Split(Settings.EventLogEntry_splitter, StringSplitOptions.RemoveEmptyEntries).ToList();
            EventlogDataSegment = EventlogDataSegment.Distinct().ToList();
            EventlogDataSegment.Sort();
            foreach (string line in EventlogDataSegment)
            {
                if (Settings.IP_RegX.IsMatch(line) && line.Contains('.') && line.Contains('\\') == false)
                {
                    Settings.IP_List_EVT_Logs.Add(line);
                }
            }
        }

        public void Dispose()
        {
            this.Dispose();
        }
        
        public void GET_FileHash()
        {
            if (LogName.ToLower().Equals("microsoft-windows-sysmon/operational") && EventData.Contains("Hashes: "))
            {
                string data = EventData;
                string[] SplitOnHash = { "Hashes: " };
                string[] SPlitOnHash2 = { "\r\n" };

                string[] datA = data.Split(SplitOnHash, StringSplitOptions.RemoveEmptyEntries).ToArray();
                string[] datAa = datA[1].Split(SPlitOnHash2, StringSplitOptions.RemoveEmptyEntries).ToArray();
                data = datAa[0];
                Settings.Hashs_From_EVT_Logs.Add(data.Split(Settings.SplitChar_ConfigVariableEquals, StringSplitOptions.RemoveEmptyEntries).ElementAt(1).ToString());
            }
        }

        private string GET_CMDLineArgs()
        {
            string commandLine="";
            try
            {
                if (EventData.Contains("commandline: ") && LogName.ToLower().Equals("microsoft-windows-sysmon/operational"))
                {
                    string data = EventData;
                    string[] delm1 = { "commandline: ", "currentdirectory: " };

                    string[] datA = data.Split(delm1, StringSplitOptions.RemoveEmptyEntries).ToArray();

                    if (datA[1].Length>commandLine.Length && (!string.IsNullOrEmpty(datA[1])))
                    {
                        commandLine = "Target-CommandLine: " + datA[1];
                    }
                }

                if (EventData.Contains("parentcommandline: ") && LogName.ToLower().Equals("microsoft-windows-sysmon/operational"))
                {
                    string data = EventData;
                    string[] delm1 = { "parentcommandline: ", "" };

                    string[] datA = data.Split(delm1, StringSplitOptions.RemoveEmptyEntries).ToArray();

                    if ((datA[1].Length + "Target-CommandLine: ".Length) > commandLine.Length && (!string.IsNullOrEmpty(datA[1])))
                    {
                        commandLine += "\nParent-CommandLine: " + datA[1];
                    }
                }

                if (EventData.Contains("commandline= ") && LogName.ToLower().Equals("windows powershell"))
                {
                    string data = EventData;
                    string[] delm1 = { "commandline=  ", "details: " };

                    string[] datA = data.Split(delm1, StringSplitOptions.RemoveEmptyEntries).ToArray();

                    if (!string.IsNullOrEmpty(datA[1]))
                        {
                        if (datA[1].Length > commandLine.Length)
                        {
                            commandLine = "Target-CommandLine: " + datA[1];
                        }
                    }
                }

                if (EventData.Contains("process command line: ") && LogName.ToLower().Equals("microsoft-windows-security-auditing") && EventID==4688)
                {
                    string data = EventData;
                    string[] delm1 = { "process command line:  ", "token elevation type " };

                    string[] datA = data.Split(delm1, StringSplitOptions.RemoveEmptyEntries).ToArray();

                    if (!string.IsNullOrEmpty(datA[1]))
                    {
                        if (datA[1].Length > commandLine.Length)
                        {
                            commandLine = "process command line: " + datA[1];
                        }
                    }
                }

                if (commandLine.Length>1)
                {
                    commandLine += "\nParent-CommandLine: " ;
                }
                CommandLineArgLength = commandLine.Length;
                CommandLineArgs = commandLine;
                return commandLine;
            }
            catch
            {
                return commandLine;
            }
        }

        private string GET_Sysmon_Netwrok_Calling_Process_Name_Dst_Port()
        {
            try
            {               
                if (EventData.Contains("destinationport: ") && LogName.ToLower().Equals("microsoft-windows-sysmon/operational") && EventID==3)
                {
                    string data = EventData;
                    string[] delm1 = { "destinationport: ", "destinationportname: "};

                    string[] datA = data.Split(delm1, StringSplitOptions.RemoveEmptyEntries).ToArray();

                    if (datA[1].Length > 0 && (!string.IsNullOrEmpty(datA[1])))
                    {
                        Sysmon_DST_Port = datA[1].Replace("\r\n","");
                    }
                }
                return Sysmon_DST_Port;
            }
            catch
            {
                return Sysmon_DST_Port="";
            }
        }

        private string GET_Sysmon_Network_Process_Name()
        {
            try
            {

                if (EventData.Contains("image: ") && LogName.ToLower().Equals("microsoft-windows-sysmon/operational") && EventID == 3)
                {
                    string data = EventData;
                    string[] delm1 = { "image: ", "user: " };

                    string[] datA = data.Split(delm1, StringSplitOptions.RemoveEmptyEntries).ToArray();
                    if (datA[1].Length > 0 && (!string.IsNullOrEmpty(datA[1])))
                    {
                        string[] filepath = datA[1].Split('\\').ToArray();

                        Sysmon_Src_Process = filepath[filepath.Length-1].Replace("\r\n", "");
                    }
                }
                return Sysmon_Src_Process;
            }
            catch
            {
                return Sysmon_Src_Process = "";
            }
        }
    }
    }
