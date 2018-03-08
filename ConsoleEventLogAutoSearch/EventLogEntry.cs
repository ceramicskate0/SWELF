//Written by Ceramicskate0
//Copyright 2018
using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using System.Collections.Generic;

namespace SWELF
{
    public class EventLogEntry
    {
        private string hash_from_log;
        private Regex IP_RegX = new Regex(@"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b");
        private List<string> IP_List = new List<string>();
        private string[] splitter = { "\n", "\r", " ", "  " };
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

        public string GET_Hash_FromLogFile
        {
            get
            {
                return GET_FileHash();
            }
        }

        public string GET_Sysmon_CommandLine_Args
        {
            get
            {
                return GET_CMDLineArgs();
            }
        }

        public List<string> GET_IP_FromLogFile
        {
            get
            {
                List<string> EventlogDataSegment = EventData.Split(splitter, StringSplitOptions.RemoveEmptyEntries).ToList();
                EventlogDataSegment = EventlogDataSegment.Distinct().ToList();
                EventlogDataSegment.Sort();
                foreach (string line in EventlogDataSegment)
                {
                    if (IP_RegX.IsMatch(line) && line.Contains('.') && line.Contains('\\') == false)
                    {
                        IP_List.Add(line);
                    }
                }
                return IP_List;
            }
        }

        public void Dispose()
        {
            this.Dispose();
        }
        
        private string GET_FileHash()
        {
            if (LogName.ToLower().Equals("microsoft-windows-sysmon/operational") && EventData.Contains("Hashes: "))
            {
                string data = EventData;
                string[] SplitOnHash = { "Hashes: " };
                string[] SPlitOnHash2 = { "\r\n" };

                string[] datA = data.Split(SplitOnHash, StringSplitOptions.RemoveEmptyEntries).ToArray();
                string[] datAa = datA[1].Split(SPlitOnHash2, StringSplitOptions.RemoveEmptyEntries).ToArray();
                data = datAa[0];
                hash_from_log = data.Split(Settings.SplitChar_ConfigVariableEquals, StringSplitOptions.RemoveEmptyEntries).ElementAt(1).ToString();
                return hash_from_log;
            }
            else
            {
                return "";
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
    }
    }
