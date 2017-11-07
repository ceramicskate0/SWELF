//Written by Ceramicskate0
//Copyright 2017
using System;
using System.Xml;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Serialization;
using System.Diagnostics.Eventing.Reader;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.IO;
using System.Xml.Linq;

namespace ConsoleEventLogAutoSearch
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
        public int PID { get; set; }
        public string Severity { get; set; }
        public string TaskDisplayName { get; set; }
        public DateTime CreatedTime { get; set; }

        public string GET_Hash_FromLogFile
        {
            get
            {
                return GET_FileHash();
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
            if (EventData.Contains("Hashes: ") && LogName.ToLower().Equals("microsoft-windows-sysmon/operational"))
            {
                string data = EventData;
                string[] SplitOnHash = { "Hashes: " };
                string[] SPlitOnHash2 = { "\r\n" };

                string[] datA = data.Split(SplitOnHash, StringSplitOptions.RemoveEmptyEntries).ToArray();
                string[] datAa = datA[1].Split(SPlitOnHash2, StringSplitOptions.RemoveEmptyEntries).ToArray();
                data = datAa[0];

                hash_from_log = data.Split('=').ElementAt(1).ToString();
                return hash_from_log;
            }
            else
            {
                return "";
            }
        }
        }
    }
