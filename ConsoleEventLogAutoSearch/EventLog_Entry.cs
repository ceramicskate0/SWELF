//Written by Ceramicskate0
//Copyright 2018
using System;
using System.Linq;
using System.Text.RegularExpressions;
using System.Collections.Generic;

namespace SWELF
{
    public class EventLog_Entry
    {
        public long EventLog_Seq_num = 0;
        private string logName = null;
        private string taskDisplayName = null;
        private string severity = null;
        private int eventRecordID = 0;
        private int eventID = 0;
        private string computerName = null;
        private string userID = null;

        private byte[] EVT_Data_Compressed;
        private int EVT_Data_Size=0;

        private byte[] XML_Data_Compressed;
        private int XML_Data_Size = 0;

        private string evntdata;
        private string xml_evntdata;

        public string EventData
        {
            get
            {
                try
                {
                    if (string.IsNullOrEmpty(evntdata))
                    {
                        return Compress.DeCompress_Contents_String(EVT_Data_Compressed, EVT_Data_Size);
                    }
                    else
                    {
                        return evntdata;
                    }
                }
                catch (Exception e)
                {
                    return evntdata;
                }
            }
            set
            {
                try
                {
                    if (string.IsNullOrEmpty(evntdata))
                    {
                        EVT_Data_Size = Compress.uniEncode.GetBytes(value).Length;
                        EVT_Data_Compressed = Compress.Compress_Contents_Byte(value);
                    }
                    else
                    {

                    }
                }
                catch (Exception e)
                {
                    evntdata = value;
                }
            }
        }
        public string GET_XML_of_Log
        {
            get
            {
                try
                {
                    if (string.IsNullOrEmpty(xml_evntdata))
                    {
                        return Compress.DeCompress_Contents_String(XML_Data_Compressed, XML_Data_Size);
                    }
                    else
                    {
                        return xml_evntdata;
                    }
                }
                catch (Exception e)
                {
                  return xml_evntdata;
                }
        }
            set
            {
                try
                {
                    if (string.IsNullOrEmpty(xml_evntdata))
                    {
                        XML_Data_Size = Compress.uniEncode.GetBytes(value).Length;
                        XML_Data_Compressed = Compress.Compress_Contents_Byte(value);
                    }
                    else
                    {

                    }
                }
                catch (Exception e)
                {
                    xml_evntdata=value;
                }
            }
        }

        public int EventRecordID
        {
            get
            {
                return eventRecordID;
            }
            set
            {
                if (eventRecordID==0)
                {
                    eventRecordID = value;
                }
                else
                {

                }
            }
        }
        public int EventID
        {
            get
            {
                return eventID;
            }
            set
            {
                if (eventID==0)
                {
                    eventID = value;
                }
                else
                {

                }
            }
        }
        public string ComputerName
        {
            get
            {
                return computerName;
            }
            set
            {
                if (string.IsNullOrEmpty(computerName) == true)
                {
                    computerName = value;
                }
                else
                {

                }
            }
        }
        public string UserID
        {
            get
            {
                return userID;
            }
            set
            {
                if (string.IsNullOrEmpty(userID) == true)
                {
                    userID = value;
                }
                else
                {

                }
            }
        }
        public string LogName
        {
            get
            {
              return logName;
            }
            set
            {
                if (string.IsNullOrEmpty(logName)==true && string.IsNullOrWhiteSpace(LogName)==true && string.IsNullOrEmpty(value) == false)
                {
                    logName = value;
                }
                else
                {
                    logName = "ERROR";//remove this line when fixed
                }
            }
        }
        public string Severity
        {
            get
            {
                return severity;
            }
            set
            {
                if (string.IsNullOrEmpty(severity) == true)
                {
                    severity = value;
                }
                else
                {

                }
            }
        }
        public string TaskDisplayName
        {
            get
            {
                return taskDisplayName;
            }
            set
            {
                if (string.IsNullOrEmpty(taskDisplayName) == true)
                {
                    taskDisplayName = value;
                }
                else
                {

                }
            }
        }

        public DateTime CreatedTime { get; set; }
        public string SearchRule { get; set; }
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
            string Eventdata = Compress.DeCompress_Contents_String(EVT_Data_Compressed,EVT_Data_Size);

            if (Settings.AppConfig_File_Args.ContainsKey("output_ips"))
                {
                List<string> EventlogDataSegment = Eventdata.Split(Settings.EventLogEntry_splitter, StringSplitOptions.RemoveEmptyEntries).ToList();
                EventlogDataSegment = EventlogDataSegment.Distinct().ToList();
                EventlogDataSegment.Sort();

                foreach (string line in EventlogDataSegment)
                {
                    if (Eventdata.Contains("destinationip: ") && LogName.ToLower().Equals("microsoft-windows-sysmon/operational") && EventID == 3)
                    {
                        string[] delm1 = { "destinationip: ", "destinationhostname: " };

                        string[] datA = Eventdata.Split(delm1, StringSplitOptions.RemoveEmptyEntries).ToArray();

                        if (datA[1].Length > 0 && (!string.IsNullOrEmpty(datA[1])))
                        {
                            Settings.IP_List_EVT_Logs.Add(datA[1].Replace("\r\n", ""));
                        }
                    }
                    else if (Settings.IP_RegX.IsMatch(line) && line.Contains('.') && line.Contains('\\') == false && string.IsNullOrEmpty(line) == false)
                    {
                        Settings.IP_List_EVT_Logs.Add(line);
                    }
                }
            }
        }

        public void GET_FileHash()
        {
            string Eventdata = Compress.DeCompress_Contents_String(EVT_Data_Compressed, EVT_Data_Size);

            if (Settings.AppConfig_File_Args.ContainsKey("output_hashs"))
            {
                if (Eventdata.Contains("hashes: ") && LogName.ToLower().Equals("microsoft-windows-sysmon/operational") && EventID == 1)
                {
                    string[] delm1 = { "hashes: ", "parentprocessguid: " };

                    string[] datA = Eventdata.Split(delm1, StringSplitOptions.RemoveEmptyEntries).ToArray();

                    if (datA[1].Length > 0 && (!string.IsNullOrEmpty(datA[1])))
                    {
                        Settings.Hashs_From_EVT_Logs.Add(datA[1].Replace("\r\n", ""));
                    }
                }
                if (Eventdata.Contains("hashes: ") && LogName.ToLower().Equals("microsoft-windows-sysmon/operational") && EventID == 6)
                {
                    string[] delm1 = { "hashes: ", "signed: " };

                    string[] datA = Eventdata.Split(delm1, StringSplitOptions.RemoveEmptyEntries).ToArray();

                    if (datA[1].Length > 0 && (!string.IsNullOrEmpty(datA[1])))
                    {
                        Settings.Hashs_From_EVT_Logs.Add(datA[1].Replace("\r\n", ""));
                    }
                }
                else if (Settings.SHA256_RegX.Matches(Eventdata).Count > 0)
                {
                    foreach (MatchCollection MatchedHash in Settings.SHA256_RegX.Matches(Eventdata))
                    {
                        Settings.Hashs_From_EVT_Logs.Add(MatchedHash.ToString());
                    }
                }
            }
        }

        public void GET_HostName_FromLogFile()
        {
            string Eventdata = Compress.DeCompress_Contents_String(EVT_Data_Compressed, EVT_Data_Size);

            List<string> EventlogDataSegment = Eventdata.Split(Settings.EventLogEntry_splitter, StringSplitOptions.RemoveEmptyEntries).ToList();
            EventlogDataSegment = EventlogDataSegment.Distinct().ToList();
            EventlogDataSegment.Sort();
            if (Settings.AppConfig_File_Args.ContainsKey("output_ips"))
            {
                foreach (string line in EventlogDataSegment)
                {
                    if (Eventdata.Contains("destinationhostname: ") && LogName.ToLower().Equals("microsoft-windows-sysmon/operational") && EventID == 3)
                    {
                        string[] delm1 = { "destinationhostname: ", "destinationhostname: " };

                        string[] datA = Eventdata.Split(delm1, StringSplitOptions.RemoveEmptyEntries).ToArray();

                        if (datA[1].Length > 0 && (!string.IsNullOrEmpty(datA[1])))
                        {
                            //add hostname
                        }
                    }
                    else if (Settings.Hostname_RegX.IsMatch(line) && line.Contains('.') && line.Contains('\\') == false && string.IsNullOrEmpty(line) == false)
                    {
                        //add hostname
                    }
                }
            }
        }
        
        private string GET_CMDLineArgs()
        {
            string commandLine="";

            try
            {
                string Eventdata = "";
                if (EVT_Data_Size<= 0 || EVT_Data_Compressed==null)
                {
                    Eventdata = evntdata;
                }
                else
                {
                    Eventdata = Compress.DeCompress_Contents_String(EVT_Data_Compressed, EVT_Data_Size);
                }

                if (Eventdata.Contains("commandline: ") && LogName.ToLower().Equals("microsoft-windows-sysmon/operational"))
                {
                    string[] delm1 = { "commandline: ", "currentdirectory: " };

                    string[] datA = Eventdata.Split(delm1, StringSplitOptions.RemoveEmptyEntries).ToArray();

                    if (datA[1].Length>commandLine.Length && (!string.IsNullOrEmpty(datA[1])))
                    {
                        commandLine = "Target-CommandLine: " + datA[1];
                    }
                }

                if (Eventdata.Contains("parentcommandline: ") && LogName.ToLower().Equals("microsoft-windows-sysmon/operational"))
                {
                    string[] delm1 = { "parentcommandline: ", "" };

                    string[] datA = Eventdata.Split(delm1, StringSplitOptions.RemoveEmptyEntries).ToArray();

                    if ((datA[1].Length + "Target-CommandLine: ".Length) > commandLine.Length && (!string.IsNullOrEmpty(datA[1])))
                    {
                        commandLine += "\nParent-CommandLine: " + datA[1];
                    }
                }

                if (Eventdata.Contains("commandline= ") && LogName.ToLower().Equals("windows powershell"))
                {
                    string[] delm1 = { "commandline=  ", "details: " };

                    string[] datA = Eventdata.Split(delm1, StringSplitOptions.RemoveEmptyEntries).ToArray();

                    if (!string.IsNullOrEmpty(datA[1]))
                        {
                        if (datA[1].Length > commandLine.Length)
                        {
                            commandLine = "Target-CommandLine: " + datA[1];
                        }
                    }
                }

                if (Eventdata.Contains("process command line: ") && LogName.ToLower().Equals("microsoft-windows-security-auditing") && EventID==4688)
                {
                    string[] delm1 = { "process command line:  ", "token elevation type " };

                    string[] datA = Eventdata.Split(delm1, StringSplitOptions.RemoveEmptyEntries).ToArray();

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
            catch (Exception e)
            {
                return commandLine;
            }
        }

        private string GET_Sysmon_Netwrok_Calling_Process_Name_Dst_Port()
        {
            try
            {
                string Eventdata = Compress.DeCompress_Contents_String(EVT_Data_Compressed, EVT_Data_Size);

                if (Eventdata.Contains("destinationport: ") && LogName.ToLower().Equals("microsoft-windows-sysmon/operational") && EventID==3)
                {
                    string[] delm1 = { "destinationport: ", "destinationportname: "};

                    string[] datA = Eventdata.Split(delm1, StringSplitOptions.RemoveEmptyEntries).ToArray();

                    if (datA[1].Length > 0 && (!string.IsNullOrEmpty(datA[1])))
                    {
                        Sysmon_DST_Port = datA[1].Replace("\r\n","");
                    }
                }
                return Sysmon_DST_Port;
            }
            catch (Exception e)
            {
                return Sysmon_DST_Port="";
            }
        }

        private string GET_Sysmon_Network_Process_Name()
        {
            try
            {
                string Eventdata = Compress.DeCompress_Contents_String(EVT_Data_Compressed, EVT_Data_Size);

                if (Eventdata.Contains("image: ") && LogName.ToLower().Equals("microsoft-windows-sysmon/operational") && EventID == 3)
                {
                    string[] delm1 = { "image: ", "user: " };

                    string[] datA = Eventdata.Split(delm1, StringSplitOptions.RemoveEmptyEntries).ToArray();
                    if (datA[1].Length > 0 && (!string.IsNullOrEmpty(datA[1])))
                    {
                        string[] filepath = datA[1].Split('\\').ToArray();

                        Sysmon_Src_Process = filepath[filepath.Length-1].Replace("\r\n", "");
                    }
                }
                return Sysmon_Src_Process;
            }
            catch (Exception e)
            {
                return Sysmon_Src_Process = "";
            }
        }
    }
    }
