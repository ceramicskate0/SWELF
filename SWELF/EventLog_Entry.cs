//Written by Ceramicskate0
//Copyright
using System;
using System.Linq;
using System.Text.RegularExpressions;
using System.Collections.Generic;

namespace SWELF
{
    internal class EventLog_Entry
    {
        internal long EventLog_Seq_num = 0;
        private string logName = null;
        private string taskDisplayName = null;
        private string severity = null;
        private int eventRecordID = 0;
        private int eventID = 0;
        private string computerName = null;
        private string userID = null;
        private string searchrule = null;
        private byte[] EVT_Data_Compressed;
        private int EVT_Data_Size=0;

        private byte[] XML_Data_Compressed;
        private int XML_Data_Size = 0;

        private string evntdata;
        private string xml_evntdata;

        internal string EventData
        {
            get
            {
                try
                {
                    if (string.IsNullOrEmpty(evntdata))
                    {
                        return Compression_Operation.DeCompress_Contents_String(EVT_Data_Compressed, EVT_Data_Size);
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
                        EVT_Data_Size = Compression_Operation.utfEncode.GetBytes(value).Length;
                        EVT_Data_Compressed = Compression_Operation.Compress_Contents_Byte(value);
                    }
                }
                catch (Exception e)
                {
                    evntdata = value;
                }
            }
        }
        internal string GET_XML_of_Log
        {
            get
            {
                try
                {
                    if (string.IsNullOrEmpty(xml_evntdata))
                    {
                        return Compression_Operation.DeCompress_Contents_String(XML_Data_Compressed, XML_Data_Size);
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
                        XML_Data_Size = Compression_Operation.utfEncode.GetBytes(value).Length;
                        XML_Data_Compressed = Compression_Operation.Compress_Contents_Byte(value);
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

        internal int EventRecordID
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
        internal int EventID
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
        internal string ComputerName
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
        internal string UserID
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
        internal string LogName
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
        internal string Severity
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
        internal string TaskDisplayName
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
        internal string ParentCMDLine = "";
        internal string ChildCMDLine = "";

        internal DateTime CreatedTime { get; set; }
        internal string SearchRule {
            get
            {
                return searchrule;
            }
            set
            {
                try
                {
                    if (string.IsNullOrEmpty(searchrule))
                    {
                        searchrule = value;
                    }
                    else
                    {

                    }
                }
                catch (Exception e)
                {
                    searchrule = value;
                }
            }
        }
        internal static int CommandLineArgLength { get; set; }
        internal static string CommandLineArgs { get; set; }
        internal static string Sysmon_DST_Port { get; set; }
        internal static string Sysmon_Src_Process { get; set; }

        internal string GET_Sysmon_CommandLine_Args
        {
            get
            {
                return GET_CMDLineArgs();
            }
        }

        internal string GET_Sysmon_Netwrok_Calling_Process_Name_Dest_Port
        {
            get
            {
                return GET_Sysmon_Netwrok_Calling_Process_Name_Dst_Port();
            }
        }

        internal string GET_Sysmon_Network_Calling_Process_Name
        {
            get
            {
                return GET_Sysmon_Network_Process_Name();
            }
        }



        internal void GET_IP_FromLogFile()
        {
            if (Settings.AppConfig_File_Args.ContainsKey(Settings.SWELF_AppConfig_Args[11]))
            {
                string Eventdata = Compression_Operation.DeCompress_Contents_String(EVT_Data_Compressed,EVT_Data_Size);

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

        internal void GET_FileHash()
        {
            if (Settings.AppConfig_File_Args.ContainsKey(Settings.SWELF_AppConfig_Args[12]))
            {
                string Eventdata = Compression_Operation.DeCompress_Contents_String(EVT_Data_Compressed, EVT_Data_Size);

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

        internal void GET_HostName_FromLogFile()
        {
            string Eventdata = Compression_Operation.DeCompress_Contents_String(EVT_Data_Compressed, EVT_Data_Size);

            List<string> EventlogDataSegment = Eventdata.Split(Settings.EventLogEntry_splitter, StringSplitOptions.RemoveEmptyEntries).ToList();
            EventlogDataSegment = EventlogDataSegment.Distinct().ToList();
            EventlogDataSegment.Sort();
            if (Settings.AppConfig_File_Args.ContainsKey(Settings.SWELF_AppConfig_Args[11]))
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
                    Eventdata = Compression_Operation.DeCompress_Contents_String(EVT_Data_Compressed, EVT_Data_Size);
                }
                
                if (Eventdata.Contains("Creator Process Name: ") && LogName.ToLower().Equals("Security"))
                {
                    string[] delm1 = { "Creator Process Name: ", "Token " };

                    string[] datA = Eventdata.Split(delm1, StringSplitOptions.RemoveEmptyEntries).ToArray();

                    if (datA[1].Length > commandLine.Length && (!string.IsNullOrEmpty(datA[1])))
                    {
                        commandLine = "\nTarget-CommandLine: " + datA[1];
                        ChildCMDLine = datA[1];
                    }
                }
                else if (LogName.ToLower().Equals("microsoft-windows-sysmon/operational"))
                {
                    if (Eventdata.Contains("commandline: "))
                    {
                        string[] delm1 = { "commandline: ", "currentdirectory: " };

                        string[] datA = Eventdata.Split(delm1, StringSplitOptions.RemoveEmptyEntries).ToArray();

                        if (datA[1].Length > commandLine.Length && (!string.IsNullOrEmpty(datA[1])))
                        {
                            commandLine = "\nTarget-CommandLine: " + datA[1];
                            ChildCMDLine = datA[1];
                        }
                    }
                    if (Eventdata.Contains("parentcommandline: "))
                    {
                        string[] delm1 = { "parentcommandline: ", "" };

                        string[] datA = Eventdata.Split(delm1, StringSplitOptions.RemoveEmptyEntries).ToArray();

                        if ((datA[1].Length + "Target-CommandLine: ".Length) > commandLine.Length && (!string.IsNullOrEmpty(datA[1])))
                        {
                            commandLine += "\nParent-CommandLine: " + datA[1];
                            ParentCMDLine = datA[1];
                        }
                    }
                }
                else if (Eventdata.Contains("commandline= ") && LogName.ToLower().Equals("windows powershell"))
                {
                    string[] delm1 = { "commandline=  ", "details: " };

                    string[] datA = Eventdata.Split(delm1, StringSplitOptions.RemoveEmptyEntries).ToArray();

                    if (!string.IsNullOrEmpty(datA[1]))
                        {
                        if (datA[1].Length > commandLine.Length)
                        {
                            commandLine = "\nTarget-CommandLine: " + datA[1];
                            ChildCMDLine = datA[1];
                        }
                    }
                }
                else  if (Eventdata.Contains("process command line: ") && LogName.ToLower().Equals("microsoft-windows-security-auditing") && EventID==4688)
                {
                    string[] delm1 = { "process command line:  ", "token elevation type " };

                    string[] datA = Eventdata.Split(delm1, StringSplitOptions.RemoveEmptyEntries).ToArray();

                    if (!string.IsNullOrEmpty(datA[1]))
                    {
                        if (datA[1].Length > commandLine.Length)
                        {
                            commandLine = "\nTarget-CommandLine: " + datA[1];
                            ParentCMDLine = datA[1];
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
                string Eventdata = Compression_Operation.DeCompress_Contents_String(EVT_Data_Compressed, EVT_Data_Size);

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
                string Eventdata = Compression_Operation.DeCompress_Contents_String(EVT_Data_Compressed, EVT_Data_Size);

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
