//Written by Ceramicskate0
//Copyright 2020
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Text.RegularExpressions;

namespace SWELF
{
    internal static class Log_Network_Forwarder
    {           
        internal static void SEND_Logs(Queue<EventLog_Entry> Event_logs)
        {
            if (Settings.Log_Forwarders_HostNames.Any(s => string.Equals(s, "127.0.0.1", StringComparison.OrdinalIgnoreCase)) == false && Settings.Log_Forwarders_HostNames.Any(s => string.IsNullOrEmpty(s)) == false)
            {
                if (Settings.AppConfig_File_Args.ContainsKey(Settings.SWELF_AppConfig_Args[14])==false)
                {
                    Settings.AppConfig_File_Args.Add(Settings.SWELF_AppConfig_Args[14], "udp");
                }

                if (Settings.AppConfig_File_Args[Settings.SWELF_AppConfig_Args[14]] == "tcp")//If user wants send logs tcp
                {
                    for (int x = 0; x < Settings.Log_Forwarders_HostNames.Count; ++x)
                    {
                        try
                        {
                            for (int y=0; y< Event_logs.Count;++y)
                            { 
                                Socket_Client_TCP(Crypto_Operation.CONVERT_To_ASCII_Bytes(GET_Log_Output_Format(Event_logs.ElementAt(y))), x);
                            }
                        }
                        catch (Exception e)
                        { 
                            Settings.Logs_Sent_to_ALL_Collectors = false;
                            Error_Operation.Log_Error("SEND_Logs() [transport_protocol] == tcp", Settings.Log_Forwarders_HostNames.ElementAt(x)+" "+ e.Message.ToString(), e.StackTrace.ToString(), Error_Operation.LogSeverity.Warning);
                        }
                    }
                    Settings.Logs_Sent_to_ALL_Collectors = true;
                    Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.Logs_Last_Sent, DateTime.Now.ToString());
                }
                else//Default send logs UDP
                {
                    for (int x = 0; x < Settings.Log_Forwarders_HostNames.Count; ++x)
                    {
                        try
                        {
                            for (int y = 0; y < Event_logs.Count; ++y)
                            {
                                Socket_Client_UDP(Crypto_Operation.CONVERT_To_ASCII_Bytes(GET_Log_Output_Format(Event_logs.ElementAt(y))), x);
                            }
                        }
                        catch (Exception e)
                        {
                            Settings.Logs_Sent_to_ALL_Collectors = false;
                            Error_Operation.Log_Error("SEND_Logs() else//Default send logs UDP", Settings.Log_Forwarders_HostNames.ElementAt(x) + " " + e.Message.ToString(), e.StackTrace.ToString(), Error_Operation.LogSeverity.Warning);
                        }
                    }
                    Settings.Logs_Sent_to_ALL_Collectors = true;
                    Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.Logs_Last_Sent, DateTime.Now.ToString());
                }
            }
        }
        internal static bool SEND_SINGLE_LOG(string Log)
        {
            bool Data_Sent = true;

            if (Settings.Log_Forwarders_HostNames.Any(s => string.Equals(s, "127.0.0.1", StringComparison.OrdinalIgnoreCase)) == false && Settings.Log_Forwarders_HostNames.Any(s => string.IsNullOrEmpty(s)) == false)
            {
                if (Settings.AppConfig_File_Args[Settings.SWELF_AppConfig_Args[14]] == "tcp")//If user wants send logs tcp
                {
                    for (int x = 0; x < Settings.Log_Forwarders_HostNames.Count; ++x)
                    {
                        try
                        {
                            Socket_Client_TCP(GET_Encoding_to_Return(Log), x);
                        }
                        catch (Exception e)
                        { 
                             Data_Sent = false;
                        }
                    }
                }
                else//Default send logs UDP
                {
                    for (int x = 0; x < Settings.Log_Forwarders_HostNames.Count; ++x)
                    {
                        try
                        {
                            UdpClient client = new UdpClient(Get_IP_from_Socket_string(Settings.Log_Forwarders_HostNames.ElementAt(x)), Settings.Log_Forwarders_Port.ElementAt(x));
                            SEND_Data_from_File_UDP(Log, client);
                            client.Close();
                        }
                        catch (Exception e)
                        {
                            Data_Sent = false;
                        }
                    }
                }
                return Data_Sent;
            }
            return Data_Sent;
        }
        public static void Socket_Client_UDP(byte[] Data,int x)
        {
                IPAddress ipAddress = IPAddress.Parse(Settings.Log_Forwarders_HostNames.ElementAt(x));
                IPEndPoint remoteEP = new IPEndPoint(ipAddress, Settings.Log_Forwarders_Port.ElementAt(x));
                Socket s = new Socket(ipAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                s.SendTo(Data, remoteEP);
                s.Close();
        }
        public static bool Socket_Client_TCP(byte[] Data, int x)
        { 
                IPAddress ipAddress = IPAddress.Parse(Settings.Log_Forwarders_HostNames.ElementAt(x));
                IPEndPoint remoteEP = new IPEndPoint(ipAddress, Settings.Log_Forwarders_Port.ElementAt(x)); 
                Socket sender = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                sender.Connect(remoteEP);
                sender.Send(Data,Data.Length,SocketFlags.None);
                sender.Shutdown(SocketShutdown.Both);
                sender.Close();
                return true;
        }
        private static bool SEND_Data_from_File_UDP(string Log_File_Data, UdpClient client)
        {
            bool Data_Sent = true;
            try
            {
                for (int x = 0; x < Settings.Log_Forwarders_HostNames.Count; ++x)
                {
                    try
                    {
                        byte[] sendBytes = GET_Encoding_to_Return(Log_File_Data);
                        client.Send(sendBytes, sendBytes.Length);
                    }
                    catch (Exception e)
                    {
                        Data_Sent = false;
                        Settings.Logs_Sent_to_ALL_Collectors = false;
                        Error_Operation.Log_Error("SEND_Data_from_File_UDP(Log_File_Data)", "SWELF NETWORK ERROR: " + e.Message.ToString(), e.StackTrace.ToString(), Error_Operation.LogSeverity.Informataion);
                    }
                }
                Settings.Logs_Sent_to_ALL_Collectors = true;
                Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.Logs_Last_Sent, DateTime.Now.ToString());
            }
            catch (Exception e)
            {
                Data_Sent = false;
                Settings.Logs_Sent_to_ALL_Collectors = false;
                Error_Operation.Log_Error("SEND_Data_from_File(string Log_File_Data)", e.Message.ToString(), e.StackTrace.ToString(), Error_Operation.LogSeverity.Warning);
            }
            return Data_Sent;
        }
        private static string GET_Log_Output_Format(EventLog_Entry data)
        {
            string format=Settings.AppConfig_File_Args[Settings.SWELF_AppConfig_Args[10]];
            string Data="";
            format=Regex.Replace(format, @"\s+", String.Empty);//remove spaces from value
            switch (format.ToLower())
            {
                case  "data":
                    {
                        string EventData = "";
                        EventData = data.EventData.Replace("\n", "").Replace("\r", "\n").Replace(":", ": ").Replace(": ", ": ").Replace(" \r ", "");
                        Data = DateTime.Now.ToString(Settings.SWELF_Date_Time_Format) + "   " + EventData;
                        break;
                    }
                case "syslog":
                    {
                        string EventData = "";
                        EventData = data.EventData.Replace("\n", "").Replace("\r", "\n").Replace(":", ": ").Replace(": ", ": ").Replace(" \r ", "");
                        Data = DateTime.Now.ToString(Settings.SWELF_Date_Time_Format) + "   " + Settings.ComputerName + "   " + data.Severity + "   " + "SWELF_Syslog" + "   " + data.EventID.ToString() + "   " + data.LogName + "   " + data.CreatedTime + "   " + data.EventRecordID + "   " + data.TaskDisplayName + "    " + data.SearchRule + "\"" + "    " + EventData;
                        break;

                    }
                case "syslogxml":
                    {
                        Data = DateTime.Now.ToString(Settings.SWELF_Date_Time_Format) + "   " + Settings.ComputerName + "   " + data.Severity + "   " + "SWELF_Syslog" + "   " + data.EventID.ToString() + "   " + data.LogName + "   " + data.CreatedTime + "   " + data.EventRecordID + "   " + data.TaskDisplayName+ "   "  + data.SearchRule + "\"" + "   " + data.GET_XML_of_Log.Replace("\n", "").Replace("\r", "\n").Replace(":", ": ").Replace(": ", ": ").Replace(" \r ", "");
                        break;

                    }
                case "xml":
                    {
                        Data = DateTime.Now.ToString(Settings.SWELF_Date_Time_Format) + "   " + data.GET_XML_of_Log.Replace("\n", "").Replace("\r", "\n").Replace(":", ": ").Replace(": ", ": ").Replace(" \r ", "");
                        break;
                    }
                case "keyvalue":
                    {
                        string EventData="";
                        EventData= data.EventData.Replace("\n", "").Replace("\r", "\n").Replace(":", ": ").Replace(": ",": ").Replace(" \r ","");
                        Data = " CreatedTime=\"" + data.CreatedTime +"\"" + "\t" + "SourceComputer=\"" + Settings.ComputerName + "\"" + "\t" + "EventID=\"" + data.EventID.ToString() + "\"" + "\t" + "EventLogName=\"" + data.LogName + "\"" + "\t" + "EventRecordID=\"" + data.EventLog_Seq_num + "\"" + "\t" + "DisplayName=\"" + data.TaskDisplayName + "\"" + "\t" + "Severity=\"" + data.Severity + "\"" + "\t" + "UserID=\"" + data.UserID + "\"" + "\t" + "Search_Rule=\"" + data.SearchRule + "\"" + "\t" + "EventData=\""+EventData+"\"" + "\t" + data.GET_Parsed_Sysmon_EventData().Replace("\n", "").Replace("\r", "\n").Replace(":", ": ").Replace(": ", ": ").Replace(" \r ", "")+"\t";
                        break;
                    }
                default:
                    {
                        Data = DateTime.Now.ToString(Settings.SWELF_Date_Time_Format) + "   " + data.SearchRule + "    " + data.GET_XML_of_Log.Replace("\n", "").Replace("\r", "\n").Replace(":", ": ").Replace(": ", ": ").Replace(" \r ", "");
                        break;
                    }
            }
            return Data;
        }
        internal static int Get_Port_from_Socket(string IPAddr)
        {
            try
            {
                if (IPAddr.ToString().Contains(':'))
                {
                    List<string> Sockets = IPAddr.Split(':').ToList();
                    try
                    {
                        return Convert.ToInt32(Sockets.ElementAt(1));
                    }
                    catch
                    {
                        return Settings.Log_Forward_Location_Port;
                    }
                }
                else
                {
                    return Settings.Log_Forward_Location_Port;
                }
            }
            catch (Exception e)
            {
                return Settings.Log_Forward_Location_Port;
            }
        }
        internal static string Get_IP_from_Socket_string(string IPAddr)
        {
            if (IPAddr.ToString().Contains(':'))
            {
                List<string> Sockets = IPAddr.Split(':').ToList();
                try
                {
                    return Sockets.ElementAt(0);
                }
                catch
                {
                    return "127.0.0.1";
                }
            }
            else
            {
                return IPAddr;
            }
        }
        private static byte[] GET_Encoding_to_Return(string Data)
        {
            return Encoding.UTF8.GetBytes(Data);
        }
    }
}
