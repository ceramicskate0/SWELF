//Written by Ceramicskate0
//Copyright 2018
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
                if (Settings.AppConfig_File_Args[Settings.SWELF_AppConfig_Args[14]] == "tcp")//If user wants send logs tcp
                {
                    for (int x = 0; x < Settings.Log_Forwarders_HostNames.Count; ++x)
                    {
                        try
                        {
                            for (int y=0; y< Event_logs.Count;++y)
                            { 
                                TcpClient client = new TcpClient(Get_IP_from_Socket_string(Settings.Log_Forwarders_HostNames.ElementAt(x)), Settings.Log_Forwarders_Port.ElementAt(x));
                                NetworkStream stream = client.GetStream();
                                var data = GET_Encoding_to_Return(Event_logs.ElementAt(y));
                                stream.Write(data, 0, data.Length);
                                stream.Close();
                                client.Close();
                            }
                        }
                        catch (Exception e)
                        { 
                            Settings.Logs_Sent_to_ALL_Collectors = false;
                            Error_Operation.Log_Error("SEND_Logs() [transport_protocol] == tcp", Settings.Log_Forwarders_HostNames.ElementAt(x)+" "+ e.Message.ToString(), Error_Operation.LogSeverity.Informataion);
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
                                UdpClient client = new UdpClient(Get_IP_from_Socket_string(Settings.Log_Forwarders_HostNames.ElementAt(x)), Settings.Log_Forwarders_Port.ElementAt(x));
                                var data = GET_Encoding_to_Return(Event_logs.ElementAt(y));
                                client.Send(data, data.Length);
                                client.Close();
                            }
                        }
                        catch (Exception e)
                        {
                            Settings.Logs_Sent_to_ALL_Collectors = false;
                            Error_Operation.Log_Error("SEND_Logs() else//Default send logs UDP", Settings.Log_Forwarders_HostNames.ElementAt(x) + " " + e.Message.ToString(), Error_Operation.LogSeverity.Verbose);
                        }
                    }
                    Settings.Logs_Sent_to_ALL_Collectors = true;
                    Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.Logs_Last_Sent, DateTime.Now.ToString());
                }
            }
        }

        internal static bool SEND_Logs(string Log, string FilePath = "", bool DeleteWhenDone = false)
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
                            TcpClient client = new TcpClient(Get_IP_from_Socket_string(Settings.Log_Forwarders_HostNames.ElementAt(x)), Settings.Log_Forwarders_Port.ElementAt(x));
                            NetworkStream stream = client.GetStream();
                            Byte[] data = GET_Encoding_to_Return(Log);
                            stream.Write(data, 0, data.Length);
                            stream.Close();
                            client.Close();
                        }
                        catch (Exception e)
                        {
                            Data_Sent = false;
                            Settings.Logs_Sent_to_ALL_Collectors = false;
                            Error_Operation.Log_Error("SEND_Logs() transport_protocol tcp", Settings.Log_Forwarders_HostNames.ElementAt(x) + " " + e.Message.ToString(), Error_Operation.LogSeverity.Informataion);
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
                            UdpClient client = new UdpClient(Get_IP_from_Socket_string(Settings.Log_Forwarders_HostNames.ElementAt(x)), Settings.Log_Forwarders_Port.ElementAt(x));
                            Data_Sent = SEND_Data_from_File_UDP(Log, client);
                            client.Close();
                        }
                        catch (Exception e)
                        {
                            Data_Sent = false;
                            Settings.Logs_Sent_to_ALL_Collectors = false;
                            Error_Operation.Log_Error("SEND_Logs() Default send logs UDP", Settings.Log_Forwarders_HostNames.ElementAt(x) + " " + e.Message.ToString(), Error_Operation.LogSeverity.Informataion);
                        }
                    }
                    Settings.Logs_Sent_to_ALL_Collectors = true;
                    Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.Logs_Last_Sent, DateTime.Now.ToString());
                }
            }
            return Data_Sent;
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
                        Error_Operation.Log_Error("SEND_Data_from_File_UDP(Log_File_Data)", "SWELF NETWORK ERROR: " + e.Message.ToString(), Error_Operation.LogSeverity.Informataion);
                    }
                }
                Settings.Logs_Sent_to_ALL_Collectors = true;
                Reg_Operation.ADD_or_CHANGE_SWELF_Reg_Key(Reg_Operation.REG_KEY.Logs_Last_Sent, DateTime.Now.ToString());
            }
            catch (Exception e)
            {
                Data_Sent = false;
                Settings.Logs_Sent_to_ALL_Collectors = false;
                Error_Operation.Log_Error("SEND_Data_from_File(string Log_File_Data)", e.Message.ToString(),Error_Operation.LogSeverity.Warning);
            }
            return Data_Sent;
        }

        private static byte[] GET_Encoding_to_Return(EventLog_Entry Data)
        {
           return Crypto_Operation.CONVERT_To_UTF8_Bytes(GET_Log_Output_Format(Data));
        }

        private static string GET_Log_Output_Format(EventLog_Entry data)
        {
            string format=Settings.AppConfig_File_Args[Settings.SWELF_AppConfig_Args[10]];
            string Data;
            format=Regex.Replace(format, @"\s+", String.Empty);//remove spaces from value
            switch (format.ToLower())
            {
                case  "data":
                    {
                        Data = DateTime.Now.ToString(Settings.SWELF_Date_Time_Format) + "   " + Regex.Replace(data.EventData, @"\n|\r|\t|\r\n|\n\r", "    ");
                        break;
                    }
                case "syslog":
                    {
                        Data = DateTime.Now.ToString(Settings.SWELF_Date_Time_Format) + "   " + Settings.ComputerName + "   " + data.Severity + "   " + "SWELF_Syslog" + "   " + data.EventID.ToString() + "   " + data.LogName + "   " + data.CreatedTime + "   " + data.EventRecordID + "   " + data.TaskDisplayName + "   " +data.SearchRule + "   " + Regex.Replace(data.EventData, @"\n|\r|\t|\r\n|\n\r", "    ");
                        break;

                    }
                case "syslogxml":
                    {
                        Data = DateTime.Now.ToString(Settings.SWELF_Date_Time_Format) + "   " + Settings.ComputerName + "   " + data.Severity + "   " + "SWELF_Syslog" + "   " + data.EventID.ToString() + "   " + data.LogName + "   " + data.CreatedTime + "   " + data.EventRecordID + "   " + data.TaskDisplayName+ "   " + data.SearchRule + "   " + Regex.Replace(data.GET_XML_of_Log, @"\n|\r|\t|\r\n|\n\r", "    ");
                        break;

                    }
                case "xml":
                    {
                        Data = DateTime.Now.ToString(Settings.SWELF_Date_Time_Format) + "   " + Regex.Replace(data.GET_XML_of_Log, @"\n|\r|\t|\r\n|\n\r", "    ");
                        break;
                    }
                case "keyvalue":
                    {
                        Data = "DateTime=\"" + data.CreatedTime + "\"" + "   " + "SourceComputer=\"" + Settings.ComputerName + "\"" + "   " + "EventID=\"" + data.EventID.ToString() + "\"" + "   " + "EventLogName=\"" + data.LogName + "\"" + "   " + "EventRecordID=\"" + data.EventRecordID + "\"" + "   " + "DisplayName=\"" + data.TaskDisplayName + "\"" + "   " + "Severity=\"" + data.Severity + "\"" + "   " + "UserID=\"" + data.UserID + "\"" + "   " +"SearchRule=\""+ data.SearchRule + "\"   " + "ParentCommandLine=\"" + Regex.Replace(data.ParentCMDLine, @"\n|\r|\t|\r\n|\n\r", "    ") + "\"   " + "ChildCommandLine=\"" + Regex.Replace(data.ChildCMDLine, @"\n|\r|\t|\r\n|\n\r", "    ")  + "\"   " + "EventData=\"" + Regex.Replace(data.EventData, @"\n|\r|\t|\r\n|\n\r", "    ") + " \"";
                        break;
                    }
                default:
                    {
                        Data = DateTime.Now.ToString(Settings.SWELF_Date_Time_Format) + "   " + "SearchRule=\""+ data.SearchRule + "\"" + "    " + Regex.Replace(data.GET_XML_of_Log, @"\n|\r|\t|\r\n|\n\r", "    ");
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

        private static IPAddress Get_IP_from_Socket(string IPAddr)
        {
            if (IPAddr.ToString().Contains(':'))
            {
                List<string> Sockets = IPAddr.Split(':').ToList();
                try
                {
                    return IPAddress.Parse((Sockets.ElementAt(0)));
                }
                catch
                {
                    return IPAddress.Parse("127.0.0.1");
                }
            }
            else
            {
                return IPAddress.Parse((IPAddr));
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
