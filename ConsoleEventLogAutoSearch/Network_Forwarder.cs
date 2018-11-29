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
    internal class Network_Forwarder
    {
        private static List<string> IPAddr = Settings.GET_LogCollector_Location();
        private static int Dst_port = Settings.Log_Forward_Location_Port;

        public static void SEND_Logs(Queue<EventLog_Entry> Event_logs)
        {
            if (Settings.GET_LogCollector_Location().ToString().Contains("127.0.0.1") == false || String.IsNullOrWhiteSpace(Settings.GET_LogCollector_Location().ToString()) == false)//Does admin want to send off logs?
            {
                if (Settings.AppConfig_File_Args["transport_protocol"] == "tcp")//If user wants send logs tcp
                {
                    for (int x = 0; x < IPAddr.Count; ++x)
                    {
                        try
                        {
                            while(Event_logs.Count > 0)
                            {
                                TcpClient client = new TcpClient(Get_IP_from_Socket_string(IPAddr.ElementAt(x)), Get_Port_from_Socket(IPAddr.ElementAt(x).ToString()));
                                NetworkStream stream = client.GetStream();
                                var data = GET_Encoding_to_Return(Event_logs.Dequeue());
                                stream.Write(data, 0, data.Length);
                                stream.Close();
                                client.Close();
                            }
                        }
                        catch (Exception e)
                        { 
                        //todo retry connection 3 times
                            Settings.Logs_Sent_to_ALL_Collectors = false;
                            Errors.Log_Error("SEND_Logs() TCP", e.Message.ToString(), Errors.LogSeverity.Critical);
                        }
                    }
                }

                else//Default send logs UDP
                {
                    for (int x = 0; x < IPAddr.Count; ++x)
                    {
                        try
                        {
                            while (Event_logs.Count > 0)
                            {
                                UdpClient client = new UdpClient(Get_Port_from_Socket(IPAddr.ElementAt(x).ToString()));
                                var data = GET_Encoding_to_Return(Event_logs.Dequeue());
                                client.Send(data, data.Length);
                                client.Close();
                            }
                        }
                        catch (Exception e)
                        {
                            Settings.Logs_Sent_to_ALL_Collectors = false;
                            Errors.Log_Error("SEND_Logs() UDP", e.Message.ToString(), Errors.LogSeverity.Critical);
                        }
                    }
                }
            }
        }

        public static bool SEND_Logs(string Log,string FilePath="",bool DeleteWhenDone=false)
        {
            bool Data_Sent = false;

            if (Settings.GET_LogCollector_Location().ToString().Contains("127.0.0.1") == false || String.IsNullOrWhiteSpace(Settings.GET_LogCollector_Location().ToString()) == false)//Does admin want to send off logs?
            {
                if (Settings.AppConfig_File_Args["transport_protocol"] == "tcp")//If user wants send logs tcp
                {
                    for (int x = 0; x < IPAddr.Count; ++x)
                    {
                        try
                        {
                            TcpClient client = new TcpClient(Settings.GET_HostName(Get_IP_from_Socket_string(IPAddr.ElementAt(x))), Get_Port_from_Socket(IPAddr.ElementAt(x).ToString()));
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
                            Errors.Log_Error("SEND_Logs_TCP_from_File()", e.Message.ToString(), Errors.LogSeverity.Warning);
                        }
                    }
                }
                else//Default send logs UDP
                {
                    for (int x = 0; x < IPAddr.Count; ++x)
                    {
                        UdpClient client = new UdpClient(Get_Port_from_Socket(IPAddr.ElementAt(x).ToString()));
                        Data_Sent=SEND_Data_from_File_UDP(Log, client);
                        client.Close();
                    }
                }
            }
            return Data_Sent;
        }

        private static bool SEND_Data_from_File_UDP(string Log_File_Data, UdpClient client)
        {
            bool Data_Sent = true;
            try
            {
                for (int x = 0; x < IPAddr.Count; ++x)
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
                        Errors.Log_Error("SEND_Data_from_File(Log_File_Data)", "SWELF NETWORK ERROR: " + e.Message.ToString(), Errors.LogSeverity.Warning);
                    }
                }
            }
            catch (Exception e)
            {
                Data_Sent = false;
                Settings.Logs_Sent_to_ALL_Collectors = false;
                Errors.Log_Error("SEND_Data_from_File(string Log_File_Data)", e.Message.ToString(),Errors.LogSeverity.Warning);
            }
            return Data_Sent;
        }

        private static void SEND_Logs_JSON(string WebLocation, EventLog_Entry Data)
        {
            //TODO: Deal with unknown file format local log file reads
            var httpWebRequest = (HttpWebRequest)WebRequest.Create("http://" + WebLocation);
            httpWebRequest.ContentType = "application/json";
            httpWebRequest.Method = "POST";

            using (var streamWriter = new StreamWriter(httpWebRequest.GetRequestStream()))
            {
                string json = @"
                {

                }
                ";

                streamWriter.Write(json);
                streamWriter.Flush();
                streamWriter.Close();
            }
            /*var httpResponse = (HttpWebResponse)httpWebRequest.GetResponse();
            using (var streamReader = new StreamReader(httpResponse.GetResponseStream()))
            {
                var result = streamReader.ReadToEnd();
            }*/
        }

        private static byte[] GET_Encoding_to_Return(EventLog_Entry Data)
        {
           return Encoding.UTF8.GetBytes(GET_Log_Output_Format(Data));
        }

        private static string GET_Log_Output_Format(EventLog_Entry data)
        {
            string format=Settings.AppConfig_File_Args["output_format"];
            string Data;
            switch (format.ToLower())
            {
                case  "data":
                    {
                        Data = DateTime.Now.ToString(Settings.SWELF_Date_Time_Format) + "   " + data.EventData;
                        break;
                    }
                case "syslog":
                    {
                        Data = DateTime.Now.ToString(Settings.SWELF_Date_Time_Format) + "   " + Settings.ComputerName + "   " + data.Severity + "   " + "SWELF_Syslog" + "   " + data.EventID.ToString() + "   " + data.LogName + "   " + data.CreatedTime + "   " + data.EventRecordID + "   " + data.TaskDisplayName + "   " +data.SearchRule + "   " + data.EventData;
                        break;

                    }
                case "syslogxml":
                    {
                        Data = DateTime.Now.ToString(Settings.SWELF_Date_Time_Format) + "   " + Settings.ComputerName + "   " + data.Severity + "   " + "SWELF_Syslog" + "   " + data.EventID.ToString() + "   " + data.LogName + "   " + data.CreatedTime + "   " + data.EventRecordID + "   " + data.TaskDisplayName+ "   " + data.SearchRule + "   " + data.GET_XML_of_Log;
                        break;

                    }
                case "xml":
                    {
                        Data = DateTime.Now.ToString(Settings.SWELF_Date_Time_Format) + "   " + data.GET_XML_of_Log;
                        break;
                    }
                case "keyvalue":
                    {
                        Data = "DateTime=\"" + data.CreatedTime + "\"" + "   " + "SourceComputer=\"" + Settings.ComputerName + "\"" + "   " + "EventID=\"" + data.EventID.ToString() + "\"" + "   " + "EventLogName=\"" + data.LogName + "\"" + "   " + "EventRecordID=\"" + data.EventRecordID + "\"" + "   " + "DisplayName=\"" + data.TaskDisplayName + "\"" + "   " + "Severity=\"" + data.Severity + "\"" + "   " + "UserID=\"" + data.UserID + "\"" + "   " +"SearchRule=\""+ data.SearchRule + "\"   " + "ParentCommandLine=\"" + Regex.Replace(data.ParentCMDLine, @"\n|\r|\t|\r\n|\n\r", "    ") + "\"   " + "ChildCommandLine=\"" + Regex.Replace(data.ChildCMDLine, @"\n|\r|\t|\r\n|\n\r", "    ")  + "\"   " + "EventData=\"" + Regex.Replace(data.EventData, @"\n|\r|\t|\r\n|\n\r", "    ") + " \"";
                        break;
                    }
                default:
                    {
                        Data = DateTime.Now.ToString(Settings.SWELF_Date_Time_Format) + "   " + data.SearchRule + "    "+data.GET_XML_of_Log;
                        break;
                    }
            }
            return Data;
        }       

        private static int FIND_Open_SourcePort()
        {
            int startingAtPort = 11000;
            int maxNumberOfPortsToCheck = 1500;
            var range = Enumerable.Range(startingAtPort, maxNumberOfPortsToCheck);
            var portsInUse =
                from p in range
                join used in System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners()
            on p equals used.Port
                select p;
            int FirstFreeUDPPortInRange = range.Except(portsInUse).FirstOrDefault();
            return FirstFreeUDPPortInRange;
        }

        private static int Get_Port_from_Socket(string IPAddr)
        {
            if (IPAddr.ToString().Contains(':'))
            {
                List<string> Sockets = IPAddr.Split(':').ToList();
                try
                {
                    return Dst_port = Convert.ToInt32(Sockets.ElementAt(1));
                }
                catch
                {
                    return Dst_port = Settings.Log_Forward_Location_Port;
                }
            }
            else
            {
                return Dst_port = Settings.Log_Forward_Location_Port;
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

        public static string Get_IP_from_Socket_string(string IPAddr)
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
