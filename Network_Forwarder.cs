//Written by Ceramicskate0
//Copyright 2018
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Web;
using System.IO;

namespace SWELF
{
    class Network_Forwarder
    {
        private static List<string> IPAddr = Settings.GET_LogCollector_Location();
        private static int Dst_port = Settings.Log_Forward_Location_Port;

        public static void SEND_Logs(EventLogEntry Data)
        {
            UdpClient udpClient = new UdpClient(Dst_port);
            try
            {
                for (int x = 0; x < IPAddr.Count; ++x)
                {
                    try
                    {
                        if (Settings.AppConfig_File_Args["output_format"] == "json")
                        {
                            //SEND_Logs_JSON(IPAddr.ElementAt(x).MapToIPv4().ToString(),Data);
                        }
                        else
                        {
                            udpClient.Connect(Get_IP_from_Socket(IPAddr.ElementAt(x)), Get_Port_from_Socket(IPAddr.ElementAt(x).ToString()));
                            byte[] sendBytes = Encoding.ASCII.GetBytes(GET_Log_OutputFormat(Data));
                            udpClient.Send(sendBytes, sendBytes.Length);
                            udpClient.Close();
                        }
                    }
                    catch (Exception e)
                    {
                        Errors.Log_Error("SEND_Logs(EventLogEntry Data)","SWELF NETWORK ERROR: "+e.Message.ToString(),Errors.LogSeverity.Warning);
                    }
                }
            }
            catch (Exception e)
            {
                Errors.Log_Error("SEND_Data_from_File(Log_File_Data)", "SWELF NETWORK ERROR: Check output command Syntax in consoleappconfig.conf. " + e.Message.ToString(), Errors.LogSeverity.Warning);
            }
        }

        public static void SEND_Data_from_File(string Log_File_Data)
        {
            UdpClient udpClient = new UdpClient(Dst_port);
            try
            {
                for (int x = 0; x < IPAddr.Count; ++x)
                {
                    try
                    {
                        //TODO: SEND IN JSON FORMAT
                        udpClient.Connect(Get_IP_from_Socket(IPAddr.ElementAt(x)), Get_Port_from_Socket(IPAddr.ElementAt(x).ToString()));
                        byte[] sendBytes = Encoding.ASCII.GetBytes(Log_File_Data);
                        udpClient.Send(sendBytes, sendBytes.Length);
                        IPEndPoint RemoteIpEndPoint = new IPEndPoint(IPAddress.Any, 0);
                        udpClient.Close();
                    }
                    catch (Exception e)
                    {
                        Errors.Log_Error("SEND_Data_from_File(Log_File_Data)", "SWELF NETWORK ERROR: " + e.Message.ToString(), Errors.LogSeverity.Warning);
                    }
                }
            }
            catch (Exception e)
            {
                Errors.Log_Error("SEND_Data_from_File(string Log_File_Data)", e.Message.ToString(),Errors.LogSeverity.Warning);
            }
        }

        private static void SEND_Logs_JSON(string WebLocation, EventLogEntry Data)
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

        private static string GET_Log_OutputFormat(EventLogEntry data)
        {
            string format=Settings.AppConfig_File_Args["output_format"];
            string Data;
            switch (format.ToLower())
            {
                case  "data":
                    {
                        Data = data.EventData;
                        break;
                    }
                case "syslog":
                    {
                        Data = DateTime.Now.ToString("MMM dd HH:mm:ss") + "   " + Settings.ComputerName + "   " + data.Severity + "   " + "SWELF_Syslog" + "   " + data.EventID.ToString() + "   " + data.LogName + "   " + data.CreatedTime + "   " + data.EventRecordID + "   " + data.TaskDisplayName + "   " + data.EventData;
                        break;

                    }
                case "syslogxml":
                    {
                        Data = DateTime.Now.ToString("MMM dd HH:mm:ss") + "   " + Settings.ComputerName + "   " + data.Severity + "   " + "SWELF_Syslog" + "   " + data.EventID.ToString() + "   " + data.LogName + "   " + data.CreatedTime + "   " + data.EventRecordID + "   " + data.TaskDisplayName + "   " + data.GET_XML_of_Log;
                        break;

                    }
                case "xml":
                    {
                        Data = data.GET_XML_of_Log;
                        break;
                    }
                case "keyvalue":
                    {
                        Data = "CreatedTime=\"" + data.CreatedTime+ "\"  ComputerName=\"" + Settings.ComputerName + "\"   EventID=\"" + data.EventID.ToString() + "\"   EventLogName=\"" + data.LogName + "\"   EventRecordID=\"" + data.EventRecordID + "\"  DisplayName=\"" + data.TaskDisplayName + "\"   Severity=\"" + data.Severity + "\"   UserID=\"" + data.UserID + "\"   ComputerName=\"" + data.ComputerName + "\"   EventData=\"" + data.EventData+"\"";
                        break;
                    }
                default:
                    {
                        Data = data.GET_XML_of_Log;
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
                    return Dst_port = Convert.ToInt32(Sockets.ElementAt(Sockets.Count - 1));
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
    }
}
