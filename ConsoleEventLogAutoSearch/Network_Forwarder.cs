//Written by Ceramicskate0
//Copyright 2017
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Web;

namespace ConsoleEventLogAutoSearch
{
    class Network_Forwarder
    {
        private static string BufferedString = "";
        private static IPAddress IPAddr = Settings.GET_LogCollector_Location().MapToIPv4();
        private static int port = Settings.LogForwardLocation_Port;

        public static void SEND_Eventlogs(EventLogEntry Data)
        {
            UdpClient udpClient = new UdpClient(11000);
            try
            {
                udpClient.Connect(IPAddr.MapToIPv4().ToString(), port);
                Byte[] sendBytes = Encoding.ASCII.GetBytes(GET_Log_OutputFormat(Data));
                udpClient.Send(sendBytes, sendBytes.Length);
                IPEndPoint RemoteIpEndPoint = new IPEndPoint(IPAddress.Any, 0);
                udpClient.Close();
            }
            catch (Exception e)
            {
                Errors.Log_Error("SWELF NETWORK ERROR: ", e.Message.ToString());
            }
        }

        public static void SEND_Data_from_File(string Data)
        {
            UdpClient udpClient = new UdpClient(11001);
            try
            {
                udpClient.Connect(IPAddr.MapToIPv4().ToString(), port);
                Byte[] sendBytes = Encoding.ASCII.GetBytes(Data);
                udpClient.Send(sendBytes, sendBytes.Length);
                IPEndPoint RemoteIpEndPoint = new IPEndPoint(IPAddress.Any, 0);
                udpClient.Close();
            }
            catch (Exception e)
            {
                Errors.Log_Error("SWELF NETWORK ERROR: ", e.Message.ToString());
            }
        }

        public static void BUFFER_Data(EventLogEntry Data)
        {
            int MaxLength= 999999999;
            string EncodedStringTMP = Convert.ToBase64String(Encoding.UTF8.GetBytes(GET_Log_OutputFormat(Data)));

            if (BufferedString.Length <= MaxLength && MaxLength < EncodedStringTMP.Length + BufferedString.Length)
            {
                BufferedString += EncodedStringTMP;
            }
            else
            {
                BufferedString += EncodedStringTMP;
                byte[] ByteData = Convert.FromBase64String(EncodedStringTMP).ToArray<Byte>();
                string converted = Encoding.ASCII.GetString(ByteData);
                SEND_Data_from_File(converted);
                BufferedString = "";
            }
        }

        private static string GET_Log_OutputFormat(EventLogEntry data)
        {
            string format=Settings.Args["outputformat"];
            string thing;
            switch (format.ToLower())
            {
                case  "data":
                    {
                        thing = data.EventData;
                        break;
                    }
                case "syslog":
                    {
                        thing= DateTime.Now.ToString("MMM dd HH:mm:ss") + " Syslog " +  data.Severity + " " + data.ComputerName + " SWELF   " + data.EventData;
                        break;

                    }
                case "syslogxml":
                    {
                        thing = DateTime.Now.ToString("MMM dd HH:mm:ss") + " Syslog " + data.Severity + " " + data.ComputerName + " SWELF   " + data.GET_XML_of_Log;
                        break;

                    }
                case "xml":
                    {
                        thing = data.GET_XML_of_Log;
                        break;
                    }
                default:
                    {
                        thing = data.EventData;
                        break;
                    }
            }
            return thing;
        }       
    }
}
