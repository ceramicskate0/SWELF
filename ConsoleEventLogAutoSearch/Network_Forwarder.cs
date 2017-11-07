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
        private static UdpClient UDP_Packet_Sender_Method1 = new UdpClient(Settings.GET_LogCollector_Location().ToString() , Settings.LogForwardLocation_Port);
        private static IPEndPoint UDP_Packet_Sender_Method2 = new IPEndPoint(Settings.GET_LogCollector_Location() , Settings.LogForwardLocation_Port);
        private static Socket LogForward_Location_OBJ = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        private static string EncodedString = "";
        private static Byte[] ByteData;

        public static void SEND_Data_from_Eventlogs(EventLogEntry Data)
        {
           ByteData = Encoding.UTF8.GetBytes(GET_Log_OutputFormat(Data));
           UDP_Packet_Sender_Method1.Send(ByteData, ByteData.Length);
        }

        public static void SEND_Data_from_File(string Data)
        {
            ByteData = Encoding.UTF8.GetBytes(Data);
            UDP_Packet_Sender_Method1.Send(ByteData, ByteData.Length);
        }
        public static void BUFFER_Data(EventLogEntry Data)
        {
            int MaxLength= 999999999;
            string EncodedStringTMP = Convert.ToBase64String(Encoding.UTF8.GetBytes(GET_Log_OutputFormat(Data)));

            if (EncodedString.Length <= MaxLength && MaxLength < EncodedStringTMP.Length + EncodedString.Length)
            {
                EncodedString += EncodedStringTMP;
            }
            else
            {
                EncodedString += EncodedStringTMP;
                ByteData = Convert.FromBase64String(EncodedStringTMP).ToArray<Byte>();
                string converted = Encoding.UTF8.GetString(ByteData);
                SEND_Data_from_File(converted);
                EncodedString = "";
            }
        }

        private static string GET_Log_OutputFormat(EventLogEntry data)
        {
            string format=Settings.Args["outputformat"];
            switch (format.ToLower())
            {
                case  "data":
                    {
                        return data.EventData;
                    }
                case "syslog":
                    {
                        return DateTime.Now.ToString("MMM dd HH:mm:ss") + " Syslog " +  data.Severity + " " + data.ComputerName + " SWELF " + data.EventData;

                    }
                case "syslogxml":
                    {
                        return DateTime.Now.ToString("MMM dd HH:mm:ss") + " Syslog " + data.Severity + " " + data.ComputerName + " SWELF " + data.GET_XML_of_Log;

                    }
                case "xml":
                    {
                        return data.GET_XML_of_Log;
                    }
                default:
                    {
                        return data.EventData;
                    }
            }
        }
    }
}
