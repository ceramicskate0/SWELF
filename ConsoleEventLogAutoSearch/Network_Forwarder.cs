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
        private static UdpClient UDP_Packet_Sender_Method = new UdpClient(Settings.GET_LogCollector_Location().ToString() , Settings.LogForwardLocation_Port);
        private static string EncodedString = "";

        private static IPEndPoint UDPClient = new IPEndPoint(Settings.GET_LogCollector_Location(), Settings.LogForwardLocation_Port);
        private static Socket SocClinet = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

        public static void SEND_Data_from_Eventlogs(EventLogEntry Data)
        {
            byte[] ByteData = Encoding.ASCII.GetBytes(GET_Log_OutputFormat(Data));
            SocClinet.SendTo(ByteData, UDPClient);
        }

        public static void SEND_Data_from_File(string Data)
        {
            byte[] ByteData = Encoding.ASCII.GetBytes(Data);
            SocClinet.SendTo(ByteData, UDPClient);
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
