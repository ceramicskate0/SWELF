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
        private static List<IPAddress> IPAddr = Settings.GET_LogCollector_Location();
        private static int port = Settings.LogForwardLocation_Port;

        public static void SEND_Eventlogs(EventLogEntry Data)
        {
            UdpClient udpClient = new UdpClient(11000);
            try
            {
                for (int x = 0; x < IPAddr.Count; ++x)
                {
                    udpClient.Connect(IPAddr.ElementAt(x).MapToIPv4().ToString(), port);
                    Byte[] sendBytes = Encoding.ASCII.GetBytes(GET_Log_OutputFormat(Data));
                    udpClient.Send(sendBytes, sendBytes.Length);
                    IPEndPoint RemoteIpEndPoint = new IPEndPoint(IPAddress.Any, 0);
                    udpClient.Close();
                }
            }
            catch (Exception e)
            {
                Errors.Log_Error("SWELF NETWORK ERROR: ", e.Message.ToString());
            }
        }

        public static void SEND_Log(string Data)
        {
            UdpClient udpClient = new UdpClient(11000);
            try
            {
                for (int x = 0; x < IPAddr.Count; ++x)
                {
                    udpClient.Connect(IPAddr.ElementAt(x).MapToIPv4().ToString(), port);
                    Byte[] sendBytes = Encoding.ASCII.GetBytes(Data);
                    udpClient.Send(sendBytes, sendBytes.Length);
                    IPEndPoint RemoteIpEndPoint = new IPEndPoint(IPAddress.Any, 0);
                    udpClient.Close();
                }
            }
            catch (Exception e)
            {
                Errors.Log_Error("SWELF SEND_Log ERROR: ", e.Message.ToString());
            }
        }

        public static void SEND_Data_from_File(string Data)
        {
            UdpClient udpClient = new UdpClient(11001);
            try
            {
                for (int x = 0; x < IPAddr.Count; ++x)
                {
                    udpClient.Connect(IPAddr.ElementAt(x).MapToIPv4().ToString(), port);
                    Byte[] sendBytes = Encoding.ASCII.GetBytes(Data);
                    udpClient.Send(sendBytes, sendBytes.Length);
                    IPEndPoint RemoteIpEndPoint = new IPEndPoint(IPAddress.Any, 0);
                    udpClient.Close();
                }
            }
            catch (Exception e)
            {
                Errors.Log_Error("SWELF NETWORK ERROR: ", e.Message.ToString());
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

        private static int FIND_Open_SourcePort()
        {
            int startingAtPort = 11000;
            int maxNumberOfPortsToCheck = 500;
            var range = Enumerable.Range(startingAtPort, maxNumberOfPortsToCheck);
            var portsInUse =
                from p in range
                join used in System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners()
            on p equals used.Port
                select p;
            int FirstFreeUDPPortInRange = range.Except(portsInUse).FirstOrDefault();
            return FirstFreeUDPPortInRange;
        }
    }
}
