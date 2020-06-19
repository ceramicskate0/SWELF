//Written by Ceramicskate0
//Copyright 2020
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Net.NetworkInformation;

namespace SWELF
{
    internal class Web_Operation
    {
        private static WebClient Wclient = new WebClient();//.net webclient to pull down central config file
        //cached web config hashs 
        internal static List<string> Config_Files_on_the_Web_Server = new List<string>();

        //cache web data
        private static string Central_Config_File_Web_Cache = "";
        internal static bool Connection_Successful = true ;
        internal static string UPDATE_Reg_Config_With_Central_Config(string WebPath)
        {
            if (string.IsNullOrEmpty(Central_Config_File_Web_Cache)==false)
            {
                return Wclient.DownloadString(WebPath);
            }
            else
            {
                return "";
            }
        }

        internal static bool VERIFY_Central_File_Config_Hash(string HTTP_File_Path, string Local_File_Path)
        {
            string HTTPFileHash;
            string LocalFileHash;
            try
            {
                ServicePointManager.Expect100Continue = true;
                ServicePointManager.CheckCertificateRevocationList = false;
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls | SecurityProtocolType.Ssl3;

                using (CustomWebClient response = new CustomWebClient())
                {
                    //string Web_Config_File_Contents = response.DownloadString(HTTP_File_Path);
                    if (Settings.Central_Config_Hashs.ContainsKey(HTTP_File_Path) == true)//determine if we use cache version 
                    {
                        HTTPFileHash = Settings.Central_Config_Hashs[HTTP_File_Path];
                    }
                    else//no cache version get from network
                    {
                        Uri uri = new Uri(HTTP_File_Path);
                        Central_Config_File_Web_Cache = Crypto_Operation.CONVERT_To_String_From_Bytes(response.DownloadData(uri), 2);//get file has from Network
                        using (var sha256 = SHA256.Create())
                        {
                            HTTPFileHash = BitConverter.ToString(sha256.ComputeHash(Encoding.UTF8.GetBytes(Central_Config_File_Web_Cache)));
                        }
                        if (Settings.Central_Config_Hashs.ContainsKey(HTTP_File_Path) == false)
                        {
                            Settings.Central_Config_Hashs.Add(HTTP_File_Path, HTTPFileHash);
                        }
                    }
                    using (var sha2562 = SHA256.Create())//Get local file hash
                    {
                        if (File_Operation.CHECK_if_File_Exists(Local_File_Path) == false)
                        {
                            return false;//no local file
                        }
                        else
                        {
                            LocalFileHash = BitConverter.ToString(sha2562.ComputeHash(Encoding.UTF8.GetBytes(File_Operation.READ_AllText(Local_File_Path))));
                        }
                    }

                    if (HTTPFileHash == LocalFileHash)
                    {
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }
            }
            catch (Exception e)
            {
                if ((!e.Message.Contains("The operation has timed out") || !e.Message.Contains("The remote name could not be resolved: ")) || (Settings.Logging_Level_To_Report.ToLower() == "informataion" || Settings.Logging_Level_To_Report.ToLower() == "verbose"))
                {
                    Error_Operation.Log_Error("VERIFY_Central_File_Config_Hash()", e.Message.ToString() + " " + HTTP_File_Path + " " + Local_File_Path,e.StackTrace.ToString(), Error_Operation.LogSeverity.Informataion);
                }
                return false;
            }
            finally
            {
                Wclient.Dispose();
            }
        }

        internal static bool VERIFY_Central_Reg_Config_Hash(string HTTP_File_Path, string RegContents)
        {
            string HTTPFileHash;
            string LocalFileHash;
            try
            {
                ServicePointManager.Expect100Continue = true;
                ServicePointManager.CheckCertificateRevocationList = false;
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls | SecurityProtocolType.Ssl3;

                using (CustomWebClient response = new CustomWebClient())
                {
                    //string Web_Config_File_Contents = response.DownloadString(HTTP_File_Path);
                    if (Settings.Central_Config_Hashs.ContainsKey(HTTP_File_Path) == true)//determine if we use cache version 
                    {
                        HTTPFileHash = Settings.Central_Config_Hashs[HTTP_File_Path];
                    }
                    else//no cache version get from network
                    {
                        Uri uri = new Uri(HTTP_File_Path);
                        Central_Config_File_Web_Cache = Crypto_Operation.CONVERT_To_String_From_Bytes(response.DownloadData(uri), 2);//get file has from Network
                        using (var sha256 = SHA256.Create())
                        {
                            HTTPFileHash = BitConverter.ToString(sha256.ComputeHash(Encoding.UTF8.GetBytes(Central_Config_File_Web_Cache)));
                        }
                        if (Settings.Central_Config_Hashs.ContainsKey(HTTP_File_Path) == false)
                        {
                            Settings.Central_Config_Hashs.Add(HTTP_File_Path, HTTPFileHash);
                        }
                    }
                    using (var sha2562 = SHA256.Create())//Get local file hash
                    {
                       LocalFileHash = BitConverter.ToString(sha2562.ComputeHash(Encoding.UTF8.GetBytes(RegContents)));
                    }
                    Connection_Successful = true;
                    if (HTTPFileHash == LocalFileHash)
                    {
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }
            }
            catch (Exception e)
            {
                Connection_Successful = false;
                if (e.Message.Contains("has timed out")==false && e.Message.Contains("The remote name could not be resolved: ")==false)
                {
                    Error_Operation.Log_Error("VERIFY_Central_File_Config_Hash()", e.Message.ToString() + " " + HTTP_File_Path + " ",e.StackTrace.ToString(), Error_Operation.LogSeverity.Informataion);
                }
                else if ((e.Message.Contains("The operation has timed out") || e.Message.Contains("The remote name could not be resolved: ")))
                {
                    Error_Operation.Log_Error("VERIFY_Central_File_Config_Hash()", "Network unavaiulable for SWELF." +e.Message.ToString() + " " + HTTP_File_Path + " ", e.StackTrace.ToString(),Error_Operation.LogSeverity.Informataion);
                }
                return false;
            }
            finally
            {
                Wclient.Dispose();
            }
        }

        private static string GET_DirectoryListingRegexForUrl(string url)
        {
            if (url.Equals(url))
            {
                return "<a href=\".*\">(?<name>.*)</a>";
            }
            throw new NotSupportedException();
        }

        internal static string GET_HostName(string IP)
        {
            try
            {
                return Dns.GetHostEntry(IPAddress.Parse(Log_Network_Forwarder.Get_IP_from_Socket_string(IP))).HostName.ToString();
            }
            catch (Exception e)
            {
                return Log_Network_Forwarder.Get_IP_from_Socket_string(IP);
            }
        }

        internal static string GET_IP(string Hostname)
        {
            try
            {
                return Dns.GetHostEntry(Hostname).AddressList.ElementAt(0).ToString();
            }
            catch
            {
                return Hostname;
            }
        }

        internal static bool IsNetworkAvailable()
        {
            try
            {
                // only recognizes changes related to Internet adapters
                if (NetworkInterface.GetIsNetworkAvailable())
                {
                    // however, this will include all adapters
                    NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();

                    foreach (NetworkInterface face in interfaces)
                    {
                        // filter so we see only Internet adapters
                        if (face.OperationalStatus == OperationalStatus.Up)
                        {
                            if ((face.NetworkInterfaceType != NetworkInterfaceType.Tunnel) && (face.NetworkInterfaceType != NetworkInterfaceType.Loopback))
                            {
                                IPv4InterfaceStatistics statistics = face.GetIPv4Statistics();
                                //see if any bytes sent recieved
                                if ((statistics.BytesReceived > 500) && (statistics.BytesSent > 500))
                                {
                                    return true;
                                }
                            }
                        }
                    }
                }

                return false;
            }
            catch (Exception e)
            {
                Error_Operation.Log_Error("IsNetworkAvailable()", e.Message.ToString(), e.StackTrace.ToString(), Error_Operation.LogSeverity.Verbose);
                return false;
            }

        }
    }

    internal class CustomWebClient : WebClient
    {
        protected override WebRequest GetWebRequest(Uri uri)
        {
            WebRequest w = base.GetWebRequest(uri);
            w.UseDefaultCredentials = true;
            w.Timeout = 5000;
            return w;
        }
    }
}
