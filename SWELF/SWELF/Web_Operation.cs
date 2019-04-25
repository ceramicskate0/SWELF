using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Security.Cryptography;

namespace SWELF
{
    internal class Web_Operation
    {
        private static WebClient Wclient = new WebClient();//.net webclient to pull down central config file
        //cached web config hashs 
        internal static List<string> Config_Files_on_the_Web_Server = new List<string>();

        //cache web data
        private static string Central_Config_File_Web_Cache = "";

        internal static void UPDATE_Local_Config_With_Central_Config(string WebPath, string LocalPath, string FileName)
        {
            if (string.IsNullOrEmpty(Central_Config_File_Web_Cache))
            {
                File_Operation.DELETE_File(LocalPath);//remove old config file
                Wclient.DownloadFile(WebPath, LocalPath); //if match read local files
            }
            else
            {
                File_Operation.DELETE_File(LocalPath);//remove old config file
                File_Operation.APPEND_AllTXT(LocalPath, Central_Config_File_Web_Cache);
            }
            Error_Operation.Log_Error("GET_Central_Config_File()", "Updated " + FileName + " from " + WebPath + ". It was downloaded to " + LocalPath, Error_Operation.LogSeverity.Verbose, Error_Operation.EventID.SWELF_Central_Config_Changed);//log change
            if (File_Operation.CHECK_File_Encrypted(LocalPath) == false)
            {
                Crypto_Operation.Secure_File(LocalPath);
            }
        }

        internal static void GET_All_Files_HTTP(string Web_Config_URL)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(Web_Config_URL);
            request.AllowAutoRedirect = false;
            request.UnsafeAuthenticatedConnectionSharing = false;
            request.Timeout = 150000;

            ServicePointManager.Expect100Continue = true;
            ServicePointManager.CheckCertificateRevocationList = false;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls | SecurityProtocolType.Ssl3;

            using (CustomWebClient response = new CustomWebClient())
            {
                string WebContents = "";

                if (string.IsNullOrEmpty(Central_Config_File_Web_Cache))
                {
                    WebContents = response.DownloadString(Web_Config_URL);//this will make app try to download data only once
                    Central_Config_File_Web_Cache = WebContents;
                }
                else
                {
                    WebContents = Central_Config_File_Web_Cache;
                }
                Regex regex = new Regex(GET_DirectoryListingRegexForUrl(WebContents));
                MatchCollection matches = regex.Matches(WebContents);
                if (matches.Count > 0)
                {
                    if (Config_Files_on_the_Web_Server.Count > 1)
                    {
                        Config_Files_on_the_Web_Server.Clear();
                    }
                    foreach (Match match in matches)
                    {
                        if (match.Success && Web_Config_URL.Contains(".txt") == false && Web_Config_URL.Contains(".conf") == false)
                        {
                            Config_Files_on_the_Web_Server.Add(Web_Config_URL + match.Groups["name"].ToString());
                        }
                        else
                        {
                            Config_Files_on_the_Web_Server.Add(Web_Config_URL);
                        }
                    }
                }
                else
                {
                    Config_Files_on_the_Web_Server.Add(Web_Config_URL);
                }
                WebContents = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
            }
        }

        internal static bool VERIFY_Central_File_Config_Hash(string HTTP_File_Path, string Local_File_Path)
        {
            string HTTPFileHash;
            string LocalFileHash;
            try
            {
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(HTTP_File_Path);
                request.AllowAutoRedirect = false;
                request.UnsafeAuthenticatedConnectionSharing = false;
                request.Timeout = 150000;

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
                        Central_Config_File_Web_Cache = Crypto_Operation.CONVERT_To_String_From_Bytes(response.DownloadData(HTTP_File_Path), 2);//get file has from Network
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
                Error_Operation.WRITE_Errors_To_Log("VERIFY_Central_File_Config_Hash()", e.Message.ToString() + " " + HTTP_File_Path + " " + Local_File_Path, Error_Operation.LogSeverity.Warning);//log change
                return false;
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
    }

    internal class CustomWebClient : WebClient
    {
        protected override WebRequest GetWebRequest(Uri uri)
        {
            WebRequest w = base.GetWebRequest(uri);
            w.Timeout = 15000;
            return w;
        }
    }
}
