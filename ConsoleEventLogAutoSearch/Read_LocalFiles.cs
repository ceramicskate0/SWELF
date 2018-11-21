//Written by Ceramicskate0
//Copyright 2018
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace SWELF
{
    class Read_LocalFiles
    {
        public static List<string> FileContents_From_FileReads = new List<string> ();
        private static Dictionary<string, int> ReadLocalFiles_Log_File_Tracking = new Dictionary<string, int>();//Filepath,Line Number where it left off

        public static void READ_Local_Log_Files()
        {
            try
            {
                List<string> FilePaths = File.ReadAllLines(File_Operation.GET_FilesToMonitor_Path()).ToList();

                for (int z = 0; z < FilePaths.Count; ++z)
                {
                    string FileContent = File.ReadAllText(FilePaths.ElementAt(z));
                    File.Delete(FilePaths.ElementAt(z));
                    FileContents_From_FileReads.Add("DateTime=" + DateTime.Now.ToString(Settings.SWELF_Date_Time_Format) +"  "+ FileContent);
                }
            }
            catch (Exception e)
            {
                Errors.Log_Error("READ_Local_Log_Files() ", e.Message.ToString(), Errors.LogSeverity.Warning);
            }
        }

        public static void READ_Local_Log_Dirs()
        {
            try
            {
                List<string> DirPaths = File.ReadAllLines(File_Operation.GET_DirToMonitor_Path()).ToList();
                for (int z = 0; z < DirPaths.Count; ++z)
                {
                    if (Directory.Exists(DirPaths.ElementAt(z)))
                    {
                        if (DirPaths.ElementAt(z).ToLower().Contains("powershell") || DirPaths.ElementAt(z).ToLower().Contains("iis"))
                        {
                            READ_Local_Log_Dirs_for_Powershell_or_IIS(DirPaths.ElementAt(z));
                        }
                        else
                        {
                            string[] FilePaths = Directory.GetFiles(DirPaths.ElementAt(z));

                            for (int x = 0; x < FilePaths.Length - 1; ++x)
                            {
                                if (File_Operation.VERIFY_if_File_Exists(FilePaths.ElementAt(x)) && (FilePaths.ElementAt(x).Contains(".txt") || FilePaths.ElementAt(x).Contains(".log")))
                                {
                                    string FileContent = File.ReadAllText(FilePaths.ElementAt(x));
                                    File.Delete(FilePaths.ElementAt(x));
                                    FileContents_From_FileReads.Add(FileContent);
                                }
                            }
                        }
                    }
                }

            }
            catch (Exception e)
            {
                Errors.Log_Error("READ_Local_Log_Dirs() ", e.Message.ToString(), Errors.LogSeverity.Warning);
            }
        }

        private static void READ_Local_Log_Dirs_for_Powershell_or_IIS(string directory)
        {
            try
            {
                if (Directory.Exists(directory))
                {
                    string[] SubDirs = Directory.GetDirectories(directory);

                    for (int x = 0; x < SubDirs.Length; ++x)
                    {
                        string[] FilePaths = Directory.GetFiles(SubDirs[x]);

                        for (int c = 0; c < FilePaths.Length; ++c)
                        {
                            if (FilePaths[c].Contains(".txt") && (FilePaths[c].ToLower().Contains("powershell_transcript.") || FilePaths[c].ToLower().Contains("iis")))
                            {
                                string FileContent = File.ReadAllText(FilePaths.ElementAt(c));
                                File.Delete(FilePaths.ElementAt(c));
                                FileContents_From_FileReads.Add("DateTime=" + DateTime.Now.ToString(Settings.SWELF_Date_Time_Format) + "  " + FileContent);
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Errors.Log_Error("READ_Local_Log_Dirs() ", e.Message.ToString(), Errors.LogSeverity.Warning);
            }
        }
    }
}
