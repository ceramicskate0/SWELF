//Written by Ceramicskate0
//Copyright 2018
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;

namespace SWELF
{
    public class System_Info
    {
        //SWELF MEMORY USAGE INFO
        private static Int64 PhysicalAvailableMemory = System_Info.GetPhysicalAvailableMemoryInMiB();
        private static Int64 tot = System_Info.GetTotalMemoryInMiB();
        private static decimal percentFree = ((decimal)PhysicalAvailableMemory / (decimal)tot) * 100;
        private static decimal percentOccupied = 100 - percentFree;
        private static decimal Available_Physical_Memory = PhysicalAvailableMemory;
        private static decimal Total_Memory = tot;
        private static decimal Percent_Free = percentFree;
        private static decimal Percent_Used = percentOccupied;
        private static int Current_Memory_Dump_Retry_Number = 0;
        private static int Max_Memory_Dump_Retry_Number = 5;
        private static decimal SWELF_Memory_MIN_Threshold = 10;

        [DllImport("psapi.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetPerformanceInfo([Out] out PerformanceInformation PerformanceInformation, [In] int Size);

        [StructLayout(LayoutKind.Sequential)]
        private struct PerformanceInformation
        {
            public int Size;
            public IntPtr CommitTotal;
            public IntPtr CommitLimit;
            public IntPtr CommitPeak;
            public IntPtr PhysicalTotal;
            public IntPtr PhysicalAvailable;
            public IntPtr SystemCache;
            public IntPtr KernelTotal;
            public IntPtr KernelPaged;
            public IntPtr KernelNonPaged;
            public IntPtr PageSize;
            public int HandlesCount;
            public int ProcessCount;
            public int ThreadCount;
        }

        private static Int64 GetPhysicalAvailableMemoryInMiB()
        {
            PerformanceInformation pi = new PerformanceInformation();
            if (GetPerformanceInfo(out pi, Marshal.SizeOf(pi)))
            {
                return Convert.ToInt64((pi.PhysicalAvailable.ToInt64() * pi.PageSize.ToInt64() / 1048576));
            }
            else
            {
                return -1;
            }

        }

        public static string GetProcessOwner(int processId)
        {
            string query = "Select * From Win32_Process Where ProcessID = " + processId;
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
            ManagementObjectCollection processList = searcher.Get();

            foreach (ManagementObject obj in processList)
            {
                string[] argList = new string[] { string.Empty, string.Empty };
                int returnVal = Convert.ToInt32(obj.InvokeMethod("GetOwner", argList));
                if (returnVal == 0)
                {
                    // return DOMAIN\user
                    return argList[1] + "\\" + argList[0];
                }
            }

            return "NO OWNER";
        }

        private static Int64 GetTotalMemoryInMiB()
        {
            PerformanceInformation pi = new PerformanceInformation();
            if (GetPerformanceInfo(out pi, Marshal.SizeOf(pi)))
            {
                return Convert.ToInt64((pi.PhysicalTotal.ToInt64() * pi.PageSize.ToInt64() / 1048576));
            }
            else
            {
                return -1;
            }

        }

        private static long Get_Allocated_Memory()
        {
            return Process.GetCurrentProcess().WorkingSet64 / 1000000;
        }

        public static decimal CHECK_Total_Memory_Useage()
        {
            Int64 phav = System_Info.GetPhysicalAvailableMemoryInMiB();
            Int64 tot = System_Info.GetTotalMemoryInMiB();
            percentFree = ((decimal)phav / (decimal)tot) * 100;
            percentOccupied = 100 - percentFree;
            Available_Physical_Memory = phav;
            Total_Memory = tot;
            Percent_Free = percentFree;
            Percent_Used = percentOccupied;

            if (phav < 0 || tot < 0 || Available_Physical_Memory < 0)
            {
                return -1;
            }
            return percentFree;
        }

        private static List<Process> GET_Running_Processes()
        {
            return Process.GetProcesses().ToList();
        }

        public static bool Is_SWELF_Running(int thresholdvalue=2)
        {
            int count = 0;
            foreach (Process theprocess in GET_Running_Processes())
            {
                if (theprocess.ProcessName.ToLower().Equals(Settings.SWELF_PROC_Name.ProcessName.ToLower()))
                {
                    ++count;
                    if (count >= thresholdvalue)
                    {
                        return false;
                    }
                }
            }
            return true;
        }

        public static void CHECK_Memory()
        {
            if (CHECK_Total_Memory_Useage() <= SWELF_Memory_MIN_Threshold)
            {
                if (Current_Memory_Dump_Retry_Number >= Max_Memory_Dump_Retry_Number)
                {
                    Errors.Log_Error("CHECK_Memory() ", "SWELF Detected MAXIMUM Memory useage and stopped after " + System_Info.Max_Memory_Dump_Retry_Number.ToString() + " tries to resolve issue.", Errors.LogSeverity.Critical,EventLog_SWELF.SWELF_MAIN_APP_ERROR_EVTID);
                    EventLog_SWELF.WRITE_Critical_EventLog("SWELF Detected MAXIMUM Memory useage and stopped after " + System_Info.Max_Memory_Dump_Retry_Number.ToString() + " tries to resolve issue.",EventLog_SWELF.SWELF_MAIN_APP_ERROR_EVTID);
                    Settings.Stop(Settings.SWELF_CRIT_ERROR_EXIT_CODE);
                }
                else
                {
                    Current_Memory_Dump_Retry_Number++;
                    Program.Start_Output_Post_Run();
                }
            }
        }
    }
}
