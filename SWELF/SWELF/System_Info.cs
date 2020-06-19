//Written by Ceramicskate0
//Copyright 2020
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

namespace SWELF
{
    internal class System_Info
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
            internal int Size;
            internal IntPtr CommitTotal;
            internal IntPtr CommitLimit;
            internal IntPtr CommitPeak;
            internal IntPtr PhysicalTotal;
            internal IntPtr PhysicalAvailable;
            internal IntPtr SystemCache;
            internal IntPtr KernelTotal;
            internal IntPtr KernelPaged;
            internal IntPtr KernelNonPaged;
            internal IntPtr PageSize;
            internal int HandlesCount;
            internal int ProcessCount;
            internal int ThreadCount;
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

        internal static decimal CHECK_Total_Memory_Useage()
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

        internal static bool Is_SWELF_Running(int thresholdvalue=2)
        {
            int count = 0;
            foreach (Process theprocess in GET_Running_Processes())
            {
                if (theprocess.ProcessName.ToLower().Equals(Settings.SWELF_PROC_Name.ProcessName.ToLower()))
                {
                    ++count;
                    if (count >= thresholdvalue)
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        internal static void CHECK_Memory()
        {
            if (CHECK_Total_Memory_Useage() <= SWELF_Memory_MIN_Threshold)
            {
                if (Current_Memory_Dump_Retry_Number >= Max_Memory_Dump_Retry_Number)
                {
                    Settings.Stop(Settings.SWELF_CRIT_ERROR_EXIT_CODE, "CHECK_Memory()", "SWELF Detected MAXIMUM Memory useage and stopped after " + Max_Memory_Dump_Retry_Number.ToString() + " tries to resolve issue.","",Error_Operation.LogSeverity.Critical);
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
