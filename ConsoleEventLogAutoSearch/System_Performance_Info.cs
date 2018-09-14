using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SWELF
{
    class System_Performance_Info
    {
        //SWELF MEMORY USAGE INFO
        private static Int64 phav = System_Performance_Info.GetPhysicalAvailableMemoryInMiB();
        private static Int64 tot = System_Performance_Info.GetTotalMemoryInMiB();
        private static decimal percentFree = ((decimal)phav / (decimal)tot) * 100;
        private static decimal percentOccupied = 100 - percentFree;
        private static decimal Available_Physical_Memory = phav;
        private static decimal Total_Memory = tot;
        private static decimal Percent_Free = percentFree;
        private static decimal Percent_Used = percentOccupied;
        public static int Current_Memory_Dump_Retry_Number = 0;
        public static int Max_Memory_Dump_Retry_Number = 5;
        public static decimal SWELF_Memory_MIN_Threshold = 10;
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

        public static Int64 GetPhysicalAvailableMemoryInMiB()
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

        public static Int64 GetTotalMemoryInMiB()
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

        public static long Get_Allocated_Memory()
        {
            return Process.GetCurrentProcess().WorkingSet64 / 1000000;
        }

        public static decimal CHECK_Total_Memory_Useage()
        {
            Int64 phav = System_Performance_Info.GetPhysicalAvailableMemoryInMiB();
            Int64 tot = System_Performance_Info.GetTotalMemoryInMiB();
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
    }
}
