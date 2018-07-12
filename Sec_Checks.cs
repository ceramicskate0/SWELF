using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;
using System.IO;
using System.Diagnostics;
using System.Management;

namespace SWELF
{
    class Sec_Checks
    {
        public static bool Run_Sec_Checks()
        {
         if(Check_EventLog_Service() &&
            Check_Reg_Keys())
            {
                return true;
            }
         else
               return false;
        }

        private static bool Check_Service_DLL()
        {
            return Settings.VERIFY_if_File_Exists("C:\\Windows\\System32\\wevtsvc.dll");
        }

        private static bool Check_Reg_Keys()
        {
            List<string> RegKeys = new List<string>
            {
                @"System\CurrentControlSet\Services\Eventlog"
            };
            for (int x = 0; x < RegKeys.Count; ++x)
            {
                try
                {
                    RegistryKey reg = Registry.LocalMachine.OpenSubKey(RegKeys.ElementAt(x));
                    if (reg != null)
                    {
                    }
                    else
                        return false;
                }
                catch (Exception e)
                {
                    Errors.WRITE_Errors_To_Log("Check_Reg_Keys()", "FAILED Security Check Registry "+e.Message.ToString(), Errors.LogSeverity.Critical);
                  return false;
                }
            }
            return true;
        }

        private static bool Check_EventLog_Service()
        {
            try
            {
                using (ServiceController sc = new ServiceController("EventLog"))
                {
                    if (sc.Status==ServiceControllerStatus.Running)
                        return true;
                    else
                        return false;
                }
            }
            catch { return false; }
        }


    }
}
