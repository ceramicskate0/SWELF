//Written by Ceramicskate0
//Copyright 2017
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleEventLogAutoSearch
{
    class APP_API
    {
        public List<string> Hashes_From_EventLog = new List<string>();
        public List<string> IP_From_EventLog = new List<string>();

        public void Add_IP(List<string> ListofIP)
        {
            foreach (string item in ListofIP)
            {
                IP_From_EventLog.Add(item);
            }
        }

    }
}
