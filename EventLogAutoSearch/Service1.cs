using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics.Eventing;

namespace EventLogAutoSearch
{
    public partial class Service1 : ServiceBase
    {
        public Service1()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            System.Diagnostics.EventLog log = new
            System.Diagnostics.EventLog("Sysmon");
        }

        protected override void OnStop()
        {

        }
    }
}
