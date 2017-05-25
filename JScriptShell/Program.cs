using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Management.Automation.Runspaces;
using System.Management.Automation;
using System.Collections.ObjectModel;

[ComVisible(true)]
public class DarkHorsePS
{
    public DarkHorsePS()
    {

    }

    public void RunPS(string encCommand)
    {
        
        string decodedCommand = @"";
        byte[] byteCommand = Convert.FromBase64String(encCommand);
        decodedCommand = Encoding.ASCII.GetString(byteCommand);
        Runspace runspace = RunspaceFactory.CreateRunspace();
        runspace.Open();
        RunspaceInvoke scriptInvoker = new RunspaceInvoke(runspace);
        Pipeline pipeline = runspace.CreatePipeline();

        //Add commands
        pipeline.Commands.AddScript(decodedCommand);

        //Prep PS for string output and invoke
        pipeline.Invoke();
        runspace.Close();
    }
    
}