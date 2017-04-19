function Invoke-WindowsEnum{

    <#
    .SYNOPSIS
    Enumerates the local host to gather information about the current user, AD and local group memberships, last 5 files opened, clipboard contents, and interesting files owned by the user. 
    Also enumerates system information such as the OS version, Services, installed applications, available shares, Anti-Virus Software and current status, firewall rules, and when the last windows update 
    was installed. 

    .DESCRIPTION
    This script conducts user, system, and network enumeration using the current user context or with a specified user and/or keyword. 

    .PARAMETER UserName
    Specify a user to enumerate. The default is the current user context. 

    .PARAMETER keywords
    Specify a keyword or array of keywords to use in file searches. 
    
    .EXAMPLE
    Conduct enumeration with a keyword for file searches. 
    
    Invoke-WindowsEnum -keyword "putty"
    
    .EXAMPLE
    Conduct enumeration with a username and keyword
    
    Invoke-WindowsEnum -User "sandersb" 

    .LINK
    https://github.com/xorrior/RandomPS-Scripts/blob/master/Invoke-WindowsEnum.ps1
    
    Author: Christopher Ross (@xorrior)
    License: BSD 3-Clause
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False,Position=0)]
        [string]$UserName,
        [Parameter(Mandatory=$False,Position=1)]
        [string[]]$keywords
    )


#function for enumerating user informtaion
    function Get-UserInfo
    {
        #check if the $user param has been defined 
        if($UserName)
        {
            "UserName: $UserName"
            "-----------------`n"
            $DomainUser = $UserName   
        
        }
        else
        {
            $DomainUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $UserName = $DomainUser.split('\')[-1]
            "UserName: $UserName"
            "-------------------`n"
        }

        #Grab the local group memberships of the user 
        #http://stackoverflow.com/questions/21280666/how-to-get-the-groups-of-a-local-user-through-powershell-script
        "Local Group Memberships"
        "---------------------------"
        #Iterate through all local groups to see if our user is a member
        $computername = $env:computername
        $server = "localhost"
        $computer = [ADSI]"WinNT://$server,computer"
        $computer.psbase.children | where-object {$_.psbase.chemaClassName -eq 'group'} | ForEach-Object {
            $groupname = $_.Name
            $group = [ADSI]$_.psbase.path
            $group.psbase.invoke("Members") | ForEach-Object {
                $member = $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
                if($member -eq $UserName)
                {
                    $groupname
                }
            }
        }

        "`n"
        #Grab all the Active Directory Group memberships for the current user 
        "Active Directory Group Memberships"
        "----------------------------------"

         #https://social.technet.microsoft.com/Forums/scriptcenter/en-US/c8001c25-edb5-44b2-ad07-37b39285995f/systemdirectoryservicesaccountmanagement-and-powershell?forum=ITCG
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        #Load assembly to User Principal and principalContext .Net classes
        $dsclass = "System.DirectoryServices.AccountManagement"
        $dsclassUP = "$dsclass.userprincipal" -as [type] 
        $iType = "SamAccountName"
        $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        #Get the current domain 
        $contextTypeDomain = New-object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain,$Domain.Name) 
        #Set the context to the current domain 
        $cName = $Domain.GetDirectoryEntry().distinguishedName
        #Get the distinguishedName for the domain 
        $usr = $dsclassUP::FindByIdentity($contextTypeDomain,$iType,$DomainUser)
        #Grab the user principal object for the domain.
        $usr.GetGroups() | foreach {$_.Name}
        #Enumerate all groups the user is apart of
        "`n"

        #Check when the user last changed their password
        "User last changed their password on"
        "------------------------------------"
        Write-Host $usr.LastPass
        Write-Host "`n"

        #Grab the files owned by the user that were last opened and sort by date accessed.

        "Last Five files opened"
        "-----------------------------------"
        $AllOpenedFiles = Get-ChildItem -Path "C:\" -Recurse -Include @("*.txt","*.pdf","*.docx","*.doc","*.xls","*.ppt") -ErrorAction SilentlyContinue | Sort-Object {$_.LastAccessTime}
        $script:LastOpenedFiles = @()
        $AllOpenedFiles | % {
            $owner = $_.GetAccessControl().Owner
            $owner = $owner.split('\')[-1]
            if($owner -eq $UserName){
                $script:LastOpenedFiles += $_
            }
        }
        if($script:LastOpenedFiles)
        {
            $script:LastOpenedFiles | Sort-Object LastAccessTime -Descending | select FullName, LastAccessTime -First 5 | Format-Table -AutoSize
        }
        "`n"
        #Search the entire host for any interesting artifacts owned by the user
        "Interesting Files"
        "----------------------------------"
        $script:NewestInterestingFiles = @()
        if($keywords)
        {
            $AllInterestingFiles = Get-ChildItem -Path "C:\" -Recurse -Include $keywords -ea SilentlyContinue | where {$_.Mode.StartsWith('d') -eq $False} | Sort-Object {$_.LastAccessTime}
            $AllInterestingFiles | ForEach-Object {
                $owner = $_.GetAccessControl().Owner
                $owner = $owner.split('\')[-1]
                if($owner -eq $UserName){
                    $script:NewestInterestingFiles += $_
                }
            } 
            if($script:NewestInterestingFiles){
                $script:NewestInterestingFiles | Sort-Object LastAccessTime -Descending | Select-Object FullName, LastAccessTime | Format-Table -AutoSize
            }
        }
        else
        {
            $AllInterestingFiles = Get-ChildItem -Path "C:\" -Recurse -Include @("*.txt","*.pdf","*.docx","*.doc","*.xls","*.ppt","*pass*","*cred*") -ErrorAction SilentlyContinue | where {$_.Mode.StartsWith('d') -eq $False} | Sort-Object {$_.LastAccessTime} 
            $AllInterestingFiles | ForEach-Object {
                $owner = $_.GetAccessControl().Owner
                $owner = $owner.split('\')[-1]
                if($owner -eq $UserName){
                    $script:NewestInterestingFiles += $_
                }
            }
            if($script:NewestInterestingFiles)
            {
                $script:NewestInterestingFiles | Sort-Object LastAccessTime -Descending | Select-Object FullName, LastAccessTime | Format-Table -AutoSize
            }
        }
        "`n"
        #Grab the contents of the clipboard. 
        "Clipboard contents"
        "-----------------------------------"
         #http://www.bgreco.net/powershell/get-clipboard/
        
        $cmd = {
            Add-Type -Assembly PresentationCore
            [Windows.Clipboard]::GetText() -replace "`r", '' -split "`n"  
        }
        if([threading.thread]::CurrentThread.GetApartmentState() -eq 'MTA')
        {
            & powershell -Sta -Command $cmd
        }
        else
        {
            $cmd
        }        

        "`n"
    }

    #Function to enumerate the local system
    function Get-Sysinfo
    {
        #Grab the OS architecture
        "System Information"
        "------------------------"
        $OSVersion = (Get-WmiObject -class Win32_OperatingSystem).Caption
        $OSArch = (Get-WmiObject -class win32_operatingsystem).OSArchitecture
        "OS: $OSVersion $OSArch"
        "`n"

        #Enumerate installed applications

        "Services"
        "-------------------"
        $script:AllServices = @()
        Get-WmiObject -class win32_service | ForEach-Object{
            $service = New-Object PSObject -Property @{
                ServiceName = $_.DisplayName
                ServiceStatus = (Get-service | where-object { $_.DisplayName -eq $ServiceName}).status
                ServicePathtoExe = $_.PathName
                StartupType = $_.StartMode
            }
            $script:AllServices += $service  
        }

        $script:AllServices | Select ServicePathtoExe, ServiceName | Format-Table -AutoSize


        "Installed Appications"
        "-----------------------" 
        if($OSArch -eq '64-bit')
        {
            $registeredAppsx64 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName | Sort-Object DisplayName
            $registeredAppsx86 = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName | Sort-Object DisplayName
            $registeredAppsx64 | Where-Object {$_.DisplayName -ne ' '} | Select-Object DisplayName | Format-Table -AutoSize
            $registeredAppsx86 | Where-Object {$_.DisplayName -ne ' '} | Select-Object DisplayName | Format-Table -AutoSize
        }
        else
        {
            $registeredAppsx86 =  Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName | Sort-Object DisplayName
            $registeredAppsx86 | Where-Object {$_.DisplayName -ne ' '} | Select-Object DisplayName | Format-Table -AutoSize  
        }

        "`n"


        "Available shares"
        "--------------------"

        Get-WmiObject -class win32_share | Format-Table -AutoSize Name, Path, Description, Status

        "`n"


        #Enumerate the installed AV solution, if any
        "Anti-Virus Installed"
        "---------------------"
        $AV = Get-WmiObject -namespace root\SecurityCenter2 -class Antivirusproduct
        if($AV)
        {
            $AV.DisplayName
            #Microsoft does not provide documentation on values pertaining to the productState property for different AV vendors.
            #Best resource found : http://neophob.com/2010/03/wmi-query-windows-securitycenter2/
            $AVstate = $AV.productState
            $statuscode = '{0:X6}' -f $AVstate
            $wscprovider = $statuscode[0,1] -join '' -as [byte]
            $wscscanner = $statuscode[2,3] -join '' -as [byte]
            $wscupdated = $statuscode[4,5] -join '' -as [byte]
            #parse the values to determine the 'health' of the AV product 

            #parse the wscanner value to determine if AV is enabled 
            if($wscscanner -ge (10 -as [byte]))
            {
                "Enabled: Yes"
            }
            elseif($wscscanner -eq (00 -as [byte]) -or $wscscanner -eq (01 -as [byte]))
            {
                "Enabled: No"
            }
            else
            {
                "Enabled: Unknown"
            }

            #Determine if the AV definitions are up to date
            if($wscupdated -eq (00 -as [byte]))
            {
                "Updated: Yes"
            }
            elseif($wscupdated -eq (10 -as [byte]))
            {
                "Updated: No"
            }
            else
            {
                "Updated: Unknown"
            }



        }
        else
        {
            "Anti-Virus not installed."
        }
        "`n"
        "Windows Last Updated"
        "--------------------`n"

        $Lastupdate = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object InstalledOn -First 1
        If($Lastupdate)
        {
            $Lastupdate.InstalledOn | Out-Host
            "`n"
        }
        else
        {
            "Unknown`n"
        }

    }
      
    #Function to enumerate network information 



    function Get-NetInfo
    {


        #Check if the host is dual homed 
        "Network Adapters"
        "----------------------`n"
        #http://thesurlyadmin.com/2013/05/20/using-powershell-to-get-adapter-information/

        $NetAdapters = Get-WmiObject -class win32_networkadapter -Filter "NetConnectionStatus='2'"
        foreach ($Adapter in $NetAdapters){
            $config = Get-WmiObject -class win32_networkadapterconfiguration -Filter "Index = '$($Adapter.Index)'"
            "Adapter: " + $Adapter.Name
            "IP Address: "
            if($config.IPAddress -is [system.array])
            {
                $config.IPAddress[0]
            }
            else
            {
                $config.IPAddress
            }
            "Mac Address: " + $Config.MacAddress

        }

       "`n"
        
        "Mapped Network Drives"
        "----------------------`n"
        #Device type 4 is specifically for network drives 
        Get-WmiObject -class win32_logicaldisk | where-object {$_.DeviceType -eq 4} | ForEach-Object{
            $NetPath = $_.ProviderName
            $DriveLetter = $_.DeviceID
            $DriveName = $_.VolumeName
            $NetworkDrive = New-Object PSObject -Property @{
                Path = $NetPath
                Drive = $DriveLetter
                Name = $DriveName
            }
            $NetworkDrive | Format-Table -wrap -auto
        }

        #Enumerate firewall rules   
        "`n"
        "Firewall Information"
        "----------------------`n"
        #Create the firewall com object to enumerate 
        $fw = New-Object -ComObject HNetCfg.FwPolicy2 
        #Retrieve all firewall rules 
        $FirewallRules = $fw.rules 
        #create a hashtable to define all values
        $fwprofiletypes = @{1GB="All";1="Domain"; 2="Private" ; 4="Public"}
        $fwaction = @{1="Allow";0="Block"}
        $FwProtocols = @{1="ICMPv4";2="IGMP";6="TCP";17="UDP";41="IPV6";43="IPv6Route"; 44="IPv6Frag";
                  47="GRE"; 58="ICMPv6";59="IPv6NoNxt";60="IPv60pts";112="VRRP"; 113="PGM";115="L2TP"}
        $fwdirection = @{1="Inbound"; 2="Outbound"} 

        #Retrieve the profile type in use and the current rules

        $fwprofiletype = $fwprofiletypes.Get_Item($fw.CurrentProfileTypes)
        $fwrules = $fw.rules

        "Current Firewall Profile Type in use: $fwprofiletype"
        $script:AllFWRules = @()
        #enumerate the firewall rules
        $fwrules | ForEach-Object{
            #Create custom object to hold properties for each firewall rule 
            $FirewallRule = New-Object PSObject -Property @{
                ApplicationName = $_.Name
                Protocol = $fwProtocols.Get_Item($_.Protocol)
                Direction = $fwdirection.Get_Item($_.Direction)
                Action = $fwaction.Get_Item($_.Action)
                LocalIP = $_.LocalAddresses
                LocalPort = $_.LocalPorts
                RemoteIP = $_.RemoteAddresses
                RemotePort = $_.RemotePorts
            }

            $script:AllFWRules += $FirewallRule

            
        } 
        $script:AllFWRules | Select-Object Action, Direction, RemoteIP, RemotePort, LocalPort, ApplicationName | Format-Table -Auto

    }

    Get-UserInfo
    Get-Sysinfo
    Get-NetInfo


}
