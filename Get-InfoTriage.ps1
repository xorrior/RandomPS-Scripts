function Get-InfoTriage{

    <#
    .SYNOPSIS
    Collects all revelant information about a host and the current user context.


    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False,Position=1)]
        [string]$User,
        [Parameter(Mandatory=$False)]
        [string]$keyword,
        [Parameter(Mandatory=$False)]
        [switch]$UserInfo,
        [Parameter(Mandatory=$False)]
        [switch]$SysInfo,
        [Parameter(Mandatory=$False)]
        [switch]$NetInfo
    )


    If($UserInfo){
        if($User){
            "UserName: $User`n"
            $UserName = $User  
        }
        else{
             #If the username was not provided, 
            $DomainUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $UserName = $DomainUser.split('\')[-1]
            "UserName: $UserName`n"
            
        }

        
        "-------------------------"
        "Local Group Memberships"
        "-------------------------`n"
        #http://stackoverflow.com/questions/21280666/how-to-get-the-groups-of-a-local-user-through-powershell-script
        $computername = $env:computername
        $server = "."  
        $computer = [ADSI]"WinNT://$server,computer"
        $computer.psbase.children | where {$_.psbase.schemaClassName -eq 'group'} | foreach {
            $groupname = $_.Name 
            $group = [ADSI]$_.psbase.path
            $group.psbase.invoke("Members") | 
            foreach {
                $member = $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
                if($member -eq $UserName){
                    Write-Host "$groupname `n"
                }
            }
        }
        
        
       

        "--------------------------"
        "AD Group Memberships"
        "-----------------------------`n"
        #https://social.technet.microsoft.com/Forums/scriptcenter/en-US/c8001c25-edb5-44b2-ad07-37b39285995f/systemdirectoryservicesaccountmanagement-and-powershell?forum=ITCG        $DC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers[0] #Grab the primary DC
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        #Load assembly to User Principal and principalContext .Net classes
        $dsclass = "System.DirectoryServices.AccountManagement"
        $dsclassUP = "$dsclass.userprincipal" -as [type] 
        $iType = "SamAccountName"
        $contextTypeDomain = [System.DirectoryServices.AccountManagement.ContextType]::Domain 
        #Set the context to the current domain  
        $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        #Get the current domain 
        $cName = $Domain.GetDirectoryEntry().distinguishedName
        #Get the distinguishedName for the domain 
        $UserPrincipal = $dsclassUP::FindByIdentity($contextTypeDomain,$iType,$DomainUser)
        #Grab the user principal object for the domain.
        $UserPrincipal.GetGroups() | % {$_.Name + "`n"}
        #Enumerate all groups the user is apart of
        
        "-------------------------------"
        "Password Last changed"
        "--------------------------------`n"

        $Userprincipal.LastPasswordSet
        Write-Host "`n"
            
        "---------------------------------"
        "Last 3 files opened "
        "----------------------------------`n"
            
        $LastOpenedFiles = gci -Path "C:\Users\$Username" -Recurse -Include @("*.txt","*.pdf","*.docx","*.doc","*.xls","*.ppt") -ea SilentlyContinue | sort {$_.LastAccessTime} | select -First 3 
        if($LastOpenedFiles){
            foreach ($file in $LastOpenedFiles){
                "Filepath: " + $file.FullName + "`n"
                "Last Accessed: " + $file.LastAccessTime + "`n"    
            }
        }
        
        "-------------------------------------"
        "Interesting Files"
        "-------------------------------------`n"
        if($keyword){
            $interestingFiles = gci -Path "C:\Users\$Username" -Recurse -Include @($keyword) -ea SilentlyContinue | where {$_.Mode.StartsWith('d') -eq $False} | sort {$_.LastAccessTime} | select -First 10
            if($interestingFiles){
                foreach($file in $interestingFiles){
                    "Filepath: " + $file.FullName + "`n"
                    "Last Accessed: " + $file.LastAccessTime + "`n"
                }
            }
        }
        else{
             $interestingFiles = gci -Path "C:\Users\$Username" -Recurse -Include @("*pass*","*admin*","*config*","*cred*","*key*","*ssh*","*putty*","*vpn*") -ea SilentlyContinue | where {$_.Mode.StartsWith('d') -eq $False} 
             if($interestingFiles){
                 foreach($file in $interestingFiles){
                     "Filepath: " + $file.FullName + "`n"
                     "Last Accessed: " + $file.LastAccessTime + "`n"
                }
             }            
        }
        
        "-------------------------------------"
        "Clipboard Contents"
        "-------------------------------------`n"
        #http://www.bgreco.net/powershell/get-clipboard/
        
        $cmd = {
            Add-Type -Assembly PresentationCore
            [Windows.Clipboard]::GetText() -replace "`r", '' -split "`n"  
        }
        if([threading.thread]::CurrentThread.GetApartmentState() -eq 'MTA'){
            & powershell -Sta -Command $cmd
        }
        else{
            $cmd
        }

    }
      

    
   


}