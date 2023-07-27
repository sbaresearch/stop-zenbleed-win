# Based of https://github.com/eclypsium/Screwed-Drivers/blob/34e7819651cb083a536965854b60d427991cc380/PowerShell/ASRock_readmsr.ps1
# Based of FuzzeySec example code located at https://www.fuzzysecurity.com/tutorials/expDev/23.html

Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

public static class Driver
{
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern IntPtr CreateFile(
        String lpFileName,
        UInt32 dwDesiredAccess,
        UInt32 dwShareMode,
        IntPtr lpSecurityAttributes,
        UInt32 dwCreationDisposition,
        UInt32 dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("Kernel32.dll", SetLastError = true)]
    public static extern bool DeviceIoControl(
        IntPtr hDevice,
        int IoControlCode,
        byte[] InBuffer,
        int nInBufferSize,
        byte[] OutBuffer,
        int nOutBufferSize,
        ref int pBytesReturned,
        IntPtr Overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,
        uint dwSize,
        UInt32 flAllocationType,
        UInt32 flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@

function InstallDriver {
    [Console]::Out.Flush()
    sc.exe create WinRing0_1_2_0 type=kernel binpath="$PSScriptRoot\WinRing0\WinRing0x64.sys"
    if ($LastExitCode -ne 0) {
        throw "Driver installation failed"
    }
}

function UninstallDriver {
    [Console]::Out.Flush()
    sc.exe delete WinRing0_1_2_0
    if ($LastExitCode -ne 0) {
        throw "Driver uninstallation failed"
    }
}

function StartDriver {
    [Console]::Out.Flush()
    sc.exe start WinRing0_1_2_0
    if ($LastExitCode -ne 0) {
        throw "Driver start failed"
    }
}

function StopDriver {
    [Console]::Out.Flush()
    sc.exe stop WinRing0_1_2_0
    if ($LastExitCode -ne 0) {
        throw "Driver stop failed"
    }
}

function OpenDriver {
    $Device = [Driver]::CreateFile("\\.\WinRing0_1_2_0", [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite, [System.IntPtr]::Zero, 0x3, 0x40000080, [System.IntPtr]::Zero)

    if ($Device -eq -1) {
        throw "Unable to get driver handle"
    }

    return $Device
}

function CloseDriver {
    param([IntPtr]$Device)

    $Result = [Driver]::CloseHandle($Device)
    if (!$Result) {
        throw "CloseHandle failed"
    }
}

function ReadMsr {
    param([IntPtr]$Device, [Int32]$Register)

    #define IOCTL_READ_MSR  CTL_CODE(40000, 0x821, METHOD_BUFFERED, FILE_ANY_ACCESS)
    $IOCTL_READ_MSR = (40000 -shl 16) -bor (0x821 -shl 2)

    $InBuffer = [System.BitConverter]::GetBytes([Int32]$Register)
    $OutBuffer = [System.BitConverter]::GetBytes([UInt64]0)
    $BytesReturned = 0
    $CallResult = [Driver]::DeviceIoControl($Device, $IOCTL_READ_MSR, $InBuffer, $InBuffer.Length, $OutBuffer, $OutBuffer.Length, [ref]$BytesReturned, [System.IntPtr]::Zero)

    if (!$CallResult) {
        throw "DeviceIoControl during ReadMsr failed"
    }
    if ($BytesReturned -ne 8) {
        throw "DeviceIoControl during ReadMsr returned unexpected length"
    }

    return [System.BitConverter]::ToUInt64($OutBuffer, 0)
}

function WriteMsr {
    param([IntPtr]$Device, [Int32]$Register, [UInt64]$Value)

    #define IOCTL_WRITE_MSR CTL_CODE(40000, 0x822, METHOD_BUFFERED, FILE_ANY_ACCESS)
    $IOCTL_WRITE_MSR = (40000 -shl 16) -bor (0x822 -shl 2)

    $InBuffer = @([System.BitConverter]::GetBytes([Int32]$Register) + [System.BitConverter]::GetBytes([UInt64]$Value))
    if ($InBuffer.Length -ne 12) {
        Write-Output "[!] Unexpected input buffer length"
    }
    $OutBuffer = [System.BitConverter]::GetBytes([UInt64]0)
    $BytesReturned = 0
    $CallResult = [Driver]::DeviceIoControl($Device, $IOCTL_WRITE_MSR, $InBuffer, $InBuffer.Length, $OutBuffer, $OutBuffer.Length, [ref]$BytesReturned, [System.IntPtr]::Zero)
    if (!$CallResult) {
        throw "DeviceIoControl during WriteMsr failed"
    }
    if ($BytesReturned -ne 0) {
        throw "DeviceIoControl during WriteMsr returned unexpected length"
    }
}

# Register from https://cmpxchg8b.com/zenbleed.html#workaround
$Register = 0xc0011029

try {
    Write-Output "[>] Installing driver..."
    InstallDriver
    try {
        Write-Output "`n[>] Starting driver..."
        StartDriver
        try {
            Write-Output "`n[>] Opening driver..."
            $Device = OpenDriver
            Write-Output "[+] Driver access OK, handle: $Device`n"

            try {
                $ProcessorCount = [Environment]::ProcessorCount
                $MyProc = Get-Process -Id $PID
                $OrigProcessorAffinity = $MyProc.ProcessorAffinity

                for ($Processor = 0; $Processor -lt $ProcessorCount; $Processor++) {
                    $MyProc.ProcessorAffinity = 1 -shl $Processor

                    for ($Try = 0; $Try -lt 10; $Try++) {
                        $Value = ReadMsr -Device $Device -Register $Register

                        if ((($Value -shr 9) -band 1) -eq 1) {
                            Write-Output ("[+] Fix is applied on processor {0} (MSR 0x{1:X}=0x{2:X})" -f ($Processor + 1), $Register, $Value)
                            break;
                        }

                        Write-Output ("[>] Try {0} to apply fix on processor {1}" -f ($Try + 1), ($Processor + 1))
                        $Value = $Value -bor (1 -shl 9)

                        WriteMsr -Device $Device -Register $Register -Value $Value
                    }
                }

                $MyProc.ProcessorAffinity = $OrigProcessorAffinity
            } finally {
                Write-Output "`n[>] Closing driver..."
                CloseDriver -Device $Device
            }
        } finally {
            Write-Output "`n[>] Stopping driver..."
            StopDriver
        }
    } finally {
        Write-Output "`n[>] Uninstalling driver..."
        UninstallDriver
    }
} catch {
    Write-Output "[!] $_"
}
