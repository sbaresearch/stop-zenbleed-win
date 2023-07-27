# Stopping Zenbleed (CVE-2023-20593) on Windows

The newly discovered Zenbleed vulnerability (CVE-2023-20593) affects all Zen2 processors from AMD.
Unfortunately, AMD will not provide microcode updates for many of its processors until November or December 2023.
How to stay safe in the meantime?
Luckily, there is a software workaround.
While applying the software workaround is a one-liner on Linux, matters are more complicated on Windows.

To apply the software workaround, a certain bit (the chicken bit `DE_CFG[9]`) has to be set in the MSR CPU register.
As [pointed out by Travis Ormandy](https://cmpxchg8b.com/zenbleed.html#workaround) the following command can be used to avoid Zenbleed on Linux:

```shellsession
# wrmsr -a 0xc0011029 $(($(rdmsr -c 0xc0011029) | (1<<9)))
```

Under Windows setting the MSR register is more difficult.
Only kernel-level drivers are allowed to write to the MSR register.
Moreover, to load a kernel-level driver, it needs to be signed.
That is why we decided to use the existing WinRing0 driver from OpenLibSys.org.
We wrote a PowerShell script that loads WinRing0, sends the appropriate MSR write requests to the drivers and unloads the WinRing0 driver immediately afterwards.
Currently, our PowerShell script only works when Hyper-V is disabled.
Our PowerShell script is hosted here: <https://github.com/sbaresearch/stop-zenbleed-win>

Please note that the PowerShell script does come with a couple of caveats.
Please read the section 'caveats' and perform a risk analysis for your specific environment before using the script.

## Usage

* Run `Stop-Zenbleed.ps1` in a PowerShell 5.x with admin permissions
* The script expects to run only on Zenbleed affected AMD Zen2 CPUs.
  It might cause unexpected issues on other systems, please be careful.

## Caveats

* You need to disable Hyper-V.
  Otherwise the Windows OS itself runs in CPU ring 1 and the kernel-level driver cannot obtain write access to the MSR.
  Disabling Hyper-V unfortunately implies disabling Credential Guard and Device Guard, two otherwise recommended security measures.
  In our view, avoiding a potential information stealing attack via JavaScript (Exploiting Zenbleed via JavaScript is at least regarded as possible by tom's Hardware: <https://www.tomshardware.com/news/zenbleed-bug-allows-data-theft-from-amds-zen-2-processors-patches-released>) by stopping the Zenbleed vulnerability (CVE-2023-20593) outweighs the risk of disabling two defense-in-depth measures.
* The WinRing0 kernel-level driver suffers from CVE-2020–14979, a local privilege escalation vulnerability.
  See <https://posts.specterops.io/cve-2020-14979-local-privilege-escalation-in-evga-precisionx1-cf63c6b95896> and <https://github.com/openhardwaremonitor/openhardwaremonitor/issues/1557>.
  WinRing0 is an open-source kernel-level driver that is used by other open-source programs as well such as the OpenHardwareMonitor library.
  The problem is that the driver creates a device object without an access control list and thereby allowing all local Windows user to communicate with the driver.
  Since the driver allows direct hardware access a privilege escalation to `NT AUTHORITY\SYSTEM` rights is possible.
  A real fix would require a change in the WinRing0 driver and thus a new signature which is complicated.
  The OpenHardwareMonitor library, as a workaround, fixes the access rights immediately after loading the driver (<https://github.com/openhardwaremonitor/openhardwaremonitor/commit/0e435cafc61fe84d429e8a9500d666e34e3de67b>).
  Our PowerShell script works around  CVE-2020–14979 by immediately unloading the driver after setting the chicken bit.
  However, a small time window of opportunity exists each time the script is executed.
  Since setting the chicken bit is not persistent, the script has to be executed on every reboot.
  In our risk analysis the benefits of a protection against Zenbleed (which can happen remotely) again outweigh the risks of a local privilege escalation.
  Moreover, we recommend running the script as early as possible in the boot process to limit the exploitability by user processes.
  Please perform a risk analysis for your specific environment before deploying the PowerShell script.
* This software workaround is meant as a temporal workaround until AMD fixes the bug in their CPUs.

## How do I know that it works?

```shellsession
PS C:\stop-zenbleed-win> powershell -ExecutionPolicy RemoteSigned .\Stop-Zenbleed.ps1
[>] Installing driver...
[SC] CreateService SUCCESS

[>] Starting driver...

SERVICE_NAME: WinRing0_1_2_0
        TYPE               : 1  KERNEL_DRIVER
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 0
        FLAGS              :

[>] Opening driver...
[+] Driver access OK, handle: 2456

[>] Try 1 to apply fix on processor 1
[+] Fix is applied on processor 1 (MSR 0xC0011029=0x300C310E08202)
[+] Fix is applied on processor 2 (MSR 0xC0011029=0x300C310E08203)
[>] Try 1 to apply fix on processor 3
[+] Fix is applied on processor 3 (MSR 0xC0011029=0x3004310E08202)
[+] Fix is applied on processor 4 (MSR 0xC0011029=0x300C310E08203)
[>] Try 1 to apply fix on processor 5
[+] Fix is applied on processor 5 (MSR 0xC0011029=0x300C310E08202)
[+] Fix is applied on processor 6 (MSR 0xC0011029=0x300C310E08203)
[>] Try 1 to apply fix on processor 7
[+] Fix is applied on processor 7 (MSR 0xC0011029=0x300C310E08202)
[+] Fix is applied on processor 8 (MSR 0xC0011029=0x300C310E08203)
[>] Try 1 to apply fix on processor 9
[+] Fix is applied on processor 9 (MSR 0xC0011029=0x300C310E08202)
[+] Fix is applied on processor 10 (MSR 0xC0011029=0x300C310E08203)
[>] Try 1 to apply fix on processor 11
[+] Fix is applied on processor 11 (MSR 0xC0011029=0x300C310E08202)
[+] Fix is applied on processor 12 (MSR 0xC0011029=0x300C310E08203)
[>] Try 1 to apply fix on processor 13
[+] Fix is applied on processor 13 (MSR 0xC0011029=0x300C310E08202)
[+] Fix is applied on processor 14 (MSR 0xC0011029=0x300C310E08203)
[>] Try 1 to apply fix on processor 15
[+] Fix is applied on processor 15 (MSR 0xC0011029=0x300C310E08202)
[+] Fix is applied on processor 16 (MSR 0xC0011029=0x300C310E08203)

[>] Closing driver...

[>] Stopping driver...

SERVICE_NAME: WinRing0_1_2_0
        TYPE               : 1  KERNEL_DRIVER
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

[>] Uninstalling driver...
[SC] DeleteService SUCCESS
```

After executing our PowerShell script, the POC exploit should not produce any more output.

## Copyright

* `Stop-Zenbleed.ps1` is provided under the GNU GPL v3.0 license: [LICENSE](LICENSE)
* WinRing0 is © 2007-2009 OpenLibSys.org and provided under the following terms: [WinRing0/LICENSE](WinRing0/LICENSE)
