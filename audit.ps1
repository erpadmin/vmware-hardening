# version 0.1

# ---------- Dropping all connections if any"
Disconnect-VIServer -Force -server * -Confirm:$false

# ---------- Setting up prerequistes"
. ./functions.ps1
set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null
Set-PowerCLIConfiguration -DefaultVIServerMode multiple -Confirm:$false | Out-Null

# vCenter Server connection details
$vCenterServer = "vcsa.lab.local"
$vCusername = "root"
$vCpassword = "VMware1!"

# common username and password for your ESXi hosts
$esxusername = "root"
$esxpassword = $vCpassword

# ---------- Connecting to vCenter"
$vCconnection = connect-viserver $vCenterServer -user $vCusername -password $vCpassword | Out-Null
$esxihosts = get-vmhost # -name <specific host>
$esxivms = get-vm # -name <specific vm>

# ---------- Start Audit`n"
$DAT = Get-Content "./settings.dat" | Select-Object -Skip 1


# establish direct connections to the esxi hosts
Connect-VIserver -server $esxihosts -user $esxusername -password $esxpassword | Out-Null

Foreach ($VMHost in $esxihosts) {
    Write-Host "`n# ----- Checking host $VMHost ...`n"
    Write-Host "`n# - Audit the list of users who are on the Exception Users List and whether the have administrator privleges"
    Write-host "Exception Users from vCenter"
    #$myhost = Get-VMHost $VMHost | Get-View
    $myhost = $VMHost | Get-View
    $lockdown = Get-View $myhost.ConfigManager.HostAccessManager
    $LDusers = $lockdown.QueryLockdownExceptions()
    Write-host $LDusers

    Write-Host "`n# - Check to see if the SSH Server Is running"
    $ServiceList = Get-VMHostService -VMhost $VMhost
    $SSHservice = $ServiceList | Where-Object {$_.Key -eq "TSM-SSH"}

    If ($SSHservice.Running -eq $true) {
        Write-Output "SSH Server on host $VMhost is running"
    }
    else {
        Write-Output "SSH Server on host $VMhost is Stopped"
    }

    Write-Host "`n# - Check the NTP Setting"
    get-guideline('ntp')
    #$VMHost | Select @{N="NTP";E={$_ | Get-VMHostNtpServer}}
    $ntp = $VMHost | Get-VMHostNtpServer
    Write-Host "NTP: $ntp" | ft

    Write-Host "`n# Check Syslog.global.logDir"
    get-guideline('Syslog')
    $VMHost | Select @{N="Syslog.global.logDir";E={$_ | Get-AdvancedSetting -Name Syslog.global.logDir | Select -ExpandProperty Values}} | ft

    Write-Host "`n# Check the SNMP Configuration"
    get-guideline('snmp')
    #$VMHost | Get-VMHostSnmp
    Write-Host "this check is erroring out, disabling it for now"

    Write-Host "`n# Check Managed Object Browser (MOB)"
    get-guideline('mob')
    $VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob | Select Name, Value | ft

    Write-Host "`n# Disable TLS 1.0 and 1.1 on ESXi Hosts if necessary"
    get-guideline('tls')
    $VMHost | Get-AdvancedSetting -Name UserVars.ESXiVPsDisabledProtocols | Select Name, Value | ft

    Write-Host "`n# Check each host and their domain membership status"
    $VMHost | Get-VMHostAuthentication | Select VmHost, Domain, DomainMembershipStatus | ft

    Write-Host "`n# Check the host profile is using vSphere Authentication proxy to add the host to the domain"
    get-guideline('auth-proxy')
    $VMHost | Select ` @{N="HostProfile";E={$_ | Get-VMHostProfile}}, ` @{N="JoinADEnabled";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, ` @{N="JoinDomainMethod";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select -ExpandProperty Policy | Where {$_.Id -eq "JoinDomainMethodPolicy"}).Policyoption.Id}} | ft

    Write-Host "`n# List iscsi Initiator and CHAP Name if defined"
    get-guideline('scsi')
    $VMHost | Get-VMHostHba | Where {$_.Type -eq "Iscsi"} | Select VMHost, Device, ChapType, @{N="CHAPName";E={$_.AuthenticationProperties.ChapName}} | ft

    Write-Host "`n# Check if Lockdown mode is enabled"
    get-guideline('normal-lockdown')
    $VMHost | Select @{N="Lockdown";E={$_.Extensiondata.Config.adminDisabled}} | ft

    #Write-Host "`n# Check Lockdown setting"
    #get-guideline('')
    #$myhost = $VMHost | Get-View
    #$lockdown = Get-View $myhost.ConfigManager.HostAccessManager
    #$lockdown.UpdateViewData()
    #$lockdownstatus = $lockdown.LockdownMode
    #Write-Host "$lockdownstatus"

    Write-Host "`n# Check remote logging for ESXi hosts "
    get-guideline('remote-syslog')
    $VMHost | Get-AdvancedSetting -Name Syslog.global.logHost | Select Name, Value | ft

    Write-Host "`n# List the services which are enabled and have rules defined for specific IP ranges to access the service"
    #get-guideline('')
    $withrules = $VMHost | Get-VMHostFirewallException | Where {$_.Enabled -and (-not $_.ExtensionData.AllowedHosts.AllIP)}
    Foreach ($withrule in $withrules) {
        Write-Host $withrule
        Write-Host $withrule.extensiondata.allowedhosts.ipaddress
    }

    Write-Host "`n# List the services which are enabled and do not have rules defined for specific IP ranges to access the service"
    #get-guideline('')
    $withoutrules = $VMHost | Get-VMHostFirewallException | Where {$_.Enabled -and ($_.ExtensionData.AllowedHosts.AllIP)}
    Foreach ($withoutrule in $withtoutrules) {
        Write-Host $withoutrule
        Write-Host $withoutrule.extensiondata.allowedhosts.ipaddress
    }

    Write-Host "`n# Set the time after which a locked account is automatically unlocked"
    get-guideline('AccountUnlockTime')
    $VMHost | Get-AdvancedSetting -Name Security.AccountUnlockTime | Select Name, Value | ft

    Write-Host "`n# Set the count of maximum failed login attempts before the account is locked out"
    get-guideline('AccountLockFailures')
    $VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures | Select Name, Value | ft

    Write-Host "`n# Set DCUI.Access to allow trusted users to override lockdown mode"
    get-guideline('DCUI.Access')
    $VMHost | Get-AdvancedSetting -Name DCUI.Access | Select Name, Value | ft

    Write-Host "`n# Audit DCUI timeout value"
    get-guideline('Dcui-TimeOut')
    $VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut | Select Name, Value | ft

    Write-Host "`n# Establish a password policy for password complexity"
    get-guideline('Security.PasswordQualityControl')
    $VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl | Select Name, Value | ft

    Write-Host "`n# Set a timeout to automatically terminate idle ESXi Shell and SSH sessions"
    get-guideline('ESXiShellInteractiveTimeOut')
    $VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut | Select Name, Value | ft

    Write-Host "`n# Set a timeout to limit how long the ESXi Shell and SSH services are allowed to run"
    get-guideline('UserVars.ESXiShellTimeOut')
    $VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut | Select Name, Value | ft

    Write-Host "`n# Ensure default setting for intra-VM TPS is correct"
    get-guideline('Mem.ShareForceSalting')
    $VMHost | Get-AdvancedSetting -Name Mem.ShareForceSalting | Select Name, Value | ft

    Write-Host "`n# List the Software AcceptanceLevel for each host"
    get-guideline('acceptance-level')
    $ESXCli = Get-EsxCli -VMHost $VMHost | Select @{N="AcceptanceLevel";E={$ESXCli.software.acceptance.get()}}
    Write-Host $ESXCli

    Write-Host "`n# List only the vibs which are not at "VMwareCertified" or "VMwareAccepted" or "PartnerSupported" acceptance level"
    get-guideline('')
    #$ESXCli = Get-EsxCli -VMHost $VMHost $ESXCli.software.vib.list() |
    #        Where { ($_.AcceptanceLevel -ne "VMwareCertified") -and ($_.AcceptanceLevel -ne "VMwareAccepted")
    #        -and ($_.AcceptanceLevel -ne "PartnerSupported") }
    Write-Host "this check is erroring out, disabling it for now"

    Write-Host "`n# BPDU filter (prevents being locked out of physical switch ports with Portfast and BPDU Guard enabled)"
    get-guideline('Net.BlockGuestBPDU')
    $VMHost | Get-AdvancedSetting -Name Net.BlockGuestBPDU | Select Name, Value | ft

    Write-Host "`n# Audit use of dvfilter network APIs"
    get-guideline('Net.DVFilterBindIpAddress')
    $VMHost | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress | Select Name, Value | ft

    ##### Networking check subsection
    Write-Host "`n# Ensure that the Forged Transmits policy is set to reject"
    get-guideline('ForgedTransmits')
    Write-Host "`n# Ensure that the MAC Address Changes policy is set to reject"
    get-guideline('MacChanges')
    Write-Host "`n# Ensure that the Promiscuous Mode policy is set to reject"
    get-guideline('AllowPromiscuous')

    foreach ($vSwitch in $VMHost | Get-VirtualSwitch -Standard) {
        Write-Host " "$vSwitch.Name
        Write-Host "`tPromiscuous mode enabled:" $vSwitch.ExtensionData.Spec.Policy.Security.AllowPromiscuous
        Write-Host "`tForged transmits enabled:" $vSwitch.ExtensionData.Spec.Policy.Security.ForgedTransmits
        Write-Host "`tMAC Changes enabled:" $vSwitch.ExtensionData.Spec.Policy.Security.MacChanges

        foreach($portgroup in ($VMHost.ExtensionData.Config.Network.Portgroup | where {$_.Vswitch -eq $vSwitch.Key})){
            Write-Host "`n`t`t"$portgroup.Spec.Name
            Write-Host "`t`t`tPromiscuous mode enabled: " -nonewline

            If ($portgroup.Spec.Policy.Security.AllowPromiscuous -eq $null) {
                Write-Host $vSwitch.ExtensionData.Spec.Policy.Security.AllowPromiscuous
            } Else {
                Write-Host $portgroup.Spec.Policy.Security.AllowPromiscuous
            }

            Write-Host "`t`t`tForged transmits enabled: " -nonewline

            If ($portgroup.Spec.Policy.Security.ForgedTransmits -eq $null) {
                Write-Host $vSwitch.ExtensionData.Spec.Policy.Security.ForgedTransmits
            } Else {
                Write-Host $portgroup.Spec.Policy.Security.ForgedTransmits
            }

            Write-Host "`t`t`tMAC Changes enabled: " -nonewline

            If ($portgroup.Spec.Policy.Security.MacChanges -eq $null) {
                Write-Host $vSwitch.ExtensionData.Spec.Policy.Security.MacChanges
            } Else {
                Write-Host $portgroup.Spec.Policy.Security.MacChanges
            }
        }
    }

    foreach ($vSwitch in $esxihosts | Get-VirtualSwitch -Distributed) {
        Write-Host " "$vSwitch.Name
        Write-Host "`tPromiscuous mode enabled:" $vSwitch.Extensiondata.Config.DefaultPortConfig.SecurityPolicy.AllowPromiscuous.Value
        Write-Host "`tForged transmits enabled:" $vSwitch.Extensiondata.Config.DefaultPortConfig.SecurityPolicy.ForgedTransmits.Value
        Write-Host "`tMAC Changes enabled:" $vSwitch.Extensiondata.Config.DefaultPortConfig.SecurityPolicy.MacChanges.Value
        Write-Host "`n# VDS network healthcheck seting"
        #$vds = Get-VDSwitch
        $vSwitch.ExtensionData.Config.HealthCheckConfig

        foreach($portgroup in (Get-VirtualPortGroup -Distributed -VirtualSwitch $vSwitch)){
            Write-Host "`n`t`t"$portgroup.Name
            Write-Host "`t`t`tPromiscuous mode enabled:" $portgroup.Extensiondata.Config.DefaultPortConfig.SecurityPolicy.AllowPromiscuous.Value
            Write-Host "`t`t`tForged transmits enabled:" $portgroup.Extensiondata.Config.DefaultPortConfig.SecurityPolicy.ForgedTransmits.Value
            Write-Host "`t`t`tMAC Changes enabled:" $portgroup.Extensiondata.Config.DefaultPortConfig.SecurityPolicy.MacChanges.Value

            #remove this later: Get-VDPortgroup | Select Name, VirtualSwitch, @{Name="NetflowEnabled";Expression={$_.Extensiondata.Config.defaultPortConfig.ipfixEnabled.Value}} | Where-Object {$_.NetflowEnabled -eq "True"}
            Write-Host "`t`t`tVDS Netflow traffic is only being sent to authorized collector IPs:" $portgroup.Extensiondata.Config.DefaultPortConfig.ipfixEnabled.Value

            Write-Host "Check port-level configuration overrides on VDS"
            $portgroup | Get-VDPortgroupOverridePolicy
        }
    }
}

Write-Host "`n# ----- Starting VM checks"

Foreach ($VM in $esxivms) {
    Write-Host "- Checking VM settings: $VM"
    Write-Host "- NOTE: if no data is returned then this setting has not been created`n"

    get-vm-setting('isolation.tools.copy.disable')
    get-vm-setting('isolation.tools.dnd.disable')
    get-vm-setting('isolation.tools.setGUIOptions.enable')
    get-vm-setting('isolation.tools.paste.disable')
    get-vm-setting('isolation.tools.diskShrink.disable')
    get-vm-setting('isolation.tools.diskWiper.disable')
    get-vm-setting('isolation.tools.hgfsServerSet.disable')

    #Write-Host "VM disk types"
    #Get-HardDisk | where {$_.Persistence -ne "Persistent"} | Select Parent, Name, Filename, DiskType, Persistence
    #get-vm-setting('')

    get-vm-setting('mks.enable3d')
    get-vm-setting('isolation.tools.ghi.autologon.disable')
    get-vm-setting('isolation.tools.ghi.launchmenu.change')
    get-vm-setting('isolation.tools.memSchedFakeSampleStats.disable')
    get-vm-setting('isolation.tools.ghi.protocolhandler.info.disable')
    get-vm-setting('isolation.ghi.host.shellAction.disable')
    get-vm-setting('isolation.tools.ghi.trayicon.disable')
    get-vm-setting('isolation.tools.unity.disable')
    get-vm-setting('isolation.tools.unityInterlockOperation.disable')
    get-vm-setting('isolation.tools.unity.push.update.disable')
    get-vm-setting('isolation.tools.unity.taskbar.disable')
    get-vm-setting('isolation.tools.unity.windowContents.disable')
    get-vm-setting('isolation.tools.vmxDnDVersionGet.disable')
    get-vm-setting('isolation.tools.guestDnDVersionSet.disable')

    #Get-FloppyDrive | Select Parent, Name, ConnectionState
    #Get-VM | Get-ParallelPort
    #Get-VM | Get-SerialPort
    #get-vm-setting('')

    get-vm-setting('svga.vgaOnly')
    get-vm-setting('tools.setInfo.sizeLimit')
    get-vm-setting('RemoteDisplay.vnc.enabled')
    get-vm-setting('tools.guestlib.enableHostInfo')
    get-vm-setting('Mem.ShareForceSalting')
    get-vm-setting('ethernet*.filter*.name*')
    get-vm-setting('pciPassthru*.present')
}
