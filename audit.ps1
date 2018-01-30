# version 0

Write-Host "`n# ---------- Dropping all connections if any"
Disconnect-VIServer -Force -server * -Confirm:$false

Write-Host "# ---------- Setting up prerequistes"
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

Write-Host "# ---------- Connecting to vCenter"
$vCconnection = connect-viserver $vCenterServer -user $vCusername -password $vCpassword | Out-Null
$esxihosts = get-vmhost
$esxivms = get-vm

Write-Host "`n# ---------- Start Audit`n"

# establish direct connections to the esxi hosts
Connect-VIserver -server $esxihosts -user $esxusername -password $esxpassword | Out-Null

Foreach ($VMHost in $esxihosts) {
    Write-Host "`n# ----- Checking host $VMHost ...`n"
    Write-Host "# Audit the list of users who are on the Exception Users List and whether the have administrator privleges"
    Write-host "Exception Users from vCenter"
    #$myhost = Get-VMHost $VMHost | Get-View
    $myhost = $VMHost | Get-View
    $lockdown = Get-View $myhost.ConfigManager.HostAccessManager
    $LDusers = $lockdown.QueryLockdownExceptions()
    Write-host $LDusers

    Write-Host "# Check to see if the SSH Server Is running"
    $ServiceList = Get-VMHostService -VMhost $VMhost
    $SSHservice = $ServiceList | Where-Object {$_.Key -eq "TSM-SSH"}

    If ($SSHservice.Running -eq $true) {
        Write-Output "SSH Server on host $VMhost is running"
    }
    else {
        Write-Output "SSH Server on host $VMhost is Stopped"
    }

    Write-Host "`n# Check the NTP Setting"
    $VMHost | Select @{N="NTP";E={$_ | Get-VMHostNtpServer}}

    Write-Host "# Check Syslog.global.logDir"
    $VMHost | Select @{N="Syslog.global.logDir";E={$_ | Get-AdvancedSetting -Name Syslog.global.logDir | Select -ExpandProperty Values}}

    Write-Host "# Check the SNMP Configuration"
    #$VMHost | Get-VMHostSnmp
    Write-Host "this check is erroring out, disabling it for now"

    Write-Host "# Check Managed Object Browser (MOB)"
    $VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob | Select Name, Value

    Write-Host "# Disable TLS 1.0 and 1.1 on ESXi Hosts if necessary"
    $VMHost | Get-AdvancedSetting -Name UserVars.ESXiVPsDisabledProtocols | Select Name, Value

    Write-Host "# Check each host and their domain membership status"
    $VMHost | Get-VMHostAuthentication | Select VmHost, Domain, DomainMembershipStatus

    Write-Host "# Check the host profile is using vSphere Authentication proxy to add the host to the domain"
    $VMHost | Select ` @{N="HostProfile";E={$_ | Get-VMHostProfile}}, ` @{N="JoinADEnabled";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, ` @{N="JoinDomainMethod";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select -ExpandProperty Policy | Where {$_.Id -eq "JoinDomainMethodPolicy"}).Policyoption.Id}}

    Write-Host "# List Iscsi Initiator and CHAP Name if defined"
    $VMHost | Get-VMHostHba | Where {$_.Type -eq "Iscsi"} | Select VMHost, Device, ChapType, @{N="CHAPName";E={$_.AuthenticationProperties.ChapName}}

    Write-Host "# Check if Lockdown mode is enabled"
    $VMHost | Select @{N="Lockdown";E={$_.Extensiondata.Config.adminDisabled}}

    Write-Host "# Check remote logging for ESXi hosts "
    $VMHost | Get-AdvancedSetting -Name Syslog.global.logHost | Select Name, Value

    Write-Host "# Check if Lockdown mode is enabled"
    $VMHost | Select @{N="Lockdown";E={$_.Extensiondata.Config.adminDisabled}}

    Write-Host "# Check Lockdown setting"
    $myhost = $VMHost | Get-View
    $lockdown = Get-View $myhost.ConfigManager.HostAccessManager
    $lockdown.UpdateViewData()
    $lockdownstatus = $lockdown.LockdownMode
    Write-Host "$lockdownstatus"

    Write-Host "`n# List the services which are enabled and have rules defined for specific IP ranges to access the service"
    $withrules = $VMHost | Get-VMHostFirewallException | Where {$_.Enabled -and (-not $_.ExtensionData.AllowedHosts.AllIP)}
    Foreach ($withrule in $withrules) {
        Write-Host $withrule
        Write-Host $withrule.extensiondata.allowedhosts.ipaddress
    }

    Write-Host "`n# List the services which are enabled and do not have rules defined for specific IP ranges to access the service"
    $withoutrules = $VMHost | Get-VMHostFirewallException | Where {$_.Enabled -and ($_.ExtensionData.AllowedHosts.AllIP)}
    Foreach ($withoutrule in $withtoutrules) {
        Write-Host $withoutrule
        Write-Host $withoutrule.extensiondata.allowedhosts.ipaddress
    }

    Write-Host "`n# Set the time after which a locked account is automatically unlocked"
    $VMHost | Get-AdvancedSetting -Name Security.AccountUnlockTime | Select Name, Value

    Write-Host "# Set the count of maximum failed login attempts before the account is locked out"
    $VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures | Select Name, Value

    Write-Host "# Set DCUI.Access to allow trusted users to override lockdown mode"
    $VMHost | Get-AdvancedSetting -Name DCUI.Access | Select Name, Value

    Write-Host "# Audit DCUI timeout value"
    $VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut | Select Name, Value

    Write-Host "# Establish a password policy for password complexity"
    $VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl | Select Name, Value

    Write-Host "# Set a timeout to automatically terminate idle ESXi Shell and SSH sessions"
    $VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut | Select Name, Value

    Write-Host "# Set a timeout to limit how long the ESXi Shell and SSH services are allowed to run"
    $VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut | Select Name, Value

    Write-Host "# Ensure default setting for intra-VM TPS is correct"
    $VMHost | Get-AdvancedSetting -Name Mem.ShareForceSalting | Select Name, Value

    Write-Host "# List the Software AcceptanceLevel for each host"
    $ESXCli = Get-EsxCli -VMHost $VMHost | Select @{N="AcceptanceLevel";E={$ESXCli.software.acceptance.get()}}
    Write-Host $ESXCli

    Write-Host "`n# List only the vibs which are not at "VMwareCertified" or "VMwareAccepted" or "PartnerSupported" acceptance level"
    #$ESXCli = Get-EsxCli -VMHost $VMHost $ESXCli.software.vib.list() |
    #        Where { ($_.AcceptanceLevel -ne "VMwareCertified") -and ($_.AcceptanceLevel -ne "VMwareAccepted")
    #        -and ($_.AcceptanceLevel -ne "PartnerSupported") }
    Write-Host "this check is erroring out, disabling it for now"

    Write-Host "`n# BPDU filter (prevents being locked out of physical switch ports with Portfast and BPDU Guard enabled)"
    $VMHost | Get-AdvancedSetting -Name Net.BlockGuestBPDU | Select Name, Value

    Write-Host "# Audit use of dvfilter network APIs"
    $VMHost | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress | Select Name, Value

    ##### Networking check subsection
    Write-Host "# Ensure that the Forged Transmits policy is set to reject"
    Write-Host "# Ensure that the MAC Address Changes policy is set to reject"
    Write-Host "# Ensure that the Promiscuous Mode policy is set to reject"

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

Write-Host "# ----- Starting VM checks"

Foreach ($VM in $esxivms) {
    Write-Host "- Checking VM settings: $VM"
    Write-Host "- NOTE: if no data is returned then this setting has not been created`n"
    Write-Host "# isolation.tools.copy.disable"
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.copy.disable" | Select Entity, Name, Value

    Write-Host "# isolation.tools.dnd.disable"
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.dnd.disable" | where {$_.value -eq "false"} | Select Entity, Name, Value

    Write-Host "# isolation.tools.setGUIOptions.enable"
    Get-AdvancedSetting -Entity $VM -Name  "isolation.tools.setGUIOptions.enable" | where {$_.value -eq "false"} |  Select Entity, Name, Value

    Write-Host "# isolation.tools.paste.disable"
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.paste.disable" | where {$_.value -eq "false"} | Select Entity, Name, Value

    Write-Host "# VM disk shrink setting"
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.diskShrink.disable" | where {$_.value -eq "false"} | Select Entity, Name, Value

    Write-Host "# VM disk wiper setting"
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.diskWiper.disable" | where {$_.value -eq "false"} | Select Entity, Name, Value

    Write-Host "# VM HGFS setting"
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.hgfsServerSet.disable" | where {$_.value -eq "false"} | Select Entity, Name, Value

    #Write-Host "VM disk types"
    #Get-HardDisk | where {$_.Persistence -ne "Persistent"} | Select Parent, Name, Filename, DiskType, Persistence

    Write-Host "# mks.enable3d"
    Get-AdvancedSetting -Entity $VM -Name  "mks.enable3d"| Select Entity, Name, Value

    Write-Host "# List VM autologon setting"
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.ghi.autologon.disable"| where {$_.Value -eq "True"} | Select Entity, Name, Value

    Write-Host "# isolation.tools.ghi.launchmenu.change"
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.ghi.launchmenu.change" | where {$_.Value -eq "False"} |  Select Entity, Name, Value

    Write-Host "# isolation.tools.memSchedFakeSampleStats.disable"
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.memSchedFakeSampleStats.disable" | where {$_.Value -eq "False"} |  Select Entity, Name, Value


    Write-Host "# isolation.tools.ghi.protocolhandler.info.disable"
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.ghi.protocolhandler.info.disable" | where {$_.Value -eq "False"} | Select Entity, Name, Value

    Write-Host "# isolation.ghi.host.shellAction.disable"
    Get-AdvancedSetting -Entity $VM -Name "isolation.ghi.host.shellAction.disable" | where {$_.Value -eq "False"} |  Select Entity, Name, Value

    Write-Host "# isolation.tools.ghi.trayicon.disable"
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.ghi.trayicon.disable"| where {$_.Value -eq "False"} |  Select Entity, Name, Value

    Write-Host "# isolation.tools.unity.disable"
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.unity.disable"| where {$_.Value -eq "False"} |  Select Entity, Name, Value

    Write-Host "# isolation.tools.unityInterlockOperation.disable"
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.unityInterlockOperation.disable"| where {$_.Value -eq "False"} |  Select Entity, Name, Value

    Write-Host "# isolation.tools.unity.push.update.disable"
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.unity.push.update.disable" | where {$_.Value -eq "False"} |  Select Entity, Name, Value

    Write-Host "# isolation.tools.unity.taskbar.disable"
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.unity.taskbar.disable" | where {$_.Value -eq "False"} |  Select Entity, Name, Value

    Write-Host "# isolation.tools.unityActive.disable"
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.unityActive.disable" | where {$_.Value -eq "False"} |  Select Entity, Name, Value

    Write-Host "# isolation.tools.unity.windowContents.disable"
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.unity.windowContents.disable" | where {$_.Value -eq "False"} |  Select Entity, Name, Value

    Write-Host "# isolation.tools.vmxDnDVersionGet.disable"
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.vmxDnDVersionGet.disable"| where {$_.Value -eq "False"} | Select Entity, Name, Value

    Write-Host "# isolation.tools.guestDnDVersionSet.disable"
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.guestDnDVersionSet.disable"| where {$_.Value -eq "False"} |  Select Entity, Name, Value

    #Get-FloppyDrive | Select Parent, Name, ConnectionState
    #Get-VM | Get-ParallelPort
    #Get-VM | Get-SerialPort

    Write-Host "# svga.vgaOnly"
    Get-AdvancedSetting -Entity $VM -Name "svga.vgaOnly" | Select Entity, Name, Value

    Write-Host "# tools.setInfo.sizeLimit"
    Get-AdvancedSetting -Entity $VM -Name "tools.setInfo.sizeLimit" | where {$_.Value -gt "1048576"} |  Select Entity, Name, Value

    Write-Host "# RemoteDisplay.vnc.enabled"
    Get-AdvancedSetting -Entity $VM -Name "RemoteDisplay.vnc.enabled" | where {$_.Value -eq "True"} |  Select Entity, Name, Value

    Write-Host "# tools.guestlib.enableHostInfo"
    Get-AdvancedSetting -Entity $VM -Name "tools.guestlib.enableHostInfo"| where {$_.Value -eq "True"} | Select Entity, Name, Value

    Write-Host "# Mem.ShareForceSalting"
    Get-AdvancedSetting -Entity $VM -Name "Mem.ShareForceSalting" | where {$_.Value -eq "1"} | Select Entity, Name, Value

    Write-Host "# ethernet*.filter*.name*"
    Get-AdvancedSetting -Entity $VM -Name  "ethernet*.filter*.name*" | Select Entity, Name, Value

    Write-Host "# pciPassthru*.present"
    Get-AdvancedSetting -Entity $VM -Name "pciPassthru*.present" | Select Entity, Name, Value
}
