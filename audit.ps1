#

Write-Host "Droping all connections if any"
Disconnect-VIServer -Force -server * -Confirm:$false

Write-Host "Setting up prerequistes"
. ./functions.ps1
set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false
Set-PowerCLIConfiguration -DefaultVIServerMode multiple -Confirm:$false

Write-Host "vCenter Server connection details"
$vCenterServer = "vcsa.lab.local"
$vCusername = "root"
$vCpassword = "VMware1!"

Write-Host "common username and password for your ESXi hosts."
$esxusername = "root"
$esxpassword = "VMware1!"

Write-Host "Connect to vCenter"
$vCconnection = connect-viserver $vCenterServer -user $vCusername -password $vCpassword
$esxihosts = get-vmhost
$esxivms = get-vm

Write-Host "Audit the list of users who are on the Exception Users List and whether the have administrator privleges"
foreach ($esxihost in $esxihosts)
{
    Write-Host "Host is: " $esxihost
    Write-host "Exception Users from vCenter"
    $myhost = Get-VMHost $esxihost | Get-View
    $lockdown = Get-View $myhost.ConfigManager.HostAccessManager
    $LDusers = $lockdown.QueryLockdownExceptions()
    Write-host $LDusers
}


Write-Host "Check to see if the SSH Server Is running"
foreach ($VMhost in (Get-VMHost))
{
    $ServiceList = Get-VMHostService -VMhost $VMhost
    $SSHservice = $ServiceList | Where-Object {$_.Key -eq "TSM-SSH"}
    If ($SSHservice.Running -eq $true) {
        Write-Output "SSH Server on host $VMhost is running"
    }
    else {
        Write-Output "SSH Server on host $VMhost is Stopped"
    }
}


Write-Host "List the NTP Settings for all hosts "
Get-VMHost | Select Name, @{N="NTPSetting";E={$_ | Get-VMHostNtpServer}}

Write-Host "List Syslog.global.logDir for each host"
Get-VMHost | Select Name, @{N="Syslog.global.logDir";E={$_ | Get-VMHostAdvancedConfiguration Syslog.global.logDir | Select -ExpandProperty Values}}

# List the SNMP Configuration of a host (single host connection required)
# will have to add some connect code for the hosts before this call works
#Get-VMHost | Get-VMHostSnmp

Write-Host "Check Managed Object Browser (MOB)"
Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob

Write-Host "Disable TLS 1.0 and 1.1 on ESXi Hosts if necessary"
Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiVPsDisabledProtocols

Write-Host "Check each host and their domain membership status"
Get-VMHost | Get-VMHostAuthentication | Select VmHost, Domain, DomainMembershipStatus


Write-Host "Check the host profile is using vSphere Authentication proxy to add the host to the domain"
Get-VMHost | Select Name, ` @{N="HostProfile";E={$_ | Get-VMHostProfile}}, ` @{N="JoinADEnabled";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, ` @{N="JoinDomainMethod";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select -ExpandProperty Policy | Where {$_.Id -eq "JoinDomainMethodPolicy"}).Policyoption.Id}}

Write-Host "List Iscsi Initiator and CHAP Name if defined"
Get-VMHost | Get-VMHostHba | Where {$_.Type -eq "Iscsi"} | Select VMHost, Device, ChapType, @{N="CHAPName";E={$_.AuthenticationProperties.ChapName}}

Write-Host "Check if Lockdown mode is enabled"
Get-VMHost | Select Name,@{N="Lockdown";E={$_.Extensiondata.Config.adminDisabled}}

Write-Host "Check remote logging for ESXi hosts "
Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost

Write-Host "Check if Lockdown mode is enabled"
Get-VMHost | Select Name,@{N="Lockdown";E={$_.Extensiondata.Config.adminDisabled}}

Write-Host "To display the mode "
foreach ($esxihost in $esxihosts)
{
    $myhost = Get-VMHost $esxihost | Get-View
    $lockdown = Get-View $myhost.ConfigManager.HostAccessManager
    Write-Host "-----------"
    $lockdown.UpdateViewData()
    $lockdownstatus = $lockdown.LockdownMode
    Write-Host "Lockdown mode on $esxihost is set to $lockdownstatus"
    Write-Host "-----------"
}

Write-Host "List the services which are enabled and have rules defined for specific IP ranges to access the service"
Get-VMHost  | Get-VMHostFirewallException | Where {$_.Enabled -and (-not $_.ExtensionData.AllowedHosts.AllIP)}

Write-Host "List the services which are enabled and do not have rules defined for specific IP ranges to access the service"
Get-VMHost  | Get-VMHostFirewallException | Where {$_.Enabled -and ($_.ExtensionData.AllowedHosts.AllIP)}

Write-Host "Set the time after which a locked account is automatically unlocked"
Get-VMHost | Get-AdvancedSetting -Name Security.AccountUnlockTime

Write-Host "Set the count of maximum failed login attempts before the account is locked out"
Get-VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures

Write-Host "Set DCUI.Access to allow trusted users to override lockdown mode"
Get-VMHost | Get-AdvancedSetting -Name DCUI.Access

Write-Host "Audit DCUI timeout value"
Get-VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut

Write-Host "Establish a password policy for password complexity"
Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl

Write-Host "Set a timeout to automatically terminate idle ESXi Shell and SSH sessions"
Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut

Write-Host "Set a timeout to limit how long the ESXi Shell and SSH services are allowed to run"
Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut

Write-Host "Ensure default setting for intra-VM TPS is correct"
Get-VMHost | Get-AdvancedSetting -Name Mem.ShareForceSalting

# establish real direct connections to the hosts
Connect-VIserver -server $esxihosts -user $esxusername -password $esxpassword


Write-Host "List the Software AcceptanceLevel for each host"
Foreach ($VMHost in $esxihosts) {
    $ESXCli = Get-EsxCli -VMHost $VMHost | Select Name, @{N="AcceptanceLevel";E={$ESXCli.software.acceptance.get()}}
    Wite-Host $ESXCli
}

# List only the vibs which are not at "VMwareCertified" or "VMwareAccepted" or "PartnerSupported" acceptance level
#Foreach ($VMHost in Get-VMHost ) {
#    $ESXCli = Get-EsxCli -VMHost $VMHost $ESXCli.software.vib.list() | \
#        Where { ($_.AcceptanceLevel -ne "VMwareCertified") -and ($_.AcceptanceLevel -ne "VMwareAccepted") \
#        -and ($_.AcceptanceLevel -ne "PartnerSupported") }
#}

# hack, drop vcenter connection 
#Disconnect-VIServer -Force -server $vCenterServer -Confirm:$false

Foreach ($VM in $esxivms) {
    Write-Host "- Checking $VM ..."
    Write-Host "isolation.tools.copy.disable"
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.copy.disable" | where {$_.value -eq "false"} | Select Entity, Name, Value

    Write-Host "isolation.tools.dnd.disable"
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.dnd.disable" | where {$_.value -eq "false"} | Select Entity, Name, Value

    Write-Host "isolation.tools.setGUIOptions.enable"
    Get-AdvancedSetting -Entity $VM -Name  "isolation.tools.setGUIOptions.enable" | where {$_.value -eq "false"} |  Select Entity, Name, Value

    Write-Host "isolation.tools.paste.disable"
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.paste.disable" | where {$_.value -eq "false"} | Select Entity, Name, Value

    Write-Host "VM disk shrink setting"
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.diskShrink.disable" | where {$_.value -eq "false"} | Select Entity, Name, Value

    Write-Host "VM disk wiper setting"
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.diskWiper.disable" | where {$_.value -eq "false"} | Select Entity, Name, Value

    Write-Host "VM HGFS setting"
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.hgfsServerSet.disable" | where {$_.value -eq "false"} | Select Entity, Name, Value

    #Write-Host "VM disk types"
    #Get-HardDisk | where {$_.Persistence -ne "Persistent"} | Select Parent, Name, Filename, DiskType, Persistence

    Write-Host "List VM 3D settings"
    Get-AdvancedSetting -Entity $VM -Name  "mks.enable3d"| Select Entity, Name, Value

    Write-Host "List VM autologon setting"
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.ghi.autologon.disable"| where {$_.Value -eq "True"} | Select Entity, Name, Value

    Write-Host "List VM settings"
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.ghi.launchmenu.change" | where {$_.Value -eq "False"} |  Select Entity, Name, Value
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.memSchedFakeSampleStats.disable" | where {$_.Value -eq "False"} |  Select Entity, Name, Value
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.ghi.protocolhandler.info.disable" | where {$_.Value -eq "False"} | Select Entity, Name, Value
    Get-AdvancedSetting -Entity $VM -Name "isolation.ghi.host.shellAction.disable" | where {$_.Value -eq "False"} |  Select Entity, Name, Value
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.ghi.trayicon.disable"| where {$_.Value -eq "False"} |  Select Entity, Name, Value
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.unity.disable"| where {$_.Value -eq "False"} |  Select Entity, Name, Value
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.unityInterlockOperation.disable"| where {$_.Value -eq "False"} |  Select Entity, Name, Value
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.unity.push.update.disable" | where {$_.Value -eq "False"} |  Select Entity, Name, Value
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.unity.taskbar.disable" | where {$_.Value -eq "False"} |  Select Entity, Name, Value
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.unityActive.disable" | where {$_.Value -eq "False"} |  Select Entity, Name, Value
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.unity.windowContents.disable" | where {$_.Value -eq "False"} |  Select Entity, Name, Value
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.vmxDnDVersionGet.disable"| where {$_.Value -eq "False"} | Select Entity, Name, Value
    Get-AdvancedSetting -Entity $VM -Name "isolation.tools.guestDnDVersionSet.disable"| where {$_.Value -eq "False"} |  Select Entity, Name, Value
    #Get-FloppyDrive | Select Parent, Name, ConnectionState
    #Get-VM | Get-ParallelPort
    #Get-VM | Get-SerialPort
    Get-AdvancedSetting -Entity $VM -Name "svga.vgaOnly " | Select Entity, Name, Value
    Get-AdvancedSetting -Entity $VM -Name "tools.setInfo.sizeLimit" | where {$_.Value -gt "1048576"} |  Select Entity, Name, Value
    Get-AdvancedSetting -Entity $VM -Name "RemoteDisplay.vnc.enabled" | where {$_.Value -eq "True"} |  Select Entity, Name, Value
    Get-AdvancedSetting -Entity $VM -Name  "tools.guestlib.enableHostInfo"| where {$_.Value -eq "True"} | Select Entity, Name, Value
    Get-AdvancedSetting -Entity $VM -Name "Mem.ShareForceSalting" | where {$_.Value -eq "1"} | Select Entity, Name, Value
    Get-AdvancedSetting -Entity $VM -Name  "ethernet*.filter*.name*" | Select Entity, Name, Value
    Get-AdvancedSetting -Entity $VM -Name "pciPassthru*.present" | Select Entity, Name, Value
}

Write-Host "Enable BPDU filter on the ESXi host to prevent being locked out of physical switch ports with Portfast and BPDU Guard enabled"
Get-VMHost | Get-AdvancedSetting -Name Net.BlockGuestBPDU

# convert this into a check
# Enable VDS network healthcheck only if you need it
#$vds = Get-VDSwitch
#$vds.ExtensionData.Config.HealthCheckConfig
#Get-View -ViewType DistributedVirtualSwitch | ?{($_.config.HealthCheckConfig | ?{$_.enable -notmatch "False"})}| %{$_.UpdateDVSHealthCheckConfig(@((New-Object Vmware.Vim.VMwareDVSVlanMtuHealthCheckConfig -property @{enable=0}),(New-Object Vmware.Vim.VMwareDVSTeamingHealthCheckConfig -property @{enable=0})))}

Write-Host "Ensure that the Forged Transmits policy is set to reject"
Get-VDSwitch | Get-VDSecurityPolicy
Get-VDPortgroup | ?{$_.IsUplink -eq $false} | Get-VDSecurityPolicy

Write-Host "Ensure that the Forged Transmits policy is set to reject"
Get-VirtualSwitch | Get-SecurityPolicy
Get-VirtualPortGroup | Get-SecurityPolicy

Write-Host "Ensure that the MAC Address Changes policy is set to reject"
Get-VDSwitch | Get-VDSecurityPolicy
Get-VDPortgroup | Get-VDSecurityPolicy

Write-Host "Ensure that the MAC Address Changes policy is set to reject"
Get-VirtualSwitch | Get-SecurityPolicy
Get-VirtualPortGroup | Get-SecurityPolicy

Write-Host "Ensure that the Promiscuous Mode policy is set to reject"
Get-VDSwitch | Get-VDSecurityPolicy
Get-VDPortgroup | Get-VDSecurityPolicy

Write-Host "Ensure that the Promiscuous Mode policy is set to reject"
Get-VirtualSwitch | Get-SecurityPolicy
Get-VirtualPortGroup | Get-SecurityPolicy

Write-Host "Ensure that VDS Netflow traffic is only being sent to authorized collector IPs"
Get-VDPortgroup | Select Name, VirtualSwitch, @{Name="NetflowEnabled";Expression={$_.Extensiondata.Config.defaultPortConfig.ipfixEnabled.Value}} | Where-Object {$_.NetflowEnabled -eq "True"}

Write-Host "Restrict port-level configuration overrides on VDS "
Get-VDPortgroup | Get-VDPortgroupOverridePolicy

Write-Host "Audit use of dvfilter network APIs"
Get-VMHost | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress

