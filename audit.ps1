# address certificate issue at some point
set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false

# Provide the username and password of an account on your ESXi hosts.
$esxusername = "root"
$esxpassword = "VMware1!"

# Provide the name of your vCenter Server
$vCenterServer = "vcsa.lab.local"

#Ensure all connections are dropped.
#Disconnect-VIServer -Force -server * -Confirm:$false

# You may need to provide the username and password of your vCenter server below
connect-viserver $vCenterServer -user $esxusername -password $esxpassword
$esxihosts = get-vmhost


#Audit the list of users who are on the Exception Users List and whether the have administrator privleges
foreach ($esxihost in $esxihosts)
{
    Write-Host "Host is: " $esxihost
    Write-host "Exception Users from vCenter"
    $myhost = Get-VMHost $esxihost | Get-View
    $lockdown = Get-View $myhost.ConfigManager.HostAccessManager
    $LDusers = $lockdown.QueryLockdownExceptions()
    Write-host $LDusers
}


# Check to see if the SSH Server Is running
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


# List the NTP Settings for all hosts 
Get-VMHost | Select Name, @{N="NTPSetting";E={$_ | Get-VMHostNtpServer}}

# List Syslog.global.logDir for each host
Get-VMHost | Select Name, @{N="Syslog.global.logDir";E={$_ | Get-VMHostAdvancedConfiguration Syslog.global.logDir | Select -ExpandProperty Values}}

# List the SNMP Configuration of a host (single host connection required)
Get-VMHost | Get-VMHostSnmp

# Check Managed Object Browser (MOB)
Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob

# Disable TLS 1.0 and 1.1 on ESXi Hosts if necessary
Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiVPsDisabledProtocols

# Check each host and their domain membership status
Get-VMHost | Get-VMHostAuthentication | Select VmHost, Domain, DomainMembershipStatus


# Check the host profile is using vSphere Authentication proxy to add the host to the domain
Get-VMHost | Select Name, ` @{N="HostProfile";E={$_ | Get-VMHostProfile}}, ` @{N="JoinADEnabled";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, ` @{N="JoinDomainMethod";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select -ExpandProperty Policy | Where {$_.Id -eq "JoinDomainMethodPolicy"}).Policyoption.Id}}

# List Iscsi Initiator and CHAP Name if defined
Get-VMHost | Get-VMHostHba | Where {$_.Type -eq "Iscsi"} | Select VMHost, Device, ChapType, @{N="CHAPName";E={$_.AuthenticationProperties.ChapName}}

# Check if Lockdown mode is enabled
Get-VMHost | Select Name,@{N="Lockdown";E={$_.Extensiondata.Config.adminDisabled}}

# Check remote logging for ESXi hosts 
Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost

# Check if Lockdown mode is enabled
Get-VMHost | Select Name,@{N="Lockdown";E={$_.Extensiondata.Config.adminDisabled}}

# To display the mode 
$esxihosts = get-vmhost
foreach ($esxihost in $esxihosts)
{
    $myhost = Get-VMHost $esxihost | Get-View
    $lockdown = Get-View $myhost.ConfigManager.HostAccessManager
    Write-Host "——————————-"
    $lockdown.UpdateViewData()
    $lockdownstatus = $lockdown.LockdownMode
    Write-Host "Lockdown mode on $esxihost is set to $lockdownstatus"
    Write-Host "——————————-"
}

# List the services which are enabled and have rules defined for specific IP ranges to access the service
Get-VMHost  | Get-VMHostFirewallException | Where {$_.Enabled -and (-not $_.ExtensionData.AllowedHosts.AllIP)}

# List the services which are enabled and do not have rules defined for specific IP ranges to access the service
Get-VMHost  | Get-VMHostFirewallException | Where {$_.Enabled -and ($_.ExtensionData.AllowedHosts.AllIP)}

# Set the time after which a locked account is automatically unlocked
Get-VMHost | Get-AdvancedSetting -Name Security.AccountUnlockTime

# Set the count of maximum failed login attempts before the account is locked out
Get-VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures

# Set DCUI.Access to allow trusted users to override lockdown mode
Get-VMHost | Get-AdvancedSetting -Name DCUI.Access

# Audit DCUI timeout value
Get-VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut

# Establish a password policy for password complexity
Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl

# Set a timeout to automatically terminate idle ESXi Shell and SSH sessions
Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut

# Set a timeout to limit how long the ESXi Shell and SSH services are allowed to run
Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut

# Ensure default setting for intra-VM TPS is correct
Get-VMHost | Get-AdvancedSetting -Name Mem.ShareForceSalting

# List the Software AcceptanceLevel for each host
Foreach ($VMHost in Get-VMHost ) { $ESXCli = Get-EsxCli -VMHost $VMHost $VMHost | Select Name, @{N="AcceptanceLevel";E={$ESXCli.software.acceptance.get()}}}

# List only the vibs which are not at "VMwareCertified" or "VMwareAccepted" or "PartnerSupported" acceptance level
Foreach ($VMHost in Get-VMHost ) { $ESXCli = Get-EsxCli -VMHost $VMHost $ESXCli.software.vib.list() | Where { ($_.AcceptanceLevel -ne "VMwareCertified") -and ($_.AcceptanceLevel -ne "VMwareAccepted") -and ($_.AcceptanceLevel -ne "PartnerSupported") }}

# List VM copy/paste settings
Get-VM | Get-AdvancedSetting -Name "isolation.tools.copy.disable" | where {$_.value -eq "false"} | Select Entity, Name, Value

# List VM copy/paste settings
Get-VM | Get-AdvancedSetting -Name "isolation.tools.dnd.disable" | where {$_.value -eq "false"} | Select Entity, Name, Value

# List VM copy/paste settings
Get-VM | Get-AdvancedSetting -Name  "isolation.tools.setGUIOptions.enable" | where {$_.value -eq "false"} |  Select Entity, Name, Value

# List VM copy/paste settings
Get-VM | Get-AdvancedSetting -Name "isolation.tools.paste.disable" | where {$_.value -eq "false"} | Select Entity, Name, Value

# List VM disk shrink setting
Get-VM | Get-AdvancedSetting -Name "isolation.tools.diskShrink.disable" | where {$_.value -eq "false"} | Select Entity, Name, Value

# List VM disk wiper setting
Get-VM | Get-AdvancedSetting -Name "isolation.tools.diskWiper.disable" | where {$_.value -eq "false"} | Select Entity, Name, Value

# Disable HGFS file transfers
# List VM HGFS setting
Get-VM | Get-AdvancedSetting -Name "isolation.tools.hgfsServerSet.disable" | where {$_.value -eq "false"} | Select Entity, Name, Value

# List VM disk types
Get-VM | Get-HardDisk | where {$_.Persistence -ne "Persistent"} | Select Parent, Name, Filename, DiskType, Persistence

# List VM 3D settings
Get-VM | Get-AdvancedSetting -Name  "mks.enable3d"| Select Entity, Name, Value

# List VM autologon setting
Get-VM | Get-AdvancedSetting -Name "isolation.tools.ghi.autologon.disable"| where {$_.Value -eq "True"} | Select Entity, Name, Value

# List VM settings
Get-VM | Get-AdvancedSetting -Name "isolation.tools.ghi.launchmenu.change" | where {$_.Value -eq "False"} |  Select Entity, Name, Value
Get-VM | Get-AdvancedSetting -Name "isolation.tools.memSchedFakeSampleStats.disable" | where {$_.Value -eq "False"} |  Select Entity, Name, Value
Get-VM | Get-AdvancedSetting -Name "isolation.tools.ghi.protocolhandler.info.disable" | where {$_.Value -eq "False"} | Select Entity, Name, Value
Get-VM | Get-AdvancedSetting -Name "isolation.ghi.host.shellAction.disable" | where {$_.Value -eq "False"} |  Select Entity, Name, Value
Get-VM | Get-AdvancedSetting -Name "isolation.tools.ghi.trayicon.disable"| where {$_.Value -eq "False"} |  Select Entity, Name, Value
Get-VM | Get-AdvancedSetting -Name "isolation.tools.unity.disable"| where {$_.Value -eq "False"} |  Select Entity, Name, Value
Get-VM | Get-AdvancedSetting -Name "isolation.tools.unityInterlockOperation.disable"| where {$_.Value -eq "False"} |  Select Entity, Name, Value
Get-VM | Get-AdvancedSetting -Name "isolation.tools.unity.push.update.disable" | where {$_.Value -eq "False"} |  Select Entity, Name, Value
Get-VM | Get-AdvancedSetting -Name "isolation.tools.unity.taskbar.disable" | where {$_.Value -eq "False"} |  Select Entity, Name, Value
Get-VM | Get-AdvancedSetting -Name "isolation.tools.unityActive.disable" | where {$_.Value -eq "False"} |  Select Entity, Name, Value
Get-VM | Get-AdvancedSetting -Name "isolation.tools.unity.windowContents.disable" | where {$_.Value -eq "False"} |  Select Entity, Name, Value
Get-VM | Get-AdvancedSetting -Name "isolation.tools.vmxDnDVersionGet.disable"| where {$_.Value -eq "False"} | Select Entity, Name, Value
Get-VM | Get-AdvancedSetting -Name "isolation.tools.guestDnDVersionSet.disable"| where {$_.Value -eq "False"} |  Select Entity, Name, Value
Get-VM | Get-FloppyDrive | Select Parent, Name, ConnectionState
Get-VM | Get-ParallelPort
Get-VM | Get-SerialPort
Get-VM | Get-AdvancedSetting -Name "svga.vgaOnly " | Select Entity, Name, Value
Get-VM | Get-AdvancedSetting -Name "tools.setInfo.sizeLimit" | where {$_.Value -gt "1048576"} |  Select Entity, Name, Value
Get-VM | Get-AdvancedSetting -Name "RemoteDisplay.vnc.enabled" | where {$_.Value -eq "True"} |  Select Entity, Name, Value
Get-VM | Get-AdvancedSetting -Name  "tools.guestlib.enableHostInfo"| where {$_.Value -eq "True"} | Select Entity, Name, Value
Get-VM | Get-AdvancedSetting -Name "Mem.ShareForceSalting" | where {$_.Value -eq "1"} | Select Entity, Name, Value
Get-VM | Get-AdvancedSetting -Name  "ethernet*.filter*.name*" | Select Entity, Name, Value
Get-VM | Get-AdvancedSetting -Name "pciPassthru*.present" | Select Entity, Name, Value

# Enable BPDU filter on the ESXi host to prevent being locked out of physical switch ports with Portfast and BPDU Guard enabled
Get-VMHost | Get-AdvancedSetting -Name Net.BlockGuestBPDU

# convert this into a check
# Enable VDS network healthcheck only if you need it
#$vds = Get-VDSwitch
#$vds.ExtensionData.Config.HealthCheckConfig
#Get-View -ViewType DistributedVirtualSwitch | ?{($_.config.HealthCheckConfig | ?{$_.enable -notmatch "False"})}| %{$_.UpdateDVSHealthCheckConfig(@((New-Object Vmware.Vim.VMwareDVSVlanMtuHealthCheckConfig -property @{enable=0}),(New-Object Vmware.Vim.VMwareDVSTeamingHealthCheckConfig -property @{enable=0})))}

# Ensure that the "Forged Transmits" policy is set to reject
Get-VDSwitch | Get-VDSecurityPolicy
Get-VDPortgroup | ?{$_.IsUplink -eq $false} | Get-VDSecurityPolicy

# Ensure that the "Forged Transmits" policy is set to reject
Get-VirtualSwitch | Get-SecurityPolicy
Get-VirtualPortGroup | Get-SecurityPolicy

# Ensure that the "MAC Address Changes" policy is set to reject
Get-VDSwitch | Get-VDSecurityPolicy
Get-VDPortgroup | Get-VDSecurityPolicy

# Ensure that the "MAC Address Changes" policy is set to reject
Get-VirtualSwitch | Get-SecurityPolicy
Get-VirtualPortGroup | Get-SecurityPolicy

# Ensure that the "Promiscuous Mode" policy is set to reject
Get-VDSwitch | Get-VDSecurityPolicy
Get-VDPortgroup | Get-VDSecurityPolicy

# Ensure that the "Promiscuous Mode" policy is set to reject
Get-VirtualSwitch | Get-SecurityPolicy
Get-VirtualPortGroup | Get-SecurityPolicy

# Ensure that VDS Netflow traffic is only being sent to authorized collector IPs
Get-VDPortgroup | Select Name, VirtualSwitch, @{Name="NetflowEnabled";Expression={$_.Extensiondata.Config.defaultPortConfig.ipfixEnabled.Value}} | Where-Object {$_.NetflowEnabled -eq "True"}

# Restrict port-level configuration overrides on VDS 
Get-VDPortgroup | Get-VDPortgroupOverridePolicy

# Audit use of dvfilter network APIs
Get-VMHost | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress

