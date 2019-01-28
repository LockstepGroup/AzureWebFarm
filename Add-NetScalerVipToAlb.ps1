[CmdletBinding()]

Param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$AlbName,

    [Parameter(Mandatory = $true, Position = 1)]
    [string]$AlbResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$NetScalerObjectPrefix,

    [Parameter(Mandatory = $true)]
    [string[]]$NetScalerVmName,

    [Parameter(Mandatory = $true)]
    [string]$NetScalerResourceGroup,

    [Parameter(Mandatory = $false)]
    [string[]]$TcpPort,

    [Parameter(Mandatory = $false)]
    [string[]]$UdpPort,

    [Parameter(Mandatory = $false)]
    [string]$AzSubscriptionId,

    [Parameter(Mandatory = $false)]
    [switch]$Resume
)

BEGIN {
    $VerbosePrefix = 'Add-NetScalerVipToAlb:'

    # Check that at least 1 port was specified
    if (($TcpPort.Count + $UdpPort.Count) -eq 0) {
        try {
            throw
        } catch {
            $PSCmdlet.ThrowTerminatingError(
                [System.Management.Automation.ErrorRecord]::new(
                    ([System.ArgumentException]"Must specify at least 1 Tcp or UDP Port."),
                    '1004',
                    [System.Management.Automation.ErrorCategory]::CloseError,
                    $null
                )
            )
        }
    }

    # Check for Az Module
    $RequiredModules = @()
    $RequiredModules += 'Az'
    $RequiredModules += 'IPv4Math'

    foreach ($module in $RequiredModules) {
        try {
            Write-Verbose "$VerbosePrefix Checking for required Module: $module"
            Import-Module -Name $module -ErrorAction Stop | Out-Null
        } catch {
            $PSCmdlet.ThrowTerminatingError($PSItem)
        }
    }

    # Check for Azure Login
    try {
        Write-Verbose "$VerbosePrefix Checking for Azure Connection"
        $AzSubscription = Get-AzSubscription
    } catch {
        switch -Regex ($_.Exception.Message) {
            'Run\ Connect-Az(ureRm)?Account\ to\ login' {
                $PSCmdlet.ThrowTerminatingError(
                    [System.Management.Automation.ErrorRecord]::new(
                        ([System.Management.Automation.PSInvalidOperationException]"Run Connect-AzAccount to login to Azure"),
                        '1000',
                        [System.Management.Automation.ErrorCategory]::InvalidOperation,
                        $null
                    )
                )
            }
        }
    }

    # Apply SubscriptionId if Specified
    if ($AzSubscriptionId) {
        $DesiredSubscription = $AzSubscription | Where-Object { $_.Id -eq $AzSubscriptionId }
        try {
            Write-Verbose "$VerbosePrefix Selecting Azure Subscription"
            Set-AzContext -SubscriptionObject $DesiredSubscription | Out-Null
        } catch {
            $PSCmdlet.ThrowTerminatingError(
                [System.Management.Automation.ErrorRecord]::new(
                    ([System.ArgumentException]"Please provide a valid Azure Subscription Id"),
                    '1001',
                    [System.Management.Automation.ErrorCategory]::CloseError,
                    $AzSubscriptionId
                )
            )
        }
    }
}

PROCESS {
    $AlbFrontEndIpConfigName = $NetScalerObjectPrefix + '_ipc_frontend'

    Write-Verbose "$VerbosePrefix Getting Azure Load Balancer."
    $Alb = Get-AzLoadBalancer -ResourceGroupName $AlbResourceGroupName -Name $AlbName

    Write-Verbose "$VerbosePrefix Getting ALB Frontend Subnet."
    $SubnetId = $Alb.FrontendIpConfigurations.subnet.id | Select-Object -Unique
    if ($SubnetId.Count -gt 1) {
        try {
            throw
        } catch {
            $PSCmdlet.ThrowTerminatingError(
                [System.Management.Automation.ErrorRecord]::new(
                    ([System.ArgumentException]"Azure Load Balancer has more than one Frontend Subnet, this is not currently supported"),
                    '1008',
                    [System.Management.Automation.ErrorCategory]::CloseError,
                    $AlbName
                )
            )
        }
    } else {
        # Find available IP in FrontEndSubnet
        $SubnetRx = [regex] 'resourceGroups\/(?<rg>[^\/]+?)\/providers\/Microsoft.Network\/virtualNetworks\/(?<vnet>[^\/]+?)\/subnets\/(?<subnet>[^\/]+?)$'
        $VnetResourceGroupName = $SubnetRx.Match($SubnetId).Groups['rg'].Value
        $VnetName = $SubnetRx.Match($SubnetId).Groups['vnet'].Value
        $SubnetName = $SubnetRx.Match($SubnetId).Groups['subnet'].Value

        $VirtualNetwork = Get-AzVirtualNetwork -Name $VnetName -ResourceGroupName $VnetResourceGroupName
        $AlbFrontEndSubnet = $VirtualNetwork | Get-AzVirtualNetworkSubnetConfig -Name $SubnetName
        $AlbFrontEndSubnetPrefix = $AlbFrontEndSubnet.AddressPrefix[0]

        $AlbFrontEndSubnetNetworkRange = Get-NetworkRange -IpAndMaskLength $AlbFrontEndSubnetPrefix

        foreach ($ip in $AlbFrontEndSubnetNetworkRange) {
            if ($null -eq $NewAlbFrontEndIp) {
                $Test = $VirtualNetwork | Test-AzPrivateIPAddressAvailability -IPAddress $ip
                if (!($Test.Available)) {
                    if ($Test.AvailableIPAddresses.Count -gt 0) {
                        $NewAlbFrontEndIp = $Test.AvailableIPAddresses[0]
                        Write-Verbose "$VerbosePrefix NewAlbFrontEndIp: $NewAlbFrontEndIp"
                    }
                } else {
                    $NewAlbFrontEndIp = $ip
                    Write-Verbose "$VerbosePrefix NewAlbFrontEndIp: $NewAlbFrontEndIp"
                }
            } else {
                break
            }
        }

        # Add new Frontend IP
        $AddIpConfig = Add-AzLoadBalancerFrontendIpConfig -LoadBalancer $Alb -Name $AlbFrontEndIpConfigName -Subnet $AlbFrontEndSubnet -PrivateIpAddress $NewAlbFrontEndIp
    }

    # Define generic Netscaler Health Probes
    $HealthProbeName = $AlbName + "_hp_tcp9000"
    $HealthProbe = Get-AzLoadBalancerProbeConfig -LoadBalancer $Alb -Name $HealthProbeName

    # Alb Frontend IP
    $AlbFrontEndIpId = (Get-AzLoadBalancerFrontendIpConfig -Name $AlbFrontEndIpConfigName -LoadBalancer $Alb).Id

    # NetScaler info
    $NicNameRx = [regex] '[^\/]+?$'
    $NetScalerNics = @()
    foreach ($netscaler in $NetScalerVmName) {
        $NetScalerVm = Get-AzVM -ResourceGroupName $NetScalerResourceGroup -Name $netscaler
        $NetScalerNicName = $NicNameRx.Match($NetScalerVm.NetworkProfile.NetworkInterfaces.Id).Value
        $NetScalerNics += Get-AzNetworkInterface -Name $NetScalerNicName -ResourceGroupName $NetScalerResourceGroup
        Write-Verbose "$VerbosePrefix NetScalerNicName: $NetScalerNicName"
    }

    $UpdateBackEndNics = $false

    function AddAlbConfig ($ports, $protocol) {

        foreach ($port in $ports) {
            $BackEndAddressPoolName = $AlbName + "_backend_" + $protocol + $port
            try {
                $CheckForBackEnd = Get-AzLoadBalancerBackendAddressPoolConfig -Name $BackEndAddressPoolName -LoadBalancer $Alb -ErrorAction Stop
                Write-Verbose "$VerbosePrefix BackEndAddressPool exists: $BackEndAddressPoolName"
            } catch {
                Write-Verbose "$VerbosePrefix BackEndAddressPool does not exist, creating: $BackEndAddressPoolName"
                if (!($CheckForBackEnd)) {
                    $Alb = $Alb | Add-AzLoadBalancerBackendAddressPoolConfig -Name $BackEndAddressPoolName
                    $UpdateBackEndNics = $true
                }
            }

            $BackEndAddressPool = $Alb.BackendAddressPools | Where-Object { $_.Name -eq $BackEndAddressPoolName }

            $LbRuleName = $NetScalerObjectPrefix + "_lbrule_" + $protocol + $port
            $Alb = $Alb | Add-AzLoadBalancerRuleConfig -Name $LbRuleName -Protocol $protocol -FrontendPort $port -BackendPort $port -EnableFloatingIP -FrontendIpConfigurationId $AlbFrontEndIpId -BackendAddressPoolId $BackEndAddressPool.Id -ProbeId $HealthProbe.Id

            if (!($CheckForBackEnd)) {
                foreach ($nic in $NetScalerNics) {
                    Write-Verbose "$VerbosePrefix Adding BackendAddressPool to Netscaler Nic $($nic.Name)"
                    $nic.IpConfigurations[0].LoadBalancerBackendAddressPools.Add($BackEndAddressPool)
                }
            }
        }
    }

    # Configure ALB Port based config
    AddAlbConfig $TcpPort tcp
    AddAlbConfig $UdpPort udp

    # update Azure Objects
    Write-Verbose "$VerbosePrefix Updating Alb $AlbName"
    $Alb = $Alb | Set-AzLoadBalancer

    foreach ($nic in $NetScalerNics) {
        Write-Verbose "$VerbosePrefix Updating Netscaler Nic $($nic.Name)"
        $nic = $nic | Set-AzNetworkInterface
    }

}

End {
}
