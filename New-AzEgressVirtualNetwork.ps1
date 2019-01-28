#requires -module Ipv4Math
#requires -module Az

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$VirtualNetworkName,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$Location,

    [Parameter(Mandatory = $true)]
    [string]$AddressPrefix,

    [Parameter(Mandatory = $false)]
    [switch]$MakeNewResourceGroup,

    [Parameter(Mandatory = $false)]
    [switch]$WithVpnGateway,

    [Parameter(Mandatory = $false)]
    [string[]]$SpokeVirtualNetwork
)

# Check to see if ResourceGroup exists
try {
    $ResourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Stop
} catch {
    if ($MakeNewResourceGroup) {
        # Create new ResourceGroup if -MakeNewResourceGroup is specified.
        $ResourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location
    } else {
        $PSCmdlet.ThrowTerminatingError(
            [System.Management.Automation.ErrorRecord]::new(
                ([System.ArgumentException]"ResourceGroup does not exist. Either specify an existing ResourceGroup or use -MakeNewResourceGroup parameter."),
                '1004',
                [System.Management.Automation.ErrorCategory]::CloseError,
                $ResourceGroupName
            )
        )
    }
}


#region Create Virtual Network
$VirtualNetworkParams = @{
    'Name'              = $VirtualNetworkName
    'ResourceGroupName' = $ResourceGroupName
    'Location'          = $Location
    'AddressPrefix'     = $AddressPrefix
}

$VirtualNetwork = New-AzVirtualNetwork @VirtualNetworkParams -ErrorAction Stop
#endregion Create Virtual Network

#region Create VPN Gateway
if ($WithVpnGateway) {

    #region Gateway Subnet
    $SubnetParams = @{
        'Name'           = 'GatewaySubnet'
        'AddressPrefix'  = ((Get-NetworkAddress -IpAndMaskLength $AddressPrefix) + '/24')
        'VirtualNetwork' = $VirtualNetwork
    }

    $VirtualNetwork = Add-AzVirtualNetworkSubnetConfig @SubnetParams | Set-AzVirtualNetwork
    $GatewaySubnet = Get-AzVirtualNetworkSubnetConfig -Name 'GatewaySubnet' -VirtualNetwork $VirtualNetwork
    #endregion Gateway Subnet

    #region Create Public IP
    $PublicIpParams = @{
        'Name'              = 'egress-gateway-pip'
        'ResourceGroupName' = $ResourceGroupName
        'Location'          = $Location
        'AllocationMethod'  = 'Dynamic'
    }

    $PublicIpAddress = New-AzPublicIpAddress @PublicIpParams
    #endregion Create Public IP

    #region Create Ip Configuration
    $IpConfigParams = @{
        'Name'              = 'egress-gateway-ipc'
        'SubnetId'          = $GatewaySubnet.Id
        'PublicIpAddressId' = $PublicIpAddress.Id
    }
    $GatewayIpConfig = New-AzVirtualNetworkGatewayIpConfig @IpConfigParams
    #endregion Create Ip Configuration

    #region Create VirtualNetworkGateway
    $VirtualNetworkGatewayParams = @{
        'Name'              = 'egress-gateway-vpn'
        'ResourceGroupName' = $ResourceGroupName
        'Location'          = $Location
        'IpConfigurations'  = $GatewayIpConfig
        'GatewayType'       = 'Vpn'
        'VpnType'           = 'RouteBased'
        'GatewaySku'        = 'VpnGw1'
    }
    $VirtualNetworkGateway = New-AzVirtualNetworkGateway @VirtualNetworkGatewayParams
    #endregion Create VirtualNetworkGateway

}
#endregion Create VPN Gateway

#region VirtualNetwork Peering
if ($SpokeVirtualNetwork) {
    $ExistingVirtualNetworks = Get-AzVirtualNetwork
    foreach ($spoke in $SpokeVirtualNetwork) {
        $ThisSpokeVirtualNetwork = $ExistingVirtualNetworks | Where-Object { $_.Name -eq $spoke }
        if ($ThisSpokeVirtualNetwork.Location -eq $VirtualNetwork.Location) {
            # Hub to Spoke
            $HubVnetPeeringParams = @{
                'Name'                   = "egress-peer-$spoke"
                'Virtualnetwork'         = $VirtualNetwork
                'RemoteVirtualNetworkId' = $ThisSpokeVirtualNetwork.Id
                'AllowForwardedTraffic'  = $true
                'AllowGatewayTransit'    = $true
            }
            $HubPeering = Add-AzVirtualNetworkPeering @HubVnetPeeringParams

            # Spoke to Hub
            $SpokeVnetPeeringParams = @{
                'Name'                   = "$spoke-peer-egress"
                'RemoteVirtualNetworkId' = $VirtualNetwork.Id
                'Virtualnetwork'         = $ThisSpokeVirtualNetwork
                'AllowForwardedTraffic'  = $true
                'UseRemoteGateways'      = $true
            }
            $SpokeVnetPeering = Add-AzVirtualNetworkPeering @SpokeVnetPeeringParams
        } else {
            Write-Warning "Specificed Spoke Network is not in the same region as new egress network: $spoke"
        }
    }
}
#endregion VirtualNetwork Peering