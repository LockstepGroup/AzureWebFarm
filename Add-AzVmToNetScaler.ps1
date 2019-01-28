[CmdletBinding()]

Param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string[]]$VmName,

    [Parameter(Mandatory = $true)]
    [string]$VmResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$NetScalerHostname,

    [Parameter(Mandatory = $true)]
    [string]$NetScalerObjectPrefix,

    [Parameter(Mandatory = $false)]
    [string[]]$TcpPort,

    [Parameter(Mandatory = $false)]
    [string[]]$UdpPort,

    [Parameter(Mandatory = $true)]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $NetScalerCredential,

    [Parameter(Mandatory = $true)]
    [string]$VirtualServerIpAddress,

    [Parameter(Mandatory = $false)]
    [string]$AzSubscriptionId,

    [Parameter(Mandatory = $false)]
    [switch]$Resume
)

BEGIN {
    $VerbosePrefix = 'Add-AzVmToNetScaler:'

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
    $RequiredModules += 'NetScaler'

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

    # Connect to NetScaler
    try {
        Write-Verbose "$VerbosePrefix Attempting to connect to NetScaler"
        Connect-NetScaler -Hostname $NetScalerHostname -Credential $NetScalerCredential -Https | Out-Null
    } catch {
        switch -Regex ($_.Exception.Message) {
            'Device\ not\ configured' {
                $PSCmdlet.ThrowTerminatingError(
                    [System.Management.Automation.ErrorRecord]::new(
                        ([System.Net.Http.HttpRequestException]"Unable to connect to Netscaler, please verify hostname/ip"),
                        '1000',
                        [System.Management.Automation.ErrorCategory]::InvalidOperation,
                        $null
                    )
                )
            }
        }
    }
}

PROCESS {
    # Get Virtual Machines and their NICs, add them to the NetScaler
    $NicNameRx = [regex] '[^\/]+?$'

    foreach ($vm in $VmName) {
        # Get the VM
        Write-Verbose "$VerbosePrefix Getting info for VM: $vm"
        $AzVm = Get-AzVM -ResourceGroupName $VmResourceGroupName -Name $vm
        $AzNetworkInterfaceName = $NicNameRx.Match($AzVM.NetworkProfile.NetworkInterfaces.Id).Value

        # Get the networkinterface (need to check for multiples)
        Write-Verbose "$VerbosePrefix AzNetworkInterfaceName: $AzNetworkInterfaceName"
        $AzNetworkInterface = Get-AzNetworkInterface -Name $AzNetworkInterfaceName -ResourceGroupName $VmResourceGroupName
        $AzIpConfigurations = $AzNetworkInterface.IpConfigurations

        # Verify there's only one IP and get it
        if ($AzIpConfigurations.Count -gt 1) {
            try {
                throw
            } catch {
                $PSCmdlet.ThrowTerminatingError(
                    [System.Management.Automation.ErrorRecord]::new(
                        ([System.ArgumentException]"VirtualMachine Network Interface has more than 1 Ip Configuration, this is not currently supported"),
                        '1002',
                        [System.Management.Automation.ErrorCategory]::CloseError,
                        $AzNetworkInterfaceName
                    )
                )
            }
        } else {
            $AzIpAddress = $AzIpConfigurations[0].PrivateIpAddress
            Write-Verbose "$VerbosePrefix AzIpAddress: $AzIpAddress"

            # Add Server to NetScaler
            try {
                Write-Verbose "$VerbosePrefix Adding NSLBServer: $vm`: $AzIpAddress"
                New-NSLBServer -Name $vm -IPAddress $AzIpAddress | Out-Null
            } catch {
                switch ($_.exception.response.reasonphrase) {
                    'Conflict' {
                        if ($Resume) {
                            Write-Warning "$VerbosePrefix Duplicate object found, but Resume specified: $vm"
                        } else {
                            $PSCmdlet.ThrowTerminatingError(
                                [System.Management.Automation.ErrorRecord]::new(
                                    ([System.ArgumentException]"NetScaler already has a Load Balanced Server configured with the given name. Use -Resume to override."),
                                    '1003',
                                    [System.Management.Automation.ErrorCategory]::InvalidOperation,
                                    $vm
                                )
                            )
                        }
                    }
                }
            }
        }
    }


    $ProtocolMap = @{}
    $ProtocolMap.'443' = 'SSL_BRIDGE'
    $ProtocolMap.'80' = 'HTTP'

    $MonitorMap = @{}
    $MonitorMap.'443' = 'https'
    $MonitorMap.'80' = 'http'

    function AddNSPortBaseConfig ($ports, $protocol) {
        foreach ($port in $ports) {
            # Generate Object Name
            $NsObjectName = $NetScalerObjectPrefix + "_" + $protocol + $port
            Write-Verbose "$VerbosePrefix NsObjectName: $NsObjectName"

            # Get Protocol Name
            if ($ProtocolMap."$port") {
                $ProtocolName = $ProtocolMap."$port"
            } else {
                $ProtocolName = $protocol
            }
            Write-Verbose "$VerbosePrefix ProtocolName: $ProtocolName"

            # Get Monitor Name
            if ($MonitorMap."$port") {
                $MonitorName = $MonitorMap."$port"
            } else {
                switch ($protocol) {
                    'tcp' {
                        $MonitorName = 'tcp'
                    }
                }
            }
            Write-Verbose "$VerbosePrefix MonitorName: $MonitorName"

            # Add Service Group
            try {
                Write-Verbose "$VerbosePrefix Adding NsServiceGroup: $NsObjectName, Protocol: $ProtocolName"
                New-NSLBServiceGroup -Name $NsObjectName -ServiceType $ProtocolName | Out-Null
            } catch {
                switch ($_.exception.response.reasonphrase) {
                    'Conflict' {
                        if ($Resume) {
                            Write-Warning "$VerbosePrefix Duplicate object found, but Resume specified: $NsObjectName"
                        } else {
                            $PSCmdlet.ThrowTerminatingError(
                                [System.Management.Automation.ErrorRecord]::new(
                                    ([System.ArgumentException]"NetScaler already has a Service Group configured with the given name. Use -Resume to override."),
                                    '1005',
                                    [System.Management.Automation.ErrorCategory]::InvalidOperation,
                                    $NsObjectName
                                )
                            )
                        }
                    }
                }
            }

            # Add Servers to Service Group
            foreach ($vm in $VmName) {
                try {
                    Write-Verbose "$VerbosePrefix Adding ServiceGroupMember '$vm' to ServiceGroup '$NsObjectName'."
                    New-NSLBServiceGroupMember -Name $NsObjectName -ServerName $vm -Port $port
                } catch {
                    switch ($_.exception.response.reasonphrase) {
                        'Conflict' {
                            if ($Resume) {
                                Write-Warning "$VerbosePrefix Duplicate object found, but Resume specified: $NsObjectName -> $vm"
                            } else {
                                $PSCmdlet.ThrowTerminatingError(
                                    [System.Management.Automation.ErrorRecord]::new(
                                        ([System.ArgumentException]"NetScaler Service Group already has a member with the name: $vm. Use -Resume to override."),
                                        '1006',
                                        [System.Management.Automation.ErrorCategory]::InvalidOperation,
                                        "$NsObjectName -> $vm"
                                    )
                                )
                            }
                        }
                    }
                }
            }

            # Add Monitors
            try {
                if ($MonitorName) {
                    Write-Verbose "$VerbosePrefix Binding Monitor '$MonitorName' to ServiceGroup '$NsObjectName'."
                    Add-NSLBServiceGroupMonitorBinding -ServiceGroupName $NsObjectName -MonitorName $MonitorName
                }
            } catch {
                switch ($_.exception.response.reasonphrase) {
                    'Conflict' {
                        if ($Resume) {
                            Write-Warning "$VerbosePrefix Monitor is already bound to Service Group, but Resume specified: $NsObjectName -> $MonitorName"
                        } else {
                            $PSCmdlet.ThrowTerminatingError(
                                [System.Management.Automation.ErrorRecord]::new(
                                    ([System.ArgumentException]"NetScaler Service Group already bound to monitor: $MonitorName. Use -Resume to override."),
                                    '1007',
                                    [System.Management.Automation.ErrorCategory]::InvalidOperation,
                                    "$NsObjectName -> $MonitorName"
                                )
                            )
                        }
                    }
                }
            }

            # Vip Settings
            $NsLbVirtualServerSettings = @{}
            $NsLbVirtualServerSettings.PersistenceType = 'NONE'
            $NsLbVirtualServerSettings.Timeout = 180
            $NsLbVirtualServerSettings.LBMethod = 'LEASTCONNECTION'
            $NsLbVirtualServerSettings.Name = $NsObjectName
            $NsLbVirtualServerSettings.IPAddress = $VirtualServerIpAddress
            $NsLbVirtualServerSettings.Port = $port
            $NsLbVirtualServerSettings.ServiceType = $ProtocolName

            try {
                Write-Verbose "$VerbosePrefix Adding NS Virtual Server '$NsObjectName'."
                New-NSLBVirtualServer @NsLbVirtualServerSettings
            } catch {
                switch ($_.exception.response.reasonphrase) {
                    'Conflict' {
                        if ($Resume) {
                            Write-Warning "$VerbosePrefix NS Virtual Server already exists, but Resume specified: $NsObjectName`."
                        } else {
                            $PSCmdlet.ThrowTerminatingError(
                                [System.Management.Automation.ErrorRecord]::new(
                                    ([System.ArgumentException]"NS Virtual Server already exists: $NsObjectName. Use -Resume to override."),
                                    '1009',
                                    [System.Management.Automation.ErrorCategory]::InvalidOperation,
                                    "$NsObjectName"
                                )
                            )
                        }
                    }
                }
            }

            # Bind Service Group to Virtual Server
            try {
                Write-Verbose "$VerbosePrefix Binding Service Group to Virtual Server: $NsObjectName -> $NsObjectName."
                Add-NSLBVirtualServerBinding -VirtualServerName $NsObjectName -ServiceGroupName $NsObjectName
            } catch {
                switch ($_.exception.response.reasonphrase) {
                    'Conflict' {
                        if ($Resume) {
                            Write-Warning "$VerbosePrefix Service Group binding already exists on Virtual Server, but Resume is specified: $NsObjectName -> $NsObjectName`."
                        } else {
                            $PSCmdlet.ThrowTerminatingError(
                                [System.Management.Automation.ErrorRecord]::new(
                                    ([System.ArgumentException]"Service Group binding already exists on Virtual Server: $NsObjectName -> $NsObjectName`. Use -Resume to override."),
                                    '1010',
                                    [System.Management.Automation.ErrorCategory]::InvalidOperation,
                                    "$NsObjectName"
                                )
                            )
                        }
                    }
                }
            }
        }
    }

    # Configure NetScaler Vip/ServiceGroups/Monitors
    AddNSPortBaseConfig $TcpPort tcp
    AddNSPortBaseConfig $UdpPort udp



}

End {
    Save-NSConfig
    Disconnect-NetScaler
}
