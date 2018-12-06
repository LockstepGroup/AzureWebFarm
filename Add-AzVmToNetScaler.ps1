[CmdletBinding()]

Param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string[]]$VmName,

    [Parameter(Mandatory = $false)]
    [string]$AzSubscriptionId
)

BEGIN {
    # Check for Az Module
    try {
        Import-Module -Name Az -ErrorAction Stop | Out-Null
    } catch {
        $PSCmdlet.ThrowTerminatingError($PSItem)
    }

    # Check for Azure Login
    try {
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
            Set-AzContext -SubscriptionObject $DesiredSubscription
        } catch {
            $PSCmdlet.ThrowTerminatingError(
                [System.Management.Automation.ErrorRecord]::new(
                    ([System.ArgumentException]"Run Connect-AzAccount to login to Azure"),
                    '1001',
                    [System.Management.Automation.ErrorCategory]::CloseError,
                    $AzSubscriptionId
                )
            )
        }
    }
}

PROCESS {

}
