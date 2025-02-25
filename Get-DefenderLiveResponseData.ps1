<#

    .SYNOPSIS
    Retrieve Live Response data from Microsoft Defender Action Center API.

    .DESCRIPTION
    This function retrieves Live Response data from Microsoft Defender Action Center API. The data can then be sent to Splunk for further analysis or viewed in the console.

    .PARAMETER StartTime
    The start time for the data retrieval. The format should be "MM/DD/YYYY HH:MM:SS AM/PM".

    .PARAMETER EndTime
    The end time for the data retrieval. The format should be "MM/DD/YYYY HH:MM:SS AM/PM".

    .PARAMETER SplunkURI
    The URI of the Splunk HTTP Event Collector (HEC) endpoint. I.E. "http://splunkserver.example.com:8088/services/collector/event".

    .PARAMETER SplunkHECKey
    The HEC key for the Splunk HTTP Event Collector. This can be retrieved from the Splunk HEC configuration.

    .PARAMETER DefenderCloudEnvironment
    The Microsoft Defender for Endpoint cloud environment. Valid values are 'Commercial', 'gcc', and 'gcchigh'.

    .PARAMETER EntraCloudEnvironment
    The Microsoft Defender for Endpoint cloud environment. Valid values are 'Commercial' and 'gcchigh'.

    .PARAMETER TenantID
    The TenantID for the spoke tenant where the action center data will be pulled from.

    .EXAMPLE
    .\Get-DefenderLiveResponseData -entracloudenvironment commercial -defendercloudenvironment gcc -tenantid "00000000-0000-0000-0000-000000000000"

    This example retrieves Live Response data from the gcc defender API for all time and outputs the results to the console and stores the results in the $LiveResponseEvents variable.

    .EXAMPLE
    .\Get-DefenderLiveResponseData -StartTime "11/15/2024 12:00:00 PM" -EndTime "12/06/2024 12:30:00 AM" -splunkURI "http://splunkserver.example.com:8088/services/collector/event" -splunkHECKey "123456789" -DefenderCloudEnvironment Commercial -EntraCloudEnvironment Commercial -tenantID "00000000-0000-0000-0000-000000000000"

    This example retrieves Live Response data from Microsoft Defender for Endpoint for the specified time range and sends it to Splunk.

    .EXAMPLE
    .\Get-DefenderLiveResponseData -splunkURI "http://splunkserver.example.com:8088/services/collector/event" -splunkHECKey "123456789" -DefenderCloudEnvironment Commercial -EntraCloudEnvironment Commercial -tenantID "00000000-0000-0000-0000-000000000000"

    This example retrieves Live Response data from Microsoft Defender for Endpoint for all time and sends it to Splunk.

#>
[CmdletBinding(DefaultParameterSetName = 'Default')]
Param(
    [Parameter(Mandatory = $false)]
    [datetime]$StartTime,

    [Parameter(Mandatory = $false)]
    [datetime]$EndTime,

    [Parameter(Mandatory = $false, ParameterSetName = "SplunkURI")]
    [string]$SplunkURI,

    [Parameter(Mandatory = $true, ParameterSetName = "SplunkURI")]
    [string]$SplunkHECKey,

    [Parameter(Mandatory = $true)]
    [validateSet('Commercial', 'gcc', 'gcchigh')]
    [string]$DefenderCloudEnvironment,

    [Parameter(Mandatory = $true)]
    [validateSet('Commercial', 'gcchigh')]
    [string]$EntraCloudEnvironment,

    [Parameter(Mandatory = $true)]
    [string]$TenantID
)

#Requires -Version 7

$ProgressPreference = 'SilentlyContinue'

Function Write-TitleMessage{
    param(
        [string]$Title,
        [switch]$Clear,
        [int]$BreakLineLength,
        [switch]$Log
    )
    $Time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    # build a line based on BreakLineLength
    $BreakLine = "-" * $BreakLineLength
    # output the line break
    If($BreakLineLength){Write-Host $BreakLine -ForegroundColor Cyan}Else{Write-Host ""}
    Write-Host "[$Time] $Title" -ForegroundColor Cyan
    If($BreakLineLength){Write-Host $BreakLine -ForegroundColor Cyan}Else{Write-Host ""}

    If($Log){Write-Log -Message $Title}

    If($Clear){Clear-Host}
}

function Write-FormattedMessage {
    param (
        [string]$Message,
        [ValidateSet("Success", "Warning", "Error", "Info")]
        [string]$Status,
        [switch]$Log,
        [switch]$FlipSymbol
    )

    # Define fixed column widths
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $messageWidth = 100

    switch ($Status) {
        "Success" { $Status = "INFO"; $Symbol = [char]::ConvertFromUtf32(0x2705)}
        "Warning" { $Status = "INFO"; $Symbol = [char]::ConvertFromUtf32(0x26A0) + " " }
        "Error" { $Status = "ERROR"; $Symbol = [char]::ConvertFromUtf32(0x274C)}
        "Info" { $Status = "INFO"; $Symbol = [char]::ConvertFromUtf32(0x2139) + " " }
    }

    # Format the message
    If ($FlipSymbol) {
        $formattedMessage = ("[{0}] {1,-$($messageWidth)} {2}" -f $TimeStamp, $Message, $Symbol)
    } Else {
        $formattedMessage = ("  {1} - {0}" -f $Message, $Symbol)
    }
    Write-Output $formattedMessage

    If ($Log) {
        Write-Log -Message $Message -Level $Status
    }
}


$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19042'
switch ($DefenderCloudEnvironment.ToLower().Trim()) {
    "commercial" {
        $Scope           = "https://securitycenter.microsoft.com/mtp/.default"
        $ActionCenterAPI = "https://m365d-autoir-ac-prd-cus3.securitycenter.windows.com/api/autoir/actioncenterui/history-actions"
        $ClientID        = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
    }
    "gcc" {
        $Scope           = "https://securitycenter.microsoft.com/mtp/.default"
        $ActionCenterAPI = "https://m365d-autoir-ac-fm-usmv.securitycenter.windows.us/api/autoir/actioncenterui/history-actions"
        $ClientID        = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
    }
    "gcchigh" {
        $Scope           = "https://securitycenter.microsoft.com/mtp/.default"
        $ActionCenterAPI = "https://m365d-autoir-ac-ff-usgv.securitycenter.windows.us/api/autoir/actioncenterui/history-actions"
        $ClientID        = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
    }
}

# TokenTacticsV2
function Get-AzureToken {

    <#
        .DESCRIPTION
        Generate a device code to be used at https://www.microsoft.com/devicelogin. Once a user has successfully authenticated, you will be presented with a JSON Web Token JWT in the variable $response.

        .EXAMPLE
        Get-AzureToken -UseCAE

        This example generates a device code and uses the 'cp1' claim to get a access token valid for 24 hours.

        .EXAMPLE
        Get-AzureToken

        This example generates a device code and uses the default claim to get a access token valid for 1 hour.

    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [Switch]$UseCAE
    )
    $Headers = @{}
    $Headers["User-Agent"] = $UserAgent

    $body = @{
        "client_id" = $ClientID
        "scope"     = $Scope
    }

    if ($EntraCloudEnvironment -eq "gcchigh") {
        $BaseUrl = "login.microsoftonline.us"
    } else {
        $BaseUrl = "login.microsoftonline.com"
    }

    # Login Process
    Write-Verbose ( $body | ConvertTo-Json )
    try {
        $authResponse = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://$BaseUrl/$tenantID/oauth2/v2.0/devicecode" -Headers $Headers -Body $body -ErrorAction SilentlyContinue
    } catch {
        Write-Verbose ( $_.Exception.Message )
        throw $_.Exception.Message
    }
    #Write-Output $authResponse.user_code
    #Write-Output $authResponse.verification_uri
    #Write-Output $authResponse.message
    $continue = $true
    $interval = $authResponse.interval
    $expires = $authResponse.expires_in
    $body = @{
        "client_id"   = $body['client_id']
        "grant_type"  = "urn:ietf:params:oauth:grant-type:device_code"
        "device_code" = $authResponse.device_code
    }
    #Write-Verbose ($body | ConvertTo-Json)
    if ($UseCAE) {
        # Add 'cp1' as client claim to get a access token valid for 24 hours
        $Claims = ( @{"access_token" = @{ "xms_cc" = @{ "values" = @("cp1") } } } | ConvertTo-Json -Compress -Depth 99 )
        $body.Add("claims", $Claims)
        #Write-Verbose ( $body | ConvertTo-Json )
    }

    # Open the Edge browser to the verification URL
    $Null = Start-Process msedge -ArgumentList "$($authResponse.verification_uri)?user_code=$($authResponse.user_code)" -PassThru

    while ($continue) {
        Start-Sleep -Seconds $interval
        $total += $interval

        if ($total -gt $expires) {
            Write-Error "Timeout occurred"
            return
        }
        # Remove response if it exists
        $Null = Remove-Variable -Name tokenResponse -Scope global -ErrorAction SilentlyContinue

        # Try to get the response. Will give 40x while pending so we need to try&catch
        try {
            $Global:tokenResponse = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://$BaseUrl/$TenantID/oauth2/v2.0/token" -Headers $Headers -Body $body -ErrorAction SilentlyContinue
        } catch {
            # This is normal flow, always returns 40x unless successful
            $details = $_.ErrorDetails.Message | ConvertFrom-Json
            $continue = $details.error -eq "authorization_pending"
            #Write-Output $details.error

            if (!$continue) {
            # Not pending so this is a real error
            Write-Error $details.error_description
            return
            }
        }

        # If we got response, all okay!
        if ($tokenResponse) {
            return $tokenResponse
        }
    }
}

Function Get-MDELiveResponseData {
    <#

    .SYNOPSIS
    Retrieve Live Response data from Microsoft Defender for Endpoint.

    .DESCRIPTION
    This function retrieves Live Response data from Microsoft Defender for Endpoint. The data can then be sent to Splunk for further analysis.

    .EXAMPLE
    Get-MDELiveResponseData -StartTime "11/15/2024 12:00:00 PM" -EndTime "12/06/2024 12:30:00 AM"

    This example retrieves Live Response data from Microsoft Defender for Endpoint for the specified time range and sends it to Splunk.

    .EXAMPLE
    Get-MDELiveResponseData

    This example retrieves Live Response data from Microsoft Defender for Endpoint for all time and outputs the results to the console.

    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        $Token,
        [Parameter(Mandatory = $false)]
        [string]$URL = $ActionCenterAPI,
        [Parameter(Mandatory = $false)]
        [ValidatePattern("^\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{2}:\d{2} (AM|PM)$")]
        [datetime]$StartTime,
        [Parameter(Mandatory = $false)]
        [ValidatePattern("^\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{2}:\d{2} (AM|PM)$")]
        [datetime]$EndTime
    )

    # Set the WebRequest headers
    $headers = [Ordered]@{
        Authorization = "Bearer $token"
        'Content-Type' = 'application/json'
        "User-Agent" = $UserAgent
        "x-ms-tenant-id" = $TenantID
    }

    if($StartTime -and $EndTime){
        # Build the filter
        [string]$StartTime = $StartTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
        [string]$EndTime = $EndTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
        $Filter = "/?useMtpApi=true&pageIndex=1&fromDate=$StartTime&toDate=$EndTime&sortByField=eventTime&sortOrder=Descending"
        $FilterURL = $URL + $Filter
    }else{
        $FilterURL = $URL
    }

    # Send the webrequest and get the results.
    try{
        $MDEAPIresponse = Invoke-WebRequest -Method Get -Uri $FilterURL -Headers $headers -ErrorAction Stop
    }catch{
        Write-Error $_.Exception.Message
        Break
    }

    $Global:LiveResponseEvents = @()
    # Extract the alerts from the results.
    $ActionCenterResults =  ($MDEAPIresponse.content | ConvertFrom-Json).results
    $ActionCenterData = $ActionCenterResults | Where-Object{$_.ActionType -eq 'LiveResponseCommand'}

    if($ActionCenterData.count -eq 0){
        Write-FormattedMessage -Message "No data found for the specified time range." -Status "Info"
    }else{
        Write-FormattedMessage -Message "Found $($ActionCenterData.count) Live Response Command events." -Status "Success"

        ForEach($Event in $ActionCenterData){

            # Build the object
            $Global:LiveResponseEvents += [PSCustomObject]@{
                StartTime = $Event.StartTime
                EndTime = $Event.EndTime
                ActionType = $Event.ActionType
                UserPrincipalName = $Event.UserPrincipalName
                DeviceName = $Event.ComputerName
                DeviceID = $Event.MachineID
                Command = $Event.AdditionalFields.raw_command
                TenantID = $TenantID
            }
        }
    }
    return $Global:LiveResponseEvents
}

# Ship data to Splunk
Function Send-SplunkEvent {
    <#
    .SYNOPSIS
        Send events to Splunk's HTTP Event Collector.
    .DESCRIPTION
        This function uses Invoke-RestMethod to send structured data to Splunk HTTP Event Collector. Use the InputObject parameter to specify the data to send.
        HostName and DateTime parameters to control Splunk's 'host' and 'time' properties for the generated event.
    .EXAMPLE
        PS C:\> .\Send-SplunkEvent.ps1 -InputObject @{message="Hello Splunk!"} -Key <token>

        This example sends a simple event containing "message": "Hello Splunk!" to the event collector running on the local system.
    .EXAMPLE
        PS C:\> Import-Csv logs.csv | .\Send-SplunkEvent -Key <token> -HostName SBC1 -Uri "https://splunk01.example.com:8088/services/collector/event"

        This example imports logs from a CSV file and sends each one of them to event collector running on splunk01.example.com.
        The HostName parameter specifies which host created the logs.
    .INPUTS
        [psobject]
    .OUTPUTS
        None.
    .NOTES
        Author: @torggler
    .LINK
    https://ntsystems.it/PowerShell/Send-SplunkEvent/
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        # Data object that will be sent to Splunk's HTTP Event Collector.
        [Parameter(Mandatory,ValueFromPipeline)]
        $InputObject,
        # URI of the Splunk HTTP Event Collector instance.
        [Parameter()]
        [string]$Uri = $SplunkURI,
        # Key for the Splunk HTTP Event Collector instance.
        [Parameter()]
        [string]$Key = $SplunkHECKey
    )
    process {
        # Create json object to send
        $Body = @{
            event = $InputObject
        } | ConvertTo-Json -Compress

        Write-TitleMessage -Title "Sending Live Response data to Splunk server: $SplunkURI" -BreakLineLength 80
        if ($PSCmdlet.ShouldProcess($Body, "Send")) {
            $r = Invoke-RestMethod -Uri $uri -Method Post -Headers @{ Authorization = "Splunk $Key" } -Body $Body -SkipCertificateCheck
            if ($r.text -ne "Success"){
                Write-FormattedMessage -Message "Failed to send Live Response data to Splunk server: $SplunkURI" -Status "Error"
            }else{
                Write-FormattedMessage -Message "Successfully sent Live Response data to Splunk server: $SplunkURI" -Status "Success"
            }
        }
    }
}

# Main script

# Check if the Splunk server is reachable
if($SplunkURI){
    Write-TitleMessage -Title "Checking if client can reach Splunk server" -BreakLineLength 80
    $SplunkServer = $SplunkURI -replace "https?://([^/:]+).*", '$1'
    $SplunkPort = $SplunkURI -replace ".*:(\d+).*", '$1'
    if(-not ($Null=Test-NetConnection $SplunkServer -Port $SplunkPort -InformationLevel Quiet)){
        Write-FormattedMessage -Message "Unable to reach Splunk server: $SplunkServer on port: $SplunkPort" -Status "Error"
        Write-FormattedMessage -Message "Verify the Splunk server address and port are correct and not blocked by a firewall or other device" -Status "info"
        Break
    }else{
        Write-FormattedMessage -Message "Successfully reached Splunk server: $SplunkServer on port: $SplunkPort" -Status "Success"
    }
}

Write-TitleMessage -Title "Attempting to aquire an access token.. please login" -BreakLineLength 80

# Retrieve the token
$accessToken = Get-AzureToken

if(!$accessToken){
    Write-FormattedMessage -Message "Failed to aquire an access token" -Status "Error"
    Break
}else{
    Write-FormattedMessage -Message "Successfully aquired an access token" -Status "Success"
}

# Retrieve the Live Response data
$Time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Write-Host ""
Write-Host "[$Time] Attempting to connect to action center api" -ForegroundColor Cyan

if($StartTime -and $EndTime){
    Get-MDELiveResponseData -Token $accessToken.access_token -StartTime $StartTime -EndTime $EndTime
}else{
    Get-MDELiveResponseData -Token $accessToken.access_token
}

if($SplunkHECKey -and $SplunkURI){
    try{
        Send-SplunkEvent -InputObject $LiveResponseEvents -Key $SplunkHECKey -Uri $SplunkURI
    }catch{
        Write-Error $_.Exception.Message
    }
}
