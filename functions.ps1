function Get-AppCfgKeyvalue {
    [CmdletBinding()]
    param (
        $AppCfgConnectionString
    )
    process {
        $appCfgParams = $AppCfgConnectionString -split ";" |
                        % {$ret = @{}} {$values = $_ -split "=",2; $ret["$($values[0])"] = $values[1]} {[pscustomobject]$ret} | select endpoint, secret, id, @{l="host"; e = {[System.Uri]::new($_.endpoint).Host}}
        $uri = [System.Uri]::new("https://$($appCfgParams.host)/kv?api-version=1.0")
        $method = "GET"
        $body = $null

        $headers = Sign-Request $uri.Authority $method $uri.PathAndQuery $body $appCfgParams.id $appCfgParams.Secret
        $headers["Content-Type"] = "application/vnd.microsoft.appconfig.kv+json"
        (Invoke-RestMethod -Uri $uri -Method $method -Headers $headers -Body $body).Items
    }
}

function Set-AppCfgKeyvalue {
    [CmdletBinding()]
    param (
        $Key,
        $Value,
        $AppCfgConnectionString
    )
    process {
        $appCfgParams = $AppCfgConnectionString -split ";" |
                        % {$ret = @{}} {$values = $_ -split "=",2; $ret["$($values[0])"] = $values[1]} {[pscustomobject]$ret} | select endpoint, secret, id, @{l="host"; e = {[System.Uri]::new($_.endpoint).Host}}
        $uri = [System.Uri]::new("https://$($appCfgParams.host)/kv/$($Key)?api-version=1.0")
        $method = "PUT"
        $body = "{`"value`": `"$Value`"}"

        $headers = Sign-Request $uri.Authority $method $uri.PathAndQuery $body $appCfgParams.id $appCfgParams.Secret
        $headers["Content-Type"] = "application/vnd.microsoft.appconfig.kv+json"
        (Invoke-RestMethod -Uri $uri -Method $method -Headers $headers -Body $body).Items
    }
}

function Sign-Request(
    [string] $hostname,
    [string] $method, # GET, PUT, POST, DELETE
    [string] $url, # path+query
    [string] $body, # request body
    [string] $credential, # access key id
    [string] $secret       # access key value (base64 encoded)
)
{
    $verb = $method.ToUpperInvariant()
    $utcNow = (Get-Date).ToUniversalTime().ToString("R", [Globalization.DateTimeFormatInfo]::InvariantInfo)
    $contentHash = Compute-SHA256Hash $body

    $signedHeaders = "x-ms-date;host;x-ms-content-sha256"; # Semicolon separated header names

    $stringToSign = $verb + "`n" +
    $url + "`n" +
    $utcNow + ";" + $hostname + ";" + $contentHash  # Semicolon separated signedHeaders values

    $signature = Compute-HMACSHA256Hash $secret $stringToSign

    # Return request headers
    return @{
        "x-ms-date"           = $utcNow;
        "x-ms-content-sha256" = $contentHash;
        "Authorization"       = "HMAC-SHA256 Credential=" + $credential + "&SignedHeaders=" + $signedHeaders + "&Signature=" + $signature
    }
}

function Compute-SHA256Hash(
    [string] $content
) {
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [Convert]::ToBase64String($sha256.ComputeHash([Text.Encoding]::ASCII.GetBytes($content)))
    }
    finally {
        $sha256.Dispose()
    }
}

function Compute-HMACSHA256Hash(
    [string] $secret, # base64 encoded
    [string] $content
) {
    $hmac = [System.Security.Cryptography.HMACSHA256]::new([Convert]::FromBase64String($secret))
    try {
        return [Convert]::ToBase64String($hmac.ComputeHash([Text.Encoding]::ASCII.GetBytes($content)))
    }
    finally {
        $hmac.Dispose()
    }
}