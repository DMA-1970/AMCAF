# Load config
$envFile = Get-Content "D:\AMCAF\config\.env"

foreach ($line in $envFile) {
    if ($line -match "=") {
        $name, $value = $line -split "=", 2
        Set-Variable -Name $name -Value $value
    }
}

Write-Host ""
Write-Host "Requesting token..."
Write-Host ""

# Request token
$Body = @{
    client_id     = $CLIENT_ID
    scope         = $GRAPH_SCOPE
    client_secret = $CLIENT_SECRET
    grant_type    = "client_credentials"
}

$Token = Invoke-RestMethod `
    -Uri "https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token" `
    -Method POST `
    -Body $Body

Write-Host "ACCESS TOKEN ACQUIRED"
Write-Host ""

# Query Graph
$Headers = @{
    Authorization = "Bearer $($Token.access_token)"
}

$Users = Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/users?`$top=5" `
    -Headers $Headers

Write-Host ""
Write-Host "CONNECTED TO TENANT SUCCESSFULLY"
Write-Host ""

$Users.value | Select-Object displayName,userPrincipalName