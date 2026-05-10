# =====================================================
# AMCAF Identity Governance Assessment
# Connects to Microsoft Graph and assesses tenant posture
# =====================================================

$ConfigPath = "D:\AMCAF\config\.env"
$ReportPath = "D:\AMCAF\logs\identity-assessment-report.json"

# ---------- Load .env ----------
if (!(Test-Path $ConfigPath)) {
    throw "Config file not found: $ConfigPath"
}

Get-Content $ConfigPath | ForEach-Object {
    if ($_ -match "=" -and -not $_.StartsWith("#")) {
        $name, $value = $_ -split "=", 2
        Set-Variable -Name $name -Value $value
    }
}

# ---------- Get Graph Token ----------
$Body = @{
    client_id     = $CLIENT_ID
    scope         = $GRAPH_SCOPE
    client_secret = $CLIENT_SECRET
    grant_type    = "client_credentials"
}

Write-Host "Requesting Microsoft Graph token..."

$Token = Invoke-RestMethod `
    -Uri "https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token" `
    -Method POST `
    -Body $Body

$Headers = @{
    Authorization = "Bearer $($Token.access_token)"
}

Write-Host "Token acquired."
Write-Host ""

# ---------- Helper Function ----------
function Invoke-GraphGet {
    param (
        [string]$Uri,
        [string]$Name
    )

    try {
        Write-Host "Collecting: $Name"
        return Invoke-RestMethod -Uri $Uri -Headers $Headers -Method GET
    }
    catch {
        Write-Warning "Failed to collect $Name : $($_.Exception.Message)"
        return $null
    }
}

# ---------- Collect Evidence ----------
$Users = Invoke-GraphGet `
    -Name "Users" `
    -Uri "https://graph.microsoft.com/v1.0/users?`$select=id,displayName,userPrincipalName,userType,accountEnabled,createdDateTime&`$top=999"

$Groups = Invoke-GraphGet `
    -Name "Groups" `
    -Uri "https://graph.microsoft.com/v1.0/groups?`$select=id,displayName,securityEnabled,mailEnabled,groupTypes&`$top=999"

$Apps = Invoke-GraphGet `
    -Name "App registrations" `
    -Uri "https://graph.microsoft.com/v1.0/applications?`$select=id,displayName,appId,createdDateTime,signInAudience&`$top=999"

$ServicePrincipals = Invoke-GraphGet `
    -Name "Enterprise applications" `
    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=id,displayName,appId,accountEnabled,servicePrincipalType&`$top=999"

$CAPolicies = Invoke-GraphGet `
    -Name "Conditional Access policies" `
    -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"

$DirectoryRoles = Invoke-GraphGet `
    -Name "Directory roles" `
    -Uri "https://graph.microsoft.com/v1.0/directoryRoles"

$MFARegistration = Invoke-GraphGet `
    -Name "Authentication method registration details" `
    -Uri "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails"

# ---------- Basic Metrics ----------
$AllUsers = @($Users.value)
$EnabledUsers = @($AllUsers | Where-Object { $_.accountEnabled -eq $true })
$GuestUsers = @($AllUsers | Where-Object { $_.userType -eq "Guest" })
$DisabledUsers = @($AllUsers | Where-Object { $_.accountEnabled -eq $false })

$AllGroups = @($Groups.value)
$AllApps = @($Apps.value)
$AllServicePrincipals = @($ServicePrincipals.value)
$AllCAPolicies = @($CAPolicies.value)
$AllDirectoryRoles = @($DirectoryRoles.value)
$MFAUsers = @($MFARegistration.value)

$MfaCapableUsers = @($MFAUsers | Where-Object { $_.isMfaCapable -eq $true })
$MfaRegisteredUsers = @($MFAUsers | Where-Object { $_.isMfaRegistered -eq $true })

# ---------- Global Admin Members ----------
$GlobalAdminRole = $AllDirectoryRoles | Where-Object { $_.displayName -eq "Global Administrator" }

$GlobalAdminMembers = @()

if ($GlobalAdminRole) {
    $RoleMembers = Invoke-GraphGet `
        -Name "Global Administrator members" `
        -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($GlobalAdminRole.id)/members"

    if ($RoleMembers) {
        $GlobalAdminMembers = @($RoleMembers.value)
    }
}

# ---------- Scoring Logic ----------
$Findings = @()

function Add-Finding {
    param (
        [string]$ControlId,
        [string]$ControlName,
        [string]$Status,
        [string]$Risk,
        [string]$Evidence,
        [string]$Recommendation,
        [string]$RegulatoryMapping
    )

    $script:Findings += [PSCustomObject]@{
        controlId = $ControlId
        controlName = $ControlName
        status = $Status
        risk = $Risk
        evidence = $Evidence
        recommendation = $Recommendation
        regulatoryMapping = $RegulatoryMapping
    }
}

# MFA assessment
if ($MFAUsers.Count -gt 0) {
    $MfaRate = [math]::Round(($MfaRegisteredUsers.Count / $EnabledUsers.Count) * 100, 2)

    if ($MfaRate -ge 90) {
        $MfaStatus = "Pass"
        $MfaRisk = "Low"
    }
    elseif ($MfaRate -ge 70) {
        $MfaStatus = "Partial"
        $MfaRisk = "Medium"
    }
    else {
        $MfaStatus = "Fail"
        $MfaRisk = "High"
    }

    Add-Finding `
        -ControlId "ID-001" `
        -ControlName "MFA registration coverage" `
        -Status $MfaStatus `
        -Risk $MfaRisk `
        -Evidence "$($MfaRegisteredUsers.Count) of $($EnabledUsers.Count) enabled users are registered for MFA. Coverage: $MfaRate%." `
        -Recommendation "Increase MFA registration coverage and enforce phishing-resistant authentication where possible." `
        -RegulatoryMapping "NIST IA-2, ISO 27001 access control, FCA operational resilience, GDPR Article 32"
}
else {
    Add-Finding `
        -ControlId "ID-001" `
        -ControlName "MFA registration coverage" `
        -Status "Unknown" `
        -Risk "Medium" `
        -Evidence "MFA registration data could not be collected. Reports.Read.All may be required." `
        -Recommendation "Add the required Microsoft Graph report permission and rerun the assessment." `
        -RegulatoryMapping "NIST IA-2, ISO 27001 access control, GDPR Article 32"
}

# Conditional Access assessment
if ($AllCAPolicies.Count -gt 0) {
    $EnabledCAPolicies = @($AllCAPolicies | Where-Object { $_.state -eq "enabled" })

    if ($EnabledCAPolicies.Count -gt 0) {
        $CAStatus = "Pass"
        $CARisk = "Low"
    }
    else {
        $CAStatus = "Fail"
        $CARisk = "High"
    }

    Add-Finding `
        -ControlId "ID-002" `
        -ControlName "Conditional Access policy enforcement" `
        -Status $CAStatus `
        -Risk $CARisk `
        -Evidence "$($AllCAPolicies.Count) Conditional Access policies found. $($EnabledCAPolicies.Count) are enabled." `
        -Recommendation "Ensure baseline Conditional Access policies are enabled for administrators, high-risk users, unmanaged devices and external access." `
        -RegulatoryMapping "NIST AC-2, NIST IA-2, ISO 27001 access control, DORA ICT risk management"
}
else {
    Add-Finding `
        -ControlId "ID-002" `
        -ControlName "Conditional Access policy enforcement" `
        -Status "Fail" `
        -Risk "High" `
        -Evidence "No Conditional Access policies were found or policies could not be collected." `
        -Recommendation "Create baseline Conditional Access policies for administrative roles, MFA enforcement and risky sign-ins." `
        -RegulatoryMapping "NIST AC-2, NIST IA-2, ISO 27001 access control, DORA ICT risk management"
}

# Global Admin assessment
if ($GlobalAdminMembers.Count -le 5 -and $GlobalAdminMembers.Count -gt 0) {
    $GAStatus = "Pass"
    $GARisk = "Low"
}
elseif ($GlobalAdminMembers.Count -gt 5) {
    $GAStatus = "Partial"
    $GARisk = "Medium"
}
else {
    $GAStatus = "Unknown"
    $GARisk = "Medium"
}

Add-Finding `
    -ControlId "ID-003" `
    -ControlName "Global Administrator exposure" `
    -Status $GAStatus `
    -Risk $GARisk `
    -Evidence "$($GlobalAdminMembers.Count) Global Administrator account(s) identified." `
    -Recommendation "Limit Global Administrator assignments, use Privileged Identity Management, and maintain break-glass accounts with strict monitoring." `
    -RegulatoryMapping "NIST AC-6, ISO 27001 privileged access management, FCA operational resilience"

# Guest user assessment
$GuestRate = 0
if ($AllUsers.Count -gt 0) {
    $GuestRate = [math]::Round(($GuestUsers.Count / $AllUsers.Count) * 100, 2)
}

if ($GuestRate -le 10) {
    $GuestStatus = "Pass"
    $GuestRisk = "Low"
}
elseif ($GuestRate -le 25) {
    $GuestStatus = "Partial"
    $GuestRisk = "Medium"
}
else {
    $GuestStatus = "Fail"
    $GuestRisk = "High"
}

Add-Finding `
    -ControlId "ID-004" `
    -ControlName "Guest account exposure" `
    -Status $GuestStatus `
    -Risk $GuestRisk `
    -Evidence "$($GuestUsers.Count) guest accounts found out of $($AllUsers.Count) total users. Guest ratio: $GuestRate%." `
    -Recommendation "Review guest users regularly, enforce access reviews, apply Conditional Access to external users and remove stale B2B accounts." `
    -RegulatoryMapping "NIST AC-2, ISO 27001 supplier/access control, GDPR Article 32"

# Application registration assessment
if ($AllApps.Count -le 20) {
    $AppStatus = "Pass"
    $AppRisk = "Low"
}
elseif ($AllApps.Count -le 50) {
    $AppStatus = "Partial"
    $AppRisk = "Medium"
}
else {
    $AppStatus = "Fail"
    $AppRisk = "High"
}

Add-Finding `
    -ControlId "ID-005" `
    -ControlName "Application registration inventory" `
    -Status $AppStatus `
    -Risk $AppRisk `
    -Evidence "$($AllApps.Count) app registrations and $($AllServicePrincipals.Count) enterprise applications identified." `
    -Recommendation "Review app ownership, consent permissions, credential expiry and unused enterprise applications." `
    -RegulatoryMapping "NIST CM-8, ISO 27001 asset management, DORA third-party ICT risk"

# Disabled accounts assessment
Add-Finding `
    -ControlId "ID-006" `
    -ControlName "Disabled account hygiene" `
    -Status "Informational" `
    -Risk "Low" `
    -Evidence "$($DisabledUsers.Count) disabled user accounts identified." `
    -Recommendation "Review disabled accounts and remove those no longer required for audit, legal hold or operational reasons." `
    -RegulatoryMapping "NIST AC-2, ISO 27001 identity lifecycle management"

# ---------- Summary Score ----------
$PassCount = @($Findings | Where-Object { $_.status -eq "Pass" }).Count
$PartialCount = @($Findings | Where-Object { $_.status -eq "Partial" }).Count
$FailCount = @($Findings | Where-Object { $_.status -eq "Fail" }).Count
$UnknownCount = @($Findings | Where-Object { $_.status -eq "Unknown" }).Count

$ScoredControls = @($Findings | Where-Object { $_.status -in @("Pass","Partial","Fail") }).Count

if ($ScoredControls -gt 0) {
    $Score = [math]::Round((($PassCount + ($PartialCount * 0.5)) / $ScoredControls) * 100, 2)
}
else {
    $Score = 0
}

# ---------- Build Report ----------
$Report = [PSCustomObject]@{
    assessmentName = "AMCAF Identity Governance Assessment"
    tenantId = $TENANT_ID
    assessmentDateUtc = (Get-Date).ToUniversalTime().ToString("s") + "Z"
    overallScore = $Score
    summary = @{
        totalUsers = $AllUsers.Count
        enabledUsers = $EnabledUsers.Count
        disabledUsers = $DisabledUsers.Count
        guestUsers = $GuestUsers.Count
        groups = $AllGroups.Count
        appRegistrations = $AllApps.Count
        enterpriseApplications = $AllServicePrincipals.Count
        conditionalAccessPolicies = $AllCAPolicies.Count
        globalAdministrators = $GlobalAdminMembers.Count
        passedControls = $PassCount
        partialControls = $PartialCount
        failedControls = $FailCount
        unknownControls = $UnknownCount
    }
    findings = $Findings
    evidence = @{
        globalAdministrators = $GlobalAdminMembers | Select-Object displayName,userPrincipalName,id
        conditionalAccessPolicies = $AllCAPolicies | Select-Object displayName,state,createdDateTime,modifiedDateTime
        guestUsers = $GuestUsers | Select-Object displayName,userPrincipalName,createdDateTime
        appRegistrations = $AllApps | Select-Object displayName,appId,createdDateTime,signInAudience
    }
}

# ---------- Save Report ----------
$Report | ConvertTo-Json -Depth 10 | Out-File $ReportPath -Encoding UTF8

Write-Host ""
Write-Host "=============================================="
Write-Host "AMCAF Identity Assessment Completed"
Write-Host "=============================================="
Write-Host "Overall Score: $Score%"
Write-Host "Passed: $PassCount | Partial: $PartialCount | Failed: $FailCount | Unknown: $UnknownCount"
Write-Host "Report saved to: $ReportPath"
Write-Host "=============================================="
Write-Host ""

$Findings | Format-Table controlId, controlName, status, risk -AutoSize