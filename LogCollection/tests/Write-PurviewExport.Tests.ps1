#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    . "$PSScriptRoot/../Get-PurviewAudit.ps1" -UserPrincipalName 'dummy@test.com'
}

Describe 'Write-PurviewExport' {
    BeforeAll {
        # The script sets StrictMode -Version Latest; reset here so Pester dynamic
        # parameter binding (Should -BeGreaterOrEqualTo etc.) is not affected.
        Set-StrictMode -Off
        $script:testDir = Join-Path $TestDrive 'purview-test'
        New-Item -ItemType Directory -Path $script:testDir | Out-Null

        $script:fakeConn = [PSCustomObject]@{
            UserPrincipalName = 'admin@contoso.com'
            TenantID          = 'aaaaaaaa-0000-0000-0000-000000000001'
        }
        $script:fakeRetention = @()
        $script:fakeDlp       = @()
        $script:fakeIrm       = [PSCustomObject]@{ settings = $null; policies = @(); communicationCompliance = @() }
        $script:fakeDspm      = @()

        $script:result = Write-PurviewExport `
            -Connection $script:fakeConn `
            -Environment 'Commercial' `
            -RetentionPolicies $script:fakeRetention `
            -DlpData $script:fakeDlp `
            -IrmData $script:fakeIrm `
            -DspmInventory $script:fakeDspm `
            -OutputPath $script:testDir
    }

    It 'Returns a result object with JsonPath' {
        $script:result.JsonPath | Should -Not -BeNullOrEmpty
    }

    It 'Creates the JSON file on disk' {
        Test-Path $script:result.JsonPath | Should -Be $true
    }

    It 'JSON file name matches the expected pattern' {
        [System.IO.Path]::GetFileName($script:result.JsonPath) |
            Should -Match '^Purview-Export-aaaaaaaa-0000-0000-0000-000000000001-Commercial-\d{8}T\d{6}Z\.json$'
    }

    It 'JSON envelope contains required top-level keys' {
        $json = Get-Content $script:result.JsonPath -Raw | ConvertFrom-Json
        $json.exportedBy              | Should -Be 'admin@contoso.com'
        $json.environment             | Should -Be 'Commercial'
        $json.tenantId                | Should -Be 'aaaaaaaa-0000-0000-0000-000000000001'
        # These keys must exist even when the tenant has no policies (empty array = [] not absent).
        # Use -Not -Be $null rather than -Not -BeNullOrEmpty: empty arrays are valid here.
        $json.PSObject.Properties['auditRetentionPolicies'] | Should -Not -Be $null -Because 'key must exist even if empty'
        $json.PSObject.Properties['dlpPolicies']            | Should -Not -Be $null -Because 'key must exist even if empty'
        $json.PSObject.Properties['dspmPolicyInventory']    | Should -Not -Be $null -Because 'key must exist even if empty'
        $json.insiderRisk             | Should -Not -BeNullOrEmpty -Because 'key must exist even if empty'
        $json.collectionLimitations   | Should -Not -BeNullOrEmpty -Because 'limitations must always be documented'
    }

    It 'collectionLimitations lists at least 5 known portal-only gaps' {
        $json = Get-Content $script:result.JsonPath -Raw | ConvertFrom-Json
        # Note: -BeGreaterOrEqualTo emits a spurious ParameterBindingException in Pester 5.7.1;
        # use -BeGreaterThan 4 which is equivalent for integer counts (>= 5 ≡ > 4).
        $json.collectionLimitations.Count | Should -BeGreaterThan 4
    }
}
