#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    . "$PSScriptRoot/../Invoke-PurviewAnalysis.ps1" -InputPath 'dummy.json'
}

Describe 'Write-PurviewAnalysisReport' {
    BeforeAll {
        # Dot-sourcing sets StrictMode -Version Latest; reset so Pester dynamic
        # parameter binding is not affected.
        Set-StrictMode -Off

        $script:testDir = Join-Path $TestDrive 'purview-analysis-test'
        New-Item -ItemType Directory -Path $script:testDir | Out-Null

        $script:fakeExport = [PSCustomObject]@{
            exportedBy          = 'admin@contoso.com'
            tenantId            = 'cccccccc-0000-0000-0000-000000000003'
            environment         = 'Commercial'
            dspmPolicyInventory = @(
                [PSCustomObject]@{ policyName = 'DSPM for AI - Block sensitive info from AI sites'; policyType = 'DLP'; detected = $false; mode = $null; enabled = $null }
            )
            collectionLimitations = @(
                [PSCustomObject]@{ setting = 'DSPM collection policy status'; reason = 'No cmdlet available.'; portalPath = 'Purview portal > DSPM for AI > Policies' }
            )
        }

        $script:fakeFindings = @(
            [PSCustomObject]@{
                ruleId         = 'P1'
                severity       = 'Warning'
                policyName     = 'DSPM for AI - Block sensitive info from AI sites'
                policyType     = 'DLP'
                summary        = 'Policy not deployed.'
                detail         = 'This policy has not been created in this tenant.'
                recommendation = 'Activate the policy in the Purview portal.'
            }
        )

        $script:result = Write-PurviewAnalysisReport `
            -Export   $script:fakeExport `
            -Findings $script:fakeFindings `
            -OutputPath $script:testDir
    }

    It 'Returns an object with MarkdownPath and JsonPath' {
        $script:result.MarkdownPath | Should -Not -BeNullOrEmpty
        $script:result.JsonPath     | Should -Not -BeNullOrEmpty
    }

    It 'Creates both output files on disk' {
        Test-Path $script:result.MarkdownPath | Should -Be $true
        Test-Path $script:result.JsonPath     | Should -Be $true
    }

    It 'Output filenames contain tenant ID, environment, and timestamp' {
        [System.IO.Path]::GetFileName($script:result.MarkdownPath) |
            Should -Match '^Purview-Analysis-cccccccc-0000-0000-0000-000000000003-Commercial-\d{8}T\d{6}Z\.md$'
    }

    It 'Markdown report contains the Warning finding' {
        $md = Get-Content $script:result.MarkdownPath -Raw
        $md | Should -Match 'Warning'
        $md | Should -Match 'DSPM for AI - Block sensitive info from AI sites'
    }

    It 'Markdown report includes DSPM for AI Policy Inventory section' {
        $md = Get-Content $script:result.MarkdownPath -Raw
        $md | Should -Match 'DSPM for AI Policy Inventory'
    }

    It 'Markdown report includes Collection Limitations section' {
        $md = Get-Content $script:result.MarkdownPath -Raw
        $md | Should -Match 'Collection Limitations'
    }

    It 'JSON output has the correct envelope structure' {
        $json = Get-Content $script:result.JsonPath -Raw | ConvertFrom-Json
        $json.analysedBy   | Should -Be 'Invoke-PurviewAnalysis.ps1'
        $json.tenantId     | Should -Be 'cccccccc-0000-0000-0000-000000000003'
        $json.findingCount | Should -Be 1
    }
}
