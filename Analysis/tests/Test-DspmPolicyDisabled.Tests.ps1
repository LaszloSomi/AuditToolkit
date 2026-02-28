#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    . "$PSScriptRoot/../Invoke-PurviewAnalysis.ps1" -InputPath 'dummy.json'
}

Describe 'Test-DspmPolicyDisabled' {
    It 'Returns no findings when a DLP policy is enabled' {
        $inventory = @(
            [PSCustomObject]@{ policyName = 'DSPM for AI - Block sensitive info from AI sites'; policyType = 'DLP'; detected = $true; mode = 'Enable'; enabled = $true }
        )
        $result = @(Test-DspmPolicyDisabled -DspmInventory $inventory)
        $result.Count | Should -Be 0
    }

    It 'Returns a Warning when a DLP policy is detected but disabled' {
        $inventory = @(
            [PSCustomObject]@{ policyName = 'DSPM for AI - Block sensitive info from AI sites'; policyType = 'DLP'; detected = $true; mode = 'Enable'; enabled = $false }
        )
        $result = @(Test-DspmPolicyDisabled -DspmInventory $inventory)
        $result.Count | Should -Be 1
        $result[0].ruleId   | Should -Be 'P3'
        $result[0].severity | Should -Be 'Warning'
    }

    It 'Does not flag IRM or CommunicationCompliance policies (enabled field is null)' {
        $inventory = @(
            [PSCustomObject]@{ policyName = 'DSPM for AI - Detect risky AI usage'; policyType = 'IRM'; detected = $true; mode = $null; enabled = $null }
        )
        $result = @(Test-DspmPolicyDisabled -DspmInventory $inventory)
        $result.Count | Should -Be 0
    }

    It 'Does not flag absent DLP policies (P1 handles those)' {
        $inventory = @(
            [PSCustomObject]@{ policyName = 'DSPM for AI - Block sensitive info from AI sites'; policyType = 'DLP'; detected = $false; mode = $null; enabled = $null }
        )
        $result = @(Test-DspmPolicyDisabled -DspmInventory $inventory)
        $result.Count | Should -Be 0
    }
}
