#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    . "$PSScriptRoot/../Invoke-PurviewAnalysis.ps1" -InputPath 'dummy.json'
}

Describe 'Test-DspmPolicyTestMode' {
    It 'Returns no findings when the DLP policy is in Enable mode' {
        $inventory = @(
            [PSCustomObject]@{ policyName = 'DSPM for AI - Block sensitive info from AI sites'; policyType = 'DLP'; detected = $true; mode = 'Enable'; enabled = $true }
        )
        $result = @(Test-DspmPolicyTestMode -DspmInventory $inventory)
        $result.Count | Should -Be 0
    }

    It 'Returns a Warning for a DLP policy in TestWithNotifications mode' {
        $inventory = @(
            [PSCustomObject]@{ policyName = 'DSPM for AI - Block sensitive info from AI sites'; policyType = 'DLP'; detected = $true; mode = 'TestWithNotifications'; enabled = $true }
        )
        $result = @(Test-DspmPolicyTestMode -DspmInventory $inventory)
        $result.Count | Should -Be 1
        $result[0].ruleId   | Should -Be 'P2'
        $result[0].severity | Should -Be 'Warning'
    }

    It 'Returns a Warning for a DLP policy in TestWithoutNotifications mode' {
        $inventory = @(
            [PSCustomObject]@{ policyName = 'DSPM for AI - Protect sensitive data from Copilot processing'; policyType = 'DLP'; detected = $true; mode = 'TestWithoutNotifications'; enabled = $true }
        )
        $result = @(Test-DspmPolicyTestMode -DspmInventory $inventory)
        $result.Count | Should -Be 1
    }

    It 'Does not flag IRM or CommunicationCompliance policies (no mode concept)' {
        $inventory = @(
            [PSCustomObject]@{ policyName = 'DSPM for AI - Detect risky AI usage'; policyType = 'IRM'; detected = $true; mode = $null; enabled = $null }
        )
        $result = @(Test-DspmPolicyTestMode -DspmInventory $inventory)
        $result.Count | Should -Be 0
    }

    It 'Does not flag absent DLP policies (P1 handles those)' {
        $inventory = @(
            [PSCustomObject]@{ policyName = 'DSPM for AI - Block sensitive info from AI sites'; policyType = 'DLP'; detected = $false; mode = $null; enabled = $null }
        )
        $result = @(Test-DspmPolicyTestMode -DspmInventory $inventory)
        $result.Count | Should -Be 0
    }
}
