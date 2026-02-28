#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    . "$PSScriptRoot/../Invoke-PurviewAnalysis.ps1" -InputPath 'dummy.json'
}

Describe 'Test-DspmPolicyNotDeployed' {
    It 'Returns no findings when all policies are detected' {
        $inventory = @(
            [PSCustomObject]@{ policyName = 'DSPM for AI - Block sensitive info from AI sites'; policyType = 'DLP'; detected = $true; mode = 'Enable'; enabled = $true }
        )
        $result = @(Test-DspmPolicyNotDeployed -DspmInventory $inventory)
        $result.Count | Should -Be 0
    }

    It 'Returns one Warning finding for each absent policy' {
        $inventory = @(
            [PSCustomObject]@{ policyName = 'DSPM for AI - Block sensitive info from AI sites'; policyType = 'DLP'; detected = $false; mode = $null; enabled = $null }
            [PSCustomObject]@{ policyName = 'DSPM for AI - Detect risky AI usage'; policyType = 'IRM'; detected = $false; mode = $null; enabled = $null }
        )
        $result = @(Test-DspmPolicyNotDeployed -DspmInventory $inventory)
        $result.Count | Should -Be 2
        $result[0].ruleId    | Should -Be 'P1'
        $result[0].severity  | Should -Be 'Warning'
    }

    It 'Does not flag a detected policy' {
        $inventory = @(
            [PSCustomObject]@{ policyName = 'DSPM for AI - Protect sensitive data from Copilot processing'; policyType = 'DLP'; detected = $true; mode = 'Enable'; enabled = $true }
        )
        $result = @(Test-DspmPolicyNotDeployed -DspmInventory $inventory)
        $result.Count | Should -Be 0
    }

    It 'Includes the policy name in the finding' {
        $inventory = @(
            [PSCustomObject]@{ policyName = 'DSPM for AI - Unethical behavior in AI apps'; policyType = 'CommunicationCompliance'; detected = $false; mode = $null; enabled = $null }
        )
        $result = @(Test-DspmPolicyNotDeployed -DspmInventory $inventory)
        $result[0].policyName | Should -Be 'DSPM for AI - Unethical behavior in AI apps'
    }
}
