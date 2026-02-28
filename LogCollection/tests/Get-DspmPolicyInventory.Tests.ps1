#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    . "$PSScriptRoot/../Get-PurviewAudit.ps1" -UserPrincipalName 'dummy@test.com'
}

Describe 'Get-DspmPolicyInventory' {
    It 'Returns 8 entries (one per known DSPM policy)' {
        $result = Get-DspmPolicyInventory -DlpPolicies @() -IrmPolicies @() -CommCompliancePolicies @()
        $result.Count | Should -Be 8
    }

    It 'Marks a matching DLP policy as detected with correct mode' {
        $fakeDlp = @([PSCustomObject]@{
            Name    = 'DSPM for AI - Protect sensitive data from Copilot processing'
            Mode    = 'Enable'
            Enabled = $true
        })
        $result = Get-DspmPolicyInventory -DlpPolicies $fakeDlp -IrmPolicies @() -CommCompliancePolicies @()
        $entry = $result | Where-Object policyName -like '*Protect sensitive data from Copilot processing*'
        $entry.detected | Should -Be $true
        $entry.mode     | Should -Be 'Enable'
        $entry.enabled  | Should -Be $true
    }

    It 'Marks an absent policy as not detected with null mode' {
        $result = Get-DspmPolicyInventory -DlpPolicies @() -IrmPolicies @() -CommCompliancePolicies @()
        $entry = $result | Where-Object policyName -like '*Protect sensitive data from Copilot processing*'
        $entry.detected | Should -Be $false
        $entry.mode     | Should -BeNullOrEmpty
    }

    It 'Detects a policy with the legacy Microsoft AI Hub prefix' {
        $fakeDlp = @([PSCustomObject]@{
            Name    = 'Microsoft AI Hub - Block sensitive info from AI sites'
            Mode    = 'TestWithNotifications'
            Enabled = $true
        })
        $result = Get-DspmPolicyInventory -DlpPolicies $fakeDlp -IrmPolicies @() -CommCompliancePolicies @()
        $entry = $result | Where-Object { $_.detected -eq $true }
        $entry | Should -Not -BeNullOrEmpty
    }

    It 'Detects a matching IRM policy' {
        $fakeIrm = @([PSCustomObject]@{
            Name = 'DSPM for AI - Detect risky AI usage'
        })
        $result = Get-DspmPolicyInventory -DlpPolicies @() -IrmPolicies $fakeIrm -CommCompliancePolicies @()
        $entry = $result | Where-Object policyName -like '*Detect risky AI usage*'
        $entry.detected    | Should -Be $true
        $entry.policyType  | Should -Be 'IRM'
    }

    It 'Detects a matching Communication Compliance policy' {
        $fakeCC = @([PSCustomObject]@{
            Name = 'DSPM for AI - Unethical behavior in AI apps'
        })
        $result = Get-DspmPolicyInventory -DlpPolicies @() -IrmPolicies @() -CommCompliancePolicies $fakeCC
        $entry = $result | Where-Object policyName -like '*Unethical behavior*'
        $entry.detected   | Should -Be $true
        $entry.policyType | Should -Be 'CommunicationCompliance'
    }
}
