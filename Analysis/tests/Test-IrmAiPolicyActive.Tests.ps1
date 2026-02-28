#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    . "$PSScriptRoot/../Invoke-PurviewAnalysis.ps1" -InputPath 'dummy.json'
}

Describe 'Test-IrmAiPolicyActive' {
    It 'Returns no findings when an active RiskyAIUsage policy exists' {
        $insiderRisk = [PSCustomObject]@{
            policies = @(
                [PSCustomObject]@{ Name = 'AI Risk Policy'; PolicyStatus = 'Active'; PolicyTemplate = 'RiskyAIUsage' }
            )
        }
        $result = @(Test-IrmAiPolicyActive -InsiderRisk $insiderRisk)
        $result.Count | Should -Be 0
    }

    It 'Returns no findings when an active DataLeak policy exists' {
        $insiderRisk = [PSCustomObject]@{
            policies = @(
                [PSCustomObject]@{ Name = 'Data Leak Policy'; PolicyStatus = 'Active'; PolicyTemplate = 'DataLeak' }
            )
        }
        $result = @(Test-IrmAiPolicyActive -InsiderRisk $insiderRisk)
        $result.Count | Should -Be 0
    }

    It 'Returns one I1 Info when no AI-relevant IRM policy is active' {
        $insiderRisk = [PSCustomObject]@{
            policies = @(
                [PSCustomObject]@{ Name = 'HR Policy'; PolicyStatus = 'Active'; PolicyTemplate = 'HRDataLeak' }
            )
        }
        $result = @(Test-IrmAiPolicyActive -InsiderRisk $insiderRisk)
        $result.Count | Should -Be 1
        $result[0].ruleId   | Should -Be 'I1'
        $result[0].severity | Should -Be 'Info'
    }

    It 'Returns one I1 Info when an AI-relevant policy exists but is inactive' {
        $insiderRisk = [PSCustomObject]@{
            policies = @(
                [PSCustomObject]@{ Name = 'AI Risk Policy'; PolicyStatus = 'Inactive'; PolicyTemplate = 'RiskyAIUsage' }
            )
        }
        $result = @(Test-IrmAiPolicyActive -InsiderRisk $insiderRisk)
        $result.Count | Should -Be 1
        $result[0].ruleId | Should -Be 'I1'
    }

    It 'Returns one I1 Info when insiderRisk is null' {
        $result = @(Test-IrmAiPolicyActive -InsiderRisk $null)
        $result.Count | Should -Be 1
        $result[0].ruleId | Should -Be 'I1'
    }

    It 'Returns one I1 Info when insiderRisk.policies is empty' {
        $insiderRisk = [PSCustomObject]@{ policies = @() }
        $result = @(Test-IrmAiPolicyActive -InsiderRisk $insiderRisk)
        $result.Count | Should -Be 1
        $result[0].ruleId | Should -Be 'I1'
    }
}
