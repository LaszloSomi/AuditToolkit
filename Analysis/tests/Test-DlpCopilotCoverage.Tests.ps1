#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    . "$PSScriptRoot/../Invoke-PurviewAnalysis.ps1" -InputPath 'dummy.json'
}

Describe 'Test-DlpCopilotCoverage' {
    It 'Returns no findings when an enforced policy covers CopilotInteractions' {
        $dlpPolicies = @(
            [PSCustomObject]@{
                policy = [PSCustomObject]@{ Name = 'Copilot DLP'; Mode = 'Enable'; Enabled = $true; Workload = 'CopilotInteractions,SharePoint' }
                rules  = @()
            }
        )
        $result = @(Test-DlpCopilotCoverage -DlpPolicies $dlpPolicies)
        $result.Count | Should -Be 0
    }

    It 'Returns no findings when an enforced policy covers M365Copilot' {
        $dlpPolicies = @(
            [PSCustomObject]@{
                policy = [PSCustomObject]@{ Name = 'Copilot DLP v2'; Mode = 'Enable'; Enabled = $true; Workload = 'M365Copilot' }
                rules  = @()
            }
        )
        $result = @(Test-DlpCopilotCoverage -DlpPolicies $dlpPolicies)
        $result.Count | Should -Be 0
    }

    It 'Returns one D1 Warning when no policy covers a Copilot workload' {
        $dlpPolicies = @(
            [PSCustomObject]@{
                policy = [PSCustomObject]@{ Name = 'Exchange DLP'; Mode = 'Enable'; Enabled = $true; Workload = 'Exchange,SharePoint' }
                rules  = @()
            }
        )
        $result = @(Test-DlpCopilotCoverage -DlpPolicies $dlpPolicies)
        $result.Count | Should -Be 1
        $result[0].ruleId   | Should -Be 'D1'
        $result[0].severity | Should -Be 'Warning'
    }

    It 'Returns one D1 Warning when the only Copilot policy is in test mode' {
        $dlpPolicies = @(
            [PSCustomObject]@{
                policy = [PSCustomObject]@{ Name = 'Copilot DLP'; Mode = 'TestWithNotifications'; Enabled = $true; Workload = 'CopilotInteractions' }
                rules  = @()
            }
        )
        $result = @(Test-DlpCopilotCoverage -DlpPolicies $dlpPolicies)
        $result.Count | Should -Be 1
        $result[0].ruleId | Should -Be 'D1'
    }

    It 'Returns one D1 Warning when the only Copilot policy is disabled' {
        $dlpPolicies = @(
            [PSCustomObject]@{
                policy = [PSCustomObject]@{ Name = 'Copilot DLP'; Mode = 'Enable'; Enabled = $false; Workload = 'CopilotInteractions' }
                rules  = @()
            }
        )
        $result = @(Test-DlpCopilotCoverage -DlpPolicies $dlpPolicies)
        $result.Count | Should -Be 1
    }

    It 'Returns one D1 Warning when dlpPolicies is null' {
        $result = @(Test-DlpCopilotCoverage -DlpPolicies $null)
        $result.Count | Should -Be 1
        $result[0].ruleId | Should -Be 'D1'
    }

    It 'Returns one D1 Warning when dlpPolicies is an empty array' {
        $result = @(Test-DlpCopilotCoverage -DlpPolicies @())
        $result.Count | Should -Be 1
        $result[0].ruleId | Should -Be 'D1'
    }
}
