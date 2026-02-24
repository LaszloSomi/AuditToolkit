#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    . "$PSScriptRoot/../Invoke-CAAnalysis.ps1" -InputPath 'dummy'
}

Describe 'Test-ReportOnlyRisk (R4)' {
    Context 'Report-only policy that would trigger R1 if enabled' {
        It 'Returns one Warning finding noting R1' {
            $policy = [PSCustomObject]@{
                id                   = 'r4-test-01'
                displayName          = 'Report-Only Block All'
                state                = 'enabledForReportingButNotEnforced'
                includeUsers         = 'All'
                includeApplications  = 'All'
                excludeApplications  = $null
                grantBuiltInControls = 'block'
                grantOperator        = 'OR'
                signInFrequency      = [PSCustomObject]@{ IsEnabled = $null; FrequencyInterval = $null }
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            $result = @(Test-ReportOnlyRisk -Policies @($policy) -CopilotAppIds @())
            $result.Count | Should -Be 1
            $result[0].ruleId   | Should -Be 'R4'
            $result[0].severity | Should -Be 'Warning'
            $result[0].summary  | Should -Match 'R1'
        }
    }

    Context 'Report-only policy that would trigger R3 if enabled' {
        It 'Returns one Warning finding noting R3' {
            $policy = [PSCustomObject]@{
                id                   = 'r4-test-02'
                displayName          = 'Report-Only Reauth Every Time'
                state                = 'enabledForReportingButNotEnforced'
                includeUsers         = 'All'
                includeApplications  = 'All'
                excludeApplications  = $null
                grantBuiltInControls = 'mfa'
                grantOperator        = 'OR'
                signInFrequency      = [PSCustomObject]@{
                    IsEnabled         = $true
                    FrequencyInterval = 'everyTime'
                }
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            $result = @(Test-ReportOnlyRisk -Policies @($policy) -CopilotAppIds @())
            $result.Count | Should -Be 1
            $result[0].ruleId  | Should -Be 'R4'
            $result[0].summary | Should -Match 'R3'
        }
    }

    Context 'Enabled policy (not report-only)' {
        It 'Returns no findings' {
            $policy = [PSCustomObject]@{
                id                   = 'r4-test-03'
                displayName          = 'Enabled Block'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = 'All'
                excludeApplications  = $null
                grantBuiltInControls = 'block'
                grantOperator        = 'OR'
                signInFrequency      = [PSCustomObject]@{ IsEnabled = $null; FrequencyInterval = $null }
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            @(Test-ReportOnlyRisk -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }

    Context 'Report-only policy that would NOT trigger R1, R2, or R3' {
        It 'Returns no findings' {
            $policy = [PSCustomObject]@{
                id                   = 'r4-test-04'
                displayName          = 'Report-Only MFA Harmless'
                state                = 'enabledForReportingButNotEnforced'
                includeUsers         = 'All'
                includeApplications  = 'All'
                excludeApplications  = $null
                grantBuiltInControls = 'mfa'
                grantOperator        = 'OR'
                signInFrequency      = [PSCustomObject]@{ IsEnabled = $null; FrequencyInterval = $null }
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            @(Test-ReportOnlyRisk -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }
}
