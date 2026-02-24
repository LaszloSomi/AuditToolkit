#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    . "$PSScriptRoot/../Invoke-CAAnalysis.ps1" -InputPath 'dummy'
}

Describe 'Test-TokenProtection (R5)' {
    Context 'Enabled policy with secureSignInSession IsEnabled = true' {
        It 'Returns one Warning finding' {
            $policy = [PSCustomObject]@{
                id                   = 'r5-test-01'
                displayName          = 'Token Protection Policy'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = 'All'
                grantBuiltInControls = 'mfa'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = [PSCustomObject]@{ IsEnabled = $true }
                authenticationStrength = $null
            }
            $result = @(Test-TokenProtection -Policies @($policy) -CopilotAppIds @())
            $result.Count | Should -Be 1
            $result[0].ruleId   | Should -Be 'R5'
            $result[0].severity | Should -Be 'Warning'
        }
    }

    Context 'Enabled policy with secureSignInSession = null' {
        It 'Returns no findings' {
            $policy = [PSCustomObject]@{
                id                   = 'r5-test-02'
                displayName          = 'No Token Protection'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = 'All'
                grantBuiltInControls = 'mfa'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            @(Test-TokenProtection -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }

    Context 'Enabled policy with secureSignInSession IsEnabled = false' {
        It 'Returns no findings' {
            $policy = [PSCustomObject]@{
                id                   = 'r5-test-03'
                displayName          = 'Token Protection Disabled'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = 'All'
                grantBuiltInControls = 'mfa'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = [PSCustomObject]@{ IsEnabled = $false }
                authenticationStrength = $null
            }
            @(Test-TokenProtection -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }

    Context 'Report-only policy with token protection enabled' {
        It 'Returns no findings' {
            $policy = [PSCustomObject]@{
                id                   = 'r5-test-04'
                displayName          = 'Report-Only Token Protection'
                state                = 'enabledForReportingButNotEnforced'
                includeUsers         = 'All'
                includeApplications  = 'All'
                grantBuiltInControls = 'mfa'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = [PSCustomObject]@{ IsEnabled = $true }
                authenticationStrength = $null
            }
            @(Test-TokenProtection -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }
}
