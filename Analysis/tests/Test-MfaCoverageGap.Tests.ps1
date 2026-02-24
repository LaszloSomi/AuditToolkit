#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    . "$PSScriptRoot/../Invoke-CAAnalysis.ps1" -InputPath 'dummy'
}

Describe 'Test-MfaCoverageGap (R6)' {
    Context 'No policy covers all users + all apps + MFA' {
        It 'Returns one Info finding' {
            $policy = [PSCustomObject]@{
                id                   = 'r6-test-01'
                displayName          = 'MFA for Admins Only'
                state                = 'enabled'
                includeUsers         = @('admin-group-guid')
                includeApplications  = 'All'
                grantBuiltInControls = 'mfa'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = [PSCustomObject]@{ Id = $null }
            }
            $result = @(Test-MfaCoverageGap -Policies @($policy) -CopilotAppIds @())
            $result.Count | Should -Be 1
            $result[0].ruleId   | Should -Be 'R6'
            $result[0].severity | Should -Be 'Info'
        }
    }

    Context 'One enabled policy covers all users + all apps + MFA' {
        It 'Returns no findings' {
            $policy = [PSCustomObject]@{
                id                   = 'r6-test-02'
                displayName          = 'MFA for All'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = 'All'
                grantBuiltInControls = 'mfa'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = [PSCustomObject]@{ Id = $null }
            }
            @(Test-MfaCoverageGap -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }

    Context 'One enabled policy covers all users + all apps + authenticationStrength' {
        It 'Returns no findings' {
            $policy = [PSCustomObject]@{
                id                   = 'r6-test-03'
                displayName          = 'Phishing-Resistant MFA for All'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = 'All'
                grantBuiltInControls = $null
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = [PSCustomObject]@{ Id = 'aaaaaaaa-auth-strength-guid-0000000001' }
            }
            @(Test-MfaCoverageGap -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }

    Context 'Report-only MFA policy covering all users + all apps' {
        It 'Returns one Info finding — report-only does not count as enforced coverage' {
            $policy = [PSCustomObject]@{
                id                   = 'r6-test-04'
                displayName          = 'Report-Only MFA for All'
                state                = 'enabledForReportingButNotEnforced'
                includeUsers         = 'All'
                includeApplications  = 'All'
                grantBuiltInControls = 'mfa'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = [PSCustomObject]@{ Id = $null }
            }
            $result = @(Test-MfaCoverageGap -Policies @($policy) -CopilotAppIds @())
            $result.Count | Should -Be 1
            $result[0].ruleId | Should -Be 'R6'
        }
    }
}
