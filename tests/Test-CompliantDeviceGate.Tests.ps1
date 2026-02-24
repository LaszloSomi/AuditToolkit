#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    . "$PSScriptRoot/../Invoke-CAAnalysis.ps1" -InputPath 'dummy'
}

Describe 'Test-CompliantDeviceGate (R2)' {
    Context 'Enabled policy — compliantDevice as sole control, all apps' {
        It 'Returns one Critical finding' {
            $policy = [PSCustomObject]@{
                id                   = 'r2-test-01'
                displayName          = 'Require Compliant Device'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = 'All'
                grantBuiltInControls = 'compliantDevice'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            $result = @(Test-CompliantDeviceGate -Policies @($policy) -CopilotAppIds @())
            $result.Count | Should -Be 1
            $result[0].ruleId   | Should -Be 'R2'
            $result[0].severity | Should -Be 'Critical'
        }
    }

    Context 'Enabled policy — compliantDevice AND mfa (AND operator)' {
        It 'Returns one Critical finding — mfa is required in addition to compliant device' {
            $policy = [PSCustomObject]@{
                id                   = 'r2-test-02'
                displayName          = 'Compliant Device AND MFA'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = 'All'
                grantBuiltInControls = @('compliantDevice', 'mfa')
                grantOperator        = 'AND'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            $result = @(Test-CompliantDeviceGate -Policies @($policy) -CopilotAppIds @())
            $result.Count | Should -Be 1
        }
    }

    Context 'Enabled policy — compliantDevice OR mfa (OR operator)' {
        It 'Returns no findings — user can satisfy policy with MFA alone' {
            $policy = [PSCustomObject]@{
                id                   = 'r2-test-03'
                displayName          = 'Compliant Device OR MFA'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = 'All'
                grantBuiltInControls = @('compliantDevice', 'mfa')
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            @(Test-CompliantDeviceGate -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }

    Context 'Report-only compliant device policy' {
        It 'Returns no findings' {
            $policy = [PSCustomObject]@{
                id                   = 'r2-test-04'
                displayName          = 'Report-Only Compliant Device'
                state                = 'enabledForReportingButNotEnforced'
                includeUsers         = 'All'
                includeApplications  = 'All'
                grantBuiltInControls = 'compliantDevice'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            @(Test-CompliantDeviceGate -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }

    Context 'Enabled compliant device policy scoped to specific app (not All)' {
        It 'Returns no findings — not all apps' {
            $policy = [PSCustomObject]@{
                id                   = 'r2-test-05'
                displayName          = 'Compliant Device for Exchange'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = @('00000002-0000-0ff1-ce00-000000000000')
                grantBuiltInControls = 'compliantDevice'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            @(Test-CompliantDeviceGate -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }
}
