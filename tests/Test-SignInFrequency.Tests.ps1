#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    . "$PSScriptRoot/../Invoke-CAAnalysis.ps1" -InputPath 'dummy'
}

Describe 'Test-SignInFrequency (R3)' {
    Context 'Enabled everyTime policy — all apps' {
        It 'Returns one Warning finding' {
            $policy = [PSCustomObject]@{
                id                  = 'r3-test-01'
                displayName         = 'Reauth Every Session'
                state               = 'enabled'
                includeUsers        = 'All'
                includeApplications = 'All'
                grantBuiltInControls = 'mfa'
                grantOperator       = 'OR'
                signInFrequency     = [PSCustomObject]@{
                    IsEnabled         = $true
                    FrequencyInterval = 'everyTime'
                    AuthenticationType = 'primaryAndSecondaryAuthentication'
                    Type              = $null
                    Value             = $null
                }
                secureSignInSession = $null
                authenticationStrength = $null
            }
            $result = @(Test-SignInFrequency -Policies @($policy) -CopilotAppIds @())
            $result.Count | Should -Be 1
            $result[0].ruleId   | Should -Be 'R3'
            $result[0].severity | Should -Be 'Warning'
        }
    }

    Context 'Report-only everyTime policy' {
        It 'Returns no findings (R4 handles this)' {
            $policy = [PSCustomObject]@{
                id                  = 'r3-test-02'
                displayName         = 'Report-Only Reauth'
                state               = 'enabledForReportingButNotEnforced'
                includeUsers        = 'All'
                includeApplications = 'All'
                grantBuiltInControls = 'mfa'
                grantOperator       = 'OR'
                signInFrequency     = [PSCustomObject]@{
                    IsEnabled         = $true
                    FrequencyInterval = 'everyTime'
                }
                secureSignInSession = $null
                authenticationStrength = $null
            }
            @(Test-SignInFrequency -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }

    Context 'Enabled policy with no signInFrequency set' {
        It 'Returns no findings' {
            $policy = [PSCustomObject]@{
                id                  = 'r3-test-03'
                displayName         = 'No SIF Policy'
                state               = 'enabled'
                includeUsers        = 'All'
                includeApplications = 'All'
                grantBuiltInControls = 'mfa'
                grantOperator       = 'OR'
                signInFrequency     = [PSCustomObject]@{
                    IsEnabled         = $null
                    FrequencyInterval = $null
                }
                secureSignInSession = $null
                authenticationStrength = $null
            }
            @(Test-SignInFrequency -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }

    Context 'Enabled everyTime policy scoped to specific app (not All)' {
        It 'Returns no findings' {
            $policy = [PSCustomObject]@{
                id                  = 'r3-test-04'
                displayName         = 'Reauth for Exchange Only'
                state               = 'enabled'
                includeUsers        = 'All'
                includeApplications = @('00000002-0000-0ff1-ce00-000000000000')
                grantBuiltInControls = 'mfa'
                grantOperator       = 'OR'
                signInFrequency     = [PSCustomObject]@{
                    IsEnabled         = $true
                    FrequencyInterval = 'everyTime'
                }
                secureSignInSession = $null
                authenticationStrength = $null
            }
            @(Test-SignInFrequency -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }
}
