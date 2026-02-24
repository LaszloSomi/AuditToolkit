#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    . "$PSScriptRoot/../Invoke-CAAnalysis.ps1" -InputPath 'dummy'
}

Describe 'Test-DirectBlock (R1)' {
    Context 'Enabled block policy — all users, all apps' {
        It 'Returns one Critical finding' {
            $policy = [PSCustomObject]@{
                id                   = 'r1-test-01'
                displayName          = 'Block All Users'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = 'All'
                excludeApplications  = $null
                grantBuiltInControls = 'block'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            $result = @(Test-DirectBlock -Policies @($policy) -CopilotAppIds @())
            $result.Count | Should -Be 1
            $result[0].ruleId    | Should -Be 'R1'
            $result[0].severity  | Should -Be 'Critical'
            $result[0].policyId  | Should -Be 'r1-test-01'
        }
    }

    Context 'Enabled block policy — all users, specific Copilot app ID' {
        It 'Returns one Critical finding when app ID matches CopilotAppIds' {
            $copilotId = 'deadbeef-0000-0000-0000-c0pilot00001'
            $policy = [PSCustomObject]@{
                id                   = 'r1-test-02'
                displayName          = 'Block Copilot App'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = @($copilotId)
                excludeApplications  = $null
                grantBuiltInControls = 'block'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            $result = @(Test-DirectBlock -Policies @($policy) -CopilotAppIds @($copilotId))
            $result.Count | Should -Be 1
            $result[0].ruleId | Should -Be 'R1'
        }
    }

    Context 'Disabled block policy' {
        It 'Returns no findings' {
            $policy = [PSCustomObject]@{
                id                   = 'r1-test-03'
                displayName          = 'Disabled Block'
                state                = 'disabled'
                includeUsers         = 'All'
                includeApplications  = 'All'
                excludeApplications  = $null
                grantBuiltInControls = 'block'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            @(Test-DirectBlock -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }

    Context 'Report-only block policy' {
        It 'Returns no findings (R4 handles report-only)' {
            $policy = [PSCustomObject]@{
                id                   = 'r1-test-04'
                displayName          = 'Report-Only Block'
                state                = 'enabledForReportingButNotEnforced'
                includeUsers         = 'All'
                includeApplications  = 'All'
                excludeApplications  = $null
                grantBuiltInControls = 'block'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            @(Test-DirectBlock -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }

    Context 'Enabled block policy scoped to user action (includeApplications is null)' {
        It 'Returns no findings — policy applies to user actions, not app access' {
            $policy = [PSCustomObject]@{
                id                   = 'r1-test-05'
                displayName          = 'Block Security Info Registration'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = $null
                excludeApplications  = $null
                grantBuiltInControls = 'block'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            @(Test-DirectBlock -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }

    Context 'Enabled MFA policy — all users, all apps' {
        It 'Returns no findings — grant is mfa not block' {
            $policy = [PSCustomObject]@{
                id                   = 'r1-test-06'
                displayName          = 'MFA for All'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = 'All'
                excludeApplications  = $null
                grantBuiltInControls = 'mfa'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            @(Test-DirectBlock -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }
}
