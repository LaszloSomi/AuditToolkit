#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    . "$PSScriptRoot/../Invoke-CAAnalysis.ps1" -InputPath 'dummy'
}

Describe 'Test-CopilotAppScoping (R7)' {
    Context 'Policy includes a known Copilot app ID in includeApplications' {
        It 'Returns one Info finding' {
            $copilotId = 'deadbeef-0000-0000-0000-c0pilot00001'
            $policy = [PSCustomObject]@{
                id                   = 'r7-test-01'
                displayName          = 'MFA with Copilot Scoped'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = @($copilotId, '00000002-0000-0ff1-ce00-000000000000')
                excludeApplications  = $null
                grantBuiltInControls = 'mfa'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            $result = @(Test-CopilotAppScoping -Policies @($policy) -CopilotAppIds @($copilotId))
            $result.Count | Should -Be 1
            $result[0].ruleId   | Should -Be 'R7'
            $result[0].severity | Should -Be 'Info'
        }
    }

    Context 'Policy excludes a known Copilot app ID in excludeApplications' {
        It 'Returns one Info finding' {
            $copilotId = 'deadbeef-0000-0000-0000-c0pilot00001'
            $policy = [PSCustomObject]@{
                id                   = 'r7-test-02'
                displayName          = 'MFA Excluding Copilot'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = 'All'
                excludeApplications  = @($copilotId)
                grantBuiltInControls = 'mfa'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            $result = @(Test-CopilotAppScoping -Policies @($policy) -CopilotAppIds @($copilotId))
            $result.Count | Should -Be 1
            $result[0].ruleId | Should -Be 'R7'
        }
    }

    Context 'Policy with Copilot ID in display-name format (GUID + name)' {
        It 'Returns one Info finding' {
            $copilotId = 'deadbeef-0000-0000-0000-c0pilot00001'
            $policy = [PSCustomObject]@{
                id                   = 'r7-test-03'
                displayName          = 'Resolved Name Policy'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = @("$copilotId (Microsoft Copilot)")
                excludeApplications  = $null
                grantBuiltInControls = 'mfa'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            $result = @(Test-CopilotAppScoping -Policies @($policy) -CopilotAppIds @($copilotId))
            $result.Count | Should -Be 1
        }
    }

    Context 'Policy with no Copilot app IDs' {
        It 'Returns no findings' {
            $policy = [PSCustomObject]@{
                id                   = 'r7-test-04'
                displayName          = 'MFA All Apps'
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
            @(Test-CopilotAppScoping -Policies @($policy) -CopilotAppIds @('deadbeef-0000-0000-0000-c0pilot00001')).Count | Should -Be 0
        }
    }
}
