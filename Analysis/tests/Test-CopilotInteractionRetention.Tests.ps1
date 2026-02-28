#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    . "$PSScriptRoot/../Invoke-PurviewAnalysis.ps1" -InputPath 'dummy.json'
}

Describe 'Test-CopilotInteractionRetention' {
    It 'Returns an Info finding when no retention policies exist' {
        $result = @(Test-CopilotInteractionRetention -RetentionPolicies @())
        $result.Count | Should -Be 1
        $result[0].ruleId   | Should -Be 'A1'
        $result[0].severity | Should -Be 'Info'
    }

    It 'Returns an Info finding when no policy covers CopilotInteraction' {
        $policies = @(
            [PSCustomObject]@{ Name = 'Default Policy'; RecordTypes = @('SharePointFileOperation', 'OneDrive') }
        )
        $result = @(Test-CopilotInteractionRetention -RetentionPolicies $policies)
        $result.Count | Should -Be 1
    }

    It 'Returns no findings when a policy covers CopilotInteraction in an array' {
        $policies = @(
            [PSCustomObject]@{ Name = 'AI Audit Retention'; RecordTypes = @('CopilotInteraction', 'AipSensitivityLabelAction') }
        )
        $result = @(Test-CopilotInteractionRetention -RetentionPolicies $policies)
        $result.Count | Should -Be 0
    }

    It 'Returns no findings when RecordTypes is a single string equal to CopilotInteraction' {
        $policies = @(
            [PSCustomObject]@{ Name = 'AI Audit Retention'; RecordTypes = 'CopilotInteraction' }
        )
        $result = @(Test-CopilotInteractionRetention -RetentionPolicies $policies)
        $result.Count | Should -Be 0
    }
}
