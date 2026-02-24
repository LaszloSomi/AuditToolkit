#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    . "$PSScriptRoot/../Invoke-CAAnalysis.ps1" -InputPath 'dummy'

    # Resolve path to real CA export test fixture (repo root is two levels up from Analysis/tests/).
    $script:ExportPath = Join-Path $PSScriptRoot '..' '..' 'CA-Export-f3b7001b-92fa-4ac8-b755-d37ead1ff538-Commercial-20260224T000613Z.json'
    $script:Export = Import-CAExport -Path $script:ExportPath

    $script:DefaultCopilotAppIds = @(
        'd3590ed6-52b3-4102-aeff-aad2292ab01c',
        '0be67e7d-4b14-4f1c-8e7a-ab3e5e3dff0c'
    )

    $script:AllFindings = @()
    $script:AllFindings += @(Test-DirectBlock         -Policies $script:Export.policies -CopilotAppIds $script:DefaultCopilotAppIds)
    $script:AllFindings += @(Test-CompliantDeviceGate -Policies $script:Export.policies -CopilotAppIds $script:DefaultCopilotAppIds)
    $script:AllFindings += @(Test-SignInFrequency     -Policies $script:Export.policies -CopilotAppIds $script:DefaultCopilotAppIds)
    $script:AllFindings += @(Test-ReportOnlyRisk      -Policies $script:Export.policies -CopilotAppIds $script:DefaultCopilotAppIds)
    $script:AllFindings += @(Test-TokenProtection     -Policies $script:Export.policies -CopilotAppIds $script:DefaultCopilotAppIds)
    $script:AllFindings += @(Test-MfaCoverageGap      -Policies $script:Export.policies -CopilotAppIds $script:DefaultCopilotAppIds)
    $script:AllFindings += @(Test-CopilotAppScoping   -Policies $script:Export.policies -CopilotAppIds $script:DefaultCopilotAppIds)
}

Describe 'Integration — CA-Export-f3b7001b (4 policies, Commercial)' {
    It 'Loads 4 policies from the export' {
        $script:Export.policies.Count | Should -Be 4
    }

    It 'Produces exactly 1 finding total' {
        $script:AllFindings.Count | Should -Be 1
    }

    It 'The one finding is R4 (report-only risk)' {
        $script:AllFindings[0].ruleId    | Should -Be 'R4'
        $script:AllFindings[0].severity  | Should -Be 'Warning'
    }

    It 'R4 finding references the reauthentication policy' {
        $script:AllFindings[0].policyName | Should -Match 'Reauthentication'
    }

    It 'R4 summary mentions R3' {
        $script:AllFindings[0].summary | Should -Match 'R3'
    }

    It 'R1 produces no findings (no enabled block on apps)' {
        @(Test-DirectBlock -Policies $script:Export.policies -CopilotAppIds $script:DefaultCopilotAppIds).Count | Should -Be 0
    }

    It 'R6 produces no findings (Policy 1 covers all users + all apps + mfa)' {
        @(Test-MfaCoverageGap -Policies $script:Export.policies -CopilotAppIds $script:DefaultCopilotAppIds).Count | Should -Be 0
    }

    Context 'Write-AnalysisReport end-to-end' {
        BeforeAll {
            $script:TempDir = Join-Path ([System.IO.Path]::GetTempPath()) "PesterIntegration-$(New-Guid)"
            New-Item -Path $script:TempDir -ItemType Directory | Out-Null
            $script:ReportResult = Write-AnalysisReport -Export $script:Export -Findings $script:AllFindings -OutputPath $script:TempDir
        }
        AfterAll {
            Remove-Item -Path $script:TempDir -Recurse -Force -ErrorAction SilentlyContinue
        }

        It 'Writes a Markdown file' {
            Test-Path $script:ReportResult.MarkdownPath | Should -Be $true
        }

        It 'Writes a JSON file' {
            Test-Path $script:ReportResult.JsonPath | Should -Be $true
        }

        It 'JSON findingCount = 1' {
            $data = Get-Content $script:ReportResult.JsonPath -Raw | ConvertFrom-Json
            $data.findingCount | Should -Be 1
        }
    }
}
