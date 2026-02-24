#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    . "$PSScriptRoot/../Invoke-CAAnalysis.ps1" -InputPath 'dummy'

    $script:TempDir = Join-Path ([System.IO.Path]::GetTempPath()) "PesterReportTest-$(New-Guid)"
    New-Item -Path $script:TempDir -ItemType Directory | Out-Null

    $script:MockExport = [PSCustomObject]@{
        tenantId    = 'test-tenant-id'
        environment = 'Commercial'
        exportedBy  = 'admin@test.onmicrosoft.com'
        policyCount = 2
        policies    = @(
            [PSCustomObject]@{ id = 'p1'; displayName = 'Clean Policy' },
            [PSCustomObject]@{ id = 'p2'; displayName = 'Policy With Finding' }
        )
    }

    $script:MockFindings = @(
        [PSCustomObject]@{
            ruleId         = 'R1'
            severity       = 'Critical'
            policyId       = 'p2'
            policyName     = 'Policy With Finding'
            policyState    = 'enabled'
            summary        = 'Test critical finding'
            detail         = 'Detail text'
            recommendation = 'Fix it'
        }
    )
}

AfterAll {
    Remove-Item -Path $script:TempDir -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Write-AnalysisReport' {
    It 'Creates both a .md and a .json file' {
        Write-AnalysisReport -Export $script:MockExport -Findings $script:MockFindings -OutputPath $script:TempDir
        $files = Get-ChildItem -Path $script:TempDir
        @($files | Where-Object Extension -eq '.md').Count  | Should -Be 1
        @($files | Where-Object Extension -eq '.json').Count | Should -Be 1
    }

    It 'Output filenames contain tenant ID, environment, and a timestamp' {
        $files = Get-ChildItem -Path $script:TempDir
        $md = $files | Where-Object Extension -eq '.md'
        $md.Name | Should -Match 'test-tenant-id'
        $md.Name | Should -Match 'Commercial'
        $md.Name | Should -Match '\d{8}T\d{6}Z'
    }

    It 'Markdown report contains the Critical finding summary' {
        $md = Get-ChildItem -Path $script:TempDir -Filter '*.md' | Select-Object -First 1
        $content = Get-Content $md.FullName -Raw
        $content | Should -Match 'R1'
        $content | Should -Match 'Test critical finding'
    }

    It 'Markdown report lists the clean policy in Policies With No Issues' {
        $md = Get-ChildItem -Path $script:TempDir -Filter '*.md' | Select-Object -First 1
        $content = Get-Content $md.FullName -Raw
        $content | Should -Match 'Clean Policy'
    }

    It 'JSON output has the correct envelope structure' {
        $json = Get-ChildItem -Path $script:TempDir -Filter '*.json' | Select-Object -First 1
        $data = Get-Content $json.FullName -Raw | ConvertFrom-Json
        $data.analysedBy   | Should -Be 'Invoke-CAAnalysis.ps1'
        $data.tenantId     | Should -Be 'test-tenant-id'
        $data.findingCount | Should -Be 1
        $data.findings[0].ruleId | Should -Be 'R1'
    }

    It 'Returns an object with MarkdownPath and JsonPath properties' {
        # Clean up previous run files first
        Get-ChildItem -Path $script:TempDir | Remove-Item -Force
        $result = Write-AnalysisReport -Export $script:MockExport -Findings @() -OutputPath $script:TempDir
        $result.MarkdownPath | Should -Not -BeNullOrEmpty
        $result.JsonPath     | Should -Not -BeNullOrEmpty
        Test-Path $result.MarkdownPath | Should -Be $true
        Test-Path $result.JsonPath     | Should -Be $true
    }
}
