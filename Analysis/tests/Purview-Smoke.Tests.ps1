#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    . "$PSScriptRoot/../Invoke-PurviewAnalysis.ps1" -InputPath 'dummy.json'
}

Describe 'Invoke-PurviewAnalysis.ps1 scaffold' {
    It 'Loads Import-PurviewExport as a function' {
        Get-Command Import-PurviewExport -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    It 'Loads Test-DspmPolicyNotDeployed as a function' {
        Get-Command Test-DspmPolicyNotDeployed -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    It 'Loads Test-DspmPolicyTestMode as a function' {
        Get-Command Test-DspmPolicyTestMode -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    It 'Loads Test-DspmPolicyDisabled as a function' {
        Get-Command Test-DspmPolicyDisabled -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}

Describe 'Import-PurviewExport' {
    It 'Throws when the file does not exist' {
        { Import-PurviewExport -Path 'nonexistent-file.json' } | Should -Throw
    }
}
