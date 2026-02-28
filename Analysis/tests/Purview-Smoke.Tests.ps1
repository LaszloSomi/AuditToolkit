#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    . "$PSScriptRoot/../Invoke-PurviewAnalysis.ps1" -InputPath 'dummy.json'
}

Describe 'Invoke-PurviewAnalysis.ps1 scaffold' {
    It 'Loads Import-PurviewExport as a function' {
        Get-Command Import-PurviewExport -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}

Describe 'Import-PurviewExport' {
    It 'Throws when the file does not exist' {
        { Import-PurviewExport -Path 'nonexistent-file.json' } | Should -Throw
    }
}
