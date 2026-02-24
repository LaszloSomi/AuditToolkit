#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    # Dot-source the script to load function definitions.
    # InvocationName inside the script will be '.' so the main block is skipped.
    . "$PSScriptRoot/../Invoke-CAAnalysis.ps1" -InputPath 'dummy'
}

Describe 'Invoke-CAAnalysis.ps1 scaffold' {
    It 'Loads Import-CAExport as a function' {
        Get-Command Import-CAExport -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    It 'Loads Get-BuiltInControls as a function' {
        Get-Command Get-BuiltInControls -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    It 'Loads Test-AppIdMatch as a function' {
        Get-Command Test-AppIdMatch -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-BuiltInControls' {
    It 'Returns empty array for null input' {
        Get-BuiltInControls $null | Should -BeNullOrEmpty
    }

    It 'Wraps a single string in an array' {
        $result = Get-BuiltInControls 'mfa'
        $result | Should -Be @('mfa')
    }

    It 'Returns an array unchanged' {
        $result = Get-BuiltInControls @('mfa', 'compliantDevice')
        $result.Count | Should -Be 2
        $result | Should -Contain 'mfa'
        $result | Should -Contain 'compliantDevice'
    }
}

Describe 'Test-AppIdMatch' {
    It 'Matches exact GUID' {
        Test-AppIdMatch -AppId 'aaaaaaaa-0000-0000-0000-000000000001' -Applications 'aaaaaaaa-0000-0000-0000-000000000001' | Should -Be $true
    }

    It 'Matches GUID with display name suffix' {
        Test-AppIdMatch -AppId 'aaaaaaaa-0000-0000-0000-000000000001' -Applications 'aaaaaaaa-0000-0000-0000-000000000001 (My App)' | Should -Be $true
    }

    It 'Does not match a different GUID' {
        Test-AppIdMatch -AppId 'aaaaaaaa-0000-0000-0000-000000000001' -Applications 'bbbbbbbb-0000-0000-0000-000000000002' | Should -Be $false
    }

    It 'Returns false for null applications' {
        Test-AppIdMatch -AppId 'aaaaaaaa-0000-0000-0000-000000000001' -Applications $null | Should -Be $false
    }
}
