#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    # Dot-source loads function definitions; main block is skipped because
    # InvocationName is '.' (dot-source) not the script name.
    . "$PSScriptRoot/../Get-PurviewAudit.ps1" -UserPrincipalName 'dummy@test.com'
}

Describe 'Get-PurviewAudit.ps1 scaffold' {
    It 'Loads Resolve-IppsEndpoint as a function' {
        Get-Command Resolve-IppsEndpoint -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
    It 'Loads Assert-IppsModule as a function' {
        Get-Command Assert-IppsModule -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
    It 'Loads Get-AuditRetentionPolicies as a function' {
        Get-Command Get-AuditRetentionPolicies -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
    It 'Loads Get-DlpPolicies as a function' {
        Get-Command Get-DlpPolicies -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}

Describe 'Resolve-IppsEndpoint' {
    It 'Returns Commercial endpoint for Commercial' {
        Resolve-IppsEndpoint 'Commercial' | Should -Be 'https://ps.compliance.protection.outlook.com/powershell-liveid'
    }
    It 'Returns same endpoint for GCC as Commercial' {
        Resolve-IppsEndpoint 'GCC' | Should -Be 'https://ps.compliance.protection.outlook.com/powershell-liveid'
    }
    It 'Returns GCCH endpoint for GCCH' {
        Resolve-IppsEndpoint 'GCCH' | Should -Be 'https://ps.compliance.protection.office365.us/powershell-liveid'
    }
    It 'Returns DoD endpoint for DoD' {
        Resolve-IppsEndpoint 'DoD' | Should -Be 'https://l5.ps.compliance.protection.office365.us/powershell-liveid'
    }
    It 'Throws for unknown environment' {
        { Resolve-IppsEndpoint 'Invalid' } | Should -Throw
    }
}
