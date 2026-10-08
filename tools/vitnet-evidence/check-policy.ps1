$ErrorActionPreference = 'Stop'
$lock = Get-Content (Join-Path $PSScriptRoot 'packages.lock.json') -Raw | ConvertFrom-Json
$assets = Get-Content (Join-Path $PSScriptRoot 'obj\project.assets.json') -Raw | ConvertFrom-Json
$folders = @($assets.packageFolders.PSObject.Properties.Name)
$allowed = @('MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'Zlib', 'CC0-1.0')
$checked = 0
foreach ($framework in $lock.dependencies.PSObject.Properties) {
    foreach ($dependency in $framework.Value.PSObject.Properties) {
        $version = $dependency.Value.resolved
        if ($version.Contains('-')) { throw "Prerelease dependency is forbidden: $($dependency.Name)/$version" }
        $relative = Join-Path $dependency.Name.ToLowerInvariant() $version
        $nuspec = $null
        foreach ($folder in $folders) {
            $candidate = Join-Path (Join-Path $folder $relative) ($dependency.Name.ToLowerInvariant() + '.nuspec')
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { $nuspec = $candidate; break }
        }
        if (-not $nuspec) { throw "Missing restored package metadata: $($dependency.Name)/$version" }
        [xml]$document = Get-Content -LiteralPath $nuspec -Raw
        $license = $document.SelectSingleNode("/*[local-name()='package']/*[local-name()='metadata']/*[local-name()='license']")
        if (-not $license -or $license.type -ne 'expression' -or $license.InnerText -notin $allowed) {
            throw "Package must declare an approved permissive license expression: $($dependency.Name)/$version"
        }
        if (-not $dependency.Value.contentHash) { throw "Missing pinned content hash: $($dependency.Name)/$version" }
        $checked++
    }
}
Write-Host "Collector dependency policy passed: $checked stable, locked, permissively licensed packages."
