param([switch]$Keep)
# Offline data-reader regressions. Only the collector and this synthetic fixture
# are compiled. The fixture entry point throws and is NEVER invoked.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = $PSScriptRoot
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('vitnet-evidence-regression-' + [Guid]::NewGuid().ToString('N'))
$utf8 = [Text.UTF8Encoding]::new($false)
$passed = [Collections.Generic.List[string]]::new()
$failures = [Collections.Generic.List[string]]::new()
$reportedFailures = 0
[IO.Directory]::CreateDirectory($fixture) | Out-Null

function Assert-Equal($Actual, $Expected, [string]$Message) {
    if ($Actual -cne $Expected) { throw "${Message}: expected <$Expected>, actual <$Actual>" }
}
function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Write-Fixture([string]$Name, [string]$Text) {
    [IO.File]::WriteAllText((Join-Path $fixture $Name), $Text, $utf8)
}
function Invoke-Build([string[]]$Arguments) {
    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Synthetic/collector compilation failed ($LASTEXITCODE): $Arguments" }
}
function Collect([string[]]$Arguments, [int]$Exit = 0, [string]$Code = '') {
    # Capture streams independently: every invocation must emit parseable JSON
    # stdout, not merely a matching stderr fragment or nonzero process exit.
    $start = [Diagnostics.ProcessStartInfo]::new('dotnet')
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.ArgumentList.Add($collector)
    foreach ($arg in $Arguments) { $start.ArgumentList.Add($arg) }
    $process = [Diagnostics.Process]::Start($start)
    try {
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $text = $stdout.GetAwaiter().GetResult()
        $errors = $stderr.GetAwaiter().GetResult()
        Assert-Equal $process.ExitCode $Exit "Collector exit ($Arguments); $errors"
        $json = $text | ConvertFrom-Json -AsHashtable
        if ($Exit -eq 0) {
            Assert-Equal $json.schema 'vitnet.evidence.v1' 'Success summary schema'
            Assert-True (-not $json.ContainsKey('error')) 'Success emitted an error'
        } else {
            Assert-Equal $json.error.code $Code 'Typed failure stdout'
            Assert-True ($errors.Contains("${Code}:")) 'Typed failure stderr'
        }
        return $json
    } finally { $process.Dispose() }
}
function Pass([string]$Name) {
    if ($failures.Count -gt $script:reportedFailures) {
        Write-Host "FAIL $Name ($($failures.Count - $script:reportedFailures) assertion failures)"
        $script:reportedFailures = $failures.Count
        return
    }
    $passed.Add($Name)
    Write-Host "PASS $Name"
}
function Assert-PreservedFailure([string[]]$Arguments, [int]$Exit, [string]$Code) {
    $before = [IO.File]::ReadAllBytes($output)
    $beforeHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($before))
    # Continue independent rejection cases, but retain every assertion failure
    # and fail the script at the end. This is not an accepted-error/skip path.
    try { Collect (@('--output', $output) + $Arguments) $Exit $Code | Out-Null }
    catch { $failures.Add($_.Exception.Message) }
    Assert-Equal ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($output)))) $beforeHash 'Committed output preservation'
    Assert-Equal @(Get-ChildItem $fixture -Filter '*.pending').Count 0 'Pending output cleanup'
}
function Make-Avalonia([int]$Version = 2, [int]$Offset = 0, [switch]$DuplicateName) {
    $index = [IO.MemoryStream]::new()
    $writer = [IO.BinaryWriter]::new($index, $utf8, $true)
    try {
        $writer.Write($Version); $writer.Write([int]2)
        foreach ($name in @('/first.bin', $(if ($DuplicateName) { '/first.bin' } else { '/duplicate.bin' }))) {
            $writer.Write([string]$name); $writer.Write($Offset); $writer.Write([int]4)
        }
        $writer.Flush()
        $stream = [IO.File]::Create((Join-Path $fixture 'assets.bin'))
        $container = [IO.BinaryWriter]::new($stream)
        try {
            $container.Write([int]$index.Length)
            $container.Write($index.ToArray())
            $container.Write([byte[]](1, 2, 3, 4))
        } finally { $container.Dispose() }
    } finally { $writer.Dispose(); $index.Dispose() }
}
function Build-Fixture {
    Invoke-Build @('build', $project, '--no-restore', '-t:Rebuild', '--nologo', '--verbosity', 'quiet', "-bl:$fixture/build.binlog;ProjectImports=None")
}

Push-Location $root
try {
    Invoke-Build @('build', '--no-restore', '--nologo', '--verbosity', 'quiet')
    $collector = Join-Path $root 'bin/Debug/net10.0/vitnet-evidence.dll'
    $output = Join-Path $fixture 'evidence.json'
    $project = Join-Path $fixture 'Fixture.csproj'
    [IO.Directory]::CreateDirectory((Join-Path $fixture 'empty-feed')) | Out-Null
    [IO.Directory]::CreateDirectory((Join-Path $fixture 'generated')) | Out-Null
    Write-Fixture 'Fixture.csproj' @'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework>
    <AssemblyName>EvidenceFixture</AssemblyName><DebugType>portable</DebugType>
    <SourceRevisionId>synthetic-revision</SourceRevisionId>
  </PropertyGroup>
  <ItemGroup>
    <EmbeddedResource Include="assets.bin" LogicalName="!AvaloniaResources" />
    <EmbeddedResource Include="values.resources" LogicalName="Fixture.values.resources" />
  </ItemGroup>
  <PropertyGroup><SourceRevisionId>synthetic-middle-revision</SourceRevisionId></PropertyGroup>
  <PropertyGroup><SourceRevisionId>synthetic-late-revision</SourceRevisionId></PropertyGroup>
  <ItemGroup>
    <SyntheticSourceRoots Include="$(MSBuildProjectDirectory)/" RevisionId="synthetic-source-root-revision" />
  </ItemGroup>
  <Target Name="SyntheticRootValues" Returns="@(SyntheticSourceRoots)" />
  <Target Name="SyntheticRecordRoot" BeforeTargets="CoreCompile">
    <CallTarget Targets="SyntheticRootValues">
      <Output TaskParameter="TargetOutputs" ItemName="SourceRoot" />
    </CallTarget>
  </Target>
</Project>
'@
    Write-Fixture 'Declarations.cs' @'
namespace Fixture;
public partial class Widget<T> { public int Value { get; set; } public void Run() { Value++; } public class Nested { } }
public enum Choice { One, Two }
public struct Point { public int X; }
public class Entry { public static void Main() => throw new System.Exception("MUST NEVER EXECUTE"); }
'@
    Write-Fixture 'Partial.cs' 'namespace Fixture; public partial class Widget<T> { public string Name = ""; }'
    Write-Fixture 'generated/Output.g.cs' 'namespace Fixture; public class GeneratedThing { public string Text => "generated"; }'
    Write-Fixture 'generated/vitnet.generator.json' '{"schema":"vitnet.generator.v1","name":"FixtureEmitter","version":"1.2.3","input_symbols":["Fixture.Widget`1"]}'
    $valuesPath = Join-Path $fixture 'values.resources'
    $writer = [Resources.ResourceWriter]::new($valuesPath)
    try {
        $writer.AddResource('Text', 'hello')
        $writer.AddResource('Bytes', [byte[]](1, 2, 3, 4))
        $writer.Generate()
    } finally { $writer.Dispose() }
    $validResources = [IO.File]::ReadAllBytes($valuesPath)
    Make-Avalonia
    # Empty local feed makes synthetic restore offline; no packages are needed.
    Invoke-Build @('restore', $project, '--source', (Join-Path $fixture 'empty-feed'), '--nologo', '--verbosity', 'quiet')
    Build-Fixture
    $assembly = Join-Path $fixture 'bin/Debug/net10.0/EvidenceFixture.dll'
    $binary = Join-Path $fixture 'bin/Debug/net10.0/EvidenceFixture.exe'
    $pdb = [IO.Path]::ChangeExtension($assembly, '.pdb')
    $originalAssembly = [IO.File]::ReadAllBytes($assembly)
    $originalPdb = [IO.File]::ReadAllBytes($pdb)
    $source = Join-Path $fixture 'Declarations.cs'
    $argsAll = @('--source-root', $fixture, '--generated-root', (Join-Path $fixture 'generated'),
        '--assembly', $assembly, '--binary', $binary, '--binlog', (Join-Path $fixture 'build.binlog'))
    Collect (@('--output', $output) + $argsAll) | Out-Null
    $evidence = Get-Content $output -Raw | ConvertFrom-Json -AsHashtable
    Assert-Equal $evidence.schema 'vitnet.evidence.v1' 'Evidence schema'
    $nested = @($evidence.assemblies[0].types | Where-Object name -CEQ 'Fixture.Widget`1+Nested')
    Assert-Equal $nested.Count 1 'Nested generic metadata identity'
    Assert-Equal $nested[0].kind 'reference' 'Nested generic kind'
    $generator = @($evidence.generators | Where-Object name -CEQ 'FixtureEmitter')[0]
    Assert-Equal $generator.version '1.2.3' 'Supplied generator version'
    Assert-Equal $generator.input_symbols[0] 'Fixture.Widget`1' 'Supplied generator input'
    Assert-Equal $generator.generated_files[0] (Join-Path $fixture 'generated/Output.g.cs') 'Exact generated file'
    $points = @($evidence.sources | Where-Object { $_.kind -eq 'pdb_sequence_point' -and $_.member -eq 'Run' })
    Assert-Equal $points.Count 3 'Nonhidden Run sequence points'
    foreach ($point in $points) {
        Assert-Equal $point.assembly 'EvidenceFixture' 'PDB matched assembly'
        Assert-Equal $point.type_name 'Fixture.Widget`1' 'PDB matched type'
        Assert-Equal $point.path $source 'PDB document path'
        Assert-Equal $point.line 2 'PDB source line'
    }
    $assets = @($evidence.resources | Where-Object storage -eq 'avalonia_asset')
    Assert-Equal $assets.Count 2 'Deduplicated Avalonia entries remain separate names'
    Assert-Equal (($assets.name | Sort-Object) -join ',') '/duplicate.bin,/first.bin' 'Exact Avalonia names'
    foreach ($asset in $assets) {
        Assert-Equal $asset.bytes 4 'Exact asset bytes'
        Assert-Equal $asset.sha256 '9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a' 'Exact asset digest'
        Assert-Equal $asset.container '!AvaloniaResources' 'Asset container'
        Assert-Equal $asset.source_path $assembly 'Asset physical provenance'
    }
    foreach ($pair in @(@('!AvaloniaResources', 'assets.bin'), @('Fixture.values.resources', 'values.resources'))) {
        $container = @($evidence.resources | Where-Object { $_.storage -eq 'manifest_container' -and $_.name -ceq $pair[0] })[0]
        Assert-Equal $container.bytes ([IO.FileInfo]::new((Join-Path $fixture $pair[1])).Length) 'Container bytes'
        Assert-Equal $container.sha256 (Get-FileHash (Join-Path $fixture $pair[1]) -Algorithm SHA256).Hash.ToLowerInvariant() 'Container digest'
    }
    $serialized = @($evidence.resources | Where-Object storage -eq 'resources_serialized')
    Assert-Equal $serialized.Count 2 'Raw serialized resources count'
    # Independently specified ResourceWriter-v2 encodings: length-prefixed UTF-8
    # string and int32-length-prefixed byte[]. No application object deserialization.
    foreach ($pair in @(@('Text', [byte[]](5, 104, 101, 108, 108, 111)), @('Bytes', [byte[]](4, 0, 0, 0, 1, 2, 3, 4)))) {
        $entry = @($serialized | Where-Object name -CEQ $pair[0])[0]
        Assert-Equal $entry.bytes $pair[1].Length 'Serialized entry bytes'
        Assert-Equal $entry.sha256 ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($pair[1])).ToLowerInvariant()) 'Serialized entry digest'
        Assert-Equal $entry.container 'Fixture.values.resources' 'Serialized container'
        $key = "resource.serialized_type:${assembly}:Fixture.values.resources:$($pair[0])"
        Assert-Equal $evidence.provenance[$key] $(if ($pair[0] -eq 'Text') { 'ResourceTypeCode.String' } else { 'ResourceTypeCode.ByteArray' }) 'Raw serialized type label'
    }
    Assert-Equal $evidence.binaries[0].file_bytes ([IO.FileInfo]::new($binary).Length) 'Physical apphost bytes'
    Assert-True ($evidence.binaries[0].sections.Count -gt 0) 'No native sections'
    $reference = @($evidence.mappings | Where-Object { $_.basis -eq 'binlog_csc_reference' -and $_.assembly -eq 'System.Runtime' })[0]
    $referencePath = $reference.identity
    Pass 'collector_exact_source_generator_pdb_and_resource_provenance'
    $revisionFacts = @($evidence.provenance.GetEnumerator() | Where-Object {
        $_.Key.StartsWith('binlog.property:') -and $_.Key.EndsWith(':SourceRevisionId')
    })
    # This SDK emits official reassignment events with an empty ProjectFile.
    # Do not fabricate a project association or assume it logged the initial set.
    $middle = @($revisionFacts | Where-Object { $_.Key.Contains(':reassignment:') -and $_.Value -ceq 'synthetic-middle-revision' })
    Assert-Equal $middle.Count 1 'Earlier property reassignment history'
    $late = @($revisionFacts | Where-Object { $_.Key.Contains(':reassignment:') -and $_.Value -ceq 'synthetic-late-revision' })
    Assert-Equal $late.Count 1 'Late property reassignment history'
    Assert-True ($late[0].Key -match ':reassignment:\d+:SourceRevisionId$') 'Sequence key missing'
    Assert-True ($middle[0].Key -cne $late[0].Key) 'Late property overwrote earlier event'
    Assert-Equal @($evidence.diagnostics | Where-Object code -eq 'binlog.revision_unknown').Count 0 'Captured revision must not be unknown'
    Pass 'collector_binlog_late_revision_properties_preserve_recorded_history'
    try {
        # Other SDK tasks can emit a mapped backslash spelling too. Pin the exact
        # original item, without pretending all spellings are one graph root.
        $rootKey = "binlog.source_revision:$(Join-Path $fixture 'build.binlog'):${fixture}/"
        Assert-Equal $evidence.provenance[$rootKey] 'synthetic-source-root-revision' 'Official SourceRoot task-parameter RevisionId with original binlog/item provenance'
    } catch { $failures.Add($_.Exception.Message) }
    Pass 'collector_source_root_task_parameter_preserves_revision_metadata'

    # Synthetic resolved assets with deliberately misleading assembly filename.
    # Compile/runtime routes and project identities are not basename guesses.
    $packageRoot = Join-Path $fixture 'packages'
    $packageJson = [ordered]@{
        version = 3
        targets = [ordered]@{
            'net10.0/win-x64' = [ordered]@{
                'Direct/1.0.0' = @{ type = 'package'; dependencies = @{ leaf = '[2.0.0]' }; compile = @{ 'lib/net10.0/Misleading.dll' = @{} } }
                'Leaf/2.0.0' = @{ type = 'package'; runtime = @{ 'lib/net10.0/Other.dll' = @{} } }
                'Local/1.0.0' = @{ type = 'project' }
            }
        }
        libraries = @{
            'Direct/1.0.0' = @{ type = 'package'; path = 'direct/1.0.0' }
            'Leaf/2.0.0' = @{ type = 'package'; path = 'leaf/2.0.0' }
            'Local/1.0.0' = @{ type = 'project' }
        }
        packageFolders = @{ $packageRoot = @{} }
        project = @{ frameworks = @{ 'net10.0' = @{ dependencies = @{ DIRECT = @{ target = 'Package'; version = '[1.0.0]' } } } } }
    }
    Write-Fixture 'resolved.json' ($packageJson | ConvertTo-Json -Depth 20)
    $resolved = Join-Path $fixture 'resolved.json'
    Collect @('--output', $output, '--assets', $resolved) | Out-Null
    $evidence = Get-Content $output -Raw | ConvertFrom-Json -AsHashtable
    Assert-Equal $evidence.packages.Count 2 'Project output excluded from package inventory'
    $direct = @($evidence.packages | Where-Object id -CEQ 'Direct')[0]
    Assert-Equal $direct.target 'net10.0/win-x64' 'Exact RID target'
    Assert-Equal $direct.direct $true 'Case-insensitive direct declaration'
    Assert-Equal $direct.dependencies[0] 'Leaf/2.0.0' 'Dependency resolved version, not range'
    Assert-Equal @($evidence.packages | Where-Object id -CEQ 'Leaf')[0].direct $false 'Leaf directness'
    $route = @($evidence.mappings | Where-Object identity -CEQ 'Direct/1.0.0')[0]
    Assert-Equal $route.basis 'assets_resolved_compile:net10.0/win-x64' 'Compile provenance'
    Assert-Equal $route.assembly 'Misleading' 'Assembly spelling remains separate'
    Assert-Equal $route.source_paths[0] (Join-Path $packageRoot 'direct/1.0.0/lib/net10.0/Misleading.dll') 'Resolved exact artifact path'
    Assert-Equal $evidence.provenance["assets.target:${resolved}:net10.0/win-x64"] 'resolved; 3 libraries' 'Per-file target provenance'
    Assert-Equal $evidence.provenance["assets.non_package:${resolved}:net10.0/win-x64:Local/1.0.0"] 'project' 'Non-package evidence'
    Pass 'collector_resolved_assets_preserve_versions_targets_and_exact_routes'

    $packageJson.targets['net10.0/win-x64']['Direct/1.0.0'].dependencies['Missing'] = '[3.0.0]'
    Write-Fixture 'second-resolved.json' ($packageJson | ConvertTo-Json -Depth 20)
    $secondResolved = Join-Path $fixture 'second-resolved.json'
    Collect @('--output', $output, '--assets', $resolved, '--assets', $secondResolved) | Out-Null
    $multiple = Get-Content $output -Raw | ConvertFrom-Json -AsHashtable
    Assert-Equal $multiple.packages.Count 4 'Separate manifest inventories'
    Assert-Equal (($multiple.packages.target | Sort-Object -Unique) -join '|') "$resolved`::net10.0/win-x64|$secondResolved`::net10.0/win-x64" 'Qualified per-file target namespaces'
    $secondDirect = @($multiple.packages | Where-Object { $_.target -ceq "${secondResolved}::net10.0/win-x64" -and $_.id -eq 'Direct' })[0]
    Assert-Equal ($secondDirect.dependencies -join '|') 'Leaf/2.0.0|unresolved:Missing/[3.0.0]' 'Missing dependency edge is not dropped'
    $firstDirect = @($multiple.packages | Where-Object { $_.target -ceq "${resolved}::net10.0/win-x64" -and $_.id -eq 'Direct' })[0]
    Assert-Equal ($firstDirect.dependencies -join '|') 'Leaf/2.0.0' 'No cross-project missing edge leakage'
    $missing = @($multiple.diagnostics | Where-Object code -eq 'assets.dependency_missing')
    Assert-Equal $missing.Count 1 'Missing dependency diagnosis'
    Assert-Equal $missing[0].path $secondResolved 'Missing edge provenance'
    Assert-Equal @($multiple.diagnostics | Where-Object code -eq 'assets.cycle').Count 0 'Unresolved dependency is not a cycle'
    $bases = @($multiple.mappings | Where-Object identity -eq 'Direct/1.0.0' | ForEach-Object basis | Sort-Object)
    Assert-Equal ($bases -join '|') "assets_resolved_compile:${resolved}::net10.0/win-x64|assets_resolved_compile:${secondResolved}::net10.0/win-x64" 'Qualified mapping provenance'
    Pass 'collector_multiple_assets_keep_project_graphs_and_unresolved_edges_separate'

    $referenceName = [IO.Path]::GetFileName($referencePath)
    $referenceDirectory = [IO.Path]::GetDirectoryName($referencePath)
    $referenceAssets = @{
        version = 3
        targets = @{ 'net10.0' = @{ 'Synthetic.Reference/1' = @{ type = 'package'; compile = @{ $referenceName = @{} } } } }
        libraries = @{ 'Synthetic.Reference/1' = @{ type = 'package'; path = '.' } }
        packageFolders = @{ $referenceDirectory = @{} }
        project = @{ frameworks = @{ 'net10.0' = @{ dependencies = @{ 'Synthetic.Reference' = @{} } } } }
    }
    Write-Fixture 'reference-assets.json' ($referenceAssets | ConvertTo-Json -Depth 20)
    $refArgs = @('--assets', (Join-Path $fixture 'reference-assets.json'), '--binlog', (Join-Path $fixture 'build.binlog'))
    Collect (@('--output', $output) + $refArgs) | Out-Null
    $referenceEvidence = Get-Content $output -Raw | ConvertFrom-Json -AsHashtable
    $routed = @($referenceEvidence.assemblies | Where-Object path -CEQ $referencePath)
    Assert-Equal $routed.Count 1 'Reference assembly emitted without explicit --assembly'
    Assert-Equal $routed[0].name 'System.Runtime' 'Metadata reference name, not filename guess'
    Assert-Equal $routed[0].package 'Synthetic.Reference/1' 'Resolved reference package route'
    Assert-Equal $routed[0].types.Count 0 'Reference remains minimal until explicitly collected'
    Collect (@('--output', $output, '--assembly', $referencePath) + $refArgs) | Out-Null
    $referenceEvidence = Get-Content $output -Raw | ConvertFrom-Json -AsHashtable
    $routed = @($referenceEvidence.assemblies | Where-Object path -CEQ $referencePath)
    Assert-Equal $routed.Count 1 'Explicit managed inspection upgrades, not duplicates'
    Assert-Equal $routed[0].package 'Synthetic.Reference/1' 'Upgrade keeps package evidence'
    Assert-True ($routed[0].types.Count -gt 0) 'Upgrade did not inspect type definitions'
    Pass 'collector_binlog_reference_routes_correlate_without_explicit_assembly_and_upgrade_once'

    Write-Fixture 'malformed.json' '{"version":3,"targets":'
    Write-Fixture 'unsupported.json' '{"version":5,"targets":{},"libraries":{}}'
    Write-Fixture 'bad.pe' 'not a PE image'
    Write-Fixture 'bad.pdb' 'not a PDB image'
    Write-Fixture 'bad.binlog' 'not a gzip binlog'
    $binlogBytes = [IO.File]::ReadAllBytes((Join-Path $fixture 'build.binlog'))
    $binlogBytes[-8] = $binlogBytes[-8] -bxor 1
    [IO.File]::WriteAllBytes((Join-Path $fixture 'bad-crc.binlog'), $binlogBytes)
    foreach ($case in @(
        @('--assets', 'malformed.json', 'collector.malformed'),
        @('--assets', 'unsupported.json', 'assets.malformed'),
        @('--assembly', 'bad.pe', 'collector.malformed'),
        @('--binary', 'bad.pe', 'collector.malformed'),
        @('--pdb', 'bad.pdb', 'pdb.malformed'),
        @('--binlog', 'bad.binlog', 'collector.malformed'),
        # The runtime gzip reader rejects a bad CRC before the collector's
        # independent trailer validator; the public classification is malformed.
        @('--binlog', 'bad-crc.binlog', 'collector.malformed')
    )) {
        Assert-PreservedFailure @($case[0], (Join-Path $fixture $case[1])) 2 $case[2]
    }
    Assert-PreservedFailure @('--assets', $resolved, '--max-file-bytes', '1') 4 'resource.collector.files'
    Assert-PreservedFailure @('--assets', $resolved, '--max-total-bytes', '1') 4 'resource.collector.files'
    Assert-PreservedFailure @('--source-root', $fixture, '--max-files', '1') 4 'resource.collector.directory'
    Assert-PreservedFailure @('--max-records', '1') 4 'resource.collector.records'
    Assert-PreservedFailure @('--assembly', $assembly, '--max-resource-bytes', '1') 4 'resource.collector.resource_bytes'
    Assert-PreservedFailure @('--binlog', (Join-Path $fixture 'build.binlog'), '--max-expanded-bytes', '1') 4 'resource.collector.binlog_expanded'
    Assert-PreservedFailure @('--max-output-bytes', '1') 4 'resource.collector.output'
    # Post-serialization failure preserves bytes and cleans .pending; exact cap
    # succeeds. A small opaque file tests file/total budgets without PE overhead.
    Collect @('--output', $output) | Out-Null
    $length = [IO.FileInfo]::new($output).Length
    $emptyEvidence = Get-Content $output -Raw | ConvertFrom-Json -AsHashtable
    $recordCount = $emptyEvidence.provenance.Count + $emptyEvidence.diagnostics.Count
    Collect @('--output', $output, '--max-records', $recordCount.ToString()) | Out-Null
    Assert-PreservedFailure @('--max-records', ($recordCount - 1).ToString()) 4 'resource.collector.records'
    Assert-PreservedFailure @('--max-output-bytes', ($length - 1).ToString()) 4 'resource.collector.output'
    Collect @('--output', $output, '--max-output-bytes', $length.ToString()) | Out-Null
    Write-Fixture 'opaque.mstat' 'abc'
    $opaque = Join-Path $fixture 'opaque.mstat'
    Collect @('--output', $output, '--mstat', $opaque, '--max-file-bytes', '3', '--max-total-bytes', '3', '--max-files', '1') | Out-Null
    $opaqueEvidence = Get-Content $output -Raw | ConvertFrom-Json -AsHashtable
    Assert-Equal $opaqueEvidence.artifacts[0].kind 'mstat' 'Opaque role'
    Assert-Equal $opaqueEvidence.artifacts[0].path $opaque 'Opaque path'
    Assert-True (@($opaqueEvidence.diagnostics | Where-Object code -eq 'artifact.validation_deferred').Count -eq 1) 'Opaque format must not be called parsed'
    Assert-PreservedFailure @('--mstat', $opaque, '--max-file-bytes', '2') 4 'resource.collector.files'
    Assert-PreservedFailure @('--mstat', $opaque, '--max-total-bytes', '2') 4 'resource.collector.files'
    Write-Fixture 'second-opaque.csv' 'xyz'
    Assert-PreservedFailure @('--mstat', $opaque, '--metadata', (Join-Path $fixture 'second-opaque.csv'), '--max-files', '1') 4 'resource.collector.files'
    $opaqueHash = (Get-FileHash $opaque).Hash
    Collect @('--output', $opaque, '--mstat', $opaque) 2 'collector.output_alias' | Out-Null
    Assert-Equal (Get-FileHash $opaque).Hash $opaqueHash 'Aliased input preservation'
    Pass 'collector_malformed_and_budget_failures_preserve_committed_output'

    # Do not rebuild: changed current source must be compared to the old PDB.
    $compiledSourceHash = (Get-FileHash $source -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::AppendAllText($source, "`n// changed after compilation", $utf8)
    Collect @('--output', $output, '--assembly', $assembly) | Out-Null
    $drift = Get-Content $output -Raw | ConvertFrom-Json -AsHashtable
    $diagnostics = @($drift.diagnostics | Where-Object code -eq 'pdb.document_drift')
    Assert-Equal $diagnostics.Count 1 'Only modified PDB document is stale'
    Assert-Equal $diagnostics[0].path $source 'Drift source path'
    $point = @($drift.sources | Where-Object { $_.kind -eq 'pdb_sequence_point' -and $_.member -eq 'Run' })[0]
    Assert-Equal $point.sha256 (Get-FileHash $source -Algorithm SHA256).Hash.ToLowerInvariant() 'Current source hash'
    Assert-True ($point.sha256 -cne $compiledSourceHash) 'Source did not change'
    Assert-Equal $point.type_name 'Fixture.Widget`1' 'Compiled symbol preserved despite drift'
    $fact = $drift.provenance["pdb.document:${pdb}:$source"]
    Assert-True ($fact.EndsWith("checksum=$compiledSourceHash")) 'Compiled checksum lost'
    Pass 'collector_pdb_document_drift_preserves_compiled_symbol_and_old_checksum'

    Build-Fixture
    # Pair the old compiled PE with the newly compiled PDB, without ever executing
    # either build. Mismatch must remove assembly/type/member attribution.
    [IO.File]::WriteAllBytes($assembly, $originalAssembly)
    Collect @('--output', $output, '--assembly', $assembly) | Out-Null
    $mismatch = Get-Content $output -Raw | ConvertFrom-Json -AsHashtable
    Assert-Equal @($mismatch.diagnostics | Where-Object code -eq 'pdb.identity_mismatch').Count 1 'PDB identity mismatch'
    Assert-Equal @($mismatch.diagnostics | Where-Object code -eq 'pdb.member_unknown').Count 1 'Unknown mismatched members'
    $points = @($mismatch.sources | Where-Object kind -eq 'pdb_sequence_point')
    Assert-True ($points.Count -gt 0) 'Mismatch lost document points'
    foreach ($point in $points) {
        Assert-Equal $point.assembly '' 'Mismatched assembly must be unknown'
        Assert-Equal $point.type_name '' 'Mismatched type must be unknown'
        Assert-True (-not $point.ContainsKey('member')) 'Mismatched PDB invented a member'
    }
    [IO.File]::WriteAllBytes($pdb, $originalPdb)
    $nativePdb = Join-Path $fixture 'native.pdb'
    [IO.File]::WriteAllBytes($nativePdb, [Text.Encoding]::ASCII.GetBytes("Microsoft C/C++ MSF 7.00`r`n$([char]26)DS`0`0`0"))
    Collect @('--output', $output, '--pdb', $nativePdb) | Out-Null
    $nativeEvidence = Get-Content $output -Raw | ConvertFrom-Json -AsHashtable
    Assert-Equal $nativeEvidence.sources.Count 0 'Native PDB is not portable evidence'
    Assert-Equal @($nativeEvidence.diagnostics | Where-Object code -eq 'pdb.native_unsupported').Count 1 'Native PDB limit explicit'
    Invoke-Build @('build', $project, '--no-restore', '-t:Rebuild', '--nologo', '--verbosity', 'quiet', '-p:DebugType=embedded')
    Assert-PreservedFailure @('--assembly', $assembly, '--max-expanded-bytes', '1') 4 'resource.collector.pdb_expanded'
    Pass 'collector_pdb_mismatch_native_format_and_embedded_expansion_are_explicit'

    Make-Avalonia -Offset 1000
    Build-Fixture
    Assert-PreservedFailure @('--assembly', $assembly) 2 'resource.avalonia_corrupt'
    Make-Avalonia -DuplicateName
    Build-Fixture
    Assert-PreservedFailure @('--assembly', $assembly) 2 'resource.avalonia_corrupt'
    Make-Avalonia
    [IO.File]::WriteAllBytes($valuesPath, [byte[]](1, 2, 3, 4))
    Build-Fixture
    Assert-PreservedFailure @('--assembly', $assembly) 2 'resource.resources_corrupt'
    [IO.File]::WriteAllBytes($valuesPath, $validResources)
    Make-Avalonia -Version 3
    Build-Fixture
    Collect @('--output', $output, '--assembly', $assembly) | Out-Null
    $unsupported = Get-Content $output -Raw | ConvertFrom-Json -AsHashtable
    Assert-Equal @($unsupported.resources | Where-Object storage -eq 'avalonia_asset').Count 0 'Unsupported version must not emit assets'
    Assert-Equal @($unsupported.resources | Where-Object { $_.storage -eq 'manifest_container' -and $_.name -eq '!AvaloniaResources' }).Count 1 'Unsupported container retained'
    Assert-Equal @($unsupported.diagnostics | Where-Object code -eq 'resource.avalonia_unsupported').Count 1 'Unsupported version diagnosis'
    Make-Avalonia
    # Header version is independent of the serialized data version. Unsupported
    # readers/versions retain the original container, never an empty success.
    $futureResources = [byte[]]$validResources.Clone()
    [BitConverter]::GetBytes([int]2).CopyTo($futureResources, 4)
    [IO.File]::WriteAllBytes($valuesPath, $futureResources)
    Build-Fixture
    Collect @('--output', $output, '--assembly', $assembly) | Out-Null
    $unsupported = Get-Content $output -Raw | ConvertFrom-Json -AsHashtable
    Assert-Equal @($unsupported.resources | Where-Object storage -eq 'resources_serialized').Count 0 'Future resources header must not emit children'
    Assert-Equal @($unsupported.resources | Where-Object { $_.storage -eq 'manifest_container' -and $_.name -eq 'Fixture.values.resources' }).Count 1 'Future resources container retained'
    Assert-Equal @($unsupported.diagnostics | Where-Object code -eq 'resource.resources_unsupported').Count 1 'Future resources diagnosis'
    Pass 'collector_resource_corruption_is_fatal_but_future_versions_are_explicit'

    if ($failures.Count -ne 0) {
        throw "Collector regression FAILED ($($failures.Count) assertions):`n$($failures -join "`n")"
    }
    Write-Host "Collector regression succeeded: $($passed.Count) groups; synthetic Main was never executed."
} finally {
    Pop-Location
    if ($Keep) { Write-Host "Fixture retained: $fixture" }
    else { Remove-Item -LiteralPath $fixture -Recurse -Force }
}
