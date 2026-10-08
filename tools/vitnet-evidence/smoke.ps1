param([switch]$Keep)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$fixture = Join-Path $root '.smoke'
$utf8 = [System.Text.UTF8Encoding]::new($false)
function Write-Fixture([string]$Path, [string]$Value) {
    [System.IO.File]::WriteAllText((Join-Path $fixture $Path), $Value, $utf8)
}
function Invoke-Checked([string[]]$Arguments) {
    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) { throw "dotnet failed ($LASTEXITCODE): $Arguments" }
}
if (Test-Path $fixture) { throw "Remove the prior collector-owned .smoke fixture before running." }
[System.IO.Directory]::CreateDirectory($fixture) | Out-Null
[System.IO.Directory]::CreateDirectory((Join-Path $fixture 'generated')) | Out-Null
Push-Location $root
try {
    Invoke-Checked @('restore', '--locked-mode', '--nologo', '--verbosity', 'quiet')
    Invoke-Checked @('build', '--no-restore', '--nologo', '--verbosity', 'quiet')
    Write-Fixture 'Fixture.csproj' @'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <AssemblyName>EvidenceFixture</AssemblyName>
    <DebugType>portable</DebugType>
    <SourceRevisionId>synthetic-revision</SourceRevisionId>
  </PropertyGroup>
  <ItemGroup>
    <EmbeddedResource Include="assets.bin" LogicalName="!AvaloniaResources" />
    <EmbeddedResource Include="values.resources" LogicalName="Fixture.values.resources" />
  </ItemGroup>
</Project>
'@
    Write-Fixture 'Declarations.cs' @'
namespace Fixture;
[System.Obsolete("synthetic root attribute")]
public partial class Widget<T>
{
    public int Value { get; set; }
    public void Run() { Value++; }
    public class Nested { }
}
public enum Choice { One, Two }
public struct Point { public int X; }
public class Entry { public static void Main() => throw new System.Exception("MUST NEVER EXECUTE"); }
'@
    Write-Fixture 'Partial.cs' @'
namespace Fixture;
public partial class Widget<T> { public string Name = ""; }
'@
    Write-Fixture 'generated\Output.g.cs' @'
namespace Fixture;
public class GeneratedThing { public string Text => "generated"; }
'@
    Write-Fixture 'generated\vitnet.generator.json' @'
{
  "schema": "vitnet.generator.v1",
  "name": "FixtureEmitter",
  "version": "1.2.3",
  "input_symbols": ["Fixture.Widget`1"]
}
'@
    $resourcePath = Join-Path $fixture 'values.resources'
    $resources = [System.Resources.ResourceWriter]::new($resourcePath)
    try {
        $resources.AddResource('Text', 'hello')
        $resources.AddResource('Bytes', [byte[]](1, 2, 3, 4))
        $resources.Generate()
    } finally { $resources.Dispose() }
    $index = [System.IO.MemoryStream]::new()
    $writer = [System.IO.BinaryWriter]::new($index, $utf8, $true)
    try {
        $writer.Write([int]2)
        $writer.Write([int]2)
        foreach ($name in @('/first.bin', '/duplicate.bin')) {
            $writer.Write([string]$name)
            $writer.Write([int]0)
            $writer.Write([int]4)
        }
        $writer.Flush()
        $stream = [System.IO.File]::Create((Join-Path $fixture 'assets.bin'))
        $container = [System.IO.BinaryWriter]::new($stream)
        try {
            $container.Write([int]$index.Length)
            $container.Write($index.ToArray())
            $container.Write([byte[]](1, 2, 3, 4))
        } finally { $container.Dispose(); $stream.Dispose() }
    } finally { $writer.Dispose(); $index.Dispose() }
    $project = Join-Path $fixture 'Fixture.csproj'
    Invoke-Checked @('build', $project, '--nologo', '--verbosity', 'quiet', "-bl:$fixture\build.binlog;ProjectImports=None")
    $dll = Join-Path $root 'bin\Debug\net10.0\vitnet-evidence.dll'
    $output = Join-Path $fixture 'evidence.json'
    Invoke-Checked @($dll, '--output', $output, '--label', 'synthetic smoke',
        '--source-root', $fixture, '--generated-root', "$fixture\generated",
        '--assembly', "$fixture\bin\Debug\net10.0\EvidenceFixture.dll",
        '--binary', "$fixture\bin\Debug\net10.0\EvidenceFixture.exe",
        '--assets', "$fixture\obj\project.assets.json", '--binlog', "$fixture\build.binlog")
    $evidence = Get-Content $output -Raw | ConvertFrom-Json
    if ($evidence.schema -ne 'vitnet.evidence.v1' -or
        -not ($evidence.sources | Where-Object type_name -eq 'Fixture.Widget`1') -or
        -not ($evidence.sources | Where-Object kind -eq 'pdb_sequence_point') -or
        -not ($evidence.generators | Where-Object name -eq 'FixtureEmitter') -or
        -not ($evidence.resources | Where-Object storage -eq 'avalonia_asset') -or
        -not ($evidence.resources | Where-Object storage -eq 'resources_serialized') -or
        -not ($evidence.assemblies.types | Where-Object kind -eq 'enum') -or
        -not ($evidence.assemblies.types | Where-Object kind -eq 'value') -or
        $evidence.binaries.Count -ne 1 -or
        -not ($evidence.mappings | Where-Object basis -eq 'binlog_csc_reference')) {
        throw 'A requested smoke collection surface was not emitted.'
    }
    Write-Host 'Collector synthetic smoke succeeded (source, partial, generated provenance, PE, portable PDB, resources, native sections, assets, binlog routes).'
} finally {
    Pop-Location
    if (-not $Keep -and (Test-Path $fixture)) { Remove-Item $fixture -Recurse -Force }
}
