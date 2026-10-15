param([switch]$Keep, [string]$ScratchRoot = $PSScriptRoot, [switch]$SourceOnly)
# Offline data-reader regressions. Only the collector and this synthetic fixture
# are compiled. The fixture entry point throws and is NEVER invoked.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = $PSScriptRoot
$fixture = Join-Path $ScratchRoot ('vitnet-evidence-regression-' + [Guid]::NewGuid().ToString('N'))
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
    $sourceTests = Join-Path $fixture 'source-tests'
    [IO.Directory]::CreateDirectory($sourceTests) | Out-Null
    Write-Fixture 'source-tests\Annotations.cs' @'
namespace AnnotationFixture;
public class MarkAttribute : System.Attribute { }
[Mark("type")] public class Outer<[Mark("outer generic")] T>([Mark("primary")] int primary)
{
    [Mark("ctor")] public Outer([param: Mark("ctor input")] string input) { }
    [Mark("method"), Other]
    [return: Mark("result")]
    public int Transform<[Mark("method generic")] V>([Mark("input"), Other] int @value, [param: Mark("explicit")] string text) => 0;
    [Mark("index")]
    [return: Mark("index result")]
    public int this[[Mark("index input")] int index] => 0;
    [Mark("nested")] public class Nested<[Mark("nested generic")] U>([Mark("nested primary")] int @value)
    {
        [Mark("nested ctor")] public Nested([Mark("nested ctor input")] string text) { }
        public void Go<[Mark("go generic")] V>([Mark("go input")] int value) { }
    }
}
[Mark("record")] public record Sample<[Mark("record generic")] T>([Mark("record input")] T item, [property: Mark("property target")] int ignored);
[Mark("delegate")]
[return: Mark("delegate result")]
public delegate int Callback<[Mark("delegate generic")] T>([Mark("delegate input")] int value);
public class Plain { }
'@
    Collect @('--output', $output, '--source-root', $sourceTests) | Out-Null
    $annotationEvidence = Get-Content $output -Raw | ConvertFrom-Json -AsHashtable
    $annotationSources = $annotationEvidence.sources
    Assert-Equal $annotationSources.Count 11 'Only original declarations own source records'
    $outer = @($annotationSources | Where-Object { $_.type_name -ceq 'AnnotationFixture.Outer`1' -and -not $_.ContainsKey('member') })[0]
    Assert-Equal ($outer.annotations.target -join '|') 'declaration|generic_parameter:T|parameter:primary' 'Type and primary parameter targets'
    Assert-Equal ($outer.attributes -join '|') 'Mark("type")' 'Legacy type attributes exclude nested targets'
    Assert-Equal $outer.annotations[1].attributes[0] 'Mark("outer generic")' 'Actual generic attribute syntax'
    Assert-Equal $outer.annotations[2].attributes[0] 'Mark("primary")' 'Primary constructor attribute syntax'
    $method = @($annotationSources | Where-Object { $_['member'] -ceq 'Transform(int,string)' })[0]
    Assert-Equal ($method.attributes -join '|') 'Mark("method")|Other|Mark("result")' 'Legacy method and return attributes unchanged'
    Assert-Equal ($method.annotations.target -join '|') 'declaration|generic_parameter:V|parameter:text|parameter:value|return' 'Method target names and escaped parameter identifier'
    Assert-Equal ($method.annotations[0].attributes -join '|') 'Mark("method")|Other' 'Declaration attribute list contents'
    Assert-Equal ($method.annotations[3].attributes -join '|') 'Mark("input")|Other' 'Multiple parameter attributes retained'
    Assert-Equal $method.annotations[4].attributes[0] 'Mark("result")' 'Return target distinguished from declaration'
    Assert-Equal $method.sha256 (Get-FileHash (Join-Path $sourceTests 'Annotations.cs') -Algorithm SHA256).Hash.ToLowerInvariant() 'Original owner source bytes'
    $definition = @($annotationSources | Where-Object type_name -CEQ 'AnnotationFixture.MarkAttribute')[0]
    Assert-Equal $definition.attributes.Count 0 'Attribute definition is not an application'
    Assert-True (-not $definition.ContainsKey('annotations')) 'Unannotated declaration preserves optional absence'
    Pass 'collector_source_annotation_targets_preserve_declarations_returns_and_legacy_attributes'
    $ctor = @($annotationSources | Where-Object { $_.type_name -ceq 'AnnotationFixture.Outer`1' -and $_['member'] -ceq '.ctor(string)' })[0]
    Assert-Equal ($ctor.annotations.target -join '|') 'declaration|parameter:input' 'Constructor parameter target'
    Assert-Equal $ctor.annotations[1].attributes[0] 'Mark("ctor input")' 'Explicit param target syntax'
    $indexer = @($annotationSources | Where-Object { $_['member'] -ceq 'this[int]' })[0]
    Assert-Equal ($indexer.annotations.target -join '|') 'declaration|parameter:index|return' 'Indexer targets'
    $delegate = @($annotationSources | Where-Object kind -CEQ 'delegate')[0]
    Assert-Equal ($delegate.annotations.target -join '|') 'declaration|generic_parameter:T|parameter:value|return' 'Delegate targets'
    Assert-Equal $delegate.annotations[2].attributes[0] 'Mark("delegate input")' 'Delegate input syntax'
    Assert-Equal $delegate.annotations[3].attributes[0] 'Mark("delegate result")' 'Delegate return syntax'
    $nested = @($annotationSources | Where-Object { $_.type_name -ceq 'AnnotationFixture.Outer`1+Nested`1' -and -not $_.ContainsKey('member') })[0]
    Assert-Equal ($nested.annotations.target -join '|') 'declaration|generic_parameter:U|parameter:value' 'Nested type owns only its immediate parameters'
    Assert-Equal $nested.annotations[1].attributes[0] 'Mark("nested generic")' 'Nested generic syntax'
    $go = @($annotationSources | Where-Object { $_['member'] -ceq 'Go(int)' })[0]
    Assert-Equal ($go.annotations.target -join '|') 'generic_parameter:V|parameter:value' 'Nested method parameter attributes are not lost'
    $record = @($annotationSources | Where-Object kind -CEQ 'record')[0]
    Assert-Equal ($record.annotations.target -join '|') 'declaration|generic_parameter:T|parameter:item' 'Record primary parameters; property-targeted attribute is not a parameter application'
    Assert-Equal $record.annotations[2].attributes[0] 'Mark("record input")' 'Record primary input syntax'
    Pass 'collector_source_annotations_cover_constructor_indexer_delegate_and_nested_primary_parameters'
    $sourceLimits = Join-Path $fixture 'source-limits'
    [IO.Directory]::CreateDirectory($sourceLimits) | Out-Null
    Write-Fixture 'source-limits\Bounded.cs' '[A] class C {}'
    Collect @('--output', $output, '--source-root', $sourceLimits) | Out-Null
    $boundedSource = Get-Content $output -Raw | ConvertFrom-Json -AsHashtable
    # Roslyn visits the declaration, attribute list, attribute and identifier.
    # The legacy string plus annotation group/string are separately budgeted.
    $sourceRecords = $boundedSource.provenance.Count + $boundedSource.artifacts.Count +
        $boundedSource.diagnostics.Count + $boundedSource.sources.Count + 4 + 1 + 1 + 1
    Collect @('--output', $output, '--source-root', $sourceLimits, '--max-records', $sourceRecords.ToString()) | Out-Null
    Assert-PreservedFailure @('--source-root', $sourceLimits, '--max-records', ($sourceRecords - 1).ToString()) 4 'resource.collector.records'
    Pass 'collector_source_annotation_items_are_budgeted_and_fail_atomically'

    $xamlTests = Join-Path $fixture 'xaml-tests'
    [IO.Directory]::CreateDirectory($xamlTests) | Out-Null
    Write-Fixture 'xaml-tests\Hint.csproj' '<Project><PropertyGroup><AssemblyName>Synthetic.Views</AssemblyName></PropertyGroup></Project>'
    Write-Fixture 'xaml-tests\A.xaml' @'
<ui:Window xmlns:ui="urn:synthetic" xmlns:a="http://schemas.microsoft.com/winfx/2006/xaml" xmlns:fake="urn:fake" a:Class="Views.Shell" Class="NotAClass">
  <ui:ResourceDictionary Source="Themes/Colors.xaml">
    <ui:Brush a:Key="zeta"/><ui:Brush a:Key="alpha"/><ui:Brush a:Key="alpha"/>
    <ui:Brush a:Key="a&amp;b"/><ui:Brush fake:Key="NotAKey"/><ui:Brush Key="NotAKey"/>
  </ui:ResourceDictionary>
  <ui:ResourceInclude Source="https://example.invalid/theme.axaml"/>
  <ui:ResourceDictionary Source="Themes/Colors.xaml"/>
  <ui:Button Source="NotAnInclude"/>
</ui:Window>
'@
    Write-Fixture 'xaml-tests\B.axaml' @'
<Styles xmlns="https://github.com/avaloniaui" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
  <StyleInclude Source="avares://Synthetic/Theme.axaml"/>
  <MergeResourceInclude Source="../Shared.axaml"/>
  <MergeStyleInclude Source="./SharedStyles.axaml"/>
  <Button x:Key="only"/>
</Styles>
'@
    Collect @('--output', $output, '--source-root', $xamlTests) | Out-Null
    $xamlEvidence = Get-Content $output -Raw | ConvertFrom-Json -AsHashtable
    Assert-Equal $xamlEvidence.xaml_documents.Count 2 'Both XAML extensions captured'
    $firstXaml = $xamlEvidence.xaml_documents[0]
    $secondXaml = $xamlEvidence.xaml_documents[1]
    Assert-Equal $firstXaml.path (Join-Path $xamlTests 'A.xaml') 'Document deterministic ordinal ordering'
    Assert-Equal $firstXaml.assembly 'Synthetic.Views' 'Textual project assembly hint'
    Assert-Equal $firstXaml.declared_class 'Views.Shell' 'Namespace-qualified Class only'
    Assert-Equal $firstXaml.root_element '{urn:synthetic}Window' 'Expanded root XML name'
    Assert-Equal ($firstXaml.keys -join '|') 'a&b|alpha|zeta' 'Sorted distinct namespace-qualified keys'
    Assert-Equal ($firstXaml.includes -join '|') 'Themes/Colors.xaml|https://example.invalid/theme.axaml' 'Raw sorted includes without fetching or resolving'
    Assert-Equal $secondXaml.root_element '{https://github.com/avaloniaui}Styles' 'Default root namespace preserved'
    Assert-True (-not $secondXaml.ContainsKey('declared_class')) 'Missing declared class stays absent'
    Assert-Equal ($secondXaml.includes -join '|') '../Shared.axaml|./SharedStyles.axaml|avares://Synthetic/Theme.axaml' 'Avalonia include forms remain literal'
    Assert-Equal ($secondXaml.keys -join '|') 'only' 'AXAML key'
    foreach ($document in $xamlEvidence.xaml_documents) {
        Assert-Equal $document.sha256 (Get-FileHash $document.path -Algorithm SHA256).Hash.ToLowerInvariant() 'Actual XAML source bytes'
        Assert-Equal @($xamlEvidence.artifacts | Where-Object { $_.kind -ceq 'source' -and $_.path -ceq $document.path }).Count 1 'Source artifact provenance'
        Assert-Equal $xamlEvidence.provenance["source.xaml_assembly_basis:$($document.path)"] 'textual_project_directory_hint; syntax-only association, not compiled ownership' 'Explicit syntax-only association'
    }
    Assert-True ($xamlEvidence.provenance['source.xaml_basis'].Contains('includes are never fetched or resolved')) 'XAML limitations are explicit'
    Assert-Equal $xamlEvidence.sources.Count 0 'XAML documents must not create fake source owners'
    $deterministicHash = (Get-FileHash $output -Algorithm SHA256).Hash
    Collect @('--output', $output, '--source-root', $xamlTests) | Out-Null
    Assert-Equal (Get-FileHash $output -Algorithm SHA256).Hash $deterministicHash 'Identical XAML collection is byte deterministic'
    Pass 'collector_xaml_documents_capture_classes_keys_includes_hashes_and_syntax_only_hints'
    Write-Fixture 'xaml-tests\Other.csproj' '<Project><PropertyGroup><AssemblyName>Other.Views</AssemblyName></PropertyGroup></Project>'
    Collect @('--output', $output, '--source-root', $xamlTests) | Out-Null
    $ambiguousXaml = Get-Content $output -Raw | ConvertFrom-Json -AsHashtable
    Assert-Equal @($ambiguousXaml.xaml_documents | Where-Object assembly -NE '').Count 0 'Ambiguous projects must not fabricate a XAML assembly'
    Assert-Equal @($ambiguousXaml.diagnostics | Where-Object code -CEQ 'source.xaml_assembly_unknown').Count 2 'Unknown XAML associations diagnosed'
    Pass 'collector_xaml_ambiguous_textual_projects_preserve_unknown_associations'

    $xamlLimits = Join-Path $fixture 'xaml-limits'
    [IO.Directory]::CreateDirectory($xamlLimits) | Out-Null
    $boundedXaml = '<Root xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" x:Key="k" padding="' + ('a' * 256) + '"/>'
    Write-Fixture 'xaml-limits\Bounded.xaml' $boundedXaml
    $xamlBytes = [IO.FileInfo]::new((Join-Path $xamlLimits 'Bounded.xaml')).Length
    Collect @('--output', $output, '--source-root', $xamlLimits, '--max-file-bytes', $xamlBytes.ToString(),
        '--max-total-bytes', $xamlBytes.ToString(), '--max-files', '1') | Out-Null
    $boundedEvidence = Get-Content $output -Raw | ConvertFrom-Json -AsHashtable
    Assert-Equal $boundedEvidence.xaml_documents[0].root_element 'Root' 'Unqualified root name'
    Assert-Equal $boundedEvidence.xaml_documents[0].assembly '' 'No project association invented'
    Assert-Equal $boundedEvidence.xaml_documents[0].includes.Count 0 'Empty include inventory remains nonnull'
    # One XML element, three attributes and one captured key are charged in
    # addition to each published artifact/document/diagnostic/provenance item.
    $xamlRecords = $boundedEvidence.provenance.Count + $boundedEvidence.artifacts.Count +
        $boundedEvidence.diagnostics.Count + $boundedEvidence.xaml_documents.Count + 1 + 3 + 1
    Collect @('--output', $output, '--source-root', $xamlLimits, '--max-records', $xamlRecords.ToString()) | Out-Null
    Assert-PreservedFailure @('--source-root', $xamlLimits, '--max-records', ($xamlRecords - 1).ToString()) 4 'resource.collector.records'
    Assert-PreservedFailure @('--source-root', $xamlLimits, '--max-file-bytes', ($xamlBytes - 1).ToString()) 4 'resource.collector.files'
    Assert-PreservedFailure @('--source-root', $xamlLimits, '--max-total-bytes', ($xamlBytes - 1).ToString()) 4 'resource.collector.files'
    Write-Fixture 'xaml-limits\Second.axaml' '<Styles/>'
    Assert-PreservedFailure @('--source-root', $xamlLimits, '--max-files', '1') 4 'resource.collector.directory'
    Collect @('--output', $output, '--source-root', $xamlLimits, '--max-files', '2') | Out-Null
    Assert-Equal (Get-Content $output -Raw | ConvertFrom-Json -AsHashtable).xaml_documents.Count 2 'Exact XAML file-count boundary'
    Pass 'collector_xaml_byte_file_and_record_limits_are_exact_and_atomic'
    Remove-Item -LiteralPath (Join-Path $xamlLimits 'Second.axaml')
    foreach ($badXaml in @(
        '<!DOCTYPE Root [<!ENTITY injected "expanded">]><Root>&injected;</Root>',
        '<!DOCTYPE Root SYSTEM "file:///not-read-or-resolved.dtd"><Root/>',
        '<Root><Child></Root>',
        '',
        '<Root/><Other/>'
    )) {
        Write-Fixture 'xaml-limits\Bounded.xaml' $badXaml
        Assert-PreservedFailure @('--source-root', $xamlLimits) 2 'source.xaml_malformed'
    }
    Write-Fixture 'xaml-limits\Bounded.xaml' ('<Root>' + ('<Child>' * 65) + ('</Child>' * 65) + '</Root>')
    Assert-PreservedFailure @('--source-root', $xamlLimits) 4 'resource.collector.xaml_depth'
    Pass 'collector_xaml_dtd_malformed_xml_and_depth_fail_typed_without_publication'
    Collect @('--output', $output) | Out-Null
    Assert-Equal (Get-Content $output -Raw | ConvertFrom-Json -AsHashtable).xaml_documents.Count 0 'No source root produces nonnull empty XAML inventory'
    Pass 'collector_xaml_capture_requires_an_explicit_source_root'
    if ($SourceOnly) {
        if ($failures.Count -ne 0) { throw "Collector source regression FAILED:`n$($failures -join "`n")" }
        Write-Host "Collector source regression succeeded: $($passed.Count) groups; no source project was compiled or executed."
        return
    }
    # Parse-only attribute fixtures are deliberately not compilable applications.
    foreach ($directory in @($sourceTests, $sourceLimits, $xamlTests, $xamlLimits)) {
        Remove-Item -LiteralPath $directory -Recurse -Force
    }
    $project = Join-Path $fixture 'Fixture.csproj'
    [IO.Directory]::CreateDirectory((Join-Path $fixture 'empty-feed')) | Out-Null
    [IO.Directory]::CreateDirectory((Join-Path $fixture 'generated')) | Out-Null
    $conventionalRoot = Join-Path $fixture 'captured'
    $conventionalFile = Join-Path $conventionalRoot 'System.Text.Json.SourceGeneration\SyntheticEmitter\Widget.g.cs'
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($conventionalFile)) | Out-Null
    Write-Fixture 'Fixture.csproj' @'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework>
    <AssemblyName>EvidenceFixture</AssemblyName><DebugType>portable</DebugType>
    <EmitCompilerGeneratedFiles>true</EmitCompilerGeneratedFiles>
    <CompilerGeneratedFilesOutputPath>$(MSBuildProjectDirectory)\captured</CompilerGeneratedFilesOutputPath>
    <SourceRevisionId>synthetic-revision</SourceRevisionId>
  </PropertyGroup>
  <ItemGroup>
    <EmbeddedResource Include="assets.bin" LogicalName="!AvaloniaResources" />
    <EmbeddedResource Include="values.resources" LogicalName="Fixture.values.resources" />
    <Analyzer Include="$(MSBuildProjectDirectory)\duplicate\AnalyzerAlias.dll" Condition="'$(EnableDuplicateAnalyzer)' == 'true'" />
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
[System.Obsolete("synthetic attribute")] public partial class Widget<T> { public int Value { get; set; } public void Run() { Value++; } public class Nested { } }
public enum Choice { One, Two }
public struct Point { public int X; }
public class Entry { public static void Main() => throw new System.Exception("MUST NEVER EXECUTE"); }
'@
    Write-Fixture 'Partial.cs' 'namespace Fixture; public partial class Widget<T> { public string Name = ""; }'
    Write-Fixture 'Shell.xaml' '<Window xmlns="urn:synthetic" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" x:Class="Fixture.Widget"/>'
    Write-Fixture 'generated/Output.g.cs' 'namespace Fixture; public class GeneratedThing { public string Text => "generated"; }'
    Write-Fixture 'generated/vitnet.generator.json' '{"schema":"vitnet.generator.v1","name":"FixtureEmitter","version":"1.2.3","input_symbols":["Fixture.Widget`1"]}'
    $capturedText = @'
namespace Fixture;
public partial class Widget<T>
{
    public int GeneratedValue() { return 42; }
#line 2 "Declarations.cs"
    public int AnchoredValue() { return 7; }
#line default
}
'@
    Write-Fixture 'captured\System.Text.Json.SourceGeneration\SyntheticEmitter\Widget.g.cs' (
        $capturedText.Replace('"Declarations.cs"', ('"' + (Join-Path $fixture 'Declarations.cs') + '"')))
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
    Assert-Equal $evidence.xaml_documents.Count 1 'Recorded compiler project route XAML document'
    Assert-Equal $evidence.xaml_documents[0].assembly 'EvidenceFixture' 'Recorded compiler assembly remains a syntax-only XAML hint'
    Assert-Equal $evidence.provenance["source.xaml_assembly_basis:$(Join-Path $fixture 'Shell.xaml')"] 'recorded_compiler_project_directory_hint; syntax-only association, not compiled ownership' 'Compiler route association basis'
    Pass 'collector_xaml_recorded_compiler_project_routes_remain_syntax_only_hints'
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
    $suppliedRun = @($evidence.generator_runs | Where-Object name -CEQ 'FixtureEmitter')[0]
    Assert-Equal $suppliedRun.status 'output_captured' 'Supplied emitter capture status'
    Assert-Equal $suppliedRun.execution_status 'not_observed' 'Supplied mapping is not execution'
    $suppliedLink = @($evidence.generator_links | Where-Object rule -eq 'manifest_input_symbol')[0]
    Assert-Equal $suppliedLink.trigger_symbol 'Fixture.Widget`1' 'Exact supplied trigger'
    Assert-Equal $suppliedLink.evidence_tier 'supplied' 'Supplied is not independently observed'
    Assert-True (-not $suppliedLink.ContainsKey('trigger_source')) 'Unresolved input symbol must not invent a source'
    $capturedRun = @($evidence.generator_runs | Where-Object name -CEQ 'SyntheticEmitter')[0]
    Assert-Equal $capturedRun.basis 'conventional_output_directory' 'Directory emitter candidate basis'
    Assert-Equal $capturedRun.status 'output_captured' 'Conventional capture status'
    Assert-Equal $capturedRun.execution_status 'not_observed' 'Stale directory must not establish execution'
    Assert-Equal $capturedRun.project_path $project 'Exact compiler project route'
    Assert-Equal $capturedRun.target_assembly 'EvidenceFixture' 'Exact compiler assembly'
    Assert-Equal $capturedRun.configuration 'Debug' 'Exact recorded configuration'
    Assert-Equal $capturedRun.target_framework 'net10.0' 'Exact recorded framework'
    Assert-True ($capturedRun.version.Length -gt 0) 'Uniquely referenced analyzer metadata version unavailable'
    Assert-Equal $capturedRun.outputs[0].path $conventionalFile 'Actual captured file path'
    Assert-Equal $capturedRun.outputs[0].sha256 (Get-FileHash $conventionalFile -Algorithm SHA256).Hash.ToLowerInvariant() 'Actual output digest'
    Assert-Equal $capturedRun.outputs[0].build_match 'matched' 'Matching PE/PDB output checksum'
    Assert-True (@($capturedRun.outputs[0].pdb_checksums | Where-Object { $_.status -eq 'matched' -and $_.assembly_match -eq 'pe_identity_verified' }).Count -gt 0) 'No verified checksum details'
    Assert-True (@($evidence.generator_runs | Where-Object status -eq 'analyzer_referenced').Count -gt 0) 'Analyzer inputs not distinguished'
    Assert-Equal @($evidence.generator_runs | Where-Object execution_status -ne 'not_observed').Count 0 'Fabricated generator execution'
    $partialLinks = @($evidence.generator_links | Where-Object rule -eq 'attributed_partial_declaration')
    Assert-True ($partialLinks.Count -gt 0) 'Attributed partial declaration candidate missing'
    Assert-Equal $partialLinks[0].evidence_tier 'candidate' 'Attribute syntax must remain candidate'
    Assert-Equal $partialLinks[0].trigger_source $source 'Candidate physical input'
    Assert-Equal $partialLinks[0].trigger_type 'Fixture.Widget`1' 'Candidate textual type'
    Assert-True (@($evidence.generator_links | Where-Object { $_.rule -eq 'line_directive' -and $_.evidence_tier -eq 'candidate' -and $_.trigger_source -eq $source }).Count -gt 0) '#line candidate missing'
    Pass 'collector_generated_capture_separates_supplied_candidates_checksums_and_execution'
    Collect @('--output', $output, '--generated-root', $conventionalRoot) | Out-Null
    $unrouted = Get-Content $output -Raw | ConvertFrom-Json -AsHashtable
    Assert-Equal $unrouted.generator_runs.Count 1 'Conventional output without binlog still captured'
    Assert-True (-not $unrouted.generator_runs[0].ContainsKey('version')) 'Version invented without analyzer inputs'
    Assert-True (-not $unrouted.generator_runs[0].ContainsKey('project_path')) 'Project invented without recorded route'
    Assert-Equal $unrouted.generator_runs[0].outputs[0].build_match 'unknown' 'Directory alone must not match a build'
    Assert-Equal $unrouted.generator_links.Count 0 'Unavailable triggers must not fabricate attribution'
    Pass 'collector_conventional_capture_preserves_unknown_version_build_and_trigger_inputs'
    $noOutput = Join-Path $fixture 'no-output'
    [IO.Directory]::CreateDirectory($noOutput) | Out-Null
    Write-Fixture 'no-output\vitnet.generator.json' '{"schema":"vitnet.generator.v1","name":"NoOutputEmitter","input_symbols":["Fixture.Unknown"]}'
    Collect @('--output', $output, '--generated-root', $noOutput) | Out-Null
    $absent = Get-Content $output -Raw | ConvertFrom-Json -AsHashtable
    Assert-Equal $absent.generator_runs[0].status 'output_unavailable' 'Missing output not reported captured'
    Assert-True (-not $absent.generator_runs[0].ContainsKey('version')) 'Missing supplied version not explicit'
    Assert-Equal $absent.generator_runs[0].outputs.Count 0 'Missing output fabricated'
    Assert-Equal $absent.generator_links.Count 0 'No output-to-input link without output'
    Assert-Equal $absent.generators[0].version '' 'Legacy field shape retained for unknown version'
    Pass 'collector_missing_manifest_version_and_output_are_explicit_unknowns'
    [IO.File]::AppendAllText($conventionalFile, "`n// changed after compiler snapshot", $utf8)
    Collect (@('--output', $output) + $argsAll) | Out-Null
    $generatedDrift = Get-Content $output -Raw | ConvertFrom-Json -AsHashtable
    $driftRun = @($generatedDrift.generator_runs | Where-Object name -CEQ 'SyntheticEmitter')[0]
    Assert-Equal $driftRun.outputs[0].build_match 'drift' 'Changed output must not match portable PDB'
    Assert-Equal $driftRun.outputs[0].sha256 (Get-FileHash $conventionalFile -Algorithm SHA256).Hash.ToLowerInvariant() 'Drift retains current output bytes'
    Assert-Equal $driftRun.execution_status 'not_observed' 'Drift must not fabricate execution'
    Pass 'collector_generated_output_checksum_drift_remains_snapshot_evidence'
    [IO.File]::WriteAllText($conventionalFile, ([IO.File]::ReadAllText($conventionalFile) -replace "`n// changed after compiler snapshot$", ''), $utf8)
    [IO.Directory]::CreateDirectory((Join-Path $fixture 'duplicate')) | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $fixture 'duplicate\AnalyzerAlias.dll'), [IO.File]::ReadAllBytes($capturedRun.assembly_path))
    Write-Fixture 'two-builds.proj' @'
<Project>
  <Target Name="Build">
    <MSBuild Projects="Fixture.csproj" Targets="Rebuild" Properties="Configuration=Debug" />
    <MSBuild Projects="Fixture.csproj" Targets="Rebuild" Properties="Configuration=Release;EnableDuplicateAnalyzer=true" />
  </Target>
</Project>
'@
    Invoke-Build @('msbuild', (Join-Path $fixture 'two-builds.proj'), '-nologo', '-verbosity:quiet', "-bl:$fixture\two-builds.binlog;ProjectImports=None")
    Collect @('--output', $output, '--binlog', (Join-Path $fixture 'two-builds.binlog'),
        '--generated-root', $conventionalRoot, '--assembly', $assembly,
        '--assembly', (Join-Path $fixture 'bin\Release\net10.0\EvidenceFixture.dll')) | Out-Null
    $ambiguous = Get-Content $output -Raw | ConvertFrom-Json -AsHashtable
    $ambiguousRun = @($ambiguous.generator_runs | Where-Object name -CEQ 'SyntheticEmitter')[0]
    Assert-True (-not $ambiguousRun.ContainsKey('assembly_path')) 'Ambiguous analyzer path must remain unknown'
    Assert-True (-not $ambiguousRun.ContainsKey('version')) 'Ambiguous analyzer version must remain unknown'
    Assert-True (-not $ambiguousRun.ContainsKey('configuration')) 'Multiple build configurations must remain unknown'
    Assert-Equal $ambiguousRun.outputs[0].build_match 'ambiguous' 'Multiple PE/PDB builds must not choose one'
    Assert-Equal @($ambiguous.diagnostics | Where-Object code -eq 'generated.analyzer_ambiguous').Count 1 'Analyzer ambiguity diagnosis'
    Assert-Equal @($ambiguous.diagnostics | Where-Object code -eq 'generated.project_ambiguous').Count 1 'Project route ambiguity diagnosis'
    Assert-Equal $ambiguousRun.execution_status 'not_observed' 'Ambiguous routes still not execution'
    Pass 'collector_generated_analyzer_and_build_route_ambiguity_is_not_guessed'
    Build-Fixture
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
