namespace Vitnet.Evidence;

public sealed class Evidence
{
    public string Schema { get; } = "vitnet.evidence.v1";
    public string Label { get; set; } = "";
    public SortedDictionary<string, string> Provenance { get; } = new(StringComparer.Ordinal);
    public List<Artifact> Artifacts { get; } = [];
    public List<Package> Packages { get; } = [];
    public List<Assembly> Assemblies { get; } = [];
    public List<Source> Sources { get; } = [];
    public List<XamlDocument> XamlDocuments { get; } = [];
    public List<Generator> Generators { get; } = [];
    public List<GeneratorRun> GeneratorRuns { get; } = [];
    public List<GeneratorLink> GeneratorLinks { get; } = [];
    public List<Resource> Resources { get; } = [];
    public List<Binary> Binaries { get; } = [];
    public List<Mapping> Mappings { get; } = [];
    public List<EvidenceDiagnostic> Diagnostics { get; } = [];
}

public sealed record Artifact(string Kind, string Path, string? Revision = null);
public sealed record Package(string Target, string Id, string Version, bool Direct, List<string> Dependencies);
public sealed record Assembly(string Name, string Path, string? Package, List<ManagedType> Types);
public sealed record ManagedType(string Name, string Kind, ulong Members);
public sealed record Source(
    string Assembly, string TypeName, string? Member, string Path, ulong Line, ulong EndLine,
    string Kind, List<string> Attributes, string? GeneratedBy = null, string? Sha256 = null,
    List<SourceAnnotation>? Annotations = null);
public sealed record SourceAnnotation(string Target, List<string> Attributes);
public sealed record XamlDocument(
    string Path, string Assembly, string? DeclaredClass, string RootElement, string Sha256,
    List<string> Includes, List<string> Keys);
public sealed record Generator(
    string Name, string Version, string AssemblyPath, List<string> GeneratedFiles, List<string> InputSymbols);
public sealed record GeneratorRun(
    string Name, string? Version, string? AssemblyPath, string? ProjectPath,
    string? TargetAssembly, string? TargetAssemblyPath, string? Configuration, string? TargetFramework,
    string Status, string Basis, List<GeneratorOutput> Outputs, string ExecutionStatus = "not_observed");
public sealed record GeneratorOutput(
    string Path, string? Sha256, string BuildMatch, List<GeneratorChecksum> PdbChecksums);
public sealed record GeneratorChecksum(
    string PdbPath, string Algorithm, string Checksum, string Status, string AssemblyMatch,
    string? TargetAssembly = null, string? TargetAssemblyPath = null);
public sealed record GeneratorLink(
    string Generator, string OutputPath, string? TriggerSource, string? TriggerType,
    string? TriggerMember, string? TriggerSymbol, string Rule, string EvidenceTier, string Basis);
public sealed record Resource(
    string Assembly, string Container, string Name, ulong Bytes, string? Sha256, string? SourcePath, string Storage);
public sealed record Binary(string Path, string Format, string Architecture, ulong FileBytes, List<BinarySection> Sections);
public sealed record BinarySection(string Name, ulong FileBytes, ulong VirtualBytes);
public sealed record Mapping(string Stream, string Identity, string Assembly, List<string> SourcePaths, string Basis);
public sealed record EvidenceDiagnostic(string Code, string Message, string? Path = null);

internal sealed class CollectionException(string code, string message, string? path = null) : Exception(message)
{
    public string Code { get; } = code;
    public string? InputPath { get; } = path;
}
