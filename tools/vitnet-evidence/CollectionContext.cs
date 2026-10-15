using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.CodeAnalysis.CSharp;

namespace Vitnet.Evidence;

internal sealed class CollectionContext(Options options)
{
    private readonly Dictionary<string, long> files = new(PathComparer);
    private readonly HashSet<string> artifacts = new(StringComparer.Ordinal);
    private long bytes;
    private long records;
    public static StringComparer PathComparer => OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
    public Options Options { get; } = options;
    public Evidence Evidence { get; } = new() { Label = options.Label };
    public Dictionary<string, HashSet<string>> SourceAssemblies { get; } = new(PathComparer);
    public Dictionary<string, string> AnalyzerVersions { get; } = new(PathComparer);
    public Dictionary<string, string> AnalyzerNames { get; } = new(PathComparer);
    public Dictionary<string, HashSet<string>> AssemblyPackages { get; } = new(PathComparer);
    public Dictionary<string, CSharpParseOptions> SourceParseOptions { get; } = new(PathComparer);
    public HashSet<string> SourceScans { get; } = new(StringComparer.Ordinal);
    public HashSet<string> PdbScans { get; } = new(PathComparer);
    public HashSet<string> GeneratedRoots { get; } = new(PathComparer);
    public Dictionary<string, List<GeneratorChecksum>> DocumentChecksums { get; } = new(PathComparer);
    public List<GeneratorCompilerRoute> GeneratorRoutes { get; } = [];

    public void Count(long count = 1)
    {
        if (count < 0 || count > Options.MaxRecords - records)
            throw new CollectionException("resource.collector.records", $"Record budget exceeded ({Options.MaxRecords}).");
        records += count;
    }

    public void Diagnostic(string code, string message, string? path = null)
    {
        Count();
        Evidence.Diagnostics.Add(new(code, message, path));
    }

    public void Fact(string key, string value)
    {
        if (!Evidence.Provenance.ContainsKey(key)) Count();
        Evidence.Provenance[key] = value;
    }

    public void Artifact(string kind, string path, string? revision = null)
    {
        path = Path.GetFullPath(path);
        if (!artifacts.Add(kind + "\0" + path)) return;
        Count();
        Evidence.Artifacts.Add(new(kind, path, revision ?? (kind is "source" or "generated" ? null : Options.Revision)));
    }

    public bool Available(string path)
    {
        path = Path.GetFullPath(path);
        if (PathComparer.Equals(path, Options.Output))
            throw new CollectionException("collector.output_alias", "Output must not overwrite an input.", path);
        if (files.ContainsKey(path)) return true;
        if (!File.Exists(path))
        {
            Diagnostic("collector.unavailable", "Input file is unavailable; no evidence was inferred.", path);
            return false;
        }
        var info = new FileInfo(path);
        RejectLink(info);
        var length = info.Length;
        if (length > Options.MaxFileBytes || length > Options.MaxTotalBytes - bytes || files.Count >= Options.MaxFiles)
            throw new CollectionException("resource.collector.files", "File size, total bytes, or file count budget exceeded.", path);
        files.Add(path, length);
        bytes += length;
        return true;
    }

    public FileStream Open(string path)
    {
        if (!Available(path))
            throw new CollectionException("collector.unavailable", "Input disappeared during collection.", path);
        var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length != files[path])
        {
            stream.Dispose();
            throw new CollectionException("collector.input_changed", "Input size changed during collection.", path);
        }
        return stream;
    }

    public byte[] ReadBytes(string path)
    {
        using var stream = Open(path);
        var data = new byte[checked((int)stream.Length)];
        stream.ReadExactly(data);
        return data;
    }

    public string Hash(string path) => Convert.ToHexStringLower(SHA256.HashData(ReadBytes(path)));
    public static string Hash(ReadOnlySpan<byte> data) => Convert.ToHexStringLower(SHA256.HashData(data));

    public JsonDocument ReadJson(string path)
    {
        using var stream = Open(path);
        return JsonDocument.Parse(stream, new() { MaxDepth = 64 });
    }

    public IEnumerable<string> Walk(string root, Func<string, bool> include)
    {
        if (!Directory.Exists(root))
        {
            Diagnostic("collector.unavailable", "Input directory is unavailable.", root);
            yield break;
        }
        var pending = new Stack<string>();
        pending.Push(root);
        long entries = 0;
        while (pending.TryPop(out var directory))
        {
            RejectLink(new DirectoryInfo(directory));
            foreach (var entry in Directory.EnumerateFileSystemEntries(directory).Order(PathComparer))
            {
                if (++entries > Options.MaxFiles)
                    throw new CollectionException("resource.collector.directory", "Directory entry budget exceeded.", root);
                var attrs = File.GetAttributes(entry);
                if ((attrs & FileAttributes.ReparsePoint) != 0)
                {
                    Diagnostic("collector.link_skipped", "Symbolic links/reparse points are not followed.", entry);
                    continue;
                }
                if ((attrs & FileAttributes.Directory) != 0)
                {
                    var name = Path.GetFileName(entry);
                    if (name is not (".git" or ".svn" or "bin" or "obj" or "node_modules" or ".smoke"))
                        pending.Push(entry);
                }
                else if (include(entry)) yield return entry;
            }
        }
    }

    private static void RejectLink(FileSystemInfo file)
    {
        if ((file.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new CollectionException("collector.link", "Explicit symbolic-link/reparse-point inputs are not followed.", file.FullName);
    }

    public void AddAssemblyHint(string source, string assembly)
    {
        source = Path.GetFullPath(source);
        if (!SourceAssemblies.TryGetValue(source, out var hints)) SourceAssemblies[source] = hints = new(StringComparer.Ordinal);
        hints.Add(assembly);
    }

    public string AssemblyHint(string source, string fallback)
    {
        if (!SourceAssemblies.TryGetValue(source, out var hints)) return fallback;
        if (hints.Count == 1) return hints.Single();
        Diagnostic("source.assembly_ambiguous", "Multiple compiler routes name this source; assembly is unknown.", source);
        return "";
    }

    public void Resource(string assembly, string container, string name, ReadOnlySpan<byte> data, string path, string storage)
    {
        if (data.Length > Options.MaxResourceBytes)
            throw new CollectionException("resource.collector.resource_bytes", "Resource byte budget exceeded.", path);
        Count();
        Evidence.Resources.Add(new(assembly, container, name, (ulong)data.Length, Hash(data), path, storage));
    }
}

internal sealed record GeneratorCompilerRoute(
    string? ProjectPath, string? TargetAssembly, string? TargetAssemblyPath, string? Configuration,
    string? TargetFramework, string? GeneratedDirectory, HashSet<string> Sources, HashSet<string> Analyzers);
