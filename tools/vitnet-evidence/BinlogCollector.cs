using System.Collections;
using System.IO.Compression;
using Microsoft.Build.Framework;
using Microsoft.Build.Logging.StructuredLogger;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace Vitnet.Evidence;

internal static class BinlogCollector
{
    private static readonly uint[] CrcTable = Enumerable.Range(0, 256).Select(value =>
    {
        var crc = (uint)value;
        for (var bit = 0; bit < 8; bit++) crc = (crc >> 1) ^ ((crc & 1) == 0 ? 0U : 0xedb88320U);
        return crc;
    }).ToArray();
    private sealed class ProjectRoute
    {
        public string Path { get; set; } = "";
        public string Assembly { get; set; } = "";
    }

    private sealed class CompilerRoute
    {
        public required ProjectRoute Project { get; init; }
        public string? CommandLine { get; set; }
        public string? OutputAssembly { get; set; }
        public CSharpParseOptions? ParseOptions { get; set; }
        public HashSet<string> Sources { get; } = new(CollectionContext.PathComparer);
        public HashSet<string> References { get; } = new(CollectionContext.PathComparer);
        public HashSet<string> Analyzers { get; } = new(CollectionContext.PathComparer);
    }

    private static readonly HashSet<string> FactProperties = new(StringComparer.Ordinal)
    {
        "SourceRevisionId", "RepositoryCommit", "GitCommit", "Revision", "NETCoreSdkVersion",
        "NETCoreSdkRuntimeIdentifier", "MSBuildVersion", "MSBuildToolsVersion", "MSBuildSDKsPath",
        "MSBuildToolsPath", "TargetFramework", "RuntimeIdentifier", "Configuration", "Platform",
        "LangVersion", "DefineConstants", "CscToolPath", "CscToolExe", "CompilerVersion",
        "EmitCompilerGeneratedFiles", "CompilerGeneratedFilesOutputPath", "PublishAot",
        "OptimizationPreference", "IlcOptimizationPreference", "IlcInstructionSet"
    };

    public static void Collect(CollectionContext context, string path)
    {
        context.Artifact("binlog", path);
        if (!context.Available(path)) return;
        using var input = context.Open(path);
        using var gzip = new GZipStream(input, CompressionMode.Decompress, leaveOpen: true);
        using var expanded = new MemoryStream();
        var buffer = new byte[64 * 1024];
        int read;
        while ((read = gzip.Read(buffer)) != 0)
        {
            if (read > context.Options.MaxExpandedBytes - expanded.Length)
                throw new CollectionException("resource.collector.binlog_expanded", "Decompressed binlog byte budget exceeded.", path);
            expanded.Write(buffer, 0, read);
        }
        if (expanded.Length < 5)
            throw new CollectionException("binlog.malformed", "Truncated binlog header.", path);
        input.Position = input.Length - 8;
        Span<byte> trailer = stackalloc byte[8];
        input.ReadExactly(trailer);
        var crc = uint.MaxValue;
        foreach (var value in expanded.GetBuffer().AsSpan(0, checked((int)expanded.Length)))
            crc = (crc >> 8) ^ CrcTable[(crc ^ value) & 255];
        if (System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(trailer) != ~crc ||
            System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(trailer[4..]) != (uint)expanded.Length)
            throw new CollectionException("binlog.gzip_truncated", "Missing/invalid single-member gzip CRC or length trailer.", path);
        expanded.Position = 0;
        var projects = new Dictionary<(int Node, int Project), ProjectRoute>();
        var compilers = new Dictionary<(int Node, int Project, int Task), CompilerRoute>();
        var reader = new BinLogReader();
        reader.OnFileFormatVersionRead += version => context.Fact($"binlog.format:{path}", version.ToString(System.Globalization.CultureInfo.InvariantCulture));
        reader.RecoverableReadError += error => throw new CollectionException("binlog.unsupported", $"Binlog reader encountered unsupported/corrupt records: {error.ErrorType}.", path);
        var eof = false;
        long propertySequence = 0;
        foreach (var record in reader.ReadRecordsFromDecompressedStream(expanded, includeAuxiliaryRecords: true))
        {
            context.Count();
            if (record.Kind == BinaryLogRecordKind.EndOfFile)
            {
                if (record.Length == 0)
                    throw new CollectionException("binlog.truncated", "Binlog ended without a final EndOfFile record.", path);
                eof = true;
            }
            var args = record.Args;
            if (args is null) continue;
            var eventContext = args.BuildEventContext;
            var projectKey = (eventContext?.NodeId ?? -1, eventContext?.ProjectContextId ?? -1);
            var taskKey = (projectKey.Item1, projectKey.Item2, eventContext?.TaskId ?? -1);
            if (args is TaskParameterEventArgs roots && roots.ItemType == "SourceRoot")
            {
                foreach (var item in roots.Items ?? Array.Empty<object>())
                {
                    context.Count();
                    if (item is ITaskItem sourceRoot && sourceRoot.GetMetadata("RevisionId") is { Length: > 0 } revision)
                        context.Fact($"binlog.source_revision:{path}:{sourceRoot.ItemSpec}", revision);
                }
            }
            switch (args)
            {
                case PropertyInitialValueSetEventArgs initial:
                    Property(context, new() { Path = initial.ProjectFile ?? "" }, initial.PropertyName,
                        initial.PropertyValue, $"initial:{propertySequence++}");
                    break;
                case PropertyReassignmentEventArgs reassigned:
                    Property(context, new() { Path = reassigned.ProjectFile ?? "" }, reassigned.PropertyName,
                        reassigned.NewValue, $"reassignment:{propertySequence++}");
                    break;
                case ProjectStartedEventArgs started:
                    if (string.IsNullOrWhiteSpace(started.ProjectFile))
                        throw new CollectionException("binlog.project", "Project-start record lacks a project path.", path);
                    var project = new ProjectRoute { Path = Resolve(started.ProjectFile, Path.GetDirectoryName(path)!) };
                    projects[projectKey] = project;
                    Properties(context, project, started.Properties, $"start:{projectKey}");
                    context.Artifact("source", project.Path);
                    context.Available(project.Path);
                    break;
                case ProjectEvaluationFinishedEventArgs evaluated:
                    if (string.IsNullOrWhiteSpace(evaluated.ProjectFile)) break;
                    var evaluation = new ProjectRoute { Path = Resolve(evaluated.ProjectFile, Path.GetDirectoryName(path)!) };
                    Properties(context, evaluation, evaluated.Properties, $"evaluation:{eventContext?.EvaluationId}");
                    Properties(context, evaluation, evaluated.GlobalProperties, $"evaluation_global:{eventContext?.EvaluationId}");
                    break;
                case TaskStartedEventArgs started when started.TaskName == "Csc":
                    if (!projects.TryGetValue(projectKey, out var owner))
                    {
                        owner = new();
                        context.Diagnostic("binlog.project_unknown", "Csc task lacks a recorded project route.", path);
                    }
                    compilers[taskKey] = new() { Project = owner };
                    context.Fact($"binlog.csc_tool:{path}:{taskKey}", started.TaskFile ?? "");
                    break;
                case TaskCommandLineEventArgs command when compilers.TryGetValue(taskKey, out var compiler):
                    compiler.CommandLine = command.CommandLine;
                    break;
                case TaskParameterEventArgs parameter when compilers.TryGetValue(taskKey, out var compiler):
                    foreach (var item in parameter.Items ?? Array.Empty<object>())
                    {
                        context.Count();
                        var value = item is ITaskItem taskItem ? taskItem.ItemSpec : item?.ToString();
                        if (string.IsNullOrEmpty(value)) continue;
                        var directory = compiler.Project.Path.Length == 0 ? Path.GetDirectoryName(path)! : Path.GetDirectoryName(compiler.Project.Path)!;
                        switch (parameter.ItemType)
                        {
                            case "Sources": compiler.Sources.Add(Resolve(value, directory)); break;
                            case "References": compiler.References.Add(Resolve(value, directory)); break;
                            case "Analyzers": compiler.Analyzers.Add(Resolve(value, directory)); break;
                            case "OutputAssembly": compiler.OutputAssembly = Resolve(value, directory); break;
                        }
                    }
                    break;
            }
        }
        if (!eof)
            throw new CollectionException("binlog.truncated", "Binlog has no final EndOfFile marker.", path);
        if (expanded.Position != expanded.Length)
            throw new CollectionException("binlog.trailing", "Binlog has trailing unparsed bytes.", path);
        foreach (var (key, compiler) in compilers.OrderBy(p => p.Key))
        {
            ParseCommandLine(context, compiler, path);
            var assembly = compiler.OutputAssembly is not null ? Path.GetFileNameWithoutExtension(compiler.OutputAssembly) : compiler.Project.Assembly;
            if (assembly.Length == 0)
                context.Diagnostic("binlog.assembly_unknown", "Compiler output assembly name was not recorded.", path);
            context.Fact($"binlog.csc_route:{path}:{key}", $"project={compiler.Project.Path};assembly={assembly};sources={compiler.Sources.Count};references={compiler.References.Count};analyzers={compiler.Analyzers.Count}");
            if (compiler.OutputAssembly is not null) context.Artifact("assembly", compiler.OutputAssembly);
            foreach (var source in compiler.Sources.Order(StringComparer.Ordinal))
            {
                context.Artifact("source", source);
                context.AddAssemblyHint(source, assembly);
                if (compiler.ParseOptions is not null) context.SourceParseOptions[source] = compiler.ParseOptions;
                if (!context.Available(source)) continue;
                context.Count();
                context.Evidence.Mappings.Add(new("source", source, assembly, [source], "binlog_csc_input"));
                SourceCollector.Read(context, source, assembly, null, compiler.ParseOptions);
            }
            foreach (var reference in compiler.References.Order(StringComparer.Ordinal))
            {
                var identity = PeCollector.Reference(context, reference);
                if (identity is null) continue;
                context.Count();
                context.Evidence.Mappings.Add(new("assembly", reference, identity.Value.Name, [], "binlog_csc_reference"));
            }
            foreach (var analyzer in compiler.Analyzers.Order(StringComparer.Ordinal))
            {
                var identity = PeCollector.Reference(context, analyzer);
                if (identity is null) continue;
                context.AnalyzerVersions[analyzer] = identity.Value.Version;
                context.Count();
                context.Evidence.Mappings.Add(new("analyzer", analyzer, identity.Value.Name, [], "binlog_csc_analyzer_input"));
            }
            context.Diagnostic("binlog.analyzer_execution_unknown", "Analyzer inputs are recorded; listing a DLL does not prove which generator ran or what annotation caused output.", path);
        }
        if (compilers.Count == 0)
            context.Diagnostic("binlog.csc_unavailable", "No Csc task is recorded (possibly an incremental or non-C# build).", path);
        if (!context.Evidence.Provenance.Keys.Any(k => k.StartsWith("binlog.source_revision:", StringComparison.Ordinal) ||
            k.StartsWith("binlog.property:", StringComparison.Ordinal) && FactProperties.Where(p => p.Contains("Revision", StringComparison.Ordinal) || p.Contains("Commit", StringComparison.Ordinal)).Any(p => k.EndsWith(":" + p, StringComparison.Ordinal))))
            context.Diagnostic("binlog.revision_unknown", "No revision property was recorded in project-start/evaluation properties.", path);
    }

    private static void Properties(CollectionContext context, ProjectRoute project, IEnumerable? properties, string scope)
    {
        if (properties is null) return;
        foreach (var property in properties)
        {
            context.Count();
            if (property is DictionaryEntry entry)
                Property(context, project, entry.Key.ToString() ?? "", entry.Value?.ToString() ?? "", scope);
            else if (property is KeyValuePair<string, string> pair)
                Property(context, project, pair.Key, pair.Value, scope);
        }
    }

    private static void Property(CollectionContext context, ProjectRoute project, string key, string value, string scope)
    {
        if (key == "AssemblyName") project.Assembly = value;
        if (FactProperties.Contains(key))
            context.Fact($"binlog.property:{project.Path}:{scope}:{key}", value);
    }

    private static void ParseCommandLine(CollectionContext context, CompilerRoute compiler, string path)
    {
        if (string.IsNullOrEmpty(compiler.CommandLine)) return;
        var directory = compiler.Project.Path.Length == 0 ? Path.GetDirectoryName(path)! : Path.GetDirectoryName(compiler.Project.Path)!;
        var tokens = CommandLineParser.SplitCommandLineIntoArguments(compiler.CommandLine, removeHashComments: false).ToList();
        context.Count(tokens.Count);
        var compilerIndex = tokens.FindIndex(t => Path.GetFileName(t) is "csc.dll" or "csc.exe" or "csc");
        if (compilerIndex >= 0) tokens = tokens.Skip(compilerIndex + 1).ToList();
        if (tokens.Any(t => t.StartsWith('@')))
        {
            context.Diagnostic("binlog.response_file_unavailable", "Response-file arguments are not opened or executed; only explicit recorded task parameters establish routes.", path);
            return;
        }
        var parsed = CSharpCommandLineParser.Default.Parse(tokens, directory, sdkDirectory: null, additionalReferenceDirectories: null);
        compiler.ParseOptions = parsed.ParseOptions;
        foreach (var source in parsed.SourceFiles) compiler.Sources.Add(Resolve(source.Path, directory));
        foreach (var reference in parsed.MetadataReferences) compiler.References.Add(Resolve(reference.Reference, directory));
        foreach (var analyzer in parsed.AnalyzerReferences) compiler.Analyzers.Add(Resolve(analyzer.FilePath, directory));
        if (parsed.OutputFileName is not null)
            compiler.OutputAssembly ??= Path.GetFullPath(Path.Combine(parsed.OutputDirectory ?? directory, parsed.OutputFileName));
        context.Fact($"binlog.csc_language:{compiler.Project.Path}", parsed.ParseOptions.LanguageVersion.ToString());
        context.Fact($"binlog.csc_defines:{compiler.Project.Path}", string.Join(";", parsed.ParseOptions.PreprocessorSymbolNames));
        if (parsed.Errors.Any(d => d.Severity == DiagnosticSeverity.Error))
            context.Diagnostic("binlog.command_line_incomplete", "Roslyn could not fully interpret the recorded command; task parameters remain the primary route evidence.", path);
    }

    private static string Resolve(string path, string directory) => Path.GetFullPath(path, directory);
}
