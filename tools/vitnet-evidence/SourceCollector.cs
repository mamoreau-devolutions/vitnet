using System.Text;
using System.Xml;
using System.Xml.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Vitnet.Evidence;

internal static class SourceCollector
{
    public static void Collect(CollectionContext context, string root)
    {
        SourceRevision.Collect(context, root);
        var paths = context.Walk(root, p => p.EndsWith(".cs", StringComparison.OrdinalIgnoreCase) || p.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase)).ToList();
        var projects = new List<(string Directory, string Assembly)>();
        foreach (var path in paths.Where(p => p.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase)))
        {
            context.Artifact("source", path);
            if (!context.Available(path)) continue;
            using var stream = context.Open(path);
            using var reader = XmlReader.Create(stream, new() { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = context.Options.MaxFileBytes });
            var project = XDocument.Load(reader);
            var names = project.Descendants().Where(e => e.Name.LocalName == "AssemblyName").Select(e => e.Value).Distinct(StringComparer.Ordinal).ToArray();
            var name = names.Length == 1 && !names[0].Contains("$(", StringComparison.Ordinal) ? names[0] : Path.GetFileNameWithoutExtension(path);
            projects.Add((Path.GetDirectoryName(path)!, name));
            context.Fact($"source.project_assembly_hint:{path}", name);
            context.Diagnostic("source.project_hint", "AssemblyName is a textual project hint; conditions, imports and Compile items are not evaluated.", path);
        }
        foreach (var path in paths.Where(p => p.EndsWith(".cs", StringComparison.OrdinalIgnoreCase)))
        {
            var owners = projects.Where(p => Inside(path, p.Directory)).OrderByDescending(p => p.Directory.Length).ToArray();
            var nearest = owners.Length == 0 ? [] : owners.Where(p => p.Directory.Length == owners[0].Directory.Length).Select(p => p.Assembly).Distinct(StringComparer.Ordinal).ToArray();
            var fallback = nearest.Length == 1 ? nearest[0] : "";
            if (nearest.Length > 1) context.Diagnostic("source.project_ambiguous", "Multiple projects share this directory; no textual assembly hint is assigned.", path);
            Read(context, path, context.AssemblyHint(path, fallback), null);
        }
        if (!paths.Any(p => p.EndsWith(".cs", StringComparison.OrdinalIgnoreCase)))
            context.Diagnostic("source.declarations_unavailable", "No C# source files were found.", root);
        context.Fact("source.declaration_basis", "Roslyn syntax only; attributes are textual, partial declarations are separate occurrences, symbols and project conditions are not evaluated");
    }

    internal static bool Inside(string path, string directory) =>
        path.StartsWith(Path.TrimEndingDirectorySeparator(directory) + Path.DirectorySeparatorChar,
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

    public static void CollectGenerated(CollectionContext context, string root)
    {
        var paths = context.Walk(root, p => p.EndsWith(".cs", StringComparison.OrdinalIgnoreCase) || Path.GetFileName(p) == "vitnet.generator.json").ToList();
        var manifests = new List<(string Directory, Generator Generator)>();
        foreach (var path in paths.Where(p => Path.GetFileName(p) == "vitnet.generator.json"))
        {
            context.Artifact("generated", path);
            if (!context.Available(path)) continue;
            using var json = context.ReadJson(path);
            var value = json.RootElement;
            if (value.GetProperty("schema").GetString() != "vitnet.generator.v1")
                throw new CollectionException("generated.provenance", "Unknown generator provenance schema.", path);
            var name = value.GetProperty("name").GetString();
            var version = value.GetProperty("version").GetString();
            if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(version))
                throw new CollectionException("generated.provenance", "Generator name and version are required.", path);
            var directory = Path.GetDirectoryName(path)!;
            var rawAssembly = value.TryGetProperty("assembly_path", out var asm) ? asm.GetString() : null;
            var assemblyPath = string.IsNullOrEmpty(rawAssembly) ? "" : Path.GetFullPath(rawAssembly, directory);
            var symbols = value.TryGetProperty("input_symbols", out var inputs)
                ? inputs.EnumerateArray().Select(i => i.GetString() ?? throw new CollectionException("generated.provenance", "input_symbols must contain strings.", path)).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList() : [];
            context.Count(symbols.Count + 1);
            var generator = new Generator(name, version, assemblyPath, [], symbols);
            context.Evidence.Generators.Add(generator);
            manifests.Add((directory, generator));
            context.Fact($"generated.provenance:{path}", "user-supplied emitter/input-symbol mapping; not independently verified by this collector");
            if (assemblyPath.Length != 0) { context.Artifact("assembly", assemblyPath); context.Available(assemblyPath); }
            if (!value.TryGetProperty("input_symbols", out _))
                context.Diagnostic("generated.input_symbols_unknown", "Generator inputs were not supplied; no annotation-to-emitter association is inferred.", path);
        }
        var inferred = new Dictionary<string, Generator>(StringComparer.Ordinal);
        foreach (var path in paths.Where(p => p.EndsWith(".cs", StringComparison.OrdinalIgnoreCase)))
        {
            var matches = manifests.Where(m => Inside(path, m.Directory)).OrderByDescending(m => m.Directory.Length).ToArray();
            Generator? generator = matches.Length != 0 ? matches[0].Generator : null;
            if (generator is null)
            {
                var relative = Path.GetRelativePath(root, path).Split(Path.DirectorySeparatorChar);
                if (relative.Length >= 3)
                {
                    var emitterAssembly = relative[0];
                    var emitter = relative[1];
                    var identity = emitterAssembly + "/" + emitter;
                    if (!inferred.TryGetValue(identity, out generator))
                    {
                        var analyzers = context.AnalyzerVersions.Keys.Where(p => Path.GetFileNameWithoutExtension(p) == emitterAssembly).ToArray();
                        var assemblyPath = analyzers.Length == 1 ? analyzers[0] : "";
                        var version = assemblyPath.Length != 0 ? context.AnalyzerVersions[assemblyPath] : "";
                        context.Count();
                        generator = new(emitter, version, assemblyPath, [], []);
                        inferred.Add(identity, generator);
                        context.Evidence.Generators.Add(generator);
                        context.Diagnostic("generated.emitter_candidate", $"Emitter {identity} is inferred only from the compiler output directory convention; input_symbols are unknown.", path);
                        if (version.Length == 0) context.Diagnostic("generated.version_unknown", "No unique analyzer metadata route establishes the emitter assembly version.", path);
                    }
                }
                else context.Diagnostic("generated.emitter_unknown", "No provenance manifest or conventional emitter directory is present.", path);
            }
            context.Count();
            generator?.GeneratedFiles.Add(path);
            context.Artifact("generated", path);
            Read(context, path, context.AssemblyHint(path, ""), generator?.Name);
        }
        foreach (var generator in context.Evidence.Generators)
            generator.GeneratedFiles.Sort(StringComparer.Ordinal);
        if (!paths.Any(p => p.EndsWith(".cs", StringComparison.OrdinalIgnoreCase)))
            context.Diagnostic("generated.files_unavailable", "No generated C# files were found.", root);
    }

    internal static void Read(CollectionContext context, string path, string assembly, string? generatedBy, CSharpParseOptions? parseOptions = null)
    {
        parseOptions ??= context.SourceParseOptions.GetValueOrDefault(path) ?? new CSharpParseOptions(LanguageVersion.Latest);
        if (!context.SourceScans.Add(path + "\0" + assembly + "\0" + parseOptions.LanguageVersion + "\0" + string.Join(";", parseOptions.PreprocessorSymbolNames)))
        {
            if (generatedBy is not null)
                for (var i = 0; i < context.Evidence.Sources.Count; i++)
                    if (CollectionContext.PathComparer.Equals(context.Evidence.Sources[i].Path, path))
                        context.Evidence.Sources[i] = context.Evidence.Sources[i] with { GeneratedBy = generatedBy };
            return;
        }
        context.Artifact("source", path);
        if (!context.Available(path)) return;
        var bytes = context.ReadBytes(path);
        var hash = CollectionContext.Hash(bytes);
        using var reader = new StreamReader(new MemoryStream(bytes), Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        var tree = CSharpSyntaxTree.ParseText(reader.ReadToEnd(), parseOptions, path);
        var error = tree.GetDiagnostics().FirstOrDefault(d => d.Severity == DiagnosticSeverity.Error);
        if (error is not null)
            throw new CollectionException("source.malformed", error.ToString(), path);
        if (assembly.Length == 0)
            context.Diagnostic("source.assembly_unknown", "No unique compiler route or textual project hint establishes an assembly.", path);
        foreach (var node in tree.GetRoot().DescendantNodes())
        {
            context.Count();
            string? typeName = null, member = null, kind = null;
            SyntaxList<AttributeListSyntax> attributes = default;
            if (node is BaseTypeDeclarationSyntax type)
            {
                typeName = TypeName(type);
                kind = type switch { EnumDeclarationSyntax => "enum", RecordDeclarationSyntax record => record.ClassOrStructKeyword.IsKind(SyntaxKind.StructKeyword) ? "record_struct" : "record", TypeDeclarationSyntax declaration => declaration.Keyword.ValueText, _ => "unknown" };
                if (type.Modifiers.Any(SyntaxKind.PartialKeyword)) kind = "partial_" + kind;
                attributes = type.AttributeLists;
            }
            else if (node is DelegateDeclarationSyntax del)
            {
                typeName = TypeName(del); kind = "delegate"; attributes = del.AttributeLists;
            }
            else
            {
                var owner = node.Ancestors().OfType<BaseTypeDeclarationSyntax>().FirstOrDefault();
                if (owner is null) continue;
                typeName = TypeName(owner);
                switch (node)
                {
                    case MethodDeclarationSyntax method: member = method.Identifier.ValueText + Parameters(method.ParameterList); kind = method.Modifiers.Any(SyntaxKind.PartialKeyword) ? "partial_method" : "method"; attributes = method.AttributeLists; break;
                    case ConstructorDeclarationSyntax ctor: member = (ctor.Modifiers.Any(SyntaxKind.StaticKeyword) ? ".cctor" : ".ctor") + Parameters(ctor.ParameterList); kind = "constructor"; attributes = ctor.AttributeLists; break;
                    case DestructorDeclarationSyntax dtor: member = "Finalize()"; kind = "destructor"; attributes = dtor.AttributeLists; break;
                    case OperatorDeclarationSyntax op: member = "operator " + op.OperatorToken.ValueText + Parameters(op.ParameterList); kind = "operator"; attributes = op.AttributeLists; break;
                    case ConversionOperatorDeclarationSyntax conversion: member = conversion.ImplicitOrExplicitKeyword.ValueText + " " + conversion.Type + Parameters(conversion.ParameterList); kind = "conversion"; attributes = conversion.AttributeLists; break;
                    case PropertyDeclarationSyntax property: member = property.Identifier.ValueText; kind = "property"; attributes = property.AttributeLists; break;
                    case IndexerDeclarationSyntax indexer: member = "this[" + string.Join(",", indexer.ParameterList.Parameters.Select(p => p.Type?.ToString())) + "]"; kind = "indexer"; attributes = indexer.AttributeLists; break;
                    case EventDeclarationSyntax ev: member = ev.Identifier.ValueText; kind = "event"; attributes = ev.AttributeLists; break;
                    case VariableDeclaratorSyntax variable when variable.Parent?.Parent is BaseFieldDeclarationSyntax field:
                        member = variable.Identifier.ValueText; kind = field is EventFieldDeclarationSyntax ? "event_field" : "field"; attributes = field.AttributeLists; break;
                    case EnumMemberDeclarationSyntax enumMember: member = enumMember.Identifier.ValueText; kind = "enum_member"; attributes = enumMember.AttributeLists; break;
                    default: continue;
                }
            }
            var span = node.GetLocation().GetLineSpan();
            context.Count();
            context.Evidence.Sources.Add(new(assembly, typeName, member, path,
                (ulong)span.StartLinePosition.Line + 1, (ulong)span.EndLinePosition.Line + 1, kind,
                attributes.SelectMany(a => a.Attributes).Select(a => a.ToString()).ToList(), generatedBy, hash));
        }
    }

    private static string Parameters(ParameterListSyntax list) =>
        "(" + string.Join(",", list.Parameters.Select(p => p.Type?.ToString())) + ")";

    private static string TypeName(MemberDeclarationSyntax declaration)
    {
        var names = declaration.AncestorsAndSelf().OfType<MemberDeclarationSyntax>().Where(n => n is BaseTypeDeclarationSyntax or DelegateDeclarationSyntax).Reverse().Select(n => n switch
        {
            TypeDeclarationSyntax t => t.Identifier.ValueText + (t.TypeParameterList is { Parameters.Count: > 0 } parameters ? "`" + parameters.Parameters.Count : ""),
            EnumDeclarationSyntax e => e.Identifier.ValueText,
            DelegateDeclarationSyntax d => d.Identifier.ValueText + (d.TypeParameterList is { Parameters.Count: > 0 } parameters ? "`" + parameters.Parameters.Count : ""),
            _ => ""
        });
        var ns = string.Join(".", declaration.Ancestors().OfType<BaseNamespaceDeclarationSyntax>().Reverse().Select(n => n.Name.ToString()));
        return (ns.Length == 0 ? "" : ns + ".") + string.Join("+", names);
    }
}
