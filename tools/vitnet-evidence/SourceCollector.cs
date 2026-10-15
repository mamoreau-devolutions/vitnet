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
        var paths = context.Walk(root, p => p.EndsWith(".cs", StringComparison.OrdinalIgnoreCase) ||
            p.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase) || IsXaml(p)).Order(StringComparer.Ordinal).ToList();
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
        foreach (var path in paths.Where(p => p.EndsWith(".cs", StringComparison.OrdinalIgnoreCase) || IsXaml(p)))
        {
            var owners = projects.Where(p => Inside(path, p.Directory)).OrderByDescending(p => p.Directory.Length).ToArray();
            var nearest = owners.Length == 0 ? [] : owners.Where(p => p.Directory.Length == owners[0].Directory.Length).Select(p => p.Assembly).Distinct(StringComparer.Ordinal).ToArray();
            var fallback = nearest.Length == 1 ? nearest[0] : "";
            if (nearest.Length > 1) context.Diagnostic("source.project_ambiguous", "Multiple projects share this directory; no textual assembly hint is assigned.", path);
            if (IsXaml(path))
            {
                var (assembly, basis) = XamlAssemblyHint(context, path, fallback, owners.Length == 0 ? 0 : owners[0].Directory.Length);
                ReadXaml(context, path, assembly, basis);
            }
            else Read(context, path, context.AssemblyHint(path, fallback), null);
        }
        if (!paths.Any(p => p.EndsWith(".cs", StringComparison.OrdinalIgnoreCase)))
            context.Diagnostic("source.declarations_unavailable", "No C# source files were found.", root);
        context.Fact("source.declaration_basis", "Roslyn syntax only; attributes are textual, partial declarations are separate occurrences, symbols and project conditions are not evaluated");
        if (context.Evidence.XamlDocuments.Count != 0)
        {
            context.Evidence.XamlDocuments.Sort((a, b) => StringComparer.Ordinal.Compare(a.Path, b.Path));
            context.Fact("source.xaml_basis", "streamed XML syntax only; class, key and include strings are not execution, ownership, retention or source/build equality evidence; includes are never fetched or resolved");
        }
    }

    private static bool IsXaml(string path) =>
        path.EndsWith(".xaml", StringComparison.OrdinalIgnoreCase) || path.EndsWith(".axaml", StringComparison.OrdinalIgnoreCase);

    private static (string Assembly, string Basis) XamlAssemblyHint(
        CollectionContext context, string path, string fallback, int projectDirectoryLength)
    {
        if (context.SourceAssemblies.ContainsKey(path))
            return (context.AssemblyHint(path, ""), "recorded_compiler_source_route_hint");
        var routes = context.GeneratorRoutes.Where(r => r.ProjectPath is not null && r.TargetAssembly is not null)
            .Select(r => (Directory: Path.GetDirectoryName(r.ProjectPath!)!, Assembly: r.TargetAssembly!))
            .Where(r => Inside(path, r.Directory)).OrderByDescending(r => r.Directory.Length).ToArray();
        if (routes.Length == 0 || routes[0].Directory.Length < projectDirectoryLength)
            return (fallback, fallback.Length == 0 ? "unknown" : "textual_project_directory_hint");
        var assemblies = routes.Where(r => r.Directory.Length == routes[0].Directory.Length)
            .Select(r => r.Assembly).Distinct(StringComparer.Ordinal).ToArray();
        if (assemblies.Length == 1) return (assemblies[0], "recorded_compiler_project_directory_hint");
        context.Diagnostic("source.xaml_assembly_ambiguous", "Multiple compiler project routes cover this directory; no XAML assembly hint is assigned.", path);
        return ("", "ambiguous_compiler_project_directory_hint");
    }

    private static void ReadXaml(CollectionContext context, string path, string assembly, string basis)
    {
        context.Artifact("source", path);
        if (!context.Available(path)) return;
        using var stream = context.Open(path);
        using var reader = XmlReader.Create(stream, new()
        {
            DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null,
            MaxCharactersInDocument = context.Options.MaxFileBytes
        });
        string? root = null, declaredClass = null;
        var includes = new HashSet<string>(StringComparer.Ordinal);
        var keys = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            while (reader.Read())
            {
                context.Count();
                if (reader.Depth > 64)
                    throw new CollectionException("resource.collector.xaml_depth", "XAML XML depth budget exceeded (64).", path);
                if (reader.NodeType != XmlNodeType.Element) continue;
                var isRoot = root is null;
                if (isRoot) root = reader.NamespaceURI.Length == 0 ? reader.LocalName : "{" + reader.NamespaceURI + "}" + reader.LocalName;
                var isInclude = reader.LocalName is "ResourceDictionary" or "ResourceInclude" or
                    "StyleInclude" or "MergeResourceInclude" or "MergeStyleInclude";
                while (reader.MoveToNextAttribute())
                {
                    context.Count();
                    if (reader.NamespaceURI is "http://schemas.microsoft.com/winfx/2006/xaml" or "http://schemas.microsoft.com/winfx/2009/xaml")
                    {
                        if (isRoot && reader.LocalName == "Class") declaredClass = reader.Value;
                        if (reader.LocalName == "Key")
                        {
                            context.Count();
                            keys.Add(reader.Value);
                        }
                    }
                    if (isInclude && reader.NamespaceURI.Length == 0 && reader.LocalName == "Source")
                    {
                        context.Count();
                        includes.Add(reader.Value);
                    }
                }
                reader.MoveToElement();
            }
        }
        catch (XmlException error)
        {
            throw new CollectionException("source.xaml_malformed", error.Message, path);
        }
        if (root is null)
            throw new CollectionException("source.xaml_malformed", "XAML XML document has no root element.", path);
        if (assembly.Length == 0)
            context.Diagnostic("source.xaml_assembly_unknown", "No unique compiler route or textual project hint establishes a XAML assembly association.", path);
        context.Fact($"source.xaml_assembly_basis:{path}", basis + "; syntax-only association, not compiled ownership");
        context.Count();
        context.Evidence.XamlDocuments.Add(new(path, assembly, declaredClass, root, context.Hash(path),
            includes.Order(StringComparer.Ordinal).ToList(), keys.Order(StringComparer.Ordinal).ToList()));
    }

    internal static bool Inside(string path, string directory) =>
        path.StartsWith(Path.TrimEndingDirectorySeparator(directory) + Path.DirectorySeparatorChar,
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

    public static void CollectGenerated(CollectionContext context, string root)
    {
        if (!context.GeneratedRoots.Add(root)) return;
        var paths = context.Walk(root, p => p.EndsWith(".cs", StringComparison.OrdinalIgnoreCase) || Path.GetFileName(p) == "vitnet.generator.json").ToList();
        var manifests = new List<(string Directory, Generator Generator, GeneratorRun Run)>();
        foreach (var path in paths.Where(p => Path.GetFileName(p) == "vitnet.generator.json"))
        {
            context.Artifact("generated", path);
            if (!context.Available(path)) continue;
            using var json = context.ReadJson(path);
            var value = json.RootElement;
            if (value.GetProperty("schema").GetString() != "vitnet.generator.v1")
                throw new CollectionException("generated.provenance", "Unknown generator provenance schema.", path);
            var name = value.GetProperty("name").GetString();
            var version = value.TryGetProperty("version", out var versionValue) ? versionValue.GetString() : null;
            if (string.IsNullOrWhiteSpace(name))
                throw new CollectionException("generated.provenance", "Generator name is required.", path);
            if (string.IsNullOrWhiteSpace(version))
                context.Diagnostic("generated.version_unknown", "The supplied manifest does not establish a generator version.", path);
            var directory = Path.GetDirectoryName(path)!;
            var rawAssembly = value.TryGetProperty("assembly_path", out var asm) ? asm.GetString() : null;
            var assemblyPath = string.IsNullOrEmpty(rawAssembly) ? "" : Path.GetFullPath(rawAssembly, directory);
            var symbols = value.TryGetProperty("input_symbols", out var inputs)
                ? inputs.EnumerateArray().Select(i => i.GetString() ?? throw new CollectionException("generated.provenance", "input_symbols must contain strings.", path)).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList() : [];
            context.Count(symbols.Count + 1);
            var generator = new Generator(name, version ?? "", assemblyPath, [], symbols);
            context.Evidence.Generators.Add(generator);
            var run = GeneratedCollector.CreateRun(generator, "supplied_manifest");
            context.Count();
            context.Evidence.GeneratorRuns.Add(run);
            manifests.Add((directory, generator, run));
            context.Fact($"generated.provenance:{path}", "user-supplied emitter/input-symbol mapping; not independently verified by this collector");
            if (assemblyPath.Length != 0) { context.Artifact("assembly", assemblyPath); context.Available(assemblyPath); }
            if (!value.TryGetProperty("input_symbols", out _))
                context.Diagnostic("generated.input_symbols_unknown", "Generator inputs were not supplied; no annotation-to-emitter association is inferred.", path);
        }
        var inferred = new Dictionary<string, (Generator Generator, GeneratorRun Run)>(StringComparer.Ordinal);
        GeneratorRun? unknown = null;
        foreach (var path in paths.Where(p => p.EndsWith(".cs", StringComparison.OrdinalIgnoreCase)))
        {
            var matches = manifests.Where(m => Inside(path, m.Directory)).OrderByDescending(m => m.Directory.Length).ToArray();
            Generator? generator = matches.Length != 0 ? matches[0].Generator : null;
            GeneratorRun? run = matches.Length != 0 ? matches[0].Run : null;
            if (generator is null)
            {
                var relative = Path.GetRelativePath(root, path).Split(Path.DirectorySeparatorChar);
                if (relative.Length >= 3)
                {
                    var emitterAssembly = relative[0];
                    var emitter = relative[1];
                    var identity = emitterAssembly + "/" + emitter;
                    if (!inferred.TryGetValue(identity, out var candidate))
                    {
                        var analyzers = context.GeneratorRoutes.SelectMany(r => r.Analyzers)
                            .Where(p => StringComparer.Ordinal.Equals(context.AnalyzerNames.GetValueOrDefault(p) ?? Path.GetFileNameWithoutExtension(p), emitterAssembly))
                            .Distinct(CollectionContext.PathComparer).ToArray();
                        var assemblyPath = analyzers.Length == 1 && context.AnalyzerNames.ContainsKey(analyzers[0]) ? analyzers[0] : "";
                        var version = assemblyPath.Length != 0 ? context.AnalyzerVersions.GetValueOrDefault(assemblyPath) ?? "" : "";
                        context.Count();
                        generator = new(emitter, version, assemblyPath, [], []);
                        run = GeneratedCollector.CreateRun(generator, "conventional_output_directory");
                        context.Count();
                        context.Evidence.GeneratorRuns.Add(run);
                        inferred.Add(identity, (generator, run));
                        context.Evidence.Generators.Add(generator);
                        context.Diagnostic("generated.emitter_candidate", $"Emitter {identity} is inferred only from the compiler output directory convention; input_symbols are unknown.", path);
                        if (version.Length == 0) context.Diagnostic("generated.version_unknown", "No unique analyzer metadata route establishes the emitter assembly version.", path);
                        if (analyzers.Length > 1) context.Diagnostic("generated.analyzer_ambiguous", "Multiple analyzer paths have this output-directory assembly name; no analyzer path/version is assigned.", path);
                    }
                    else (generator, run) = candidate;
                }
                else
                {
                    context.Diagnostic("generated.emitter_unknown", "No provenance manifest or conventional emitter directory is present.", path);
                    if (unknown is null)
                    {
                        context.Count();
                        unknown = new("", null, null, null, null, null, null, null, "output_unavailable", "emitter_unknown", []);
                        context.Evidence.GeneratorRuns.Add(unknown);
                    }
                    run = unknown;
                }
            }
            context.Count();
            generator?.GeneratedFiles.Add(path);
            context.Artifact("generated", path);
            GeneratedCollector.Capture(context, run!, generator, path);
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
            var legacyAttributes = new List<string>();
            foreach (var attribute in attributes.SelectMany(a => a.Attributes))
            {
                context.Count();
                legacyAttributes.Add(attribute.ToString());
            }
            var annotations = Annotations(context, node, attributes);
            context.Count();
            context.Evidence.Sources.Add(new(assembly, typeName, member, path,
                (ulong)span.StartLinePosition.Line + 1, (ulong)span.EndLinePosition.Line + 1, kind,
                legacyAttributes, generatedBy, hash, annotations));
        }
    }

    private static List<SourceAnnotation>? Annotations(
        CollectionContext context, SyntaxNode node, SyntaxList<AttributeListSyntax> attributes)
    {
        var targets = new SortedDictionary<string, List<string>>(StringComparer.Ordinal);
        void Add(string target, AttributeListSyntax list)
        {
            if (list.Attributes.Count == 0) return;
            if (!targets.TryGetValue(target, out var values))
            {
                context.Count();
                targets.Add(target, values = []);
            }
            foreach (var attribute in list.Attributes)
            {
                context.Count();
                values.Add(attribute.ToString());
            }
        }
        foreach (var list in attributes)
            Add(list.Target?.Identifier.ValueText == "return" ? "return" : "declaration", list);
        var parameters = node switch
        {
            TypeDeclarationSyntax type => type.ParameterList?.Parameters ?? default,
            DelegateDeclarationSyntax del => del.ParameterList.Parameters,
            BaseMethodDeclarationSyntax method => method.ParameterList.Parameters,
            IndexerDeclarationSyntax indexer => indexer.ParameterList.Parameters,
            _ => default
        };
        foreach (var parameter in parameters)
            foreach (var list in parameter.AttributeLists)
                if (list.Target is null || list.Target.Identifier.ValueText == "param")
                    Add("parameter:" + parameter.Identifier.ValueText, list);
        var typeParameters = node switch
        {
            TypeDeclarationSyntax type => type.TypeParameterList?.Parameters ?? default,
            DelegateDeclarationSyntax del => del.TypeParameterList?.Parameters ?? default,
            MethodDeclarationSyntax method => method.TypeParameterList?.Parameters ?? default,
            _ => default
        };
        foreach (var parameter in typeParameters)
            foreach (var list in parameter.AttributeLists)
                Add("generic_parameter:" + parameter.Identifier.ValueText, list);
        return targets.Count == 0 ? null : targets.Select(p => new SourceAnnotation(p.Key, p.Value)).ToList();
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
