using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Vitnet.Evidence;

internal static class GeneratedCollector
{
    public static GeneratorRun CreateRun(Generator generator, string basis) =>
        new(generator.Name, Empty(generator.Version), Empty(generator.AssemblyPath), null, null, null, null, null,
            "output_unavailable", basis, []);

    public static void Capture(CollectionContext context, GeneratorRun run, Generator? generator, string path)
    {
        if (run.Outputs.Any(o => CollectionContext.PathComparer.Equals(o.Path, path))) return;
        if (!context.Available(path)) return;
        var bytes = context.ReadBytes(path);
        foreach (var route in context.GeneratorRoutes)
        {
            context.Count();
            if (Matches(route, path) && route.TargetAssembly is not null)
                context.AddAssemblyHint(path, route.TargetAssembly);
        }
        context.Count();
        run.Outputs.Add(new(path, CollectionContext.Hash(bytes), "unknown", []));
        if (generator is null) return;
        foreach (var symbol in generator.InputSymbols)
        {
            context.Count();
            context.Evidence.GeneratorLinks.Add(new(generator.Name, path, null, null, null, symbol,
                "manifest_input_symbol", "supplied", "vitnet.generator.v1 input_symbols; caller assertion, not independently verified"));
        }
    }

    public static void Finish(CollectionContext context)
    {
        var generatedPaths = context.Evidence.GeneratorRuns.SelectMany(r => r.Outputs)
            .Select(o => o.Path).ToHashSet(CollectionContext.PathComparer);
        var syntaxSources = context.Evidence.Sources.Where(s => s.Kind != "pdb_sequence_point" && !generatedPaths.Contains(s.Path)).ToArray();
        var partials = syntaxSources.Where(s => s.Kind.StartsWith("partial_", StringComparison.Ordinal) && s.Attributes.Count != 0)
            .GroupBy(s => s.TypeName, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.ToArray(), StringComparer.Ordinal);
        var sourcesByPath = syntaxSources.GroupBy(s => s.Path, CollectionContext.PathComparer)
            .ToDictionary(g => g.Key, g => g.ToArray(), CollectionContext.PathComparer);
        var declarationsByPath = context.Evidence.Sources.Where(s => s.Kind.StartsWith("partial_", StringComparison.Ordinal) && generatedPaths.Contains(s.Path))
            .GroupBy(s => s.Path, CollectionContext.PathComparer).ToDictionary(g => g.Key, g => g.ToArray(), CollectionContext.PathComparer);
        var seenLinks = new HashSet<GeneratorLink>(context.Evidence.GeneratorLinks);
        var assemblyHashes = new Dictionary<string, string?>(CollectionContext.PathComparer);
        for (var index = 0; index < context.Evidence.GeneratorRuns.Count; index++)
        {
            var run = context.Evidence.GeneratorRuns[index];
            if (run.Status == "analyzer_referenced") continue;
            run.Outputs.Sort((a, b) => StringComparer.Ordinal.Compare(a.Path, b.Path));
            var routes = context.GeneratorRoutes.Where(r => run.Outputs.Count != 0 && run.Outputs.All(o =>
            {
                context.Count();
                return Matches(r, o.Path);
            })).ToArray();
            var provenance = routes.Select(r => (r.ProjectPath, r.TargetAssembly, r.TargetAssemblyPath, r.Configuration, r.TargetFramework))
                .Distinct().ToArray();
            if (provenance.Length == 1)
            {
                var route = provenance[0];
                run = run with { ProjectPath = route.ProjectPath, TargetAssembly = route.TargetAssembly,
                    TargetAssemblyPath = route.TargetAssemblyPath, Configuration = route.Configuration, TargetFramework = route.TargetFramework };
            }
            else if (provenance.Length > 1)
                context.Diagnostic("generated.project_ambiguous", "Multiple recorded compiler routes own this generated directory; project/build provenance remains unknown.", run.Outputs[0].Path);
            for (var outputIndex = 0; outputIndex < run.Outputs.Count; outputIndex++)
            {
                var output = run.Outputs[outputIndex];
                if (context.Hash(output.Path) != output.Sha256)
                    throw new CollectionException("collector.input_changed", "Generated output bytes changed during collection.", output.Path);
                var checksums = context.DocumentChecksums.GetValueOrDefault(output.Path) ?? [];
                var applicable = checksums.Where(c => c.AssemblyMatch == "pe_identity_verified" &&
                    (run.TargetAssemblyPath is null || SameBuild(context, assemblyHashes, run.TargetAssemblyPath, c.TargetAssemblyPath))).ToArray();
                var states = applicable.Select(c => c.Status).Distinct(StringComparer.Ordinal).ToArray();
                var builds = applicable.Select(c => c.TargetAssemblyPath).Distinct(CollectionContext.PathComparer).Count();
                var buildMatch = builds > 1 || states.Length > 1 ? "ambiguous" :
                    states.Length == 1 && states[0] is "matched" or "drift" ? states[0] : "unknown";
                context.Count(checksums.Count);
                output = output with { BuildMatch = buildMatch, PdbChecksums = checksums.OrderBy(c => c.PdbPath, StringComparer.Ordinal)
                    .ThenBy(c => c.TargetAssemblyPath, StringComparer.Ordinal).ThenBy(c => c.Algorithm, StringComparer.Ordinal).ToList() };
                run.Outputs[outputIndex] = output;
                if (run.Name.Length == 0) continue;
                foreach (var declaration in declarationsByPath.GetValueOrDefault(output.Path) ?? [])
                    foreach (var source in partials.GetValueOrDefault(declaration.TypeName) ?? [])
                    {
                        context.Count();
                        if (!CompatibleAssembly(source, declaration, run) ||
                            declaration.Member != source.Member) continue;
                        AddLink(context, seenLinks, new(run.Name, output.Path, source.Path, source.TypeName, source.Member, null,
                            "attributed_partial_declaration", "candidate",
                            "same textual partial type/member in output and attributed source: " + string.Join("; ", source.Attributes)));
                    }
                LineLinks(context, run, output, sourcesByPath, seenLinks);
            }
            if (run.TargetAssemblyPath is null && provenance.Length == 0)
            {
                var builds = run.Outputs.SelectMany(o => o.PdbChecksums).Where(c => c.AssemblyMatch == "pe_identity_verified")
                    .Select(c => (c.TargetAssembly, c.TargetAssemblyPath)).Distinct().ToArray();
                if (builds.Length == 1)
                    run = run with { TargetAssembly = builds[0].TargetAssembly, TargetAssemblyPath = builds[0].TargetAssemblyPath };
            }
            context.Evidence.GeneratorRuns[index] = run with { Status = run.Outputs.Count == 0 ? "output_unavailable" : "output_captured" };
            if (run.Outputs.Count == 0)
                context.Diagnostic("generated.output_unavailable", "Supplied emitter identity has no captured output; generator execution is not observed.");
        }
    }

    private static bool Matches(GeneratorCompilerRoute route, string path) =>
        route.Sources.Contains(path) || route.GeneratedDirectory is not null && SourceCollector.Inside(path, route.GeneratedDirectory);

    private static bool SameBuild(CollectionContext context, Dictionary<string, string?> hashes, string expected, string? actual)
    {
        if (actual is null) return false;
        if (CollectionContext.PathComparer.Equals(expected, actual)) return true;
        foreach (var path in new[] { expected, actual })
            if (!hashes.ContainsKey(path))
            {
                context.Count();
                hashes[path] = context.Available(path) ? context.Hash(path) : null;
            }
        return hashes[expected] is not null && hashes[expected] == hashes[actual];
    }

    private static bool CompatibleAssembly(Source source, Source output, GeneratorRun run) =>
        (source.Assembly.Length == 0 || output.Assembly.Length == 0 || source.Assembly == output.Assembly) &&
        (run.TargetAssembly is null || source.Assembly.Length == 0 || source.Assembly == run.TargetAssembly);

    private static void LineLinks(CollectionContext context, GeneratorRun run, GeneratorOutput output,
        Dictionary<string, Source[]> sources, HashSet<GeneratorLink> seen)
    {
        var bytes = context.ReadBytes(output.Path);
        if (CollectionContext.Hash(bytes) != output.Sha256)
            throw new CollectionException("collector.input_changed", "Generated output bytes changed during collection.", output.Path);
        using var reader = new StreamReader(new MemoryStream(bytes), detectEncodingFromByteOrderMarks: true);
        var tree = CSharpSyntaxTree.ParseText(reader.ReadToEnd(),
            context.SourceParseOptions.GetValueOrDefault(output.Path) ?? new CSharpParseOptions(LanguageVersion.Latest), output.Path);
        foreach (var trivia in tree.GetRoot().DescendantTrivia(descendIntoTrivia: true))
        {
            context.Count();
            if (trivia.GetStructure() is not LineDirectiveTriviaSyntax { IsActive: true } directive ||
                !directive.File.IsKind(SyntaxKind.StringLiteralToken) || directive.Line.Value is not int line || line < 1) continue;
            var rawPath = directive.File.ValueText;
            if (string.IsNullOrWhiteSpace(rawPath)) continue;
            var candidates = new HashSet<string>(CollectionContext.PathComparer);
            try
            {
                candidates.Add(Path.GetFullPath(rawPath, Path.GetDirectoryName(output.Path)!));
                if (run.ProjectPath is not null)
                    candidates.Add(Path.GetFullPath(rawPath, Path.GetDirectoryName(run.ProjectPath)!));
            }
            catch (Exception error) when (error is ArgumentException or NotSupportedException)
            {
                context.Diagnostic("generated.line_anchor_unknown", "A #line anchor is not a local physical path; no trigger ownership is inferred.", output.Path);
                continue;
            }
            var paths = candidates.Where(sources.ContainsKey).ToArray();
            if (paths.Length != 1)
            {
                context.Diagnostic("generated.line_anchor_unknown", "A #line anchor has no unique collected physical source route; no trigger ownership is inferred.", output.Path);
                continue;
            }
            var sourcePath = paths[0];
            var owners = sources[sourcePath].Where(s => s.Line <= (ulong)line && s.EndLine >= (ulong)line &&
                (run.TargetAssembly is null || s.Assembly.Length == 0 || s.Assembly == run.TargetAssembly)).ToArray();
            if (owners.Length == 0)
                AddLink(context, seen, new(run.Name, output.Path, sourcePath, null, null, null, "line_directive", "candidate",
                    $"#line {line}: textual source location, not generator execution/causation"));
            foreach (var source in owners)
            {
                context.Count();
                AddLink(context, seen, new(run.Name, output.Path, sourcePath, source.TypeName, source.Member, null,
                    "line_directive", "candidate", $"#line {line}: textual source location, not generator execution/causation"));
            }
        }
    }

    private static void AddLink(CollectionContext context, HashSet<GeneratorLink> seen, GeneratorLink link)
    {
        if (!seen.Add(link)) return;
        context.Count();
        context.Evidence.GeneratorLinks.Add(link);
    }

    private static string? Empty(string value) => string.IsNullOrWhiteSpace(value) ? null : value;
}
