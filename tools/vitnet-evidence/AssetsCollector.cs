using System.Text.Json;

namespace Vitnet.Evidence;

internal static class AssetsCollector
{
    public static void Collect(CollectionContext context, string path)
    {
        context.Artifact("assets", path);
        if (!context.Available(path)) return;
        using var json = context.ReadJson(path);
        var root = json.RootElement;
        if (!root.TryGetProperty("version", out var version) || version.GetInt32() is not (3 or 4) ||
            !root.TryGetProperty("targets", out var targets) || targets.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty("libraries", out var libraries) || libraries.ValueKind != JsonValueKind.Object)
            throw new CollectionException("assets.malformed", "Expected resolved project.assets.json version 3/4 with targets and libraries.", path);
        context.Fact($"assets.format:{path}", version.GetInt32().ToString(System.Globalization.CultureInfo.InvariantCulture));
        if (!targets.EnumerateObject().Any())
            context.Diagnostic("assets.targets_missing", "No resolved targets are present.", path);
        var folders = root.TryGetProperty("packageFolders", out var packageFolders)
            ? packageFolders.EnumerateObject().Select(p => p.Name).ToArray() : [];
        foreach (var target in targets.EnumerateObject())
        {
            context.Count();
            var targetScope = context.Options.Paths("assets").Skip(1).Any() ? path + "::" + target.Name : target.Name;
            if (target.Value.ValueKind != JsonValueKind.Object)
                throw new CollectionException("assets.malformed", "Target must be an object.", path);
            var resolved = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var values = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);
            foreach (var library in target.Value.EnumerateObject())
            {
                context.Count();
                var split = library.Name.LastIndexOf('/');
                if (split <= 0 || split == library.Name.Length - 1 || !resolved.TryAdd(library.Name[..split], library.Name))
                    throw new CollectionException("assets.identity", "Target library keys must be unique id/version identities.", path);
                values.Add(library.Name, library.Value);
                if (!libraries.TryGetProperty(library.Name, out _))
                    throw new CollectionException("assets.library_missing", $"Resolved library {library.Name} has no libraries entry.", path);
            }
            var direct = DirectDependencies(context, root, target.Name, path);
            var graph = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var library in values.OrderBy(p => p.Key, StringComparer.Ordinal))
            {
                var key = library.Key;
                var value = library.Value;
                var dependencies = new List<string>();
                if (value.TryGetProperty("dependencies", out var deps))
                {
                    foreach (var dependency in deps.EnumerateObject())
                    {
                        context.Count();
                        if (resolved.TryGetValue(dependency.Name, out var resolvedKey)) dependencies.Add(resolvedKey);
                        else
                        {
                            dependencies.Add("unresolved:" + dependency.Name + "/" + dependency.Value);
                            context.Diagnostic("assets.dependency_missing", $"Target {target.Name}: {key} depends on unresolved {dependency.Name}/{dependency.Value}.", path);
                        }
                    }
                }
                dependencies.Sort(StringComparer.Ordinal);
                graph.Add(key, dependencies);
                var type = value.GetProperty("type").GetString();
                if (type != "package")
                {
                    context.Fact($"assets.non_package:{path}:{target.Name}:{key}", type ?? "unknown");
                    continue;
                }
                var split = key.LastIndexOf('/');
                context.Count();
                context.Evidence.Packages.Add(new(targetScope, key[..split], key[(split + 1)..], direct.Contains(key[..split]), dependencies));
                if (libraries.GetProperty(key).TryGetProperty("path", out var libraryPath))
                {
                    foreach (var role in new[] { "compile", "runtime", "runtimeTargets" })
                    {
                        if (!value.TryGetProperty(role, out var items)) continue;
                        foreach (var item in items.EnumerateObject())
                        {
                            context.Count();
                            if (!item.Name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) continue;
                            foreach (var folder in folders)
                            {
                                var assemblyPath = Path.GetFullPath(Path.Combine(folder, libraryPath.GetString()!, item.Name.Replace('/', Path.DirectorySeparatorChar)));
                                if (!context.AssemblyPackages.TryGetValue(assemblyPath, out var packages))
                                    context.AssemblyPackages[assemblyPath] = packages = new(StringComparer.Ordinal);
                                packages.Add(key);
                                context.Count();
                                context.Evidence.Mappings.Add(new("package", key, Path.GetFileNameWithoutExtension(item.Name), [assemblyPath], $"assets_resolved_{role}:{targetScope}"));
                            }
                        }
                    }
                }
            }
            foreach (var id in direct.Where(id => !resolved.ContainsKey(id)))
                context.Diagnostic("assets.direct_missing", $"Direct dependency {id} is missing from target {target.Name}.", path);
            DetectCycles(context, graph, target.Name, path);
            context.Fact($"assets.target:{path}:{target.Name}", $"resolved; {resolved.Count} libraries");
        }
        if (root.TryGetProperty("project", out var project) &&
            project.TryGetProperty("restore", out var restore) && restore.TryGetProperty("projectPath", out var projectPath))
            context.Fact($"assets.project:{path}", projectPath.GetString() ?? "");
    }

    private static HashSet<string> DirectDependencies(CollectionContext context, JsonElement root, string target, string path)
    {
        var direct = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var tfm = target.Split('/')[0];
        if (root.TryGetProperty("project", out var project) && project.TryGetProperty("frameworks", out var frameworks) &&
            frameworks.TryGetProperty(tfm, out var framework))
        {
            if (framework.TryGetProperty("dependencies", out var dependencies))
                foreach (var dependency in dependencies.EnumerateObject()) { context.Count(); direct.Add(dependency.Name); }
        }
        else if (root.TryGetProperty("projectFileDependencyGroups", out var groups) && groups.TryGetProperty(tfm, out var group))
        {
            foreach (var item in group.EnumerateArray())
            {
                context.Count();
                var declaration = item.GetString() ?? throw new CollectionException("assets.malformed", "Dependency declaration is not a string.", path);
                direct.Add(declaration.Split(' ', 2)[0]);
            }
        }
        else context.Diagnostic("assets.direct_unknown", $"Direct dependency declarations are absent for target {target}; direct=false does not establish transitive ownership.", path);
        return direct;
    }

    private static void DetectCycles(CollectionContext context, Dictionary<string, List<string>> graph, string target, string path)
    {
        var state = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var root in graph.Keys.Order(StringComparer.Ordinal))
        {
            if (state.ContainsKey(root)) continue;
            var pending = new Stack<(string Key, bool Exit)>();
            pending.Push((root, false));
            while (pending.TryPop(out var node))
            {
                if (node.Exit) { state[node.Key] = 2; continue; }
                if (state.ContainsKey(node.Key)) continue;
                state[node.Key] = 1;
                pending.Push((node.Key, true));
                foreach (var dependency in graph[node.Key].AsEnumerable().Reverse())
                {
                    if (!graph.ContainsKey(dependency)) continue;
                    if (state.GetValueOrDefault(dependency) == 1)
                        context.Diagnostic("assets.cycle", $"Target {target} has a dependency cycle through {node.Key} -> {dependency}.", path);
                    else if (!state.ContainsKey(dependency)) pending.Push((dependency, false));
                }
            }
        }
    }
}
