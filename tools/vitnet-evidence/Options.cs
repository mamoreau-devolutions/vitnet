using System.Globalization;

namespace Vitnet.Evidence;

internal sealed class Options
{
    public string Output { get; private set; } = "";
    public string Label { get; private set; } = "";
    public string? Revision { get; private set; }
    public Dictionary<string, List<string>> Inputs { get; } = new(StringComparer.Ordinal);
    public long MaxFileBytes { get; private set; } = 128 * 1024 * 1024;
    public long MaxTotalBytes { get; private set; } = 1024L * 1024 * 1024;
    public long MaxExpandedBytes { get; private set; } = 512L * 1024 * 1024;
    public long MaxResourceBytes { get; private set; } = 64L * 1024 * 1024;
    public long MaxOutputBytes { get; private set; } = 256L * 1024 * 1024;
    public long MaxFiles { get; private set; } = 10_000;
    public long MaxRecords { get; private set; } = 1_000_000;

    public IEnumerable<string> Paths(string kind) => Inputs.GetValueOrDefault(kind) ?? [];

    public static Options Parse(string[] args)
    {
        var options = new Options();
        var singles = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < args.Length; i++)
        {
            var key = args[i];
            if (!key.StartsWith("--", StringComparison.Ordinal) || i + 1 >= args.Length)
                throw new CollectionException("collector.arguments", $"Expected an option and value, got '{key}'.");
            var value = args[++i];
            if (value.StartsWith("--", StringComparison.Ordinal))
                throw new CollectionException("collector.arguments", $"Missing value for {key}.");
            if (key is not ("--assets" or "--assembly" or "--binary" or "--pdb") && !singles.Add(key))
                throw new CollectionException("collector.arguments", $"Duplicate option {key}.");
            switch (key)
            {
                case "--output": options.Output = System.IO.Path.GetFullPath(value); break;
                case "--label": options.Label = value; break;
                case "--revision": options.Revision = value; break;
                case "--max-file-bytes": options.MaxFileBytes = Limit(value, key); break;
                case "--max-total-bytes": options.MaxTotalBytes = Limit(value, key); break;
                case "--max-expanded-bytes": options.MaxExpandedBytes = Limit(value, key); break;
                case "--max-resource-bytes": options.MaxResourceBytes = Limit(value, key); break;
                case "--max-output-bytes": options.MaxOutputBytes = Limit(value, key); break;
                case "--max-files": options.MaxFiles = Limit(value, key); break;
                case "--max-records": options.MaxRecords = Limit(value, key); break;
                case "--source-root": case "--generated-root": case "--binlog": case "--assets":
                case "--assembly": case "--binary": case "--metadata": case "--mstat":
                case "--scan-index": case "--codegen-index": case "--pdb":
                    var kind = key[2..].Replace('-', '_');
                    if (!options.Inputs.TryGetValue(kind, out var paths))
                        options.Inputs[kind] = paths = [];
                    paths.Add(System.IO.Path.GetFullPath(value));
                    break;
                default: throw new CollectionException("collector.arguments", $"Unknown option {key}.");
            }
        }
        if (options.Output.Length == 0)
            throw new CollectionException("collector.arguments", "--output is required.");
        return options;
    }

    private static long Limit(string value, string key)
    {
        if (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var limit) ||
            limit < 1 || limit > int.MaxValue)
            throw new CollectionException("collector.arguments", $"{key} must be between 1 and {int.MaxValue}.");
        return limit;
    }
}
