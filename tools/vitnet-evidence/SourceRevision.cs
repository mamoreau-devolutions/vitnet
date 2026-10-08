using System.Diagnostics;

namespace Vitnet.Evidence;

internal static class SourceRevision
{
    public static void Collect(CollectionContext context, string root)
    {
        if (!Directory.Exists(root)) return;
        try
        {
            var revision = Git(context, root, "rev-parse", "--verify", "HEAD");
            if (revision is null)
            {
                context.Diagnostic("source.revision_unknown", "Source root is not an available Git checkout, or its HEAD cannot be resolved.", root);
                return;
            }
            context.Fact($"source.current_revision:{root}", revision.Trim());
            var dirty = Git(context, root, "status", "--porcelain=v1", "--untracked-files=normal", "--", ".");
            context.Fact($"source.current_dirty:{root}", dirty is null ? "unknown" : dirty.Length == 0 ? "false" : "true");
            context.Fact($"source.revision_scope:{root}", "current local HEAD and source-root Git status (respecting ignores); independent of compiled binlog SourceRevisionId; ignored/untracked bytes are established only by checksums, not HEAD");
        }
        catch (System.ComponentModel.Win32Exception)
        {
            context.Diagnostic("source.revision_unknown", "Git executable is unavailable; current source revision/dirty state are unknown.", root);
        }
    }

    private static string? Git(CollectionContext context, string root, params string[] args)
    {
        var start = new ProcessStartInfo("git")
        {
            UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (var argument in new[] { "--no-optional-locks", "-c", "core.fsmonitor=false", "-C", root }.Concat(args))
            start.ArgumentList.Add(argument);
        using var process = Process.Start(start)!;
        var stdout = ReadBounded(process.StandardOutput, context.Options.MaxFileBytes);
        var stderr = ReadBounded(process.StandardError, context.Options.MaxFileBytes);
        if (!process.WaitForExit(30_000))
        {
            process.Kill(entireProcessTree: true);
            throw new CollectionException("resource.collector.git_timeout", "Read-only Git provenance query timed out.", root);
        }
        var output = stdout.GetAwaiter().GetResult();
        _ = stderr.GetAwaiter().GetResult();
        return process.ExitCode == 0 ? output : null;
    }

    private static async System.Threading.Tasks.Task<string> ReadBounded(StreamReader reader, long limit)
    {
        var builder = new System.Text.StringBuilder();
        var buffer = new char[4096];
        var overLimit = false;
        int read;
        while ((read = await reader.ReadAsync(buffer)) != 0)
        {
            if (read > limit - builder.Length) overLimit = true;
            if (!overLimit) builder.Append(buffer, 0, read);
        }
        if (overLimit)
            throw new CollectionException("resource.collector.git_output", "Git provenance output exceeds byte/character budget.");
        return builder.ToString();
    }
}
