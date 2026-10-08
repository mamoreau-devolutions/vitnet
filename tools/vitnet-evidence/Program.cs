using System.Text.Json;
using System.Text.Json.Serialization;

namespace Vitnet.Evidence;

internal static class Program
{
    internal static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = true
    };

    public static int Main(string[] args)
    {
        string? stage = null;
        try
        {
            if (args is ["--help"])
            {
                Console.WriteLine(JsonSerializer.Serialize(new
                {
                    schema = "vitnet.evidence.v1",
                    usage = "vitnet-evidence --output evidence.json [--source-root DIR] [--binlog FILE] [--assets FILE]* [--assembly FILE]* [--generated-root DIR] [--binary FILE]* [--pdb FILE]* [--metadata FILE] [--mstat FILE] [--scan-index FILE] [--codegen-index FILE] [--revision FACT] [--label LABEL]",
                    limits = new[] { "--max-file-bytes", "--max-total-bytes", "--max-expanded-bytes", "--max-resource-bytes", "--max-output-bytes", "--max-files", "--max-records" }
                }, Json));
                return 0;
            }
            var options = Options.Parse(args);
            var context = new CollectionContext(options);
            context.Fact("collector.version", "1.0.0");
            context.Fact("collector.runtime", System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription);
            context.Fact("collector.metadata_provider", typeof(System.Reflection.PortableExecutable.PEReader).Assembly
                .GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
                .Cast<System.Reflection.AssemblyInformationalVersionAttribute>().Single().InformationalVersion);
            context.Fact("collector.roslyn", "Microsoft.CodeAnalysis.CSharp/5.0.0");
            context.Fact("collector.structured_logger", "MSBuild.StructuredLogger/2.3.246");
            if (options.Revision is not null) context.Fact("input.revision", options.Revision);
            if (options.Inputs.Count == 0)
                context.Diagnostic("collector.inputs_unknown", "No evidence inputs were supplied.");
            foreach (var kind in new[] { "metadata", "mstat", "scan_index", "codegen_index" })
                foreach (var path in options.Paths(kind))
                {
                    stage = path;
                    context.Artifact(kind, path);
                    context.Available(path);
                    context.Fact($"artifact.role:{kind}:{path}", "opaque handle; format validation and graph ingestion belong to Rust");
                    context.Diagnostic("artifact.validation_deferred", $"{kind} is a declared opaque artifact, not parsed evidence; validate/import it with the Rust format reader.", path);
                }
            foreach (var path in options.Paths("assets"))
            {
                stage = path;
                AssetsCollector.Collect(context, path);
            }
            foreach (var path in options.Paths("binlog"))
            {
                stage = path;
                BinlogCollector.Collect(context, path);
            }
            foreach (var path in options.Paths("source_root"))
            {
                stage = path;
                SourceCollector.Collect(context, path);
            }
            foreach (var path in options.Paths("generated_root"))
            {
                stage = path;
                SourceCollector.CollectGenerated(context, path);
            }
            foreach (var path in options.Paths("assembly"))
            {
                stage = path;
                PeCollector.Managed(context, path);
            }
            foreach (var path in options.Paths("pdb"))
            {
                stage = path;
                PeCollector.Pdb(context, path, null, "");
            }
            foreach (var path in options.Paths("binary"))
            {
                stage = path;
                PeCollector.Native(context, path);
            }
            context.Diagnostic("evidence.root_annotations_unknown", "Compiler root annotations are not inferred from names/attributes; use explicit graph witnesses or supplied generator input_symbols.");
            context.Diagnostic("evidence.revision_scope", "Revision/toolchain labels are recorded facts, not proof of a clean or matching checkout.");
            Sort(context.Evidence);
            stage = options.Output;
            var outputDirectory = Path.GetDirectoryName(options.Output)!;
            if (!Directory.Exists(outputDirectory))
                throw new CollectionException("collector.output_directory", "Output directory must already exist.", outputDirectory);
            var scratch = options.Output + "." + Guid.NewGuid().ToString("N") + ".pending";
            try
            {
                using (var file = new FileStream(scratch, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                using (var bounded = new BoundedWriteStream(file, options.MaxOutputBytes))
                {
                    JsonSerializer.Serialize(bounded, context.Evidence, Json);
                    file.Flush(flushToDisk: true);
                }
                File.Move(scratch, options.Output, overwrite: true);
            }
            finally
            {
                if (File.Exists(scratch)) File.Delete(scratch);
            }
            foreach (var diagnostic in context.Evidence.Diagnostics)
                Console.Error.WriteLine($"{diagnostic.Code}: {diagnostic.Message}");
            Console.WriteLine(JsonSerializer.Serialize(new { schema = context.Evidence.Schema, output = options.Output, artifacts = context.Evidence.Artifacts.Count, sources = context.Evidence.Sources.Count, diagnostics = context.Evidence.Diagnostics.Count }, Json));
            return 0;
        }
        catch (Exception error) when (error is not OutOfMemoryException and not StackOverflowException)
        {
            var code = error is CollectionException known ? known.Code :
                error is IOException or UnauthorizedAccessException ? "collector.io" : "collector.malformed";
            var path = (error as CollectionException)?.InputPath ?? stage;
            Console.Error.WriteLine($"{code}: {error.Message}");
            Console.WriteLine(JsonSerializer.Serialize(new { error = new EvidenceDiagnostic(code, error.Message, path) }, Json));
            return code.StartsWith("resource.collector.", StringComparison.Ordinal) ? 4 : code == "collector.io" ? 3 : 2;
        }
    }

    private static void Sort(Evidence evidence)
    {
        evidence.Artifacts.Sort((a, b) => Compare(a.Kind, b.Kind, a.Path, b.Path));
        evidence.Packages.Sort((a, b) => Compare(a.Target, b.Target, a.Id + "/" + a.Version, b.Id + "/" + b.Version));
        evidence.Assemblies.Sort((a, b) => Compare(a.Name, b.Name, a.Path, b.Path));
        evidence.Sources.Sort((a, b) => Compare(a.Path, b.Path, $"{a.Line:D12}:{a.TypeName}:{a.Member}:{a.Assembly}:{a.Kind}", $"{b.Line:D12}:{b.TypeName}:{b.Member}:{b.Assembly}:{b.Kind}"));
        evidence.Generators.Sort((a, b) => Compare(a.Name, b.Name, a.AssemblyPath, b.AssemblyPath));
        evidence.Resources.Sort((a, b) => Compare(a.Assembly, b.Assembly, a.Container + ":" + a.Name, b.Container + ":" + b.Name));
        evidence.Binaries.Sort((a, b) => StringComparer.Ordinal.Compare(a.Path, b.Path));
        evidence.Mappings.Sort((a, b) => Compare(a.Stream, b.Stream, a.Identity + ":" + a.Assembly + ":" + a.Basis, b.Identity + ":" + b.Assembly + ":" + b.Basis));
        evidence.Diagnostics.Sort((a, b) => Compare(a.Code, b.Code, a.Path + ":" + a.Message, b.Path + ":" + b.Message));
    }

    private static int Compare(string a, string b, string c, string d)
    {
        var first = StringComparer.Ordinal.Compare(a, b);
        return first != 0 ? first : StringComparer.Ordinal.Compare(c, d);
    }
}

internal sealed class BoundedWriteStream(Stream inner, long limit) : Stream
{
    private long written;
    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
    public override void Write(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length > limit - written)
            throw new CollectionException("resource.collector.output", "Output byte budget exceeded.");
        inner.Write(buffer);
        written += buffer.Length;
    }
    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => written;
    public override long Position { get => written; set => throw new NotSupportedException(); }
    public override void Flush() => inner.Flush();
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}
