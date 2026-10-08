using System.Buffers.Binary;
using System.Collections;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Resources;
using System.Text;

namespace Vitnet.Evidence;

internal static class ResourcesCollector
{
    private const string AvaloniaSource = "https://github.com/AvaloniaUI/Avalonia/blob/6dd9eb473b74a56cc42e5bc118cfe918b48a940b/src/Avalonia.Base/Utilities/AvaloniaResourcesIndex.cs";

    public static void Collect(CollectionContext context, string path, PEReader pe, MetadataReader reader, string assembly)
    {
        if (reader.ManifestResources.Count == 0) return;
        var directory = pe.PEHeaders.CorHeader!.ResourcesDirectory;
        if (directory.Size < 0)
            throw new CollectionException("resource.manifest", "Negative managed resource directory size.", path);
        var block = directory.Size == 0 ? default : pe.GetSectionData(directory.RelativeVirtualAddress);
        foreach (var handle in reader.ManifestResources)
        {
            context.Count();
            var resource = reader.GetManifestResource(handle);
            var name = reader.GetString(resource.Name);
            if (!resource.Implementation.IsNil)
            {
                context.Diagnostic("resource.external_unavailable", $"Manifest resource {name} is linked/forwarded; it was not assigned zero bytes.", path);
                continue;
            }
            if (resource.Offset > int.MaxValue || resource.Offset > directory.Size - 4L)
                throw new CollectionException("resource.manifest", $"Resource {name} has an invalid offset.", path);
            var offset = (int)resource.Offset;
            var prefix = block.GetContent(offset, 4).AsSpan();
            var size = BinaryPrimitives.ReadInt32LittleEndian(prefix);
            if (size < 0 || (long)offset + 4 + size > directory.Size || (long)offset + 4 + size > block.Length)
                throw new CollectionException("resource.manifest", $"Resource {name} is truncated.", path);
            if (size > context.Options.MaxResourceBytes)
                throw new CollectionException("resource.collector.resource_bytes", $"Manifest resource {name} exceeds resource byte budget.", path);
            var data = block.GetContent(offset + 4, size).AsSpan();
            context.Resource(assembly, name, name, data, path, "manifest_container");
            if (name == "!AvaloniaResources")
                Avalonia(context, assembly, name, data, path);
            else if (name.EndsWith(".resources", StringComparison.OrdinalIgnoreCase))
                DotNetResources(context, assembly, name, data, path);
        }
    }

    private static void Avalonia(CollectionContext context, string assembly, string container, ReadOnlySpan<byte> data, string path)
    {
        context.Fact("resource.avalonia.format_source", AvaloniaSource);
        context.Fact("resource.avalonia.producer_version", "Avalonia 11.3.8; binary index version 2");
        if (data.Length < 8)
            throw new CollectionException("resource.avalonia_corrupt", "Truncated Avalonia resource index header.", path);
        var length = BinaryPrimitives.ReadInt32LittleEndian(data);
        if (length < 4 || length > data.Length - 4)
            throw new CollectionException("resource.avalonia_corrupt", "Invalid Avalonia resource index length.", path);
        var version = BinaryPrimitives.ReadInt32LittleEndian(data[4..]);
        if (version != 2)
        {
            context.Diagnostic("resource.avalonia_unsupported", $"Avalonia index version {version} is unsupported; only container bytes are known.", path);
            return;
        }
        if (length < 8)
            throw new CollectionException("resource.avalonia_corrupt", "Truncated Avalonia resource entry count.", path);
        using var stream = new MemoryStream(data.Slice(4, length).ToArray(), writable: false);
        using var reader = new BinaryReader(stream, new UTF8Encoding(false, true));
        reader.ReadInt32();
        var count = reader.ReadInt32();
        if (count < 0 || count > (length - 8) / 9)
            throw new CollectionException("resource.avalonia_corrupt", "Impossible Avalonia resource count.", path);
        context.Count(count);
        var names = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < count; i++)
        {
            var name = reader.ReadString();
            var offset = reader.ReadInt32();
            var size = reader.ReadInt32();
            if (name.Length == 0 || !names.Add(name) || offset < 0 || size < 0 || (long)length + 4 + offset + size > data.Length)
                throw new CollectionException("resource.avalonia_corrupt", "Invalid/duplicate Avalonia resource name or data range.", path);
            context.Resource(assembly, container, name, data.Slice(length + 4 + offset, size), path, "avalonia_asset");
        }
        if (stream.Position != stream.Length)
            throw new CollectionException("resource.avalonia_corrupt", "Unexpected trailing Avalonia index bytes.", path);
    }

    private static void DotNetResources(CollectionContext context, string assembly, string container, ReadOnlySpan<byte> data, string path)
    {
        if (data.Length < 12 || BinaryPrimitives.ReadUInt32LittleEndian(data) != 0xbeefcace)
            throw new CollectionException("resource.resources_corrupt", "Invalid .resources header.", path);
        var headerVersion = BinaryPrimitives.ReadInt32LittleEndian(data[4..]);
        if (headerVersion != 1)
        {
            context.Diagnostic("resource.resources_unsupported", $"Unsupported .resources header version {headerVersion}; only container bytes are known.", path);
            return;
        }
        var headerBytes = BinaryPrimitives.ReadInt32LittleEndian(data[8..]);
        if (headerBytes < 0 || headerBytes > data.Length - 12)
            throw new CollectionException("resource.resources_corrupt", "Invalid .resources reader header range.", path);
        using var stream = new MemoryStream(data.ToArray(), writable: false);
        using (var header = new BinaryReader(stream, new UTF8Encoding(false, true), leaveOpen: true))
        {
            stream.Position = 12;
            var readerName = header.ReadString();
            if (!readerName.StartsWith("System.Resources.ResourceReader,", StringComparison.Ordinal))
            {
                context.Diagnostic("resource.resources_reader_unsupported", "Custom .resources readers are not instantiated; only container bytes are known.", path);
                return;
            }
            stream.Position = 12 + headerBytes;
            var version = header.ReadInt32();
            if (version != 2)
            {
                context.Diagnostic("resource.resources_unsupported", $".resources data version {version} is unsupported; only container bytes are known.", path);
                return;
            }
            var count = header.ReadInt32();
            var types = header.ReadInt32();
            if (count < 0 || types < 0 || count > data.Length / 8 || types > data.Length)
                throw new CollectionException("resource.resources_corrupt", "Impossible .resources name/type count.", path);
            context.Count((long)count + types);
        }
        stream.Position = 0;
        using var resources = new ResourceReader(stream);
        IDictionaryEnumerator enumerator = resources.GetEnumerator();
        while (enumerator.MoveNext())
        {
            var name = (string)enumerator.Key;
            // GetResourceData returns serialized bytes, never application objects.
            resources.GetResourceData(name, out var typeName, out var bytes);
            context.Resource(assembly, container, name, bytes, path, "resources_serialized");
            context.Fact($"resource.serialized_type:{path}:{container}:{name}", typeName);
        }
    }
}
