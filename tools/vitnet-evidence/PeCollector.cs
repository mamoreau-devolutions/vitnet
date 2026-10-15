using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;

namespace Vitnet.Evidence;

internal static class PeCollector
{
    public static void Managed(CollectionContext context, string path)
    {
        context.Artifact("assembly", path);
        if (!context.Available(path)) return;
        using var stream = context.Open(path);
        using var pe = new PEReader(stream);
        ValidatePe(pe, stream.Length, path);
        if (!pe.HasMetadata)
            throw new CollectionException("assembly.not_managed", "Supplied assembly has no ECMA-335 metadata.", path);
        var reader = pe.GetMetadataReader();
        var name = Identity(context, reader, path);
        var types = new List<ManagedType>();
        foreach (var handle in reader.TypeDefinitions)
        {
            context.Count();
            var type = reader.GetTypeDefinition(handle);
            var typeName = TypeName(reader, handle);
            if (typeName == "<Module>") continue;
            var baseType = EntityTypeName(reader, type.BaseType);
            var kind = baseType == "System.Enum" ? "enum" : baseType == "System.ValueType" ? "value" : "reference";
            var members = (ulong)(type.GetMethods().Count + type.GetFields().Count + type.GetProperties().Count + type.GetEvents().Count);
            context.Count((long)members);
            types.Add(new(typeName, kind, members));
        }
        types.Sort((a, b) => StringComparer.Ordinal.Compare(a.Name, b.Name));
        var packages = context.AssemblyPackages.GetValueOrDefault(path);
        if (packages is { Count: > 1 })
            context.Diagnostic("assembly.package_ambiguous", "Multiple resolved packages route to this assembly; package is unknown.", path);
        context.Count();
        var captured = new Assembly(name, path, packages?.Count == 1 ? packages.Single() : null, types);
        var existing = context.Evidence.Assemblies.FindIndex(assembly => CollectionContext.PathComparer.Equals(assembly.Path, path));
        if (existing >= 0) context.Evidence.Assemblies[existing] = captured;
        else context.Evidence.Assemblies.Add(captured);
        context.Fact("assembly.member_count_basis", "ECMA-335 method+field+property+event definitions, including accessor methods; not source occurrence counts");
        ResourcesCollector.Collect(context, path, pe, reader, name);
        var found = false;
        var debugEntries = pe.ReadDebugDirectory();
        var embeddedPdb = debugEntries.Any(d => d.Type == DebugDirectoryEntryType.EmbeddedPortablePdb);
        foreach (var debug in debugEntries)
        {
            context.Count();
            if (debug.Type == DebugDirectoryEntryType.EmbeddedPortablePdb)
            {
                if (debug.DataSize < 8)
                    throw new CollectionException("pdb.embedded_corrupt", "Embedded portable PDB header is truncated.", path);
                var prefix = pe.GetSectionData(debug.DataRelativeVirtualAddress).GetContent(0, 8).AsSpan();
                var expandedSize = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(prefix[4..]);
                if (expandedSize > context.Options.MaxExpandedBytes)
                    throw new CollectionException("resource.collector.pdb_expanded", "Embedded PDB expanded byte budget exceeded.", path);
                using var provider = pe.ReadEmbeddedPortablePdbDebugDirectoryData(debug);
                context.Fact($"pdb.embedded:{path}", "portable");
                ReadPdb(context, provider.GetMetadataReader(), reader, name, path, Path.GetDirectoryName(path)!, path, "pe_identity_verified");
                found = true;
            }
            else if (debug.Type == DebugDirectoryEntryType.CodeView)
            {
                var codeView = pe.ReadCodeViewDebugDirectoryData(debug);
                context.Fact($"pdb.codeview:{path}", $"{codeView.Guid:D}/{codeView.Age}:{codeView.Path}");
                if (embeddedPdb) continue;
                var pdb = Path.ChangeExtension(path, ".pdb");
                if (!File.Exists(pdb) && Path.IsPathFullyQualified(codeView.Path)) pdb = codeView.Path;
                context.Artifact("pdb", pdb);
                if (context.Available(pdb))
                {
                    Pdb(context, pdb, reader, name, new BlobContentId(codeView.Guid, debug.Stamp), path);
                    found = true;
                }
            }
        }
        if (!found)
            context.Diagnostic("pdb.unavailable", "No available portable PDB provides sequence-point evidence.", path);
    }

    internal static string Identity(CollectionContext context, MetadataReader reader, string path)
    {
        if (!reader.IsAssembly)
            throw new CollectionException("assembly.netmodule", "A managed assembly definition is required (netmodules are unsupported).", path);
        var definition = reader.GetAssemblyDefinition();
        var name = reader.GetString(definition.Name);
        var culture = definition.Culture.IsNil ? "neutral" : reader.GetString(definition.Culture);
        var publicKey = reader.GetBlobBytes(definition.PublicKey);
        var token = publicKey.Length == 0 ? "null" : Convert.ToHexStringLower(SHA1.HashData(publicKey).TakeLast(8).Reverse().ToArray());
        context.Fact($"assembly.identity:{path}", $"{name}, Version={definition.Version}, Culture={culture}, PublicKeyToken={token}");
        context.Fact($"assembly.mvid:{path}", reader.GetGuid(reader.GetModuleDefinition().Mvid).ToString("D"));
        return name;
    }

    internal static (string Name, string Version)? Reference(CollectionContext context, string path)
    {
        context.Artifact("assembly", path);
        if (!context.Available(path)) return null;
        using var stream = context.Open(path);
        using var pe = new PEReader(stream);
        ValidatePe(pe, stream.Length, path);
        if (!pe.HasMetadata)
            throw new CollectionException("assembly.not_managed", "Compiler input assembly is not managed.", path);
        var reader = pe.GetMetadataReader();
        var name = Identity(context, reader, path);
        if (!context.Evidence.Assemblies.Any(assembly => CollectionContext.PathComparer.Equals(assembly.Path, path)))
        {
            var packages = context.AssemblyPackages.GetValueOrDefault(path);
            if (packages is { Count: > 1 })
                context.Diagnostic("assembly.package_ambiguous", "Multiple resolved packages route to this compiler input; package is unknown.", path);
            context.Count();
            context.Evidence.Assemblies.Add(new(name, path, packages?.Count == 1 ? packages.Single() : null, []));
        }
        return (name, reader.GetAssemblyDefinition().Version.ToString());
    }

    public static void Native(CollectionContext context, string path)
    {
        context.Artifact("binary", path);
        if (!context.Available(path)) return;
        using var stream = context.Open(path);
        using var pe = new PEReader(stream);
        ValidatePe(pe, stream.Length, path);
        var sections = new List<BinarySection>();
        foreach (var section in pe.PEHeaders.SectionHeaders)
        {
            context.Count();
            sections.Add(new(section.Name, (ulong)section.SizeOfRawData, (ulong)section.VirtualSize));
        }
        var architecture = pe.PEHeaders.CoffHeader.Machine switch
        {
            Machine.I386 => "x86", Machine.Amd64 => "x64", Machine.Arm64 => "arm64",
            Machine.Arm or Machine.ArmThumb2 => "arm", var machine => $"unknown_0x{(ushort)machine:x4}"
        };
        if (architecture.StartsWith("unknown_", StringComparison.Ordinal))
            context.Diagnostic("binary.architecture_unknown", "PE machine is not one of the named architecture mappings.", path);
        context.Count();
        context.Evidence.Binaries.Add(new(path, pe.PEHeaders.PEHeader!.Magic == PEMagic.PE32Plus ? "pe32_plus" : "pe32", architecture, (ulong)stream.Length, sections));
        context.Fact($"binary.managed_metadata:{path}", pe.HasMetadata ? "present (PE container sizes still physical)" : "absent");
        context.Fact("binary.section_basis", "SizeOfRawData vs VirtualSize; file total also includes headers, overlay/certificates, alignment; not a section sum");
    }

    private static void ValidatePe(PEReader pe, long length, string path)
    {
        if (pe.PEHeaders.PEHeader is not { } header)
            throw new CollectionException("pe.malformed", "Expected a PE image, not a COFF object.", path);
        if (header.SizeOfHeaders < 0 || header.SizeOfHeaders > length)
            throw new CollectionException("pe.truncated", "PE headers extend beyond the file.", path);
        foreach (var section in pe.PEHeaders.SectionHeaders)
        {
            if (section.PointerToRawData < 0 || section.SizeOfRawData < 0 || section.VirtualSize < 0 ||
                section.VirtualAddress < 0 || (long)section.PointerToRawData + section.SizeOfRawData > length)
                throw new CollectionException("pe.truncated", "Invalid or truncated PE section range.", path);
        }
    }

    public static void Pdb(CollectionContext context, string path, MetadataReader? assemblyReader, string assembly, BlobContentId? expected = null, string? assemblyPath = null)
    {
        if (!context.PdbScans.Add(path)) return;
        context.Artifact("pdb", path);
        if (!context.Available(path)) return;
        using var stream = context.Open(path);
        Span<byte> magic = stackalloc byte[4];
        stream.ReadExactly(magic);
        stream.Position = 0;
        if (magic.SequenceEqual("Micr"u8))
        {
            Span<byte> header = stackalloc byte[44];
            var length = stream.Read(header);
            stream.Position = 0;
            if (length >= 32 && header[..32].SequenceEqual("Microsoft C/C++ MSF 7.00\r\n\u001aDS\0\0\0"u8) ||
                length >= 44 && header.SequenceEqual("Microsoft C/C++ program database 2.00\r\n\u001aJG\0\0"u8))
            {
                context.Diagnostic("pdb.native_unsupported", "Native/MSF PDB sequence points are unavailable; this is not portable PDB success.", path);
                return;
            }
            throw new CollectionException("pdb.malformed", "Unrecognized/truncated native PDB signature.", path);
        }
        if (!magic.SequenceEqual("BSJB"u8))
            throw new CollectionException("pdb.malformed", "Expected portable PDB metadata or a recognized native PDB signature.", path);
        using var provider = MetadataReaderProvider.FromPortablePdbStream(stream, MetadataStreamOptions.LeaveOpen);
        var pdb = provider.GetMetadataReader();
        if (pdb.DebugMetadataHeader is null)
            throw new CollectionException("pdb.malformed", "Metadata is not a portable PDB.", path);
        var id = new BlobContentId(pdb.DebugMetadataHeader.Id);
        context.Fact($"pdb.identity:{path}", $"{id.Guid:D}/{id.Stamp}");
        var assemblyMatch = expected.HasValue ? "pe_identity_verified" : "unverified";
        if (expected.HasValue && id != expected.Value)
        {
            context.Diagnostic("pdb.identity_mismatch", "PDB does not match the PE CodeView identity; no assembly/member attribution is assigned.", path);
            assemblyReader = null;
            assembly = "";
            assemblyMatch = "pe_identity_mismatch";
        }
        ReadPdb(context, pdb, assemblyReader, assembly, path, Path.GetDirectoryName(path)!, assemblyPath, assemblyMatch);
    }

    private static void ReadPdb(CollectionContext context, MetadataReader pdb, MetadataReader? assemblyReader, string assembly,
        string pdbPath, string baseDirectory, string? assemblyPath, string assemblyMatch)
    {
        var documents = new Dictionary<DocumentHandle, (string Path, string? Hash)>();
        foreach (var handle in pdb.Documents)
        {
            context.Count();
            var document = pdb.GetDocument(handle);
            var rawPath = pdb.GetString(document.Name);
            if (rawPath.Length == 0)
                throw new CollectionException("pdb.document", "PDB document has an empty name.", pdbPath);
            var path = Path.GetFullPath(rawPath, baseDirectory);
            var algorithm = document.HashAlgorithm.IsNil ? Guid.Empty : pdb.GetGuid(document.HashAlgorithm);
            var recordedHash = Convert.ToHexStringLower(pdb.GetBlobBytes(document.Hash));
            context.Fact($"pdb.document:{pdbPath}:{rawPath}", $"algorithm={algorithm:D};checksum={recordedHash}");
            context.Artifact("source", path);
            string? hash = null;
            var checksumStatus = "unavailable";
            var algorithmName = algorithm == new Guid("8829d00f-11b8-4213-878b-770e8597ac16") ? "sha256" :
                algorithm == new Guid("ff1816ec-aa5e-4d10-87f7-6f4963833460") ? "sha1" : algorithm.ToString("D");
            if (context.Available(path))
            {
                var data = context.ReadBytes(path);
                hash = CollectionContext.Hash(data);
                var actual = algorithm == new Guid("8829d00f-11b8-4213-878b-770e8597ac16") ? hash :
                    algorithm == new Guid("ff1816ec-aa5e-4d10-87f7-6f4963833460") ? Convert.ToHexStringLower(SHA1.HashData(data)) : null;
                if (actual is not null && actual != recordedHash)
                    context.Diagnostic("pdb.document_drift", "Available source checksum differs from the PDB document.", path);
                if (actual is null)
                    context.Diagnostic("pdb.checksum_unknown", "Document checksum algorithm is unsupported.", path);
                checksumStatus = actual is null ? "unsupported" : actual == recordedHash ? "matched" : "drift";
            }
            if (!context.DocumentChecksums.TryGetValue(path, out var checksums))
                context.DocumentChecksums[path] = checksums = [];
            context.Count();
            checksums.Add(new(pdbPath, algorithmName, recordedHash, checksumStatus, assemblyMatch,
                assembly.Length == 0 ? null : assembly, assemblyPath));
            documents.Add(handle, (path, hash));
        }
        foreach (var handle in pdb.MethodDebugInformation)
        {
            context.Count();
            var debug = pdb.GetMethodDebugInformation(handle);
            var row = MetadataTokens.GetRowNumber(handle);
            var typeName = "";
            string? member = null;
            if (assemblyReader is not null)
            {
                if (row > assemblyReader.MethodDefinitions.Count)
                    throw new CollectionException("pdb.method", "PDB method row lies outside associated assembly metadata.", pdbPath);
                var method = assemblyReader.GetMethodDefinition(MetadataTokens.MethodDefinitionHandle(row));
                typeName = TypeName(assemblyReader, method.GetDeclaringType());
                member = assemblyReader.GetString(method.Name);
            }
            foreach (var point in debug.GetSequencePoints())
            {
                context.Count();
                if (point.IsHidden) continue;
                var documentHandle = point.Document.IsNil ? debug.Document : point.Document;
                if (!documents.TryGetValue(documentHandle, out var document))
                    throw new CollectionException("pdb.document", "Sequence point references a missing document.", pdbPath);
                if (point.StartLine < 1 || point.EndLine < point.StartLine)
                    throw new CollectionException("pdb.sequence_point", "Sequence point has invalid line bounds.", pdbPath);
                context.Count();
                context.Evidence.Sources.Add(new(assembly, typeName, member, document.Path, (ulong)point.StartLine, (ulong)point.EndLine,
                    "pdb_sequence_point", [], null, document.Hash));
            }
        }
        if (assemblyReader is null)
            context.Diagnostic("pdb.member_unknown", "Standalone/mismatched PDB has document and sequence-point evidence but no verified assembly/type/member names.", pdbPath);
        if (pdb.CustomDebugInformation.Count != 0)
            context.Diagnostic("pdb.custom_debug_not_used", "SourceLink, embedded-source and other custom PDB records are not downloaded or used as ownership evidence.", pdbPath);
    }

    internal static string TypeName(MetadataReader reader, TypeDefinitionHandle handle)
    {
        var names = new List<string>();
        var seen = new HashSet<TypeDefinitionHandle>();
        string ns = "";
        while (!handle.IsNil)
        {
            if (!seen.Add(handle) || seen.Count > reader.TypeDefinitions.Count)
                throw new BadImageFormatException("Cyclic nested type metadata.");
            var type = reader.GetTypeDefinition(handle);
            names.Add(reader.GetString(type.Name));
            if (!type.Namespace.IsNil) ns = reader.GetString(type.Namespace);
            handle = type.GetDeclaringType();
        }
        names.Reverse();
        return (ns.Length == 0 ? "" : ns + ".") + string.Join("+", names);
    }

    private static string EntityTypeName(MetadataReader reader, EntityHandle handle)
    {
        if (handle.Kind == HandleKind.TypeDefinition) return TypeName(reader, (TypeDefinitionHandle)handle);
        if (handle.Kind != HandleKind.TypeReference) return "";
        var type = reader.GetTypeReference((TypeReferenceHandle)handle);
        var ns = reader.GetString(type.Namespace);
        return (ns.Length == 0 ? "" : ns + ".") + reader.GetString(type.Name);
    }
}
