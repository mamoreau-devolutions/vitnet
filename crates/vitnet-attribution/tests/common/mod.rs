//! Independently assembled data-only ECMA-335/MSTAT fixture, following the
//! repository's `vitnet-mstat/tests/summary.rs` format convention. No executable
//! entry point, producer binaries or application compilation are involved.

pub struct Image {
    bodies: [Vec<u8>; 7],
    names: Vec<u8>,
    strings: Vec<u8>,
}

impl Image {
    pub fn new() -> Self {
        Self {
            bodies: std::array::from_fn(|_| Vec::new()),
            names: Vec::new(),
            strings: vec![0],
        }
    }

    pub fn method(&mut self, raw_name: &[u8], bytes: i32) {
        let offset = i32::try_from(self.names.len()).unwrap();
        compressed(&mut self.names, raw_name.len());
        self.names.extend_from_slice(raw_name);
        let body = &mut self.bodies[0];
        body.push(0xd0);
        body.extend_from_slice(&0x0a00_0001_u32.to_le_bytes());
        for value in [bytes, 0, 0, offset] {
            i4(body, value);
        }
    }

    pub fn blob(&mut self, raw_utf16: &[u16], bytes: i32) {
        let offset = as_u32(self.strings.len());
        compressed(&mut self.strings, raw_utf16.len() * 2 + 1);
        self.strings
            .extend(raw_utf16.iter().flat_map(|unit| unit.to_le_bytes()));
        self.strings.push(1);
        self.bodies[2].push(0x72);
        self.bodies[2].extend_from_slice(&(0x7000_0000 | offset).to_le_bytes());
        i4(&mut self.bodies[2], bytes);
    }

    #[allow(clippy::too_many_lines)] // Keep the synthetic binary layout in one place.
    pub fn bytes(self) -> Vec<u8> {
        let mut strings = vec![0];
        let mut names = Vec::new();
        for name in [
            "Methods",
            "Types",
            "Blobs",
            "RvaFields",
            "FrozenObjects",
            "ManifestResources",
            "DeduplicatedMethods",
            "synthetic.mstat",
        ] {
            names.push(u16::try_from(strings.len()).unwrap());
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
        }
        let metadata = |rvas: &[u32]| {
            let mut tables = vec![0, 0, 0, 0, 2, 0, 0, 1];
            let valid =
                (1_u64 << 0) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 10) | (1 << 26) | (1 << 32);
            tables.extend_from_slice(&valid.to_le_bytes());
            tables.extend_from_slice(&0_u64.to_le_bytes());
            for count in [1_u32, 1, 1, 7, 1, 1, 1] {
                tables.extend_from_slice(&count.to_le_bytes());
            }
            tables.extend_from_slice(&[0; 10]); // Module
            tables.extend_from_slice(&0_u32.to_le_bytes()); // TypeDef flags
            for value in [0_u16, 0, 0, 1, 1] {
                tables.extend_from_slice(&value.to_le_bytes());
            }
            tables.extend_from_slice(&[0; 6]); // Field
            for (rva, name) in rvas.iter().zip(&names[..7]) {
                tables.extend_from_slice(&rva.to_le_bytes());
                for value in [0_u16, 0, *name, 1, 1] {
                    tables.extend_from_slice(&value.to_le_bytes());
                }
            }
            for value in [10_u16, names[0], 1] {
                tables.extend_from_slice(&value.to_le_bytes());
            }
            tables.extend_from_slice(&0_u16.to_le_bytes()); // Explicitly unsupported ModuleRef owner.
            tables.extend_from_slice(&0_u32.to_le_bytes()); // Assembly hash
            for value in [2_u16, 2, u16::MAX, u16::MAX] {
                tables.extend_from_slice(&value.to_le_bytes());
            }
            tables.extend_from_slice(&0_u32.to_le_bytes());
            for value in [0_u16, names[7], 0] {
                tables.extend_from_slice(&value.to_le_bytes());
            }
            let mut root = Vec::new();
            root.extend_from_slice(&0x424a_5342_u32.to_le_bytes());
            root.extend_from_slice(&[1, 0, 1, 0, 0, 0, 0, 0]);
            root.extend_from_slice(&12_u32.to_le_bytes());
            root.extend_from_slice(b"v4.0.30319\0\0");
            root.extend_from_slice(&[0, 0, 4, 0]);
            let blobs = [0_u8, 3, 0, 0, 1]; // Static void(), used by the data-only stream and MemberRef.
            let mut offset = 92_u32;
            for (name, data) in [
                (&b"#~\0\0"[..], &tables[..]),
                (&b"#Strings\0\0\0\0"[..], &strings[..]),
                (&b"#US\0"[..], &self.strings[..]),
                (&b"#Blob\0\0\0"[..], &blobs[..]),
            ] {
                root.extend_from_slice(&offset.to_le_bytes());
                root.extend_from_slice(&as_u32(data.len()).to_le_bytes());
                root.extend_from_slice(name);
                offset += as_u32(data.len());
            }
            assert_eq!(root.len(), 92);
            root.extend_from_slice(&tables);
            root.extend_from_slice(&strings);
            root.extend_from_slice(&self.strings);
            root.extend_from_slice(&blobs);
            root
        };
        let placeholder = metadata(&[0; 7]);
        let mut cursor = align(0x80 + placeholder.len(), 4);
        let mut rvas = Vec::new();
        for body in &self.bodies {
            cursor = align(cursor, 4);
            rvas.push(0x2000 + as_u32(cursor));
            cursor += if body.len() < 64 { 1 } else { 12 };
            cursor += body.len();
        }
        let text_size = align(cursor, 512);
        let names_offset = 512 + text_size;
        let mut bytes = vec![0; names_offset + align(self.names.len().max(1), 512)];
        bytes[..2].copy_from_slice(b"MZ");
        u32_at(&mut bytes, 0x3c, 0x80);
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        u16_at(&mut bytes, 0x84, 0x14c);
        u16_at(&mut bytes, 0x86, 2);
        u16_at(&mut bytes, 0x94, 0xe0);
        u16_at(&mut bytes, 0x98, 0x10b);
        u32_at(&mut bytes, 0x98 + 92, 16);
        u32_at(&mut bytes, 0x98 + 96 + 14 * 8, 0x2000);
        u32_at(&mut bytes, 0x98 + 96 + 14 * 8 + 4, 72);
        for (header, name, virtual_size, rva, raw_size, pointer) in [
            (0x178, &b".text"[..], text_size, 0x2000, text_size, 512),
            (
                0x1a0,
                &b".names"[..],
                self.names.len(),
                0x4000,
                align(self.names.len().max(1), 512),
                names_offset,
            ),
        ] {
            bytes[header..header + name.len()].copy_from_slice(name);
            u32_at(&mut bytes, header + 8, as_u32(virtual_size));
            u32_at(&mut bytes, header + 12, rva);
            u32_at(&mut bytes, header + 16, as_u32(raw_size));
            u32_at(&mut bytes, header + 20, as_u32(pointer));
        }
        let meta = metadata(&rvas);
        u32_at(&mut bytes, 512, 72);
        u16_at(&mut bytes, 516, 2);
        u16_at(&mut bytes, 518, 5);
        u32_at(&mut bytes, 520, 0x2080);
        u32_at(&mut bytes, 524, as_u32(meta.len()));
        bytes[640..640 + meta.len()].copy_from_slice(&meta);
        for (rva, body) in rvas.iter().zip(&self.bodies) {
            let at = 512 + (*rva as usize - 0x2000);
            let header = if body.len() < 64 {
                bytes[at] = u8::try_from(body.len()).unwrap() << 2 | 2;
                1
            } else {
                u16_at(&mut bytes, at, 0x3003);
                u16_at(&mut bytes, at + 2, 8);
                u32_at(&mut bytes, at + 4, as_u32(body.len()));
                12
            };
            bytes[at + header..at + header + body.len()].copy_from_slice(body);
        }
        bytes[names_offset..names_offset + self.names.len()].copy_from_slice(&self.names);
        bytes
    }
}

fn compressed(bytes: &mut Vec<u8>, value: usize) {
    let value = as_u32(value);
    if value < 0x80 {
        bytes.push(u8::try_from(value).unwrap());
    } else if value < 0x4000 {
        bytes.extend_from_slice(&(u16::try_from(value).unwrap() | 0x8000).to_be_bytes());
    } else {
        bytes.extend_from_slice(&(value | 0xc000_0000).to_be_bytes());
    }
}

fn i4(bytes: &mut Vec<u8>, value: i32) {
    bytes.push(0x20);
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn as_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap()
}

fn u16_at(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

pub fn u32_at(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn align(value: usize, boundary: usize) -> usize {
    (value + boundary - 1) & !(boundary - 1)
}
