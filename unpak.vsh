#!/usr/bin/env -S v

struct PakFile {
	name string
	size int
}

pak_file_name := 'main.pak'
decrypted_pak_file_name := 'main.pak.decrypted'

// --- DECRYPTION ---

{
	mut pak_file := open_file(pak_file_name, 'rb')!
	defer { pak_file.close() }

	pak_file.seek(0, .end)!
	file_size := int(pak_file.tell()!)
	pak_file.seek(0, .start)!

	mut bytes := pak_file.read_bytes(file_size)

	for mut byte in bytes {
		byte ^= 0xF7
	}

	mut decrypted_pak_file := open_file(decrypted_pak_file_name, 'wb')!
	defer { decrypted_pak_file.close() }

	unsafe { decrypted_pak_file.write_full_buffer(bytes.data, usize(bytes.len))! }
}

// --- DUMPING ---

{
	mut decrypted_pak_file := open_file(decrypted_pak_file_name, 'rb')!
	defer { decrypted_pak_file.close() }

	magic := decrypted_pak_file.read_le[u32]()!
	assert magic == 0xBAC04AC0
	version := decrypted_pak_file.read_le[u32]()!
	assert version <= 0

	mut files := []PakFile{}

	for {
		flags := if f := decrypted_pak_file.read_le[u8]() {
			f
		} else {
			break
		}
		if flags & 0x80 != 0 {
			break
		}

		name_length := decrypted_pak_file.read_le[u8]()!
		name := []u8{len: int(name_length)}
		decrypted_pak_file.read_into_ptr(name.data, name.len)!

		size := decrypted_pak_file.read_le[int]()!
		file_time_1 := decrypted_pak_file.read_le[u32]()!
		_ := file_time_1
		file_time_2 := decrypted_pak_file.read_le[u32]()!
		_ := file_time_2

		files << PakFile{
			name: name.bytestr()
			size: size
		}
	}

	for file in files {
		path := file.name.replace('\\', '/')

		parent := dir(path)
		mkdir_all(parent)!

		mut dumped_file := open_file(path, 'wb')!

		data := []u8{len: file.size}
		decrypted_pak_file.read_into_ptr(data.data, data.len)!

		unsafe { dumped_file.write_full_buffer(data.data, usize(data.len))! }

		dumped_file.close()
	}
}
