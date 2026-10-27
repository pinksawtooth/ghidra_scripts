# Ghidra Scripts

[日本語](README.ja.md)

A collection of Python and Java scripts for reverse engineering and malware analysis with Ghidra.

## ApplySig.py

Loads an IDA FLIRT `.sig` file, matches its signatures against functions in the current program, and renames matched default `FUN_` functions. Run it from **Tools > Function ID > ApplySig**.

## ApplyFlirtSignatures.java

A native Java extension of `ApplySig.py` for stricter and more comprehensive FLIRT analysis. Run it from Ghidra's Script Manager.

Additional features include:

- Runs entirely inside Ghidra without launching Rizin or reading `validation.json` or other sidecar files.
- Parses binary IDASGN versions 5 through 10, including compressed signatures for versions 6 through 10.
- Validates exact patterns, CRCs, and tail bytes before modifying the program.
- Discovers candidates beyond existing functions by using entry points, calls, references, relocations, typed pointers, pointer tables, code boundaries, and rare signature anchors.
- Creates functions at verified undefined locations and safely splits contained function candidates only when structural evidence is sufficient.
- Resolves candidates with FLIRT reference-graph and structural evidence; unresolved ambiguity fails closed and is recorded with a bookmark and repeatable comment.
- Names a site whose Rust candidates differ only by the legacy hash or `.llvm` suffix with their shared demangled name, and lists the candidate hashes in a repeatable comment.
- Turns a public symbol at a non-zero module offset into a function only when the address has independent function-start evidence such as a call or an entry point; otherwise it becomes a label.
- When the remaining candidates share a demangled meaning (Rust or MSVC C++), adds an approximate `ambig_` name or label, such as `scalar_deleting_destructor` for the deleting destructors of different classes; when only the owning type or module is shared, adds an `ambig_type_` label instead.
- Preserves user-defined function names and names from the loader, exports or PDB (the loader placeholders `entry` and `tls_callback_<n>` are replaced only by a strong match), groups applied symbols under the signature library namespace, and normalizes or demangles supported Rust symbols (legacy and v0 mangling).
- Records which signature named each function, so applying several signatures one after another never replaces an earlier name with a different identity; such a disagreement keeps the earlier name and is recorded with a bookmark and repeatable comment.
- Supports `--dry-run` analysis, which counts the functions a real run would create and rename without changing the program, and optional JSON reports through `--report-json`.

## findcrypt.py

Searches the current program for known cryptographic constants, including exact arrays, sparse arrays, and immediate operands, then labels or comments on matches.

Memory is read in large pieces and searched with Python's byte search instead of asking Ghidra to search once per constant. On x86, only the instructions that contain the bytes of one of the immediate constants are decoded; set `USE_X86_BYTE_PREFILTER = False` at the top of the script to decode every instruction instead (RIP-relative operands whose target address equals a constant are then reported as well). Other processors always decode every instruction. The scan stops when the task is cancelled. The script needs PyGhidra (CPython 3) and does not run under Jython.

## shellcode_hash_search.py

Looks up immediate values and DWORD arrays in a shellcode API-hash database. It annotates resolved API names and can create structures for consecutive matches.

## struct_typer.py

Matches structure-member or stack-variable names with function definitions in the open data type managers and applies the corresponding function-pointer types. An optional regular expression can remove prefixes from names before matching.

## make_sc_hash_db.py

A standalone Python utility that reads exports from PE files in a directory, calculates common shellcode API hashes, and stores them in a SQLite database for `shellcode_hash_search.py`. Requires the `pefile` package.

## consts.py

The constant database used by `findcrypt.py`. Running it directly prints the supported algorithms and constant names.

## Bundled data

`sc_hashes.zip` contains `sc_hashes.db`, the prebuilt database used by `shellcode_hash_search.py`. Extract `sc_hashes.db` into the same directory as the script, or select the database when prompted.

To build a database from your own PE files instead, run:

```text
python make_sc_hash_db.py <db_path> <dll_dir>
```

## License

See [LICENSE](LICENSE).
