# Ghidra Scripts

[日本語](README.ja.md)

A collection of Python and Java scripts for reverse engineering and malware analysis with Ghidra.

## ApplySig.py

Loads an IDA FLIRT `.sig` file, matches its signatures against functions in the current program, and renames matched default `FUN_` functions. Run it from **Tools > Function ID > ApplySig**.

## ApplyFlirtSignatures.java

A native Java extension of `ApplySig.py` for stricter and more comprehensive FLIRT analysis. It reads binary IDASGN versions 5 through 10 directly without Rizin or sidecar files, validates patterns, CRCs, and tail bytes before modifying the program, and can discover and create previously undefined functions. Ambiguous matches are annotated instead of being guessed. Dry-run mode and JSON reports are also supported. Run it from **Tools > FLIRT > Apply FLIRT Signatures**.

## findcrypt.py

Searches the current program for known cryptographic constants, including exact arrays, sparse arrays, and immediate operands, then labels or comments on matches.

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
