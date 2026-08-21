// Apply standard IDASGN FLIRT signatures in Ghidra without Rizin at runtime.
//@category FLIRT
//@menupath Tools.FLIRT.Apply FLIRT Signatures

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.NavigableSet;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.InflaterInputStream;

import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.analysis.rust.demangler.RustDemangler;
import ghidra.app.plugin.core.analysis.rust.demangler.RustDemanglerOptions;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.MangledContext;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

/**
 * Native Java implementation of strict SIG-only FLIRT signature application.
 *
 * <p>The selected .sig is read-only.  The script never launches Rizin and
 * never consumes validation.json or a sidecar.  It supports IDASGN versions
 * 5..10, including the compressed Rizin 0.9.1 v10 files used by this project.
 * Exact pattern, CRC and tail checks are performed before any Program DB
 * mutation.  Ambiguous identities fail closed and receive an Analysis /
 * FLIRT/Ambiguous bookmark plus a repeatable comment.</p>
 */
public class ApplyFlirtSignatures extends GhidraScript {
    private static final String TOOL_VERSION = "1.0";
    private static final int FEATURE_COMPRESSED = 0x10;
    private static final int MORE_PUBLICS = 0x01;
    private static final int READ_TAILS = 0x02;
    private static final int READ_REFS = 0x04;
    private static final int MORE_SAME_CRC = 0x08;
    private static final int MORE_MODULES = 0x10;
    private static final int FUNCTION_LOCAL = 0x02;
    private static final int FUNCTION_COLLISION = 0x08;

    private static final int MATCH_WINDOW = 512;
    private static final int SIG_ANCHOR_BYTES = 8;
    private static final int SIG_ANCHOR_MAX_TREE_FANOUT = 64;
    private static final int SIG_ANCHOR_MIN_SEPARATION = SIG_ANCHOR_BYTES;
    private static final int MAX_SIG_ANCHOR_CANDIDATES = 250_000;
    private static final int MAX_EXECUTABLE_SNAPSHOT_CHUNK = 64 * 1024 * 1024;
    private static final int MIN_RENAME_FIXED = 16;
    private static final int MIN_CREATE_FIXED = 20;
    private static final int MIN_RENAME_CORROBORATED = 8;
    private static final int MIN_CREATE_CORROBORATED = 10;
    private static final int MIN_CRC = 4;
    private static final int MIN_STRUCTURAL_FIXED = 10;
    private static final int MAX_LOW_EVIDENCE_FANOUT = 4;
    private static final int MAX_CFG_INSTRUCTIONS = 512;
    private static final int MAX_CFG_BYTES = 0x4000;
    private static final int MAX_POINTER_SLOTS = 2_000_000;
    private static final int POINTER_CHUNK = 0x10000;
    private static final int MAX_SIGNATURE_BYTES = 256 * 1024 * 1024;
    private static final int MAX_INFLATED_BYTES = 512 * 1024 * 1024;
    private static final int MAX_NAME = 1024;
    private static final int NAME_CACHE_LIMIT = 100_000;
    private static final boolean TRUST_EXACT_DATA_RELOCATION_POINTERS = true;
    private static final boolean ENABLE_SIG_REFERENCE_GRAPH = true;
    private static final int SOURCE_EXISTING = 1;
    private static final int SOURCE_ENTRY = 2;
    private static final int SOURCE_LINEAR_CALL = 4;
    private static final int SOURCE_LINEAR_TAIL = 8;
    private static final int SOURCE_REFERENCE = 16;
    private static final int SOURCE_RELOCATION = 32;
    private static final int SOURCE_TYPED_POINTER = 64;
    private static final int SOURCE_POINTER_TABLE = 128;
    private static final int SOURCE_BOUNDARY = 256;
    private static final int SOURCE_SIG_ANCHOR = 512;
    private static final int SOURCE_SIG_ANCHOR_VERIFIED = 1024;
    /** Exact pointer-sized relocation stored in initialized non-executable data. */
    private static final int SOURCE_DATA_RELOCATION_POINTER = 2048;

    private static final Pattern RUST_UNICODE =
        Pattern.compile("_u([0-9A-Fa-f]{2,6})_");
    private static final Pattern RUST_CANONICAL_UNICODE =
        Pattern.compile("\\$u([0-9A-Fa-f]{2,6})\\$");
    private static final Pattern RUST_STRUCTURAL_SANITIZED =
        Pattern.compile("_(?:LT|GT|SP|BP|RF|LP|RP)_|_u[0-9A-Fa-f]{2,6}_");
    private static final Map<String, String> RUST_RESTORE_CACHE = new HashMap<>();
    private static final Map<String, String> RUST_DEMANGLE_CACHE = new HashMap<>();
    private static final Map<String, String> RUST_SEMANTIC_CACHE = new HashMap<>();

    private Memory memory;
    private Listing listing;
    private FunctionManager functions;
    private ReferenceManager references;
    private SymbolTable symbols;
    private Namespace libraryNamespace;
    private SigFile signature;
    private Path signaturePath;
    private boolean dryRun;
    private Path reportPath;

    private final Map<Long, Site> sites = new TreeMap<>();
    private final Map<Long, Integer> discoveredSources = new HashMap<>();
    private final Map<String, Set<Long>> fanoutSites = new HashMap<>();
    private final Map<Long, Set<Long>> dataRelocationPointerSources = new HashMap<>();
    private final Set<Long> appliedFunctionSites = new HashSet<>();
    private final List<Site> ambiguousSites = new ArrayList<>();
    private final List<ExecutableSnapshot> executableSnapshots = new ArrayList<>();
    private final Map<Long, List<AnchorProbe>> rareAnchorIndex = new HashMap<>();
    private final List<SemanticDiagnostic> semanticDiagnostics = new ArrayList<>();
    private final List<FunctionProofDiagnostic> functionProofDiagnostics = new ArrayList<>();
    private final List<DataRelocationNameDiagnostic> dataRelocationNameDiagnostics =
        new ArrayList<>();
    private final List<Long> sigGraphResolvedSites = new ArrayList<>();
    private final List<Long> structuralResolvedSites = new ArrayList<>();
    private final List<Long> dataRelocationIdentityResolvedSites = new ArrayList<>();
    private final Map<String, Long> functionOnlyFailureReasons = new TreeMap<>();
    private final NavigableSet<Long> protectedFunctionEntries = new TreeSet<>();

    private long functionsMatched;
    private long functionsCreated;
    private long functionsSplit;
    private long splitsRejected;
    private long splitRestoreFailures;
    private long renamed;
    private long alreadyCorrect;
    private long skippedUserNames;
    private long errors;
    private long namespaceErrors;
    private long nativeInstructions;
    private long nativeDecodeFailures;
    private long nativeCallFlows;
    private long nativeTailFlows;
    private long referenceCandidates;
    private long relocationCandidates;
    private long dataRelocationStructureAccepted;
    private long structuralIdentitiesResolved;
    private long dataRelocationIdentitiesResolved;
    private long typedPointerCandidates;
    private long pointerSlotsScanned;
    private long pointerTableCandidates;
    private long boundaryCandidates;
    private long boundaryMatches;
    private long flowCandidates;
    private long nativeTested;
    private long nativeSigMatches;
    private long weakRejected;
    private long ambiguousRejected;
    private long fanoutRejected;
    private long acceptedStrong;
    private long acceptedCrcTail;
    private long acceptedReference;
    private long acceptedStructure;
    private long ambiguousAnnotated;
    private long ambiguousFunctionsCreated;
    private long logicalConsensusSymbols;
    private long semanticAliases;
    private long semanticExisting;
    private long semanticNameSkips;
    private long semanticNoFunction;
    private long semanticLabels;
    private long semanticLabelsExisting;
    private long semanticLabelsContainingSkipped;
    private long semanticLabelErrors;
    private long operationConsensusSites;
    private long operationLabels;
    private long operationLabelsExisting;
    private long operationLabelSkips;
    private long operationLabelErrors;
    private long functionOnlyAttempts;
    private long functionOnlyProofs;
    private long functionOnlyCreated;
    private long paddingCfgProofs;
    private long naturalCfgProofs;
    private long explicitBodyCreated;
    private long nonContiguousBodyCreated;
    private long layoutCandidatesPruned;
    private long layoutSitesNarrowed;
    private long layoutIdentitiesResolved;
    private long computedCfgSites;
    private long computedCfgResolved;
    private long computedCfgRejected;
    private long sigGraphRounds;
    private long sigGraphConstraints;
    private long sigGraphCandidatesPruned;
    private long sigGraphSitesNarrowed;
    private long sigGraphIdentitiesResolved;
    private long sigGraphConflicts;
    private long pseudoScanAttempts;
    private long structuralDecodeCacheHits;
    private long structuralDecodeCacheMisses;
    private long validSubroutineCacheHits;
    private long validSubroutineCacheMisses;
    private long executableSnapshotBytes;
    private long executableSnapshotBlocks;
    private long executableSnapshotReads;
    private long executableSnapshotFallbacks;
    private long sigAnchorLeafPaths;
    private long sigAnchorAnchoredPaths;
    private long sigAnchorFanoutSkipped;
    private long sigAnchorFixedWindows;
    private long sigAnchorSecondaryPaths;
    private long sigAnchorSecondaryChecks;
    private long sigAnchorSecondaryRejected;
    private long sigAnchorBytesScanned;
    private long sigAnchorRawHits;
    private long sigAnchorCandidates;
    private long sigAnchorSignatureHits;
    private long sigAnchorCfgRejected;
    private long rustNamesRestored;
    private long rustNamesDemangled;
    private long rustDemangleFailed;
    private long rawNamesPreserved;
    private long startedNanos;
    private long parseNanos;
    private long initialMatchNanos;
    private long discoveryNanos;
    private long probeNanos;
    private long applyNanos;
    private long snapshotNanos;
    private long anchorIndexNanos;
    private long anchorScanNanos;
    private int changeLogCount;
    private boolean changeLogSuppressed;

    private static final class Cursor {
        final byte[] data;
        int p;
        Cursor(byte[] data) { this.data = data; }
        int remaining() { return data.length - p; }
        int u8() throws IOException {
            if (p >= data.length) throw new IOException("unexpected end of SIG");
            return data[p++] & 0xff;
        }
        int u16le() throws IOException { return u8() | (u8() << 8); }
        int u16be() throws IOException { return (u8() << 8) | u8(); }
        long u32le() throws IOException {
            return Integer.toUnsignedLong(u8() | (u8() << 8) |
                (u8() << 16) | (u8() << 24));
        }
        long u32be() throws IOException {
            return Integer.toUnsignedLong((u8() << 24) | (u8() << 16) |
                (u8() << 8) | u8());
        }
        int u24be() throws IOException { return (u8() << 16) | (u8() << 8) | u8(); }
        byte[] bytes(int n) throws IOException {
            if (n < 0 || n > remaining()) throw new IOException("truncated SIG field");
            byte[] result = Arrays.copyOfRange(data, p, p + n);
            p += n;
            return result;
        }
        int max2() throws IOException {
            int b = u8();
            return (b & 0x80) != 0 ? ((b & 0x7f) << 8) | u8() : b;
        }
        long multiple() throws IOException {
            int b = u8();
            if ((b & 0x80) == 0) return b;
            if ((b & 0xc0) != 0xc0) return ((long)(b & 0x7f) << 8) | u8();
            if ((b & 0xe0) != 0xe0) return ((long)(b & 0x3f) << 24) | u24be();
            return u32be();
        }
    }

    private static final class Header {
        int version;
        int arch;
        long fileTypes;
        int osTypes;
        int appTypes;
        int features;
        long nFunctions;
        int patternSize;
        String libraryName;
    }

    private static final class PublicSymbol {
        final String name;
        final long offset;
        final boolean negative;
        final boolean local;
        final boolean collision;
        PublicSymbol(String name, long offset, boolean negative,
                     boolean local, boolean collision) {
            this.name = name;
            this.offset = offset;
            this.negative = negative;
            this.local = local;
            this.collision = collision;
        }
    }

    private static final class TailByte {
        final long offset;
        final int value;
        TailByte(long offset, int value) { this.offset = offset; this.value = value; }
    }

    private static final class Module {
        final int crcLength;
        final int crc16;
        final long length;
        final List<PublicSymbol> publics;
        final List<TailByte> tails;
        final List<PublicSymbol> refs;
        int fixedBytes;
        int wildcardBytes;
        int patternBytes;
        int leafCandidates;
        Module(int crcLength, int crc16, long length,
               List<PublicSymbol> publics, List<TailByte> tails,
               List<PublicSymbol> refs) {
            this.crcLength = crcLength;
            this.crc16 = crc16;
            this.length = length;
            this.publics = publics;
            this.tails = tails;
            this.refs = refs;
        }
        String primaryName() {
            PublicSymbol best = null;
            for (PublicSymbol item : publics) {
                if (item.local || item.name.isEmpty() || item.name.equals("?")) continue;
                if (best == null || item.offset < best.offset) best = item;
            }
            if (best != null) return best.name;
            for (PublicSymbol item : publics) {
                if (!item.name.isEmpty() && !item.name.equals("?")) return item.name;
            }
            return null;
        }
    }

    private static final class Node {
        final int length;
        final boolean[] wildcard;
        final byte[] pattern;
        final List<Node> children = new ArrayList<>();
        final List<Module> modules = new ArrayList<>();
        Node(int length, boolean[] wildcard, byte[] pattern) {
            this.length = length;
            this.wildcard = wildcard;
            this.pattern = pattern;
        }
        boolean leaf() { return children.isEmpty(); }
    }

    private static final class SigFile {
        final Header header;
        final Node root;
        final Map<Integer, List<Node>> firstByte = new HashMap<>();
        final List<Node> firstFallback = new ArrayList<>();
        long modules;
        SigFile(Header header, Node root) {
            this.header = header;
            this.root = root;
            for (Node child : root.children) {
                if (child.length > 0 && !child.wildcard[0]) {
                    firstByte.computeIfAbsent(child.pattern[0] & 0xff,
                        ignored -> new ArrayList<>()).add(child);
                }
                else firstFallback.add(child);
            }
            Deque<Node> work = new ArrayDeque<>();
            work.push(root);
            while (!work.isEmpty()) {
                Node node = work.pop();
                modules += node.modules.size();
                work.addAll(node.children);
            }
        }
    }

    private static final class MatchResult {
        final Module module;
        final int patternEnd;
        MatchResult(Module module, int patternEnd) {
            this.module = module;
            this.patternEnd = patternEnd;
        }
    }

    private static final class Site {
        final Address address;
        int sources;
        boolean existing;
        List<MatchResult> matches = Collections.emptyList();
        List<MatchResult> survivors = Collections.emptyList();
        Integer provenLength;
        boolean functionOnlyProof;
        AddressSet provenBody;
        String functionProofKind;
        List<Long> functionProofSigLengths = Collections.emptyList();
        String functionCreationFailure;
        Site(Address address) { this.address = address; }
    }

    private static final class LeafPattern {
        final byte[] pattern;
        final boolean[] wildcard;
        LeafPattern(byte[] pattern, boolean[] wildcard) {
            this.pattern = pattern;
            this.wildcard = wildcard;
        }
    }

    private static final class AnchorProbe {
        final int primaryOffset;
        final int secondaryOffset;
        final long secondaryKey;
        AnchorProbe(int primaryOffset, int secondaryOffset, long secondaryKey) {
            this.primaryOffset = primaryOffset;
            this.secondaryOffset = secondaryOffset;
            this.secondaryKey = secondaryKey;
        }
        boolean hasSecondary() { return secondaryOffset >= 0; }
        @Override
        public boolean equals(Object value) {
            if (!(value instanceof AnchorProbe)) return false;
            AnchorProbe other = (AnchorProbe)value;
            return primaryOffset == other.primaryOffset &&
                secondaryOffset == other.secondaryOffset && secondaryKey == other.secondaryKey;
        }
        @Override
        public int hashCode() {
            return java.util.Objects.hash(primaryOffset, secondaryOffset, secondaryKey);
        }
    }

    private static final class ExecutableSnapshot {
        final Address start;
        final Address end;
        final byte[] bytes;
        ExecutableSnapshot(Address start, Address end, byte[] bytes) {
            this.start = start;
            this.end = end;
            this.bytes = bytes;
        }
        boolean contains(Address address) {
            return address.compareTo(start) >= 0 && address.compareTo(end) <= 0;
        }
    }

    private static final class SemanticDiagnostic {
        final String kind;
        final Address address;
        final String reason;
        final String existingName;
        final String existingSource;
        final String semantic;
        final String proposedAlias;
        final List<String> candidates;
        final boolean labelApplied;
        SemanticDiagnostic(String kind, Address address, String reason,
                           String existingName, String existingSource,
                           String semantic, String proposedAlias,
                           List<String> candidates, boolean labelApplied) {
            this.kind = kind;
            this.address = address;
            this.reason = reason;
            this.existingName = existingName;
            this.existingSource = existingSource;
            this.semantic = semantic;
            this.proposedAlias = proposedAlias;
            this.candidates = candidates;
            this.labelApplied = labelApplied;
        }
    }

    private static final class FunctionProofDiagnostic {
        final Address address;
        final String proofKind;
        final int sources;
        final int bodyRanges;
        final long bodyBytes;
        final List<Long> signatureLengths;
        final String semantic;
        final int dataRelocationPointers;
        FunctionProofDiagnostic(Site site, String semantic,
                                int dataRelocationPointers) {
            this.address = site.address;
            this.proofKind = site.functionProofKind;
            this.sources = site.sources;
            this.bodyRanges = site.provenBody == null ? 0 :
                site.provenBody.getNumAddressRanges();
            this.bodyBytes = site.provenBody == null ? 0 :
                site.provenBody.getNumAddresses();
            this.signatureLengths = new ArrayList<>(site.functionProofSigLengths);
            this.semantic = semantic;
            this.dataRelocationPointers = dataRelocationPointers;
        }
    }

    private static final class StructuralEvidence {
        boolean validSubroutine;
        boolean allPathsClosed;
        boolean terminalExact;
        boolean exactExtent;
        boolean trustedOrigin;
        boolean computedJumpSeen;
        boolean computedJumpResolved;
        boolean safePaddingExact;
        AddressSet reachableBody;
        long maxInstructionEnd = -1;
        int terminalCount;
        int instructionCount;
        boolean verified() {
            return trustedOrigin && allPathsClosed && terminalExact &&
                (validSubroutine || exactExtent || computedJumpResolved);
        }
        boolean functionBoundaryVerified() {
            return trustedOrigin && allPathsClosed &&
                (terminalExact || safePaddingExact) &&
                (validSubroutine || computedJumpResolved);
        }
    }

    private static final class DataRelocationNameDiagnostic {
        final Address address;
        final String identity;
        final int pointerSources;
        final int fixedBytes;
        final int crcBytes;
        final int leafCandidates;
        final int nameFanout;
        final long moduleLength;
        final long bodyBytes;
        DataRelocationNameDiagnostic(Address address, String identity,
                                     int pointerSources, Module module,
                                     int nameFanout, long bodyBytes) {
            this.address = address;
            this.identity = identity;
            this.pointerSources = pointerSources;
            this.fixedBytes = module.fixedBytes;
            this.crcBytes = module.crcLength;
            this.leafCandidates = module.leafCandidates;
            this.nameFanout = nameFanout;
            this.moduleLength = module.length;
            this.bodyBytes = bodyBytes;
        }
    }

    @Override
    protected void run() throws Exception {
        startedNanos = System.nanoTime();
        resetNameCaches();
        parseArguments();
        initializeProgramHandles();

        long phase = System.nanoTime();
        signature = parseSignature(signaturePath);
        parseNanos = System.nanoTime() - phase;
        validateTarget();
        libraryNamespace = dryRun ? null : makeNamespace(libraryName());

        phase = System.nanoTime();
        snapshotExecutableMemory();
        snapshotNanos = System.nanoTime() - phase;

        phase = System.nanoTime();
        buildRareAnchorIndex();
        anchorIndexNanos = System.nanoTime() - phase;

        printf("Apply FLIRT Signatures %s: parsed %,d modules from %s%n",
            TOOL_VERSION, signature.modules, signaturePath);

        phase = System.nanoTime();
        collectExistingFunctionSites();
        initialMatchNanos = System.nanoTime() - phase;

        phase = System.nanoTime();
        discoverNativeCandidates();
        discoveryNanos = System.nanoTime() - phase;

        phase = System.nanoTime();
        probeNativeSites();
        buildGlobalFanout();
        probeNanos = System.nanoTime() - phase;

        phase = System.nanoTime();
        decideAndApply();
        resolveBySigReferenceGraph();
        processAmbiguousSites();
        applyNanos = System.nanoTime() - phase;

        printReport();
        if (reportPath != null) writeJsonReport(reportPath);
    }

    private void parseArguments() throws Exception {
        String[] args = getScriptArgs();
        Path selected = null;
        for (int argumentIndex = 0; argumentIndex < args.length; argumentIndex++) {
            String arg = args[argumentIndex];
            if (arg.equals("--dry-run")) dryRun = true;
            else if (arg.equals("--report-json")) {
                if (++argumentIndex >= args.length)
                    throw new IllegalArgumentException("--report-json requires a path");
                reportPath = Path.of(args[argumentIndex]).toAbsolutePath();
            }
            else if (arg.startsWith("--report-json=")) {
                reportPath = Path.of(arg.substring("--report-json=".length())).toAbsolutePath();
            }
            else if (arg.startsWith("--")) {
                throw new IllegalArgumentException("unknown option: " + arg);
            }
            else if (selected == null) selected = Path.of(arg).toAbsolutePath();
            else throw new IllegalArgumentException("only one signature path is allowed");
        }
        if (selected == null) {
            File file = askFile("Select IDASGN FLIRT signature", "Open");
            if (file == null) throw new IllegalArgumentException("no signature selected");
            selected = file.toPath().toAbsolutePath();
        }
        if (!Files.isRegularFile(selected))
            throw new IllegalArgumentException("signature does not exist: " + selected);
        if (Files.size(selected) > MAX_SIGNATURE_BYTES)
            throw new IllegalArgumentException("signature is too large: " + selected);
        signaturePath = selected;
        if (reportPath != null) {
            if (!reportPath.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".json"))
                throw new IllegalArgumentException("report path must end in .json");
            if (reportPath.equals(signaturePath))
                throw new IllegalArgumentException("report path must not be the signature path");
            Path parent = reportPath.getParent();
            if (parent == null || !Files.isDirectory(parent))
                throw new IllegalArgumentException("report directory does not exist: " + parent);
        }
    }

    private void initializeProgramHandles() {
        memory = currentProgram.getMemory();
        listing = currentProgram.getListing();
        functions = currentProgram.getFunctionManager();
        references = currentProgram.getReferenceManager();
        symbols = currentProgram.getSymbolTable();
        FunctionIterator iterator = functions.getFunctions(true);
        while (iterator.hasNext()) {
            Function function = iterator.next();
            if (protectedLayoutFunction(function))
                protectedFunctionEntries.add(function.getEntryPoint().getOffset());
        }
    }

    private SigFile parseSignature(Path path) throws Exception {
        byte[] raw = Files.readAllBytes(path);
        Cursor input = new Cursor(raw);
        String magic = new String(input.bytes(6), StandardCharsets.US_ASCII);
        if (!magic.equals("IDASGN"))
            throw new IOException("only binary IDASGN .sig is supported by the Java script");
        Header h = new Header();
        h.version = input.u8();
        if (h.version < 5 || h.version > 10)
            throw new IOException("unsupported IDASGN version: " + h.version);
        h.arch = input.u8();
        h.fileTypes = input.u32le();
        h.osTypes = input.u16le();
        h.appTypes = input.u16le();
        h.features = input.u16le();
        int oldFunctions = input.u16le();
        input.u16le();
        input.bytes(12);
        int libraryLength = input.u8();
        input.u16le();
        h.nFunctions = oldFunctions;
        if (h.version >= 6) {
            h.nFunctions = input.u32le();
            if (h.version >= 8) {
                h.patternSize = input.u16le();
                if (h.version > 9) input.u16le();
            }
        }
        h.libraryName = new String(input.bytes(libraryLength), StandardCharsets.ISO_8859_1)
            .replace("\0", "").trim();
        byte[] treeBytes = input.bytes(input.remaining());
        if ((h.features & FEATURE_COMPRESSED) != 0) {
            if (h.version == 5) throw new IOException("compressed v5 SIG is unsupported");
            treeBytes = inflateBounded(treeBytes);
        }
        Cursor tree = new Cursor(treeBytes);
        Node root = parseTree(tree, h.version, true);
        if (tree.remaining() != 0) {
            // Rizin emits a complete single tree.  Trailing bytes indicate a
            // parser/format mismatch and are rejected rather than guessed.
            throw new IOException("unexpected trailing SIG tree bytes: " + tree.remaining());
        }
        return new SigFile(h, root);
    }

    private static byte[] inflateBounded(byte[] compressed) throws IOException {
        try (InflaterInputStream in = new InflaterInputStream(new ByteArrayInputStream(compressed));
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[65536];
            int total = 0;
            for (;;) {
                int read = in.read(buffer);
                if (read < 0) break;
                total += read;
                if (total > MAX_INFLATED_BYTES)
                    throw new IOException("inflated signature exceeds safety limit");
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        }
    }

    private static Node parseTree(Cursor c, int version, boolean root) throws IOException {
        int length = 0;
        boolean[] wildcard = new boolean[0];
        byte[] pattern = new byte[0];
        if (!root) {
            length = c.u8();
            long mask = readVariantMask(c, length);
            wildcard = new boolean[length];
            pattern = new byte[length];
            long bit = 1L << (length - 1);
            for (int i = 0; i < length; i++, bit >>>= 1) {
                wildcard[i] = (mask & bit) != 0;
                if (!wildcard[i]) pattern[i] = (byte)c.u8();
            }
        }
        Node result = new Node(length, wildcard, pattern);
        long countLong = c.multiple();
        if (countLong > Integer.MAX_VALUE) throw new IOException("excessive child count");
        int count = (int)countLong;
        if (count == 0) result.modules.addAll(parseModules(c, version));
        else {
            for (int i = 0; i < count; i++) result.children.add(parseTree(c, version, false));
        }
        return result;
    }

    private static long readVariantMask(Cursor c, int length) throws IOException {
        if (length <= 0 || length > 64) throw new IOException("invalid node length: " + length);
        if (length < 0x10) return c.max2();
        if (length <= 0x20) return c.multiple();
        return (c.multiple() << 32) | c.multiple();
    }

    private static List<Module> parseModules(Cursor c, int version) throws IOException {
        List<Module> result = new ArrayList<>();
        int flags;
        do {
            int crcLength = c.u8();
            int crc = c.u16be();
            do {
                ParseModule parsed = parseModule(c, version, crcLength, crc);
                result.add(parsed.module);
                flags = parsed.flags;
            } while ((flags & MORE_SAME_CRC) != 0);
        } while ((flags & MORE_MODULES) != 0);
        return result;
    }

    private static final class ParseModule {
        final Module module;
        final int flags;
        ParseModule(Module module, int flags) { this.module = module; this.flags = flags; }
    }

    private static ParseModule parseModule(Cursor c, int version,
                                           int crcLength, int crc) throws IOException {
        long length = version >= 9 ? c.multiple() : c.max2();
        List<PublicSymbol> publics = new ArrayList<>();
        long offset = 0;
        int flags;
        do {
            offset += version >= 9 ? c.multiple() : c.max2();
            int b = c.u8();
            boolean local = false;
            boolean collision = false;
            if (b < 0x20) {
                local = (b & FUNCTION_LOCAL) != 0;
                collision = (b & FUNCTION_COLLISION) != 0;
                b = c.u8();
            }
            ByteArrayOutputStream name = new ByteArrayOutputStream();
            boolean ended = false;
            for (int i = 0; i < MAX_NAME; i++) {
                if (b < 0x20) { ended = true; break; }
                name.write(b);
                b = c.u8();
            }
            if (!ended) throw new IOException("FLIRT public name exceeds limit");
            flags = b;
            publics.add(new PublicSymbol(name.toString(StandardCharsets.US_ASCII),
                offset, false, local, collision));
        } while ((flags & MORE_PUBLICS) != 0);

        List<TailByte> tails = new ArrayList<>();
        if ((flags & READ_TAILS) != 0) {
            int count = version >= 8 ? c.u8() : 1;
            for (int i = 0; i < count; i++) {
                long tailOffset = version >= 9 ? c.multiple() : c.max2();
                tails.add(new TailByte(tailOffset, c.u8()));
            }
        }
        List<PublicSymbol> refs = new ArrayList<>();
        if ((flags & READ_REFS) != 0) {
            int count = version >= 8 ? c.u8() : 1;
            for (int i = 0; i < count; i++) {
                long refOffset = version >= 9 ? c.multiple() : c.max2();
                long n = c.u8();
                if (n == 0) n = c.multiple();
                if (n > MAX_NAME) throw new IOException("FLIRT reference name exceeds limit");
                byte[] rawName = c.bytes((int)n);
                boolean negative = rawName.length > 0 && rawName[rawName.length - 1] == 0;
                if (negative) rawName = Arrays.copyOf(rawName, rawName.length - 1);
                refs.add(new PublicSymbol(new String(rawName, StandardCharsets.US_ASCII),
                    refOffset, negative, false, false));
            }
        }
        return new ParseModule(new Module(crcLength, crc, length, publics, tails, refs), flags);
    }

    private void validateTarget() {
        String processor = currentProgram.getLanguage().getProcessor().toString().toLowerCase(Locale.ROOT);
        if (signature.header.arch == 0 &&
            !(processor.contains("x86") || processor.contains("386"))) {
            throw new IllegalArgumentException(
                "x86 FLIRT signature cannot be applied to processor " + processor);
        }
        int pointerSize = currentProgram.getDefaultPointerSize();
        boolean admits32 = (signature.header.appTypes & 0x0001) != 0;
        boolean admits64 = (signature.header.appTypes & 0x0100) != 0;
        if (admits64 && !admits32 && pointerSize != 8)
            throw new IllegalArgumentException("64-bit signature/program mismatch");
        if (admits32 && !admits64 && pointerSize != 4 && pointerSize != 2)
            throw new IllegalArgumentException("32-bit signature/program mismatch");
    }

    /**
     * Read every initialized executable block once.  This script mutates Program
     * metadata only, so these bytes remain immutable for the complete run.
     */
    private void snapshotExecutableMemory() throws Exception {
        executableSnapshots.clear();
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized() || !block.isExecute()) continue;
            long blockSize = block.getSize();
            for (long position = 0; position < blockSize;) {
                monitor.checkCancelled();
                int wanted = (int)Math.min((long)MAX_EXECUTABLE_SNAPSHOT_CHUNK,
                    blockSize - position);
                Address start = block.getStart().add(position);
                byte[] bytes = new byte[wanted];
                int actual;
                try { actual = memory.getBytes(start, bytes); }
                catch (Exception exception) { actual = 0; }
                if (actual <= 0) {
                    executableSnapshotFallbacks++;
                    break;
                }
                if (actual != bytes.length) bytes = Arrays.copyOf(bytes, actual);
                Address end = start.add(bytes.length - 1L);
                executableSnapshots.add(new ExecutableSnapshot(start, end, bytes));
                executableSnapshotBlocks++;
                executableSnapshotBytes += bytes.length;
                position += bytes.length;
                if (actual < wanted) {
                    executableSnapshotFallbacks++;
                    break;
                }
            }
        }
        executableSnapshots.sort((left, right) -> left.start.compareTo(right.start));
    }

    private ExecutableSnapshot executableSnapshot(Address address) {
        int low = 0;
        int high = executableSnapshots.size() - 1;
        while (low <= high) {
            int middle = (low + high) >>> 1;
            ExecutableSnapshot range = executableSnapshots.get(middle);
            if (address.compareTo(range.start) < 0) high = middle - 1;
            else if (address.compareTo(range.end) > 0) low = middle + 1;
            else return range;
        }
        return null;
    }

    /**
     * Build a rare fixed-anchor index.  Rarity is measured over every usable
     * eight-byte window in every SIG leaf path rather than choosing the first
     * window of the longest run.  When a second non-overlapping window exists,
     * it is retained as a cheap exact prefilter before full SIG matching.
     */
    private void buildRareAnchorIndex() {
        rareAnchorIndex.clear();
        List<LeafPattern> leaves = new ArrayList<>();
        collectLeafPatterns(signature.root, new byte[0], new boolean[0], leaves);
        Map<Long, Integer> uses = new HashMap<>();
        for (LeafPattern leaf : leaves) {
            Set<Long> seen = new HashSet<>();
            for (int offset : fixedAnchorOffsets(leaf)) {
                sigAnchorFixedWindows++;
                long key = anchorKey(leaf.pattern, offset);
                if (seen.add(key)) uses.merge(key, 1, Integer::sum);
            }
        }
        for (LeafPattern leaf : leaves) {
            List<Integer> windows = fixedAnchorOffsets(leaf);
            if (windows.isEmpty()) continue;
            int primary = rarestAnchorOffset(leaf, windows, uses, -1);
            long primaryKey = anchorKey(leaf.pattern, primary);
            if (uses.getOrDefault(primaryKey, 0) > SIG_ANCHOR_MAX_TREE_FANOUT) {
                sigAnchorFanoutSkipped++;
                continue;
            }
            int secondary = rarestAnchorOffset(leaf, windows, uses, primary);
            long secondaryKey = secondary < 0 ? 0 : anchorKey(leaf.pattern, secondary);
            AnchorProbe probe = new AnchorProbe(primary, secondary, secondaryKey);
            List<AnchorProbe> probes = rareAnchorIndex.computeIfAbsent(
                primaryKey, ignored -> new ArrayList<>());
            if (!probes.contains(probe)) probes.add(probe);
            if (secondary >= 0) sigAnchorSecondaryPaths++;
            sigAnchorAnchoredPaths++;
        }
        for (List<AnchorProbe> probes : rareAnchorIndex.values())
            probes.sort(Comparator.comparingInt((AnchorProbe value) -> value.primaryOffset)
                .thenComparingInt(value -> value.secondaryOffset)
                .thenComparingLong(value -> value.secondaryKey));
    }

    private void collectLeafPatterns(Node node, byte[] prefix, boolean[] prefixMask,
                                     List<LeafPattern> leaves) {
        byte[] pattern = prefix;
        boolean[] mask = prefixMask;
        if (node.length != 0) {
            pattern = Arrays.copyOf(prefix, prefix.length + node.length);
            System.arraycopy(node.pattern, 0, pattern, prefix.length, node.length);
            mask = Arrays.copyOf(prefixMask, prefixMask.length + node.length);
            System.arraycopy(node.wildcard, 0, mask, prefixMask.length, node.length);
        }
        if (node.leaf()) {
            sigAnchorLeafPaths++;
            leaves.add(new LeafPattern(pattern, mask));
            return;
        }
        for (Node child : node.children)
            collectLeafPatterns(child, pattern, mask, leaves);
    }

    private static List<Integer> fixedAnchorOffsets(LeafPattern leaf) {
        List<Integer> offsets = new ArrayList<>();
        int fixedRun = 0;
        for (int index = 0; index < leaf.pattern.length; index++) {
            if (leaf.wildcard[index]) fixedRun = 0;
            else fixedRun++;
            if (fixedRun >= SIG_ANCHOR_BYTES)
                offsets.add(index - SIG_ANCHOR_BYTES + 1);
        }
        return offsets;
    }

    private static int rarestAnchorOffset(LeafPattern leaf, List<Integer> windows,
                                          Map<Long, Integer> uses,
                                          int separatedFrom) {
        int best = -1;
        int bestUses = Integer.MAX_VALUE;
        for (int offset : windows) {
            if (separatedFrom >= 0 &&
                Math.abs(offset - separatedFrom) < SIG_ANCHOR_MIN_SEPARATION) continue;
            int count = uses.getOrDefault(anchorKey(leaf.pattern, offset), Integer.MAX_VALUE);
            if (count < bestUses || (count == bestUses && offset < best)) {
                best = offset;
                bestUses = count;
            }
        }
        return best;
    }

    private static long anchorKey(byte[] bytes, int offset) {
        long key = 0;
        for (int index = 0; index < SIG_ANCHOR_BYTES; index++)
            key = (key << 8) | (bytes[offset + index] & 0xffL);
        return key;
    }

    private byte[] readWindow(Address address) {
        ExecutableSnapshot snapshot = executableSnapshot(address);
        if (snapshot != null) {
            try {
                int offset = Math.toIntExact(address.subtract(snapshot.start));
                int wanted = Math.min(MATCH_WINDOW, snapshot.bytes.length - offset);
                MemoryBlock block = memory.getBlock(address);
                boolean artificialEnd = block != null &&
                    snapshot.end.compareTo(block.getEnd()) < 0 && wanted < MATCH_WINDOW;
                if (!artificialEnd && wanted > 0) {
                    executableSnapshotReads++;
                    return Arrays.copyOfRange(snapshot.bytes, offset, offset + wanted);
                }
            }
            catch (Exception ignored) { }
        }
        executableSnapshotFallbacks++;
        try {
            MemoryBlock block = memory.getBlock(address);
            if (block == null || !block.isInitialized()) return null;
            long available = block.getEnd().subtract(address) + 1;
            int wanted = (int)Math.min(MATCH_WINDOW, Math.max(0, available));
            if (wanted <= 0) return null;
            byte[] result = new byte[wanted];
            int read = memory.getBytes(address, result);
            if (read <= 0) return null;
            return read == result.length ? result : Arrays.copyOf(result, read);
        }
        catch (Exception exception) {
            return null;
        }
    }

    private List<MatchResult> matchAt(Address address) {
        byte[] bytes = readWindow(address);
        if (bytes == null || bytes.length == 0) return Collections.emptyList();
        List<Node> roots = new ArrayList<>();
        List<Node> indexed = signature.firstByte.get(bytes[0] & 0xff);
        if (indexed != null) roots.addAll(indexed);
        roots.addAll(signature.firstFallback);
        List<MatchResult> out = new ArrayList<>();
        Map<Long, Integer> crcCache = new HashMap<>();
        for (Node node : roots) collectMatches(node, bytes, 0, 0, 0, out, crcCache);
        return out;
    }

    private static void collectMatches(Node node, byte[] bytes, int offset,
                                       int fixed, int wildcards,
                                       List<MatchResult> out,
                                       Map<Long, Integer> crcCache) {
        if (offset < 0 || offset + node.length > bytes.length) return;
        int localWildcards = 0;
        for (int i = 0; i < node.length; i++) {
            if (node.wildcard[i]) localWildcards++;
            else if (bytes[offset + i] != node.pattern[i]) return;
        }
        fixed += node.length - localWildcards;
        wildcards += localWildcards;
        int patternEnd = offset + node.length;
        if (node.leaf()) {
            int leafCount = node.modules.size();
            for (Module module : node.modules) {
                if (!modulePasses(module, bytes, patternEnd, crcCache)) continue;
                module.fixedBytes = fixed;
                module.wildcardBytes = wildcards;
                module.patternBytes = patternEnd;
                module.leafCandidates = leafCount;
                out.add(new MatchResult(module, patternEnd));
            }
        }
        else {
            for (Node child : node.children) {
                collectMatches(child, bytes, patternEnd, fixed, wildcards, out, crcCache);
            }
        }
    }

    private static boolean modulePasses(Module module, byte[] bytes,
                                        int patternEnd,
                                        Map<Long, Integer> crcCache) {
        if (module.crcLength != 0) {
            int end = patternEnd + module.crcLength;
            if (end > bytes.length) return false;
            long key = ((long)patternEnd << 32) | Integer.toUnsignedLong(module.crcLength);
            Integer actual = crcCache.get(key);
            if (actual == null) {
                actual = crc16(bytes, patternEnd, module.crcLength);
                crcCache.put(key, actual);
            }
            if (actual != module.crc16) return false;
        }
        for (TailByte tail : module.tails) {
            long index = (long)patternEnd + module.crcLength + tail.offset;
            if (index < 0 || index >= bytes.length) return false;
            if ((bytes[(int)index] & 0xff) != tail.value) return false;
        }
        return true;
    }

    /** IDA/FLIRT CRC-16, matching the Python implementation byte-for-byte. */
    private static int crc16(byte[] bytes, int offset, int length) {
        int value = 0xffff;
        final int reflectedPolynomial = 0x8408; // reflected 0x1021
        for (int index = 0; index < length; index++) {
            int b = bytes[offset + index] & 0xff;
            for (int bit = 0; bit < 8; bit++) {
                if (((value ^ b) & 1) != 0) value = (value >>> 1) ^ reflectedPolynomial;
                else value >>>= 1;
                b >>>= 1;
            }
        }
        value = (~value) & 0xffff;
        return ((value & 0xff) << 8) | ((value >>> 8) & 0xff);
    }

    private Site getSite(Address address) {
        long key = address.getOffset();
        Site result = sites.get(key);
        if (result == null) {
            result = new Site(address);
            sites.put(key, result);
        }
        return result;
    }

    private boolean addCandidate(Address address, int source) {
        if (address == null) return false;
        try {
            MemoryBlock block = memory.getBlock(address);
            if (block == null || !block.isInitialized() || !block.isExecute()) return false;
            discoveredSources.merge(address.getOffset(), source,
                (left, right) -> left | right);
            Site site = getSite(address);
            // Python's two-phase path keeps an already-matched function's
            // evidence as "existing".  Native CALL/relocation hints discovered
            // later must not turn an inexact existing body into a structural
            // collision winner.
            if (site.existing) return false;
            boolean added = (site.sources & source) == 0;
            site.sources |= source;
            return added;
        }
        catch (Exception exception) {
            return false;
        }
    }

    private void collectExistingFunctionSites() throws Exception {
        FunctionIterator iterator = functions.getFunctions(true);
        long index = 0;
        long total = functions.getFunctionCount();
        while (iterator.hasNext()) {
            if ((index++ % 200) == 0) {
                monitor.checkCancelled();
                monitor.setMessage(String.format(
                    "Apply FLIRT Signatures: matching existing functions %,d/%,d", index, total));
            }
            Function function = iterator.next();
            Address address = function.getEntryPoint();
            List<MatchResult> matches = matchAt(address);
            if (matches.isEmpty()) continue;
            Site site = getSite(address);
            site.sources |= SOURCE_EXISTING;
            site.existing = true;
            site.matches = matches;
            functionsMatched++;
        }
    }

    private void discoverNativeCandidates() throws Exception {
        AddressIterator entries = symbols.getExternalEntryPointIterator();
        while (entries.hasNext()) addCandidate(entries.next(), SOURCE_ENTRY);

        PseudoDisassembler pseudo = new PseudoDisassembler(currentProgram);
        pseudo.setRespectExecuteFlag(true);
        List<MemoryBlock> executableBlocks = new ArrayList<>();
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.isInitialized() && block.isExecute()) executableBlocks.add(block);
        }
        executableBlocks.sort(Comparator.comparing(MemoryBlock::getStart));
        for (MemoryBlock block : executableBlocks) {
            if (!block.isInitialized() || !block.isExecute()) continue;
            Address end = block.getEnd();
            Address address = block.getStart();
            while (address.compareTo(end) <= 0) {
                if (nativeInstructions != 0 && nativeInstructions % 100_000 == 0) {
                    monitor.checkCancelled();
                    monitor.setMessage(String.format(
                        "Apply FLIRT Signatures: native scan %,d instructions, %,d targets",
                        nativeInstructions, sites.size()));
                }
                int size = 1;
                try {
                    pseudoScanAttempts++;
                    Instruction instruction = pseudo.disassemble(address);
                    size = Math.max(1, instruction.getLength());
                    nativeInstructions++;
                    collectNativeFlows(instruction, address);
                }
                catch (Exception exception) {
                    nativeDecodeFailures++;
                }
                try { address = address.add(size); }
                catch (Exception exception) { break; }
            }
        }
        discoverAnalyzedReferences();
        discoverRelocations();
        discoverDefinedPointers();
        discoverPointerTables();
        discoverInitialBoundaries();
        long anchorPhase = System.nanoTime();
        discoverSignatureAnchorCandidates();
        anchorScanNanos = System.nanoTime() - anchorPhase;
    }

    /** One rolling pass over the immutable executable snapshots. */
    private void discoverSignatureAnchorCandidates() throws Exception {
        if (rareAnchorIndex.isEmpty()) return;
        Map<Long, Address> found = new TreeMap<>();
        int rangeIndex = 0;
        for (ExecutableSnapshot snapshot : executableSnapshots) {
            monitor.checkCancelled();
            byte[] bytes = snapshot.bytes;
            sigAnchorBytesScanned += bytes.length;
            if (bytes.length < SIG_ANCHOR_BYTES) continue;
            long key = anchorKey(bytes, 0);
            for (int end = SIG_ANCHOR_BYTES - 1; end < bytes.length; end++) {
                if (end >= SIG_ANCHOR_BYTES)
                    key = (key << 8) | (bytes[end] & 0xffL);
                List<AnchorProbe> probes = rareAnchorIndex.get(key);
                if (probes == null) continue;
                sigAnchorRawHits++;
                Address anchor = snapshot.start.add(end - SIG_ANCHOR_BYTES + 1L);
                for (AnchorProbe probe : probes) {
                    if (found.size() >= MAX_SIG_ANCHOR_CANDIDATES) break;
                    Address candidate;
                    try { candidate = anchor.subtract(probe.primaryOffset); }
                    catch (Exception exception) { continue; }
                    if (probe.hasSecondary()) {
                        sigAnchorSecondaryChecks++;
                        if (!anchorMatches(candidate, probe.secondaryOffset,
                                           probe.secondaryKey)) {
                            sigAnchorSecondaryRejected++;
                            continue;
                        }
                    }
                    MemoryBlock block = memory.getBlock(candidate);
                    if (block == null || !block.isInitialized() || !block.isExecute()) continue;
                    if (functions.getFunctionContaining(candidate) != null) continue;
                    if (listing.getDefinedDataContaining(candidate) != null) continue;
                    found.put(candidate.getOffset(), candidate);
                }
                if ((end & 0xfffff) == 0) monitor.checkCancelled();
            }
            monitor.setMessage(String.format(
                "Apply FLIRT Signatures: SIG anchor scan %,d/%,d, %,d bytes, %,d candidates",
                ++rangeIndex, executableSnapshots.size(), sigAnchorBytesScanned, found.size()));
            if (found.size() >= MAX_SIG_ANCHOR_CANDIDATES) break;
        }
        sigAnchorCandidates = found.size();
        for (Address candidate : found.values()) addCandidate(candidate, SOURCE_SIG_ANCHOR);
    }

    private boolean anchorMatches(Address candidate, int offset, long expected) {
        try {
            Address address = candidate.add(offset);
            ExecutableSnapshot snapshot = executableSnapshot(address);
            if (snapshot != null) {
                long last = address.getOffset() + SIG_ANCHOR_BYTES - 1L;
                if (last <= snapshot.end.getOffset()) {
                    int start = Math.toIntExact(address.subtract(snapshot.start));
                    return anchorKey(snapshot.bytes, start) == expected;
                }
            }
            byte[] bytes = new byte[SIG_ANCHOR_BYTES];
            return memory.getBytes(address, bytes) == bytes.length &&
                anchorKey(bytes, 0) == expected;
        }
        catch (Exception exception) { return false; }
    }

    private void collectNativeFlows(Instruction instruction, Address source) {
        String mnemonic = instruction.getMnemonicString().toUpperCase(Locale.ROOT);
        FlowType flow = instruction.getFlowType();
        if (flow.isCall() || mnemonic.equals("CALL")) {
            for (Address target : instruction.getFlows()) {
                nativeCallFlows++;
                addCandidate(target, SOURCE_LINEAR_CALL);
            }
        }
        else if (flow.isJump() && flow.isUnConditional() &&
                 !flow.isComputed() && instruction.getFallThrough() == null) {
            for (Address target : instruction.getFlows()) {
                if (externalTail(source, target)) {
                    nativeTailFlows++;
                    addCandidate(target, SOURCE_LINEAR_TAIL);
                }
            }
        }
    }

    private boolean externalTail(Address source, Address target) {
        try {
            Function function = functions.getFunctionContaining(source);
            return function == null || !function.getBody().contains(target);
        }
        catch (Exception exception) { return false; }
    }

    private void discoverAnalyzedReferences() {
        try {
            AddressIterator destinations = references.getReferenceDestinationIterator(
                memory.getExecuteSet(), true);
            while (destinations.hasNext()) {
                Address destination = destinations.next();
                ReferenceIterator iterator = references.getReferencesTo(destination);
                boolean sawReference = false;
                while (iterator.hasNext()) {
                    Reference reference = iterator.next();
                    Address source = reference.getFromAddress();
                    if (reference.getReferenceType().isCall()) {
                        addCandidate(destination, SOURCE_LINEAR_CALL);
                    }
                    else if (reference.getReferenceType().isJump()) {
                        Instruction instruction = listing.getInstructionContaining(source);
                        if (instruction != null && instruction.getFallThrough() == null &&
                            externalTail(source, destination)) {
                            addCandidate(destination, SOURCE_LINEAR_TAIL);
                        }
                    }
                    else {
                        sawReference |= addCandidate(destination, SOURCE_REFERENCE);
                        Data data = listing.getDataContaining(source);
                        if (data != null && data.isPointer()) {
                            if (addCandidate(destination, SOURCE_TYPED_POINTER))
                                typedPointerCandidates++;
                        }
                    }
                }
                if (sawReference) referenceCandidates++;
            }
        }
        catch (Exception exception) {
            printerr("Apply FLIRT Signatures: analyzed-reference discovery incomplete: " + exception);
        }
    }

    private void discoverRelocations() {
        try {
            Iterator<Relocation> iterator = currentProgram.getRelocationTable().getRelocations();
            while (iterator.hasNext()) {
                Relocation relocation = iterator.next();
                Address siteAddress = relocation.getAddress();
                boolean found = false;
                Reference[] from = references.getReferencesFrom(siteAddress);
                for (Reference reference : from) {
                    Address target = reference.getToAddress();
                    if (addCandidate(target, SOURCE_RELOCATION)) found = true;
                    recordDataRelocationPointer(siteAddress, target);
                    Data data = listing.getDataContaining(siteAddress);
                    if (data != null && data.isPointer() &&
                        addCandidate(target, SOURCE_TYPED_POINTER)) typedPointerCandidates++;
                }
                if (!found) {
                    MemoryBlock siteBlock = memory.getBlock(siteAddress);
                    if (siteBlock != null && !siteBlock.isExecute()) {
                        Address target = pointerTarget(siteAddress);
                        if (addCandidate(target, SOURCE_RELOCATION)) found = true;
                        recordDataRelocationPointer(siteAddress, target);
                    }
                }
                if (found) relocationCandidates++;
            }
        }
        catch (Exception exception) {
            printerr("Apply FLIRT Signatures: relocation discovery incomplete: " + exception);
        }
    }

    private void discoverDefinedPointers() {
        try {
            DataIterator roots = listing.getDefinedData(true);
            int examined = 0;
            while (roots.hasNext() && examined < MAX_POINTER_SLOTS) {
                Deque<Data> work = new ArrayDeque<>();
                work.push(roots.next());
                while (!work.isEmpty() && examined++ < MAX_POINTER_SLOTS) {
                    Data data = work.pop();
                    try {
                        if (data.isPointer() && data.getValue() instanceof Address) {
                            if (addCandidate((Address)data.getValue(), SOURCE_TYPED_POINTER))
                                typedPointerCandidates++;
                        }
                    }
                    catch (Exception ignored) { }
                    int count = Math.min(4096, Math.max(0, data.getNumComponents()));
                    for (int i = 0; i < count; i++) {
                        Data child = data.getComponent(i);
                        if (child != null) work.push(child);
                    }
                }
            }
        }
        catch (Exception exception) {
            printerr("Apply FLIRT Signatures: typed-pointer discovery incomplete: " + exception);
        }
    }

    private Address pointerTarget(Address site) {
        try {
            int width = currentProgram.getDefaultPointerSize();
            if (width != 4 && width != 8) return null;
            byte[] bytes = new byte[width];
            if (memory.getBytes(site, bytes) != width) return null;
            long value = 0;
            if (memory.isBigEndian()) {
                for (byte b : bytes) value = (value << 8) | (b & 0xffL);
            }
            else {
                for (int i = width - 1; i >= 0; i--) value = (value << 8) | (bytes[i] & 0xffL);
            }
            return toAddr(value);
        }
        catch (Exception exception) { return null; }
    }

    /**
     * A loader relocation in non-executable memory is accepted as independent
     * entry evidence only when the relocation cell itself contains the exact
     * pointer-sized target.  Relocation metadata alone is format-specific and
     * is never interpreted as a target address.
     */
    private boolean exactDataRelocationPointer(Address site, Address target) {
        if (site == null || target == null) return false;
        try {
            int width = currentProgram.getDefaultPointerSize();
            if (width != 4 && width != 8) return false;
            MemoryBlock block = memory.getBlock(site);
            if (block == null || !block.isInitialized() || block.isExecute()) return false;
            if (Math.floorMod(site.getOffset(), width) != 0) return false;
            Address actual = pointerTarget(site);
            return target.equals(actual);
        }
        catch (Exception exception) { return false; }
    }

    private void recordDataRelocationPointer(Address site, Address target) {
        if (!exactDataRelocationPointer(site, target)) return;
        MemoryBlock targetBlock = memory.getBlock(target);
        if (targetBlock == null || !targetBlock.isInitialized() ||
            !targetBlock.isExecute()) return;
        dataRelocationPointerSources.computeIfAbsent(target.getOffset(),
            ignored -> new TreeSet<>()).add(site.getOffset());
        addCandidate(target, SOURCE_DATA_RELOCATION_POINTER);
    }

    private void discoverPointerTables() {
        int width = currentProgram.getDefaultPointerSize();
        if (width != 4 && width != 8) return;
        boolean bigEndian = memory.isBigEndian();
        long scanned = 0;
        try {
            for (MemoryBlock block : memory.getBlocks()) {
                if (!block.isInitialized() || block.isExecute()) continue;
                long start = block.getStart().getOffset();
                long end = block.getEnd().getOffset();
                long position = start + Math.floorMod(-start, width);
                List<Address> run = new ArrayList<>();
                while (position + width - 1 <= end && scanned < MAX_POINTER_SLOTS) {
                    monitor.checkCancelled();
                    long cells = Math.min((end - position + 1) / width,
                        Math.min((long)POINTER_CHUNK / width, MAX_POINTER_SLOTS - scanned));
                    if (cells <= 0) break;
                    int byteCount = Math.toIntExact(cells * width);
                    byte[] bytes = new byte[byteCount];
                    Address chunkAddress = block.getStart().add(position - start);
                    int actual = memory.getBytes(chunkAddress, bytes);
                    int actualCells = Math.max(0, actual / width);
                    if (actualCells == 0) break;
                    for (int cell = 0; cell < actualCells; cell++) {
                        long value = 0;
                        if (bigEndian) {
                            for (int i = 0; i < width; i++)
                                value = (value << 8) | (bytes[cell * width + i] & 0xffL);
                        }
                        else {
                            for (int i = width - 1; i >= 0; i--)
                                value = (value << 8) | (bytes[cell * width + i] & 0xffL);
                        }
                        Address target = toAddr(value);
                        MemoryBlock targetBlock = target == null ? null : memory.getBlock(target);
                        if (targetBlock != null && targetBlock.isInitialized() && targetBlock.isExecute()) {
                            run.add(target);
                        }
                        else {
                            commitPointerRun(run);
                            run.clear();
                        }
                    }
                    scanned += actualCells;
                    position += (long)actualCells * width;
                }
                commitPointerRun(run);
                if (scanned >= MAX_POINTER_SLOTS) break;
            }
        }
        catch (Exception exception) {
            printerr("Apply FLIRT Signatures: pointer-table discovery incomplete: " + exception);
        }
        pointerSlotsScanned = scanned;
    }

    private void commitPointerRun(List<Address> run) {
        if (run.size() < 2) return;
        for (Address address : run) {
            if (addCandidate(address, SOURCE_POINTER_TABLE)) pointerTableCandidates++;
        }
    }

    private void discoverInitialBoundaries() throws Exception {
        FunctionIterator iterator = functions.getFunctions(true);
        while (iterator.hasNext()) {
            for (Address address : terminalBoundaryCandidates(iterator.next())) {
                addCandidate(address, SOURCE_BOUNDARY);
            }
        }
    }

    private List<Address> terminalBoundaryCandidates(Function function) {
        List<Address> result = new ArrayList<>();
        try {
            PseudoDisassembler pseudo = new PseudoDisassembler(currentProgram);
            pseudo.setRespectExecuteFlag(true);
            InstructionIterator iterator = listing.getInstructions(function.getBody(), true);
            while (iterator.hasNext()) {
                Instruction instruction = iterator.next();
                if (!instruction.getMaxAddress().equals(function.getBody().getMaxAddress())) continue;
                FlowType flow = instruction.getFlowType();
                boolean terminal = flow.isTerminal() ||
                    (flow.isJump() && flow.isUnConditional() && !flow.isComputed() &&
                     instruction.getFallThrough() == null);
                if (!terminal) continue;
                Address after = instruction.getMaxAddress().add(1);
                long offset = after.getOffset();
                long alignedOffset = (offset + 15) & ~15L;
                if (alignedOffset - offset < 0 || alignedOffset - offset > 0x20) continue;
                Address candidate = toAddr(alignedOffset);
                MemoryBlock block = memory.getBlock(candidate);
                if (block == null || !block.isInitialized() || !block.isExecute()) continue;
                if (listing.getDefinedDataContaining(candidate) != null) continue;
                Address padding = after;
                boolean validPadding = true;
                while (padding.compareTo(candidate) < 0) {
                    PseudoInstruction item = pseudo.disassemble(padding);
                    int length = item.getLength();
                    String mnemonic = item.getMnemonicString().toUpperCase(Locale.ROOT);
                    if (length <= 0 || !(mnemonic.equals("NOP") || mnemonic.equals("INT3")) ||
                        padding.getOffset() + length > candidate.getOffset()) {
                        validPadding = false;
                        break;
                    }
                    padding = padding.add(length);
                }
                if (!validPadding || !pseudo.checkValidSubroutine(candidate, true, true, false))
                    continue;
                if (functions.getFunctionContaining(candidate) != null) continue;
                result.add(candidate);
            }
        }
        catch (Exception ignored) { }
        return result;
    }

    private void probeNativeSites() throws Exception {
        int index = 0;
        for (Site site : sites.values()) {
            if (site.existing) continue;
            if ((index++ % 250) == 0) {
                monitor.checkCancelled();
                monitor.setMessage(String.format(
                    "Apply FLIRT Signatures: probing native candidates %,d/%,d", index, sites.size()));
            }
            if (functions.getFunctionAt(site.address) != null) continue;
            boolean boundaryOnly = site.sources == SOURCE_BOUNDARY;
            if (boundaryOnly) boundaryCandidates++;
            else nativeTested++;
            List<MatchResult> matches = matchAt(site.address);
            if (matches.isEmpty()) continue;
            if (site.sources == SOURCE_SIG_ANCHOR) {
                sigAnchorSignatureHits++;
                site.sources |= SOURCE_SIG_ANCHOR_VERIFIED;
                List<MatchResult> verified = new ArrayList<>();
                for (MatchResult match : matches) {
                    Module module = match.module;
                    boolean strong = module.fixedBytes >= MIN_CREATE_FIXED;
                    boolean corroborated = module.fixedBytes >= MIN_CREATE_CORROBORATED &&
                        (module.crcLength >= MIN_CRC || !module.tails.isEmpty());
                    if (!(strong || corroborated)) continue;
                    StructuralEvidence evidence = structuralEvidence(site, module);
                    if (evidence.validSubroutine && evidence.allPathsClosed &&
                        evidence.terminalExact) verified.add(match);
                }
                if (verified.isEmpty()) {
                    site.sources &= ~SOURCE_SIG_ANCHOR_VERIFIED;
                    sigAnchorCfgRejected++;
                    continue;
                }
                matches = verified;
                discoveredSources.merge(site.address.getOffset(),
                    SOURCE_SIG_ANCHOR_VERIFIED, (left, right) -> left | right);
            }
            site.matches = matches;
            functionsMatched++;
            if (boundaryOnly) boundaryMatches++;
            else nativeSigMatches++;
        }
    }

    private void buildGlobalFanout() {
        for (Site site : sites.values()) {
            if (site.matches.isEmpty()) continue;
            Set<String> once = new HashSet<>();
            for (MatchResult result : site.matches) {
                String identity = canonicalIdentity(result.module.primaryName());
                if (identity != null && once.add(identity)) {
                    fanoutSites.computeIfAbsent(identity, ignored -> new HashSet<>())
                        .add(site.address.getOffset());
                }
            }
        }
    }

    private enum Decision {
        STRONG, CRC_TAIL, REFERENCE, STRUCTURE,
        WEAK_REJECT, FANOUT_REJECT
    }

    private Decision confidence(Site site, MatchResult candidate, boolean create) {
        Module module = candidate.module;
        int fanout = nameFanout(module);
        boolean lowEvidence = module.fixedBytes < MIN_CREATE_FIXED &&
            module.crcLength < MIN_CRC && module.tails.isEmpty() && module.refs.isEmpty();
        if (module.fixedBytes <= 9 && module.crcLength == 0 &&
            module.tails.isEmpty() && module.refs.isEmpty()) return Decision.WEAK_REJECT;
        if (fanout > MAX_LOW_EVIDENCE_FANOUT && lowEvidence)
            return Decision.FANOUT_REJECT;
        int fixedThreshold = create ? MIN_CREATE_FIXED : MIN_RENAME_FIXED;
        if (module.fixedBytes >= fixedThreshold) return Decision.STRONG;
        int corroborated = create ? MIN_CREATE_CORROBORATED : MIN_RENAME_CORROBORATED;
        if (module.fixedBytes >= corroborated &&
            (module.crcLength >= MIN_CRC || !module.tails.isEmpty()))
            return Decision.CRC_TAIL;
        // A reference record is positive evidence only after its exact target
        // already has the expected non-default canonical name.
        if (module.fixedBytes >= corroborated && verifiedReferenceCount(site, module) > 0)
            return Decision.REFERENCE;
        if (module.fixedBytes >= MIN_STRUCTURAL_FIXED && module.leafCandidates == 1 &&
            fanout == 1 && singlePublicAtZero(module) &&
            structuralEvidence(site, module).verified())
            return Decision.STRUCTURE;
        return Decision.WEAK_REJECT;
    }

    private int nameFanout(Module module) {
        Set<Long> addresses = fanoutSites.get(canonicalIdentity(module.primaryName()));
        return addresses == null ? 0 : addresses.size();
    }

    private int verifiedReferenceCount(Site site, Module module) {
        int count = 0;
        for (PublicSymbol reference : module.refs) {
            try {
                long signed = reference.negative ? -reference.offset : reference.offset;
                Address source = site.address.add(signed);
                Instruction instruction = listing.getInstructionContaining(source);
                if (instruction == null) continue;
                for (Address target : instruction.getFlows()) {
                    Function function = functions.getFunctionAt(target);
                    if (function == null || function.getSymbol() == null ||
                        function.getSymbol().getSource() == SourceType.DEFAULT) continue;
                    if (canonicalIdentity(reference.name).equals(
                        canonicalIdentity(function.getName()))) count++;
                }
            }
            catch (Exception ignored) { }
        }
        return count;
    }

    private final Map<String, StructuralEvidence> structuralCache = new HashMap<>();
    private final Map<String, Address> sigReferenceTargetCache = new HashMap<>();
    private final Set<String> sigReferenceTargetMisses = new HashSet<>();
    private final Map<Long, PseudoInstruction> structuralInstructionCache = new HashMap<>();
    private final Set<Long> structuralDecodeFailureCache = new HashSet<>();
    private final Map<Long, Boolean> validSubroutineCache = new HashMap<>();
    private PseudoDisassembler structuralPseudo;

    private static boolean singlePublicAtZero(Module module) {
        int usable = 0;
        long onlyOffset = -1;
        for (PublicSymbol symbol : module.publics) {
            if (!symbol.name.isEmpty() && !symbol.name.equals("?") && !symbol.collision) {
                usable++;
                onlyOffset = symbol.offset;
            }
        }
        return usable == 1 && onlyOffset == 0;
    }

    private StructuralEvidence structuralEvidence(Site site, Module module) {
        String key = site.address.getOffset() + ":" + module.length + ":" + site.sources;
        StructuralEvidence cached = structuralCache.get(key);
        if (cached != null) return cached;
        StructuralEvidence result = new StructuralEvidence();
        structuralCache.put(key, result);
        if (module.length <= 0 || module.length > MAX_CFG_BYTES) return result;

        Function existing = functions.getFunctionAt(site.address);
        if (existing != null) {
            try {
                result.exactExtent = existing.getBody().getNumAddresses() == module.length &&
                    existing.getBody().getMaxAddress().subtract(site.address) + 1 == module.length;
            }
            catch (Exception ignored) { }
        }
        result.trustedOrigin = (site.sources &
            (SOURCE_LINEAR_CALL | SOURCE_ENTRY | SOURCE_SIG_ANCHOR_VERIFIED)) != 0;
        if ((site.sources & SOURCE_EXISTING) != 0 && result.exactExtent)
            result.trustedOrigin = true;
        if ((site.sources & SOURCE_RELOCATION) != 0 &&
            (site.sources & (SOURCE_TYPED_POINTER | SOURCE_POINTER_TABLE)) != 0)
            result.trustedOrigin = true;
        if (TRUST_EXACT_DATA_RELOCATION_POINTERS &&
            (site.sources & SOURCE_DATA_RELOCATION_POINTER) != 0)
            result.trustedOrigin = true;

        try {
            result.validSubroutine = validSubroutine(site.address);
            long start = site.address.getOffset();
            long end = start + module.length - 1;
            Deque<Address> work = new ArrayDeque<>();
            Set<Long> visited = new HashSet<>();
            List<long[]> ranges = new ArrayList<>();
            Set<Long> terminalEnds = new HashSet<>();
            result.reachableBody = new AddressSet();
            work.push(site.address);
            boolean closed = true;
            boolean exactTerminal = false;
            boolean computedFailed = false;
            while (!work.isEmpty() && visited.size() < MAX_CFG_INSTRUCTIONS) {
                Address cursor = work.pop();
                long cursorOffset = cursor.getOffset();
                if (!visited.add(cursorOffset)) continue;
                if (cursorOffset < start || cursorOffset > end) { closed = false; break; }
                PseudoInstruction instruction = structuralInstruction(cursor);
                if (instruction == null) { closed = false; break; }
                int size = instruction.getLength();
                long instructionEnd = cursorOffset + size - 1;
                if (size <= 0 || instructionEnd > end) { closed = false; break; }
                for (long[] range : ranges) {
                    if (!(instructionEnd < range[0] || cursorOffset > range[1])) {
                        closed = false;
                        break;
                    }
                }
                if (!closed) break;
                ranges.add(new long[] { cursorOffset, instructionEnd });
                result.reachableBody.add(cursor, cursor.add(size - 1L));
                result.maxInstructionEnd = Math.max(result.maxInstructionEnd, instructionEnd);
                FlowType flow = instruction.getFlowType();
                Address fall = instruction.getFallThrough();
                boolean terminalHere = false;
                if (flow.isComputed() && flow.isJump()) {
                    result.computedJumpSeen = true;
                    Instruction analyzed = listing.getInstructionAt(cursor);
                    if (analyzed == null || analyzed.getLength() != size ||
                        !analyzed.getFlowType().isComputed() ||
                        !analyzed.getFlowType().isJump()) {
                        computedFailed = true;
                        closed = false;
                        break;
                    }
                    Address[] targets = analyzed.getFlows();
                    if (targets == null || targets.length == 0) {
                        computedFailed = true;
                        closed = false;
                        break;
                    }
                    Set<Long> distinctTargets = new HashSet<>();
                    for (Address target : targets) {
                        if (target == null || !distinctTargets.add(target.getOffset())) continue;
                        if (inside(target, start, end)) work.push(target);
                        else {
                            computedFailed = true;
                            closed = false;
                            break;
                        }
                    }
                    if (!closed) break;
                    Address analyzedFall = analyzed.getFallThrough();
                    if (analyzedFall != null) {
                        if (inside(analyzedFall, start, end)) work.push(analyzedFall);
                        else {
                            computedFailed = true;
                            closed = false;
                            break;
                        }
                    }
                }
                else if (flow.isTerminal()) terminalHere = true;
                else if (flow.isCall()) {
                    if (fall == null) terminalHere = true;
                    else if (inside(fall, start, end)) work.push(fall);
                    else { closed = false; break; }
                }
                else if (flow.isJump()) {
                    Address[] targets = instruction.getFlows();
                    for (Address target : targets) {
                        if (inside(target, start, end)) work.push(target);
                        else if (flow.isUnConditional() && fall == null) terminalHere = true;
                        else { closed = false; break; }
                    }
                    if (!closed) break;
                    if (fall != null) {
                        if (inside(fall, start, end)) work.push(fall);
                        else { closed = false; break; }
                    }
                    else if (flow.isUnConditional()) terminalHere = true;
                }
                else {
                    if (fall == null) { closed = false; break; }
                    if (inside(fall, start, end)) work.push(fall);
                    else { closed = false; break; }
                }
                if (terminalHere) {
                    result.terminalCount++;
                    terminalEnds.add(instructionEnd);
                    if (instructionEnd == end) exactTerminal = true;
                }
            }
            if (!work.isEmpty()) closed = false;
            result.instructionCount = visited.size();
            result.allPathsClosed = closed && !visited.isEmpty();
            result.terminalExact = result.allPathsClosed && exactTerminal;
            result.computedJumpResolved = result.computedJumpSeen &&
                !computedFailed && result.allPathsClosed;
            if (result.allPathsClosed && result.maxInstructionEnd >= start &&
                result.maxInstructionEnd < end &&
                terminalEnds.contains(result.maxInstructionEnd)) {
                result.safePaddingExact = safeExecutablePadding(
                    toAddr(result.maxInstructionEnd + 1), toAddr(end));
            }
        }
        catch (Exception ignored) { }
        if (result.computedJumpSeen) {
            computedCfgSites++;
            if (result.computedJumpResolved && result.terminalExact) computedCfgResolved++;
            else computedCfgRejected++;
        }
        return result;
    }

    private PseudoDisassembler structuralPseudo() {
        if (structuralPseudo == null) {
            structuralPseudo = new PseudoDisassembler(currentProgram);
            structuralPseudo.setRespectExecuteFlag(true);
            structuralPseudo.setMaxInstructions(MAX_CFG_INSTRUCTIONS);
        }
        return structuralPseudo;
    }

    private boolean validSubroutine(Address address) {
        long key = address.getOffset();
        Boolean cached = validSubroutineCache.get(key);
        if (cached != null) {
            validSubroutineCacheHits++;
            return cached;
        }
        validSubroutineCacheMisses++;
        boolean valid = false;
        try {
            valid = structuralPseudo().checkValidSubroutine(address, true, true, false);
        }
        catch (Exception ignored) { }
        validSubroutineCache.put(key, valid);
        return valid;
    }

    private PseudoInstruction structuralInstruction(Address address) {
        long key = address.getOffset();
        PseudoInstruction cached = structuralInstructionCache.get(key);
        if (cached != null) {
            structuralDecodeCacheHits++;
            return cached;
        }
        if (structuralDecodeFailureCache.contains(key)) {
            structuralDecodeCacheHits++;
            return null;
        }
        structuralDecodeCacheMisses++;
        try {
            PseudoInstruction decoded = structuralPseudo().disassemble(address);
            structuralInstructionCache.put(key, decoded);
            return decoded;
        }
        catch (Exception exception) {
            structuralDecodeFailureCache.add(key);
            return null;
        }
    }

    private boolean safeExecutablePadding(Address start, Address end) {
        try {
            Address cursor = start;
            while (cursor.compareTo(end) <= 0) {
                PseudoInstruction instruction = structuralInstruction(cursor);
                if (instruction == null) return false;
                int size = instruction.getLength();
                if (size <= 0 || cursor.getOffset() + size - 1 > end.getOffset()) return false;
                String mnemonic = instruction.getMnemonicString().toUpperCase(Locale.ROOT);
                if (!(mnemonic.equals("NOP") || mnemonic.equals("INT3"))) return false;
                cursor = cursor.add(size);
            }
            return cursor.getOffset() == end.getOffset() + 1;
        }
        catch (Exception exception) { return false; }
    }

    private static boolean inside(Address address, long start, long end) {
        long value = address.getOffset();
        return value >= start && value <= end;
    }

    private void decideAndApply() throws Exception {
        int index = 0;
        for (Site site : sites.values()) {
            if (site.matches.isEmpty()) continue;
            if ((index++ % 100) == 0) {
                monitor.checkCancelled();
                monitor.setMessage(String.format(
                    "Apply FLIRT Signatures: deciding matches %,d/%,d", index, sites.size()));
            }
            boolean create = functions.getFunctionAt(site.address) == null;
            List<MatchResult> survivors = new ArrayList<>();
            Decision strongestRejection = Decision.WEAK_REJECT;
            for (MatchResult match : site.matches) {
                Decision decision = confidence(site, match, create);
                if (accepted(decision)) survivors.add(match);
                else if (decision == Decision.FANOUT_REJECT)
                    strongestRejection = Decision.FANOUT_REJECT;
            }
            site.survivors = survivors;
            if (survivors.isEmpty()) {
                if (strongestRejection == Decision.FANOUT_REJECT) fanoutRejected++;
                else weakRejected++;
                continue;
            }
            int identitiesBeforeLayout = groupByIdentity(survivors).size();
            List<MatchResult> layoutNarrowed = narrowByKnownLayout(site, survivors);
            int identitiesAfterLayout = groupByIdentity(layoutNarrowed).size();
            if (identitiesBeforeLayout > 1 && identitiesAfterLayout == 1)
                layoutIdentitiesResolved++;
            int identitiesBeforeStructure = identitiesAfterLayout;
            List<MatchResult> narrowed = narrowByExactStructure(site, layoutNarrowed);
            site.survivors = narrowed;
            Map<String, List<MatchResult>> identities = groupByIdentity(narrowed);
            if (identitiesBeforeStructure > 1 && identities.size() == 1) {
                structuralIdentitiesResolved++;
                structuralResolvedSites.add(site.address.getOffset());
                if ((site.sources & SOURCE_DATA_RELOCATION_POINTER) != 0) {
                    dataRelocationIdentitiesResolved++;
                    dataRelocationIdentityResolvedSites.add(site.address.getOffset());
                }
            }
            if (identities.size() != 1) {
                ambiguousSites.add(site);
                continue;
            }
            List<MatchResult> identityMatches = identities.values().iterator().next();
            MatchResult selected = identityMatches.get(0);
            Decision finalDecision = confidence(site, selected, create);
            countAccepted(finalDecision);
            if (finalDecision == Decision.STRUCTURE &&
                (site.sources & SOURCE_DATA_RELOCATION_POINTER) != 0) {
                StructuralEvidence evidence = structuralEvidence(site, selected.module);
                long bodyBytes = evidence.reachableBody == null ? 0 :
                    evidence.reachableBody.getNumAddresses();
                dataRelocationStructureAccepted++;
                dataRelocationNameDiagnostics.add(new DataRelocationNameDiagnostic(
                    site.address, canonicalIdentity(selected.module.primaryName()),
                    dataRelocationPointerSourceCount(site.address), selected.module,
                    nameFanout(selected.module), bodyBytes));
            }
            ensurePrimaryFunction(site, selected.module);
            if (identityMatches.size() == narrowed.size() && narrowed.size() > 1)
                applyConsensusSymbols(site, narrowed, true);
            else applyModule(site, selected.module);
        }
    }

    /**
     * Arc-consistency over exact IDASGN reference records.  This pass never
     * invents a relationship: an edge participates only when the reference
     * offset lands in one analyzed direct CALL/JMP with one concrete target.
     * Missing SIG reference records are wildcards, while a present record is
     * a hard exact-name constraint.  Candidates are removed only when they
     * have no support in the target site's current domain.  Empty domains are
     * rejected as conflicts, so corrupt/incomplete graph metadata fails open
     * to the original ambiguity rather than selecting a guess.
     */
    private void resolveBySigReferenceGraph() throws Exception {
        if (!ENABLE_SIG_REFERENCE_GRAPH || ambiguousSites.isEmpty()) return;
        Set<Long> narrowedSites = new HashSet<>();
        for (int round = 1; round <= 32; round++) {
            monitor.checkCancelled();
            Map<Site, Set<MatchResult>> removals = new HashMap<>();

            // Outgoing consistency: a candidate that explicitly names a
            // target must be supported by that target's current candidates.
            for (Site source : sites.values()) {
                if (source.survivors.isEmpty()) continue;
                for (MatchResult candidate : source.survivors) {
                    if (!candidateGraphCompatible(source, candidate))
                        removals.computeIfAbsent(source, ignored -> new HashSet<>())
                            .add(candidate);
                }
            }

            // Incoming consistency is used only when every candidate at the
            // source records the same concrete edge.  A candidate lacking the
            // record makes the edge incomplete and therefore non-pruning.
            for (Site source : sites.values()) {
                if (source.survivors.isEmpty()) continue;
                Set<Long> offsets = new HashSet<>();
                for (MatchResult candidate : source.survivors) {
                    for (PublicSymbol reference : candidate.module.refs) {
                        String expected = canonicalIdentity(reference.name);
                        if (expected == null || expected.equals("?")) continue;
                        offsets.add(reference.negative ? -reference.offset : reference.offset);
                    }
                }
                for (long signedOffset : offsets) {
                    Address target = directSigReferenceTarget(source, signedOffset);
                    if (target == null) continue;
                    Site targetSite = sites.get(target.getOffset());
                    if (targetSite == null || targetSite.survivors.isEmpty()) continue;
                    Set<String> allowed = new HashSet<>();
                    boolean complete = true;
                    for (MatchResult candidate : source.survivors) {
                        Set<String> expected = expectedReferencesAt(
                            candidate.module, signedOffset);
                        if (expected.isEmpty()) { complete = false; break; }
                        allowed.addAll(expected);
                    }
                    if (!complete || allowed.isEmpty()) continue;
                    sigGraphConstraints++;
                    for (MatchResult targetCandidate : targetSite.survivors) {
                        String identity = canonicalIdentity(
                            targetCandidate.module.primaryName());
                        if (identity != null && !allowed.contains(identity))
                            removals.computeIfAbsent(targetSite,
                                ignored -> new HashSet<>()).add(targetCandidate);
                    }
                }
            }

            boolean changed = false;
            for (Map.Entry<Site, Set<MatchResult>> entry : removals.entrySet()) {
                Site site = entry.getKey();
                Set<MatchResult> removed = entry.getValue();
                if (removed.isEmpty()) continue;
                List<MatchResult> retained = new ArrayList<>();
                for (MatchResult candidate : site.survivors)
                    if (!removed.contains(candidate)) retained.add(candidate);
                if (retained.isEmpty()) {
                    sigGraphConflicts++;
                    continue;
                }
                if (retained.size() == site.survivors.size()) continue;
                sigGraphCandidatesPruned += site.survivors.size() - retained.size();
                site.survivors = retained;
                narrowedSites.add(site.address.getOffset());
                changed = true;
            }
            sigGraphRounds = round;
            if (!changed) break;
        }
        sigGraphSitesNarrowed = narrowedSites.size();

        List<Site> unresolved = new ArrayList<>();
        for (Site site : ambiguousSites) {
            Map<String, List<MatchResult>> identities = groupByIdentity(site.survivors);
            if (identities.size() != 1) {
                unresolved.add(site);
                continue;
            }
            List<MatchResult> identityMatches = identities.values().iterator().next();
            MatchResult selected = identityMatches.get(0);
            boolean create = functions.getFunctionAt(site.address) == null;
            countAccepted(confidence(site, selected, create));
            ensurePrimaryFunction(site, selected.module);
            if (identityMatches.size() > 1)
                applyConsensusSymbols(site, identityMatches, true);
            else applyModule(site, selected.module);
            sigGraphIdentitiesResolved++;
            sigGraphResolvedSites.add(site.address.getOffset());
        }
        ambiguousSites.clear();
        ambiguousSites.addAll(unresolved);
    }

    private boolean candidateGraphCompatible(Site source, MatchResult candidate) {
        Map<Long, Set<String>> expectedByOffset = new HashMap<>();
        for (PublicSymbol reference : candidate.module.refs) {
            String expected = canonicalIdentity(reference.name);
            if (expected == null || expected.equals("?")) continue;
            long signed = reference.negative ? -reference.offset : reference.offset;
            expectedByOffset.computeIfAbsent(signed, ignored -> new HashSet<>()).add(expected);
        }
        for (Map.Entry<Long, Set<String>> entry : expectedByOffset.entrySet()) {
            Address target = directSigReferenceTarget(source, entry.getKey());
            if (target == null) continue;
            Set<String> targetDomain = graphIdentitiesAt(target);
            if (targetDomain.isEmpty()) continue;
            sigGraphConstraints++;
            if (Collections.disjoint(entry.getValue(), targetDomain)) return false;
        }
        return true;
    }

    private Set<String> graphIdentitiesAt(Address target) {
        Set<String> result = new HashSet<>();
        Site site = sites.get(target.getOffset());
        if (site != null && !site.survivors.isEmpty()) {
            result.addAll(groupByIdentity(site.survivors).keySet());
            result.remove("?");
            if (!result.isEmpty()) return result;
        }
        try {
            for (Symbol symbol : symbols.getSymbols(target)) {
                if (symbol.getSource() == SourceType.DEFAULT) continue;
                if (libraryNamespace == null ||
                    !symbol.getParentNamespace().equals(libraryNamespace)) continue;
                String identity = canonicalIdentity(symbol.getName());
                if (identity != null && !identity.equals("?")) result.add(identity);
            }
        }
        catch (Exception ignored) { }
        return result;
    }

    private static Set<String> expectedReferencesAt(Module module, long signedOffset) {
        Set<String> result = new HashSet<>();
        for (PublicSymbol reference : module.refs) {
            long signed = reference.negative ? -reference.offset : reference.offset;
            if (signed != signedOffset) continue;
            String identity = canonicalIdentity(reference.name);
            if (identity != null && !identity.equals("?")) result.add(identity);
        }
        return result;
    }

    private Address directSigReferenceTarget(Site source, long signedOffset) {
        String key = source.address.getOffset() + ":" + signedOffset;
        Address cached = sigReferenceTargetCache.get(key);
        if (cached != null) return cached;
        if (sigReferenceTargetMisses.contains(key)) return null;
        try {
            Address referenceSite = source.address.add(signedOffset);
            Instruction instruction = listing.getInstructionContaining(referenceSite);
            if (instruction == null) {
                sigReferenceTargetMisses.add(key);
                return null;
            }
            FlowType flow = instruction.getFlowType();
            if (flow.isComputed() || !(flow.isCall() || flow.isJump())) {
                sigReferenceTargetMisses.add(key);
                return null;
            }
            Set<Address> concrete = new HashSet<>();
            for (Address target : instruction.getFlows()) if (target != null) concrete.add(target);
            if (concrete.size() != 1) {
                sigReferenceTargetMisses.add(key);
                return null;
            }
            Address target = concrete.iterator().next();
            sigReferenceTargetCache.put(key, target);
            return target;
        }
        catch (Exception exception) {
            sigReferenceTargetMisses.add(key);
            return null;
        }
    }

    private void ensurePrimaryFunction(Site site, Module module) {
        if (dryRun || functions.getFunctionAt(site.address) != null) return;
        Function containing = functions.getFunctionContaining(site.address);
        if (containing == null) {
            createFunctionAt(site.address);
            return;
        }
        StructuralEvidence splitEvidence = structuralEvidence(site, module);
        boolean splitStartSafe = safeSplitStart(containing, site.address);
        boolean exactContainedRange = exactContainedRange(
            containing, site.address, module.length);
        boolean structurallySplittable = splitEvidence.verified() ||
            (splitEvidence.validSubroutine && exactContainedRange);
        if ((site.sources & SOURCE_LINEAR_CALL) == 0 ||
            !structurallySplittable || !splitStartSafe) {
            printf("  split rejected %s: sources=0x%X trusted=%s valid=%s closed=%s terminal=%s exact=%s exactChunk=%s safeStart=%s len=0x%X%n",
                site.address, site.sources, splitEvidence.trustedOrigin,
                splitEvidence.validSubroutine, splitEvidence.allPathsClosed,
                splitEvidence.terminalExact, splitEvidence.exactExtent,
                exactContainedRange, splitStartSafe, module.length);
            splitsRejected++;
            return;
        }
        AddressSet original = new AddressSet(containing.getBody());
        try {
            AddressSet remainder = new AddressSet(original);
            remainder.delete(site.address, site.address.add(module.length - 1));
            if (remainder.isEmpty() || !remainder.contains(containing.getEntryPoint())) {
                splitsRejected++;
                return;
            }
            containing.setBody(remainder);
            Function created = createFunctionAt(site.address);
            if (created != null) {
                functionsSplit++;
                return;
            }
            splitsRejected++;
            containing.setBody(original);
        }
        catch (Exception exception) {
            splitsRejected++;
            try { containing.setBody(original); }
            catch (Exception restoreException) { splitRestoreFailures++; errors++; }
        }
    }

    private boolean exactContainedRange(Function containing, Address address,
                                        long length) {
        try {
            Address expectedEnd = address.add(length - 1);
            AddressRangeIterator ranges = containing.getBody().getAddressRanges();
            while (ranges.hasNext()) {
                AddressRange range = ranges.next();
                if (range.getMinAddress().equals(address))
                    return range.getMaxAddress().equals(expectedEnd);
            }
        }
        catch (Exception ignored) { }
        return false;
    }

    private boolean safeSplitStart(Function containing, Address address) {
        try {
            if (!containing.getBody().contains(address)) return false;
            Symbol symbol = containing.getSymbol();
            if (symbol != null && symbol.getSource() == SourceType.USER_DEFINED) return false;
            if (listing.getDefinedDataContaining(address) != null) return false;
            Instruction current = listing.getInstructionContaining(address);
            if (current != null && !current.getMinAddress().equals(address)) return false;
            Instruction previous = listing.getInstructionBefore(address);
            if (previous != null && containing.getBody().contains(previous.getMinAddress()) &&
                address.equals(previous.getFallThrough())) return false;
            ReferenceIterator iterator = references.getReferencesTo(address);
            while (iterator.hasNext()) {
                Reference reference = iterator.next();
                Address source = reference.getFromAddress();
                if (source == null || !containing.getBody().contains(source)) continue;
                Instruction instruction = listing.getInstructionContaining(source);
                if (instruction == null || address.equals(instruction.getFallThrough())) return false;
                if (reference.getReferenceType().isCall()) continue;
                FlowType flow = instruction.getFlowType();
                if (reference.getReferenceType().isJump() && flow.isJump() &&
                    flow.isUnConditional() && !flow.isComputed() &&
                    instruction.getFallThrough() == null) continue;
                return false;
            }
            return true;
        }
        catch (Exception exception) { return false; }
    }

    private static boolean accepted(Decision decision) {
        return decision == Decision.STRONG || decision == Decision.CRC_TAIL ||
            decision == Decision.REFERENCE || decision == Decision.STRUCTURE;
    }

    private void countAccepted(Decision decision) {
        if (decision == Decision.STRONG) acceptedStrong++;
        else if (decision == Decision.CRC_TAIL) acceptedCrcTail++;
        else if (decision == Decision.REFERENCE) acceptedReference++;
        else if (decision == Decision.STRUCTURE) acceptedStructure++;
    }

    private Map<String, List<MatchResult>> groupByIdentity(List<MatchResult> matches) {
        Map<String, List<MatchResult>> result = new LinkedHashMap<>();
        for (MatchResult match : matches) {
            String identity = canonicalIdentity(match.module.primaryName());
            if (identity == null) identity = "?";
            result.computeIfAbsent(identity, ignored -> new ArrayList<>()).add(match);
        }
        return result;
    }

    private List<MatchResult> narrowByExactStructure(Site site,
                                                     List<MatchResult> matches) {
        if (groupByIdentity(matches).size() <= 1) return matches;
        Map<Long, List<MatchResult>> lengths = new LinkedHashMap<>();
        boolean comparable = true;
        for (MatchResult match : matches) {
            Module module = match.module;
            int usable = 0;
            long onlyOffset = -1;
            for (PublicSymbol symbol : module.publics) {
                if (!symbol.name.isEmpty() && !symbol.name.equals("?") && !symbol.collision) {
                    usable++;
                    onlyOffset = symbol.offset;
                }
            }
            if (module.fixedBytes < MIN_STRUCTURAL_FIXED || usable != 1 ||
                onlyOffset != 0 || module.length <= 0) {
                comparable = false;
                break;
            }
            lengths.computeIfAbsent(module.length, ignored -> new ArrayList<>()).add(match);
        }
        if (!comparable || lengths.isEmpty()) return matches;
        List<Long> proven = new ArrayList<>();
        for (Map.Entry<Long, List<MatchResult>> entry : lengths.entrySet()) {
            if (structuralEvidence(site, entry.getValue().get(0).module).verified())
                proven.add(entry.getKey());
        }
        if (proven.size() == 1) {
            site.provenLength = Math.toIntExact(proven.get(0));
            return lengths.get(proven.get(0));
        }
        return matches;
    }

    /** Remove only candidates contradicted by immutable/protected program layout. */
    private List<MatchResult> narrowByKnownLayout(Site site,
                                                  List<MatchResult> matches) {
        if (matches.size() < 2) return matches;
        List<MatchResult> retained = new ArrayList<>();
        for (MatchResult match : matches) {
            if (moduleFitsKnownLayout(site.address, match.module)) retained.add(match);
            else layoutCandidatesPruned++;
        }
        // Fail closed if the Program DB evidence somehow contradicts every SIG
        // candidate.  Layout is a veto/pruning signal, never a fallback guess.
        if (retained.isEmpty()) return matches;
        if (retained.size() < matches.size()) layoutSitesNarrowed++;
        return retained;
    }

    private boolean moduleFitsKnownLayout(Address address, Module module) {
        if (module.length <= 0 || module.length > MAX_CFG_BYTES) return false;
        try {
            Address end = address.add(module.length - 1);
            MemoryBlock block = memory.getBlock(address);
            if (block == null || !block.isInitialized() || !block.isExecute() ||
                end.compareTo(block.getEnd()) > 0) return false;
            boolean publicAtEntry = false;
            for (PublicSymbol symbol : module.publics) {
                if (symbol.name.isEmpty() || symbol.name.equals("?") || symbol.collision) continue;
                if (symbol.offset < 0 || symbol.offset >= module.length) return false;
                if (symbol.offset == 0) publicAtEntry = true;
            }
            if (!publicAtEntry) return false;

            Function next = nextProtectedFunctionAfter(address);
            if (next != null && next.getEntryPoint().compareTo(end) <= 0 &&
                protectedLayoutFunction(next)) return false;

            Function existing = functions.getFunctionAt(address);
            if (existing != null && protectedLayoutFunction(existing)) {
                AddressRangeIterator ranges = existing.getBody().getAddressRanges();
                if (!ranges.hasNext()) return false;
                AddressRange only = ranges.next();
                if (ranges.hasNext() || !only.getMinAddress().equals(address) ||
                    !only.getMaxAddress().equals(end)) return false;
            }
            return true;
        }
        catch (Exception exception) { return false; }
    }

    private static boolean protectedLayoutFunction(Function function) {
        try {
            Symbol symbol = function.getSymbol();
            if (symbol == null) return false;
            SourceType source = symbol.getSource();
            return source == SourceType.USER_DEFINED || source == SourceType.IMPORTED;
        }
        catch (Exception exception) { return false; }
    }

    private Function nextProtectedFunctionAfter(Address address) {
        try {
            Long offset = protectedFunctionEntries.higher(address.getOffset());
            return offset == null ? null : functions.getFunctionAt(toAddr(offset));
        }
        catch (Exception ignored) { }
        return null;
    }

    private void applyModule(Site site, Module module) {
        for (PublicSymbol symbol : module.publics) {
            if (symbol.name.isEmpty() || symbol.name.equals("?") ||
                symbol.collision) continue;
            try {
                renameAt(site.address.add(symbol.offset), symbol.name, true,
                    symbol.offset != 0);
            }
            catch (Exception exception) {
                errors++;
                printerr("Apply FLIRT Signatures: rename target failed: " + exception);
            }
        }
    }

    private static String symbolRecord(PublicSymbol symbol) {
        return symbol.offset + "\u0000" + canonicalIdentity(symbol.name) +
            "\u0000" + symbol.local;
    }

    private void applyConsensusSymbols(Site site, List<MatchResult> matches,
                                       boolean allowCreatePrimary) {
        Set<String> common = null;
        Map<String, PublicSymbol> representative = new HashMap<>();
        for (MatchResult match : matches) {
            Set<String> records = new HashSet<>();
            for (PublicSymbol symbol : match.module.publics) {
                if (symbol.name.isEmpty() || symbol.name.equals("?") || symbol.collision) continue;
                String record = symbolRecord(symbol);
                records.add(record);
                representative.put(record, symbol);
            }
            if (common == null) common = records;
            else common.retainAll(records);
        }
        if (common == null) return;
        for (String record : new TreeSet<>(common)) {
            PublicSymbol symbol = representative.get(record);
            if (!allowCreatePrimary && symbol.offset == 0 &&
                functions.getFunctionAt(site.address) == null) continue;
            try { renameAt(site.address.add(symbol.offset), symbol.name,
                allowCreatePrimary, symbol.offset != 0); }
            catch (Exception exception) { errors++; }
        }
    }

    private Function createFunctionAt(Address address) {
        return createFunctionAt(address, false);
    }

    private Function createFunctionAt(Address address, boolean allowContained) {
        if (dryRun) return null;
        try {
            Function exact = functions.getFunctionAt(address);
            if (exact != null) return exact;
            if (!allowContained && functions.getFunctionContaining(address) != null) return null;
            if (listing.getInstructionAt(address) == null) disassemble(address);
            exact = functions.getFunctionAt(address);
            if (exact == null) exact = createFunction(address, null);
            if (exact != null) functionsCreated++;
            return exact;
        }
        catch (Exception exception) { return null; }
    }

    private void renameAt(Address address, String rawName, boolean allowCreate) {
        renameAt(address, rawName, allowCreate, false);
    }

    private void renameAt(Address address, String rawName, boolean allowCreate,
                          boolean allowContainedCreate) {
        Function function = functions.getFunctionAt(address);
        if (function == null && allowCreate)
            function = createFunctionAt(address, allowContainedCreate);
        if (function == null) return;
        Symbol symbol = function.getSymbol();
        SourceType source = symbol == null ? SourceType.DEFAULT : symbol.getSource();
        if (source == SourceType.USER_DEFINED) {
            skippedUserNames++;
            return;
        }
        String canonical = canonicalIdentity(rawName);
        if (canonical == null || canonical.isEmpty()) return;
        if (canonical.equals(function.getName()) &&
            function.getParentNamespace() == libraryNamespace) {
            alreadyCorrect++;
            appliedFunctionSites.add(address.getOffset());
            return;
        }
        if (dryRun) {
            renamed++;
            appliedFunctionSites.add(address.getOffset());
            return;
        }
        try {
            boolean demangled = false;
            if (isLegacyRust(canonical)) {
                demangled = applyRustDemangled(address, canonical);
                if (demangled) rustNamesDemangled++;
                else rustDemangleFailed++;
            }
            if (!demangled) {
                function.setName(canonical, SourceType.ANALYSIS);
                if (libraryNamespace != null && function.getParentNamespace() != libraryNamespace)
                    function.setParentNamespace(libraryNamespace);
            }
            if (!canonical.equals(rawName)) rustNamesRestored++;
            if (isLegacyRust(canonical)) preserveRustIdentity(address, rawName, canonical);
            renamed++;
            appliedFunctionSites.add(address.getOffset());
            logChange(String.format("  %s : %s", address, canonical));
        }
        catch (Exception exception) {
            errors++;
            printerr("Apply FLIRT Signatures: rename failed " + address + " -> " + canonical + ": " + exception);
        }
    }

    private void logChange(String message) {
        changeLogCount++;
        if (changeLogCount <= 50) println(message);
        else if (!changeLogSuppressed) {
            changeLogSuppressed = true;
            println("  ... further successful changes suppressed (limit=50)");
        }
    }

    private boolean applyRustDemangled(Address address, String canonical) {
        try {
            RustDemangler demangler = new RustDemangler();
            RustDemanglerOptions options = new RustDemanglerOptions();
            MangledContext context = demangler.createMangledContext(
                canonical, options, currentProgram, address);
            DemangledObject object = demangler.demangle(context);
            return object != null && object.applyTo(
                currentProgram, address, options, monitor);
        }
        catch (Exception exception) { return false; }
    }

    private void preserveRustIdentity(Address address, String rawName, String canonical) {
        boolean preserved = false;
        try {
            boolean exists = false;
            Symbol[] atAddress = symbols.getSymbols(address);
            for (Symbol item : atAddress) {
                if (item.getName().equals(canonical)) { exists = true; break; }
            }
            if (!exists) symbols.createLabel(address, canonical, libraryNamespace, SourceType.ANALYSIS);
            preserved = true;
        }
        catch (Exception ignored) { }
        try {
            String previous = listing.getComment(CodeUnit.REPEATABLE_COMMENT, address);
            if (previous == null) previous = "";
            String note = "FLIRT canonical Rust: " + canonical;
            if (!rawName.equals(canonical)) note += "\nFLIRT signature source: " + rawName;
            if (!previous.contains("FLIRT canonical Rust: " + canonical))
                listing.setComment(address, CodeUnit.REPEATABLE_COMMENT,
                    (previous + "\n" + note).trim());
            preserved = true;
        }
        catch (Exception ignored) { }
        if (preserved) rawNamesPreserved++;
    }

    private Namespace makeNamespace(String name) {
        try {
            String safe = sanitize(name);
            Namespace result = symbols.getNamespace(safe, null);
            if (result == null) result = symbols.createNameSpace(null, safe, SourceType.ANALYSIS);
            return result;
        }
        catch (Exception exception) {
            namespaceErrors++;
            printerr("Apply FLIRT Signatures: namespace unavailable: " + exception);
            return null;
        }
    }

    private String libraryName() {
        String producer = signature.header.libraryName;
        if (producer != null && !producer.toLowerCase(Locale.ROOT).startsWith("built with "))
            return producer;
        String stem = signaturePath.getFileName().toString();
        int dot = stem.lastIndexOf('.');
        if (dot > 0) stem = stem.substring(0, dot);
        int marker = stem.toLowerCase(Locale.ROOT).indexOf("_rust-");
        if (marker >= 0) stem = stem.substring(marker + 1);
        return "FLIRT_" + sanitize(stem);
    }

    private static String sanitize(String name) {
        String result = name == null ? "" : name.trim().replaceAll("[^A-Za-z0-9_.$+\\-]", "_");
        return result.isEmpty() ? "FLIRT" : result;
    }

    private static boolean isLegacyRust(String name) {
        return parseRustComponents(name) != null;
    }

    private static String canonicalIdentity(String name) {
        if (name == null) return null;
        if (RUST_RESTORE_CACHE.containsKey(name)) return RUST_RESTORE_CACHE.get(name);
        String result = computeCanonicalIdentity(name);
        cacheNameResult(RUST_RESTORE_CACHE, name, result);
        return result;
    }

    private static String computeCanonicalIdentity(String name) {
        List<int[]> components = parseRustComponents(name);
        if (components == null) return name;
        String prefix = name.startsWith("__ZN") ? "__ZN" : "_ZN";
        StringBuilder rebuilt = new StringBuilder(name.length());
        rebuilt.append(prefix);
        boolean changed = false;
        for (int[] range : components) {
            String component = name.substring(range[0], range[1]);
            String restored = component;
            if (RUST_STRUCTURAL_SANITIZED.matcher(component).find()) {
                restored = restored.replace("_LT_", "$LT$").replace("_GT_", "$GT$")
                    .replace("_SP_", "$SP$").replace("_BP_", "$BP$")
                    .replace("_RF_", "$RF$").replace("_LP_", "$LP$")
                    .replace("_RP_", "$RP$").replace("_C_", "$C$");
                Matcher matcher = RUST_UNICODE.matcher(restored);
                StringBuffer buffer = new StringBuffer();
                while (matcher.find()) matcher.appendReplacement(buffer,
                    Matcher.quoteReplacement("$u" + matcher.group(1) + "$"));
                matcher.appendTail(buffer);
                restored = buffer.toString();
            }
            if (!restored.equals(component)) changed = true;
            if (restored.length() != component.length()) return name;
            rebuilt.append(component.length()).append(restored);
        }
        int terminator = components.get(components.size() - 1)[1];
        rebuilt.append('E').append(name.substring(terminator + 1));
        String restoredName = rebuilt.toString();
        return !changed || parseRustComponents(restoredName) == null ? name : restoredName;
    }

    private static void resetNameCaches() {
        RUST_RESTORE_CACHE.clear();
        RUST_DEMANGLE_CACHE.clear();
        RUST_SEMANTIC_CACHE.clear();
    }

    private static void cacheNameResult(Map<String, String> cache,
                                        String name, String result) {
        if (cache.size() >= NAME_CACHE_LIMIT) cache.clear();
        cache.put(name, result);
    }

    /** component ranges, or null when the legacy mangling is malformed. */
    private static List<int[]> parseRustComponents(String name) {
        if (name == null) return null;
        int position;
        if (name.startsWith("__ZN")) position = 4;
        else if (name.startsWith("_ZN")) position = 3;
        else return null;
        List<int[]> result = new ArrayList<>();
        while (position < name.length() && name.charAt(position) != 'E') {
            int digits = position;
            while (position < name.length() && Character.isDigit(name.charAt(position))) position++;
            if (digits == position) return null;
            int size;
            try { size = Integer.parseInt(name.substring(digits, position)); }
            catch (NumberFormatException exception) { return null; }
            if (size <= 0 || position + size > name.length()) return null;
            result.add(new int[] { position, position + size });
            position += size;
        }
        if (result.isEmpty() || position >= name.length() || name.charAt(position) != 'E')
            return null;
        String suffix = name.substring(position + 1);
        if (!suffix.isEmpty() && !suffix.matches("\\.llvm\\.[0-9]+")) return null;
        return result;
    }

    private void processAmbiguousSites() throws Exception {
        Namespace semanticNamespace = null;
        if (!dryRun) {
            try { semanticNamespace = symbols.getNamespace("FLIRT_Ambiguous", null); }
            catch (Exception ignored) { }
        }
        int index = 0;
        for (Site site : ambiguousSites) {
            if ((index++ % 50) == 0) monitor.checkCancelled();
            List<MatchResult> candidates = narrowByExactStructure(site, site.survivors);
            site.survivors = candidates;
            proveFunctionOnlyExtent(site, candidates);
            boolean created = createVerifiedAmbiguousFunction(site);
            applyConsensusSymbols(site, candidates, false);
            applyLogicalConsensusSymbols(site, candidates);
            String digest = ambiguityDigest(candidates);
            String ambiguityId = "AMBIG-" + digest.substring(0, 12);
            String semantic = semanticConsensus(candidates);
            String alias = null;
            String operation = semantic == null ? operationConsensus(candidates) : null;
            String operationAlias = null;
            if (semantic != null) {
                String proposedAlias = semanticAlias(semantic, ambiguityId);
                Function function = functions.getFunctionAt(site.address);
                if (function == null) {
                    semanticNoFunction++;
                    boolean labelApplied = false;
                    if (!dryRun) {
                        if (semanticNamespace == null)
                            semanticNamespace = makeNamespace("FLIRT_Ambiguous");
                        labelApplied = applySemanticLabel(
                            site.address, proposedAlias, semanticNamespace);
                        if (labelApplied) alias = proposedAlias;
                    }
                    semanticDiagnostics.add(new SemanticDiagnostic(
                        "no_function", site.address,
                        site.functionCreationFailure == null ?
                            "no_function_at_address" : site.functionCreationFailure,
                        null, null, semantic, proposedAlias,
                        candidateIdentityNames(candidates), labelApplied));
                }
                else {
                    alias = proposedAlias;
                    Symbol functionSymbol = function.getSymbol();
                    SourceType source = functionSymbol == null ? SourceType.DEFAULT :
                        functionSymbol.getSource();
                    boolean semanticOwned = namespaceIsSemanticOwned(
                        function.getParentNamespace(), semanticNamespace);
                    if (source != SourceType.DEFAULT && !semanticOwned) {
                        semanticNameSkips++;
                        String existingName = function.getName();
                        try { existingName = function.getName(true); }
                        catch (Exception ignored) { }
                        semanticDiagnostics.add(new SemanticDiagnostic(
                            "protected_name", site.address,
                            "existing_non_default_name_is_not_applysig_owned",
                            existingName, source.toString(), semantic, proposedAlias,
                            candidateIdentityNames(candidates), false));
                        alias = null;
                    }
                    else if (semanticOwned && function.getName().equals(alias)) {
                        semanticExisting++;
                    }
                    else if (!dryRun) {
                        if (semanticNamespace == null)
                            semanticNamespace = makeNamespace("FLIRT_Ambiguous");
                        try {
                            function.setName(alias, SourceType.ANALYSIS);
                            semanticAliases++;
                            if (semanticNamespace != null)
                                function.setParentNamespace(semanticNamespace);
                        }
                        catch (Exception exception) {
                            errors++;
                            alias = null;
                        }
                    }
                }
            }
            if (operation != null) {
                operationConsensusSites++;
                String proposed = operationAlias(operation, ambiguityId);
                boolean applied = false;
                if (!dryRun) {
                    if (semanticNamespace == null)
                        semanticNamespace = makeNamespace("FLIRT_Ambiguous");
                    applied = applyOperationLabel(site.address, proposed, semanticNamespace);
                    if (applied) operationAlias = proposed;
                }
                Function function = functions.getFunctionAt(site.address);
                String existingName = null;
                String existingSource = null;
                if (function != null) {
                    existingName = function.getName();
                    try { existingName = function.getName(true); }
                    catch (Exception ignored) { }
                    try { existingSource = function.getSymbol().getSource().toString(); }
                    catch (Exception ignored) { }
                }
                semanticDiagnostics.add(new SemanticDiagnostic(
                    "operation_consensus", site.address,
                    "common_terminal_operation_only", existingName, existingSource,
                    operation, proposed, candidateIdentityNames(candidates), applied));
            }
            annotateAmbiguous(site, candidates, ambiguityId, digest,
                created, semantic, alias, operation, operationAlias);
            ambiguousRejected++;
        }
    }

    private boolean applySemanticLabel(Address address, String name,
                                       Namespace semanticNamespace) {
        if (semanticNamespace == null || name == null || name.isEmpty()) return false;
        try {
            if (functions.getFunctionContaining(address) != null) {
                semanticLabelsContainingSkipped++;
                return false;
            }
            if (listing.getDefinedDataContaining(address) != null) return false;
            for (Symbol symbol : symbols.getSymbols(address)) {
                if (symbol.getName().equals(name) &&
                    symbol.getParentNamespace().equals(semanticNamespace)) {
                    semanticLabelsExisting++;
                    return true;
                }
            }
            symbols.createLabel(address, name, semanticNamespace, SourceType.ANALYSIS);
            semanticLabels++;
            return true;
        }
        catch (Exception exception) {
            semanticLabelErrors++;
            return false;
        }
    }

    /** Add an explicitly approximate secondary symbol without renaming a function. */
    private boolean applyOperationLabel(Address address, String name,
                                        Namespace semanticNamespace) {
        if (semanticNamespace == null || name == null || name.isEmpty()) return false;
        try {
            Function containing = functions.getFunctionContaining(address);
            if (containing != null && !containing.getEntryPoint().equals(address)) {
                operationLabelSkips++;
                return false;
            }
            if (containing == null && listing.getDefinedDataContaining(address) != null) {
                operationLabelSkips++;
                return false;
            }
            for (Symbol symbol : symbols.getSymbols(address)) {
                if (symbol.getName().equals(name) &&
                    symbol.getParentNamespace().equals(semanticNamespace)) {
                    operationLabelsExisting++;
                    return true;
                }
            }
            Function exact = functions.getFunctionAt(address);
            if (exact != null && exact.getSymbol().getSource() == SourceType.DEFAULT) {
                // SymbolTable.createLabel() intentionally renames a default function
                // instead of creating a second symbol.  Temporarily make the function
                // non-default, create the secondary label, then restore the dynamic
                // FUN_* identity.  The approximate operation must never become the
                // function's primary name.
                Symbol functionSymbol = exact.getSymbol();
                String originalName = exact.getName();
                Namespace originalNamespace = exact.getParentNamespace();
                String holdName = "__appsig_operation_hold_" +
                    Long.toHexString(address.getOffset());
                Symbol created = null;
                try {
                    functionSymbol.setName(holdName, SourceType.ANALYSIS);
                    created = symbols.createLabel(
                        address, name, semanticNamespace, SourceType.ANALYSIS);
                }
                finally {
                    try {
                        functionSymbol.setNameAndNamespace(
                            originalName, originalNamespace, SourceType.DEFAULT);
                    }
                    catch (Exception restoreException) {
                        if (created != null) try { created.delete(); }
                        catch (Exception ignored) { }
                        throw restoreException;
                    }
                }
            }
            else {
                symbols.createLabel(address, name, semanticNamespace, SourceType.ANALYSIS);
            }
            operationLabels++;
            return true;
        }
        catch (Exception exception) {
            operationLabelErrors++;
            return false;
        }
    }

    private static boolean namespaceIsSemanticOwned(Namespace namespace,
                                                     Namespace semanticNamespace) {
        if (namespace == null || semanticNamespace == null) return false;
        Namespace current = namespace;
        for (int depth = 0; depth < 64; depth++) {
            if (current.equals(semanticNamespace)) return true;
            Namespace parent;
            try { parent = current.getParentNamespace(); }
            catch (Exception exception) { return false; }
            if (parent == null || parent.equals(current)) return false;
            current = parent;
        }
        return false;
    }

    private void applyLogicalConsensusSymbols(Site site,
                                              List<MatchResult> matches) {
        Set<String> common = null;
        Map<String, PublicSymbol> representative = new HashMap<>();
        for (MatchResult match : matches) {
            Set<String> records = new HashSet<>();
            for (PublicSymbol symbol : match.module.publics) {
                if (symbol.name.isEmpty() || symbol.name.equals("?") || symbol.collision) continue;
                String record = symbol.offset + "\u0000" + logicalIdentity(symbol.name) +
                    "\u0000" + symbol.local;
                records.add(record);
                representative.put(record, symbol);
            }
            if (common == null) common = records;
            else common.retainAll(records);
        }
        if (common == null) return;
        for (String record : new TreeSet<>(common)) {
            PublicSymbol original = representative.get(record);
            if (original.offset == 0 && functions.getFunctionAt(site.address) == null) continue;
            String logicalName = logicalIdentity(original.name);
            int before = appliedFunctionSites.size();
            try { renameAt(site.address.add(original.offset), logicalName, false); }
            catch (Exception exception) { errors++; }
            if (appliedFunctionSites.size() != before) logicalConsensusSymbols++;
        }
    }

    private static String logicalIdentity(String name) {
        String canonical = canonicalIdentity(name);
        return canonical == null ? null : canonical.replaceFirst("\\.llvm\\.[0-9]+$", "");
    }

    /**
     * Prove a boundary without choosing a full identity.  This is intentionally
     * stricter than ordinary name application: every surviving SIG candidate
     * must describe the same extent, the address must have a strong entry
     * origin, and the exact CFG must close at that extent.  Multiple public
     * symbols are allowed here only as in-range labels; at least one must be at
     * offset zero.
     */
    private void proveFunctionOnlyExtent(Site site, List<MatchResult> matches) {
        if (site.provenLength != null || matches.size() < 2 ||
            functions.getFunctionAt(site.address) != null) return;
        functionOnlyAttempts++;
        if (!strongFunctionOrigin(site)) {
            rejectFunctionOnly(String.format(Locale.ROOT,
                "no_strong_or_independent_entry_evidence[sources=0x%X]", site.sources));
            return;
        }
        if (functions.getFunctionContaining(site.address) != null ||
            listing.getDefinedDataContaining(site.address) != null) {
            rejectFunctionOnly("entry_overlaps_existing_function_or_data");
            return;
        }
        if (semanticConsensus(matches) == null && operationConsensus(matches) == null) {
            rejectFunctionOnly("no_common_semantic_or_operation");
            return;
        }

        Map<Long, Module> lengths = new TreeMap<>();
        for (MatchResult match : matches) {
            Module module = match.module;
            if (module.fixedBytes < MIN_STRUCTURAL_FIXED ||
                !moduleFunctionLayoutSafe(module) ||
                !moduleFitsKnownLayout(site.address, module)) {
                rejectFunctionOnly("candidate_layout_not_safe");
                return;
            }
            lengths.putIfAbsent(module.length, module);
        }
        List<Map.Entry<Long, StructuralEvidence>> proven = new ArrayList<>();
        for (Map.Entry<Long, Module> entry : lengths.entrySet()) {
            StructuralEvidence evidence = structuralEvidence(site, entry.getValue());
            if (evidence.functionBoundaryVerified() &&
                safeExplicitFunctionBody(site.address, evidence.reachableBody))
                proven.add(new java.util.AbstractMap.SimpleImmutableEntry<>(
                    entry.getKey(), evidence));
        }
        if (proven.isEmpty()) {
            if (proveNaturalCfgBody(site, matches, lengths)) return;
            rejectFunctionOnly(functionBoundaryFailureSummary(site, lengths));
            return;
        }
        if (proven.size() != 1) {
            rejectFunctionOnly("multiple_lengths_passed_closed_cfg_or_padding");
            return;
        }
        Map.Entry<Long, StructuralEvidence> selected = proven.get(0);
        site.provenLength = Math.toIntExact(selected.getKey());
        site.provenBody = new AddressSet(selected.getValue().reachableBody);
        site.functionOnlyProof = true;
        site.functionProofKind = selected.getValue().safePaddingExact ?
            "sig_extent_with_safe_padding" : "sig_extent_exact";
        site.functionProofSigLengths = new ArrayList<>(lengths.keySet());
        functionOnlyProofs++;
        if (selected.getValue().safePaddingExact) paddingCfgProofs++;
    }

    /**
     * Some Rust object variants share an exact strong prefix and semantic but
     * carry different trailing extents.  A function boundary may still be
     * proven without selecting a module length when every candidate extent is
     * large enough to decode the same terminating CFG body.  This path creates
     * only that common body and never uses the result to choose a full name.
     */
    private boolean proveNaturalCfgBody(Site site, List<MatchResult> matches,
                                        Map<Long, Module> lengths) {
        for (MatchResult match : matches) {
            Module module = match.module;
            boolean strong = module.fixedBytes >= MIN_CREATE_FIXED;
            boolean corroborated = module.fixedBytes >= MIN_CREATE_CORROBORATED &&
                (module.crcLength >= MIN_CRC || !module.tails.isEmpty());
            if (!(strong || corroborated)) return false;
        }
        AddressSet commonBody = null;
        long maximumEnd = -1;
        for (Map.Entry<Long, Module> entry : lengths.entrySet()) {
            StructuralEvidence evidence = structuralEvidence(site, entry.getValue());
            if (!evidence.trustedOrigin || !evidence.validSubroutine ||
                !evidence.allPathsClosed || evidence.terminalCount == 0 ||
                (evidence.computedJumpSeen && !evidence.computedJumpResolved) ||
                !safeExplicitFunctionBody(site.address, evidence.reachableBody)) return false;
            if (commonBody == null) commonBody = new AddressSet(evidence.reachableBody);
            else if (!sameAddressSet(commonBody, evidence.reachableBody)) return false;
            maximumEnd = Math.max(maximumEnd, evidence.maxInstructionEnd);
        }
        if (commonBody == null || maximumEnd < site.address.getOffset()) return false;
        site.provenLength = Math.toIntExact(maximumEnd - site.address.getOffset() + 1);
        site.provenBody = commonBody;
        site.functionOnlyProof = true;
        site.functionProofKind = "common_natural_cfg_body";
        site.functionProofSigLengths = new ArrayList<>(lengths.keySet());
        functionOnlyProofs++;
        naturalCfgProofs++;
        return true;
    }

    private boolean strongFunctionOrigin(Site site) {
        if ((site.sources & (SOURCE_LINEAR_CALL | SOURCE_ENTRY |
             SOURCE_SIG_ANCHOR_VERIFIED)) != 0) return true;
        if ((site.sources & SOURCE_RELOCATION) != 0 &&
            (site.sources & (SOURCE_TYPED_POINTER | SOURCE_POINTER_TABLE)) != 0) return true;
        if (TRUST_EXACT_DATA_RELOCATION_POINTERS &&
            (site.sources & SOURCE_DATA_RELOCATION_POINTER) != 0) return true;
        return (site.sources & SOURCE_LINEAR_TAIL) != 0 &&
            (site.sources & (SOURCE_REFERENCE | SOURCE_RELOCATION |
             SOURCE_TYPED_POINTER | SOURCE_POINTER_TABLE)) != 0;
    }

    private void rejectFunctionOnly(String reason) {
        functionOnlyFailureReasons.merge(reason, 1L, Long::sum);
    }

    private String functionBoundaryFailureSummary(Site site, Map<Long, Module> lengths) {
        Set<String> states = new TreeSet<>();
        for (Map.Entry<Long, Module> entry : lengths.entrySet()) {
            StructuralEvidence evidence = structuralEvidence(site, entry.getValue());
            states.add(String.format(Locale.ROOT,
                "len=%X:v%d:c%d:t%d:p%d:j%d:b%d", entry.getKey(),
                evidence.validSubroutine ? 1 : 0,
                evidence.allPathsClosed ? 1 : 0,
                evidence.terminalExact ? 1 : 0,
                evidence.safePaddingExact ? 1 : 0,
                evidence.computedJumpResolved ? 1 : 0,
                safeExplicitFunctionBody(site.address, evidence.reachableBody) ? 1 : 0));
        }
        return String.format(Locale.ROOT,
            "no_length_passed_cfg[sources=0x%X;%s]", site.sources,
            String.join("|", states));
    }

    private boolean safeExplicitFunctionBody(Address entry, AddressSet body) {
        if (body == null || body.isEmpty() || !body.contains(entry)) return false;
        try {
            FunctionIterator entries = functions.getFunctions(body, true);
            if (entries.hasNext()) return false;
            AddressRangeIterator ranges = body.getAddressRanges();
            while (ranges.hasNext()) {
                AddressRange range = ranges.next();
                if (functions.getFunctionContaining(range.getMinAddress()) != null ||
                    functions.getFunctionContaining(range.getMaxAddress()) != null) return false;
                if (listing.getDefinedDataContaining(range.getMinAddress()) != null ||
                    listing.getDefinedDataContaining(range.getMaxAddress()) != null) return false;
            }
            return !listing.getDefinedData(body, true).hasNext();
        }
        catch (Exception exception) { return false; }
    }

    private static boolean moduleFunctionLayoutSafe(Module module) {
        if (module.length <= 0 || module.length > MAX_CFG_BYTES) return false;
        boolean entryPublic = false;
        for (PublicSymbol symbol : module.publics) {
            if (symbol.name.isEmpty() || symbol.name.equals("?") || symbol.collision) continue;
            if (symbol.offset < 0 || symbol.offset >= module.length) return false;
            if (symbol.offset == 0) entryPublic = true;
        }
        return entryPublic;
    }

    private boolean createVerifiedAmbiguousFunction(Site site) {
        site.functionCreationFailure = null;
        if (functions.getFunctionAt(site.address) != null) return false;
        if (site.provenLength == null) {
            site.functionCreationFailure = diagnoseUnprovenFunctionExtent(site);
            return false;
        }
        Function containing = functions.getFunctionContaining(site.address);
        if (containing != null) {
            site.functionCreationFailure = "inside_existing_function@" +
                containing.getEntryPoint() + ":" + containing.getName();
            return false;
        }
        if (dryRun) return true;
        Function function = site.functionOnlyProof && site.provenBody != null ?
            createFunctionWithBody(site.address, site.provenBody) :
            createFunctionAt(site.address);
        if (function == null) {
            site.functionCreationFailure = "ghidra_create_function_failed";
            return false;
        }
        try {
            boolean exact;
            if (site.functionOnlyProof && site.provenBody != null) {
                exact = sameAddressSet(function.getBody(), site.provenBody);
            }
            else {
                exact = function.getBody().getNumAddresses() == site.provenLength &&
                    function.getBody().getMaxAddress().subtract(site.address) + 1 == site.provenLength;
            }
            if (exact) {
                ambiguousFunctionsCreated++;
                if (site.functionOnlyProof) {
                    functionOnlyCreated++;
                    String semantic = semanticConsensus(site.survivors);
                    if (semantic == null) semantic = operationConsensus(site.survivors);
                    functionProofDiagnostics.add(new FunctionProofDiagnostic(site, semantic,
                        dataRelocationPointerSourceCount(site.address)));
                }
                return true;
            }
            site.functionCreationFailure = "created_body_extent_mismatch";
            functions.removeFunction(site.address);
            functionsCreated--;
            if (site.functionOnlyProof && site.provenBody != null) {
                explicitBodyCreated--;
                if (site.provenBody.getNumAddressRanges() > 1) nonContiguousBodyCreated--;
            }
        }
        catch (Exception exception) {
            site.functionCreationFailure = "function_creation_exception:" +
                exception.getClass().getSimpleName();
            try {
                functions.removeFunction(site.address);
                functionsCreated--;
                if (site.functionOnlyProof && site.provenBody != null) {
                    explicitBodyCreated--;
                    if (site.provenBody.getNumAddressRanges() > 1) nonContiguousBodyCreated--;
                }
            }
            catch (Exception ignored) { errors++; }
        }
        return false;
    }

    private Function createFunctionWithBody(Address entry, AddressSet body) {
        if (dryRun) return null;
        try {
            if (functions.getFunctionAt(entry) != null ||
                functions.getFunctionContaining(entry) != null) return null;
            if (listing.getInstructionAt(entry) == null) disassemble(entry);
            CreateFunctionCmd command = new CreateFunctionCmd(
                null, entry, body, SourceType.DEFAULT, false, false);
            if (!command.applyTo(currentProgram, monitor)) return null;
            Function function = functions.getFunctionAt(entry);
            if (function != null) {
                functionsCreated++;
                explicitBodyCreated++;
                if (body.getNumAddressRanges() > 1) nonContiguousBodyCreated++;
            }
            return function;
        }
        catch (Exception exception) { return null; }
    }

    private static boolean sameAddressSet(AddressSetView left, AddressSetView right) {
        return left != null && right != null &&
            left.getNumAddresses() == right.getNumAddresses() &&
            left.contains(right) && right.contains(left);
    }

    private String diagnoseUnprovenFunctionExtent(Site site) {
        int shortFixed = 0;
        int nonSinglePublic = 0;
        int invalidLength = 0;
        Map<Long, Module> lengths = new TreeMap<>();
        for (MatchResult match : site.survivors) {
            Module module = match.module;
            int usable = 0;
            long onlyOffset = -1;
            for (PublicSymbol symbol : module.publics) {
                if (!symbol.name.isEmpty() && !symbol.name.equals("?") && !symbol.collision) {
                    usable++;
                    onlyOffset = symbol.offset;
                }
            }
            if (module.fixedBytes < MIN_STRUCTURAL_FIXED) shortFixed++;
            if (usable != 1 || onlyOffset != 0) nonSinglePublic++;
            if (module.length <= 0 || module.length > MAX_CFG_BYTES) invalidLength++;
            if (module.fixedBytes >= MIN_STRUCTURAL_FIXED && usable == 1 &&
                onlyOffset == 0 && module.length > 0 && module.length <= MAX_CFG_BYTES)
                lengths.putIfAbsent(module.length, module);
        }
        if (shortFixed != 0 || nonSinglePublic != 0 || invalidLength != 0)
            return String.format(Locale.ROOT,
                "signature_layout_not_safely_comparable(short_fixed=%d,non_single_public=%d,invalid_length=%d)",
                shortFixed, nonSinglePublic, invalidLength);
        List<Long> proven = new ArrayList<>();
        for (Map.Entry<Long, Module> entry : lengths.entrySet()) {
            StructuralEvidence evidence = structuralEvidence(site, entry.getValue());
            if (evidence.verified()) proven.add(entry.getKey());
        }
        if (proven.isEmpty()) return "no_candidate_length_passed_exact_closed_cfg";
        if (proven.size() > 1) return "multiple_candidate_lengths_passed_exact_closed_cfg:" + proven;
        return "unique_cfg_extent_was_not_retained";
    }

    private List<String> candidateIdentityNames(List<MatchResult> matches) {
        List<String> names = new ArrayList<>(groupByIdentity(matches).keySet());
        Collections.sort(names);
        return names;
    }

    private static String ambiguityDigest(List<MatchResult> matches) {
        try {
            List<String> rows = new ArrayList<>();
            for (MatchResult match : matches) {
                Module module = match.module;
                Map<String, PublicSymbol> uniqueFacts = new HashMap<>();
                for (PublicSymbol symbol : module.publics) {
                    if (!symbol.name.isEmpty() && !symbol.name.equals("?") && !symbol.collision) {
                        String canonical = canonicalIdentity(symbol.name);
                        uniqueFacts.put(symbol.offset + "\u0000" + canonical +
                            "\u0000" + symbol.local, symbol);
                    }
                }
                List<PublicSymbol> facts = new ArrayList<>(uniqueFacts.values());
                facts.sort(Comparator.comparingLong((PublicSymbol symbol) -> symbol.offset)
                    .thenComparing(symbol -> canonicalIdentity(symbol.name))
                    .thenComparing(symbol -> symbol.local));
                List<PublicSymbol> refs = new ArrayList<>(module.refs);
                refs.sort(Comparator.comparingLong((PublicSymbol symbol) -> symbol.offset)
                    .thenComparing(symbol -> symbol.negative)
                    .thenComparing(symbol -> canonicalIdentity(symbol.name)));
                List<String> factRows = new ArrayList<>();
                for (PublicSymbol symbol : facts)
                    factRows.add("(" + symbol.offset + ", " +
                        pythonStringRepr(canonicalIdentity(symbol.name)) + ", " +
                        (symbol.local ? "True" : "False") + ")");
                List<String> refRows = new ArrayList<>();
                for (PublicSymbol ref : refs)
                    refRows.add("(" + ref.offset + ", " +
                        (ref.negative ? "True" : "False") + ", " +
                        pythonStringRepr(canonicalIdentity(ref.name)) + ")");
                rows.add("(" + module.length + ", [" +
                    String.join(", ", factRows) + "], [" +
                    String.join(", ", refRows) + "])");
            }
            Collections.sort(rows);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] value = digest.digest(String.join("\n", rows)
                .getBytes(StandardCharsets.UTF_8));
            return hex(value);
        }
        catch (Exception exception) { return "00000000000000000000000000000000"; }
    }

    /** Python 3 string repr for the ASCII symbol alphabet used by IDASGN. */
    private static String pythonStringRepr(String value) {
        char quote = value.indexOf('\'') >= 0 && value.indexOf('"') < 0 ? '"' : '\'';
        StringBuilder result = new StringBuilder(value.length() + 2).append(quote);
        for (int index = 0; index < value.length(); index++) {
            char ch = value.charAt(index);
            if (ch == '\\' || ch == quote) result.append('\\').append(ch);
            else if (ch == '\t') result.append("\\t");
            else if (ch == '\n') result.append("\\n");
            else if (ch == '\r') result.append("\\r");
            else if (ch < 0x20 || ch == 0x7f)
                result.append(String.format("\\x%02x", (int)ch));
            else result.append(ch);
        }
        return result.append(quote).toString();
    }

    private static String demangleRust(String name) {
        if (name == null) return null;
        if (RUST_DEMANGLE_CACHE.containsKey(name)) return RUST_DEMANGLE_CACHE.get(name);
        String result = computeDemangledRust(name);
        cacheNameResult(RUST_DEMANGLE_CACHE, name, result);
        return result;
    }

    private static String computeDemangledRust(String name) {
        String canonical = canonicalIdentity(name);
        List<int[]> components = parseRustComponents(canonical);
        if (components == null) return null;
        List<String> values = new ArrayList<>();
        for (int[] range : components) {
            String value = canonical.substring(range[0], range[1]);
            value = value.replace("$LT$", "<").replace("$GT$", ">")
                .replace("$SP$", "@").replace("$BP$", "*")
                .replace("$RF$", "&").replace("$LP$", "(")
                .replace("$RP$", ")").replace("$C$", ",")
                .replace("..", "::");
            value = decodeRustUnicode(value);
            if (value.startsWith("_<")) value = value.substring(1);
            value = value.replace("GenericShunt<I,R>", "GenericShunt<I,C,R>");
            values.add(value);
        }
        return String.join("::", values);
    }

    private static String decodeRustUnicode(String value) {
        Matcher matcher = RUST_CANONICAL_UNICODE.matcher(value);
        StringBuffer result = new StringBuffer();
        while (matcher.find()) {
            String replacement = matcher.group(0);
            try {
                int codePoint = Integer.parseInt(matcher.group(1), 16);
                if (Character.isValidCodePoint(codePoint) &&
                    !(0xD800 <= codePoint && codePoint <= 0xDFFF))
                    replacement = new String(Character.toChars(codePoint));
            }
            catch (RuntimeException ignored) { }
            matcher.appendReplacement(result, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(result);
        return result.toString();
    }

    private static String semanticConsensus(List<MatchResult> matches) {
        if (matches.size() < 2) return null;
        Set<String> values = new HashSet<>();
        for (MatchResult match : matches) {
            String semantic = semanticRustIdentity(match.module.primaryName());
            if (semantic == null) return null;
            values.add(semantic);
        }
        return values.size() == 1 ? values.iterator().next() : null;
    }

    /** Return only the terminal Rust operation when every identity agrees. */
    private static String operationConsensus(List<MatchResult> matches) {
        if (matches.size() < 2) return null;
        String common = null;
        Set<String> identities = new HashSet<>();
        for (MatchResult match : matches) {
            String identity = canonicalIdentity(match.module.primaryName());
            if (identity == null) return null;
            identities.add(identity);
            String semantic = semanticRustIdentity(match.module.primaryName());
            if (semantic == null) return null;
            List<String> parts = splitRustPath(semantic);
            if (parts.isEmpty()) return null;
            String operation = parts.get(parts.size() - 1);
            if (!usefulOperation(operation)) return null;
            if (common == null) common = operation;
            else if (!common.equals(operation)) return null;
        }
        return identities.size() >= 2 ? common : null;
    }

    private static boolean usefulOperation(String operation) {
        if (operation == null || operation.length() < 3) return false;
        if (!operation.matches("[A-Za-z_][A-Za-z0-9_]{2,127}")) return false;
        if (operation.equals("unknown") || operation.equals("function") ||
            operation.equals("closure") || operation.matches("h[0-9a-fA-F]{16}"))
            return false;
        return true;
    }

    private static String semanticRustIdentity(String name) {
        if (name == null) return null;
        if (RUST_SEMANTIC_CACHE.containsKey(name)) return RUST_SEMANTIC_CACHE.get(name);
        String display = demangleRust(logicalIdentity(name));
        String result = null;
        if (display != null) {
            List<String> parts = splitRustPath(display);
            if (!parts.isEmpty() && parts.get(parts.size() - 1).matches("h[0-9a-fA-F]{16}"))
                parts.remove(parts.size() - 1);
            List<String> normalized = new ArrayList<>();
            for (String part : parts) {
                String value = stripGenericArguments(part);
                if (!value.isEmpty()) normalized.addAll(splitRustPath(value));
            }
            if (normalized.size() >= 2) {
                String operation = normalized.get(normalized.size() - 1);
                if (!operation.isEmpty() && !operation.equals("?") &&
                    !operation.equals("unknown") &&
                    !operation.matches("h[0-9a-fA-F]{16}"))
                    result = String.join("::", normalized);
            }
        }
        cacheNameResult(RUST_SEMANTIC_CACHE, name, result);
        return result;
    }

    private static List<String> splitRustPath(String value) {
        List<String> parts = new ArrayList<>();
        int start = 0, angle = 0, paren = 0, square = 0, brace = 0;
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (ch == '<') angle++;
            else if (ch == '>' && angle > 0) angle--;
            else if (ch == '(') paren++;
            else if (ch == ')' && paren > 0) paren--;
            else if (ch == '[') square++;
            else if (ch == ']' && square > 0) square--;
            else if (ch == '{') brace++;
            else if (ch == '}' && brace > 0) brace--;
            else if (ch == ':' && i + 1 < value.length() && value.charAt(i + 1) == ':' &&
                     angle == 0 && paren == 0 && square == 0 && brace == 0) {
                if (i > start) parts.add(value.substring(start, i));
                i++;
                start = i + 1;
            }
        }
        if (start < value.length()) parts.add(value.substring(start));
        return parts;
    }

    private static String stripGenericArguments(String input) {
        String value = input.trim();
        if (value.startsWith("<") && value.endsWith(">")) {
            String inner = value.substring(1, value.length() - 1).trim();
            int marker = inner.lastIndexOf(" as ");
            if (marker >= 0) inner = inner.substring(marker + 4).trim();
            List<String> nested = splitRustPath(inner);
            List<String> normalized = new ArrayList<>();
            for (String part : nested) normalized.add(stripGenericArguments(part));
            return String.join("::", normalized);
        }
        int generic = value.indexOf('<');
        return (generic > 0 ? value.substring(0, generic) : value).trim();
    }

    private static String semanticAlias(String semantic, String ambiguityId) {
        String base = semantic.replaceAll("[^A-Za-z0-9_]+", "_")
            .replaceAll("_+", "_").replaceAll("^_+|_+$", "");
        if (base.isEmpty()) base = "rust_operation";
        String suffix = "__" + ambiguityId.replace('-', '_');
        int room = Math.max(1, 180 - "ambig_".length() - suffix.length());
        if (base.length() > room) base = base.substring(0, room).replaceAll("_+$", "");
        return "ambig_" + base + suffix;
    }

    private static String operationAlias(String operation, String ambiguityId) {
        String base = operation.replaceAll("[^A-Za-z0-9_]+", "_")
            .replaceAll("_+", "_").replaceAll("^_+|_+$", "");
        if (base.isEmpty()) base = "rust_operation";
        String suffix = "__" + ambiguityId.replace('-', '_');
        int room = Math.max(1, 180 - "ambig_op_".length() - suffix.length());
        if (base.length() > room) base = base.substring(0, room).replaceAll("_+$", "");
        return "ambig_op_" + base + suffix;
    }

    private void annotateAmbiguous(Site site, List<MatchResult> candidates,
                                   String ambiguityId, String digest,
                                   boolean functionCreated, String semantic,
                                   String alias, String operation,
                                   String operationAlias) {
        List<String> names = new ArrayList<>(groupByIdentity(candidates).keySet());
        Collections.sort(names);
        StringBuilder note = new StringBuilder();
        note.append("FLIRT ambiguous ").append(ambiguityId).append('\n');
        note.append("candidates: ").append(candidates.size()).append('\n');
        if (site.provenLength != null)
            note.append("proven CFG extent: 0x")
                .append(Integer.toHexString(site.provenLength).toUpperCase(Locale.ROOT)).append('\n');
        if (functionCreated) note.append("function created from exact CFG; identity unresolved\n");
        if (semantic != null) {
            note.append("semantic alias (approximate): ").append(semantic).append('\n');
            if (alias != null) note.append("semantic Ghidra symbol: ").append(alias).append('\n');
        }
        if (operation != null) {
            note.append("common operation only (approximate): ").append(operation).append('\n');
            if (operationAlias != null)
                note.append("operation Ghidra symbol: ").append(operationAlias).append('\n');
        }
        note.append("candidate-set SHA256: ").append(digest).append('\n');
        for (int i = 0; i < Math.min(12, names.size()); i++)
            note.append("candidate: ").append(names.get(i), 0,
                Math.min(300, names.get(i).length())).append('\n');
        if (dryRun) return;
        boolean annotated = false;
        try {
            String previous = listing.getComment(CodeUnit.REPEATABLE_COMMENT, site.address);
            if (previous == null) previous = "";
            if (!previous.contains("FLIRT ambiguous " + ambiguityId))
                listing.setComment(site.address, CodeUnit.REPEATABLE_COMMENT,
                    (previous + "\n" + note).trim());
            annotated = true;
        }
        catch (Exception ignored) { }
        try {
            BookmarkManager manager = currentProgram.getBookmarkManager();
            manager.setBookmark(site.address, "Analysis", "FLIRT/Ambiguous", note.toString().trim());
            annotated = true;
        }
        catch (Exception ignored) { }
        if (annotated) ambiguousAnnotated++;
    }

    private void printReport() throws Exception {
        double elapsed = (System.nanoTime() - startedNanos) / 1_000_000_000.0;
        println("================ Apply FLIRT Signatures report ================");
        printf(" tool version       : %s%n", TOOL_VERSION);
        printf(" library            : %s%n", libraryName());
        printf(" signature producer : %s%n", signature.header.libraryName);
        printf(" mode               : %s%n", dryRun ? "dry-run" : "apply");
        printf(" strict verification: True%n");
        printf(" evidence mode      : SIG only%n");
        printf(" signature funcs    : %,d%n", signature.header.nFunctions);
        printf(" signature modules  : %,d%n", signature.modules);
        printf(" executable snapshots: %,d%n", executableSnapshotBlocks);
        printf(" executable bytes   : %,d%n", executableSnapshotBytes);
        printf(" snapshot read hits : %,d%n", executableSnapshotReads);
        printf(" snapshot fallbacks : %,d%n", executableSnapshotFallbacks);
        printf(" SIG anchor leaves  : %,d%n", sigAnchorLeafPaths);
        printf(" SIG anchor covered : %,d%n", sigAnchorAnchoredPaths);
        printf(" SIG anchor index   : %,d%n", rareAnchorIndex.size());
        printf(" anchor fanout skip : %,d%n", sigAnchorFanoutSkipped);
        printf(" anchor fixed windows: %,d%n", sigAnchorFixedWindows);
        printf(" anchor second paths: %,d%n", sigAnchorSecondaryPaths);
        printf(" anchor second checks: %,d%n", sigAnchorSecondaryChecks);
        printf(" anchor second reject: %,d%n", sigAnchorSecondaryRejected);
        printf(" SIG anchor bytes   : %,d%n", sigAnchorBytesScanned);
        printf(" SIG anchor raw hits: %,d%n", sigAnchorRawHits);
        printf(" SIG anchor cands   : %,d%n", sigAnchorCandidates);
        printf(" SIG anchor matches : %,d%n", sigAnchorSignatureHits);
        printf(" SIG anchor rejected: %,d%n", sigAnchorCfgRejected);
        printf(" functions matched  : %,d%n", functionsMatched);
        printf(" created (undefined): %,d%n", functionsCreated);
        printf(" functions split     : %,d%n", functionsSplit);
        printf(" splits rejected     : %,d%n", splitsRejected);
        printf(" split restore fails : %,d%n", splitRestoreFailures);
        printf(" renamed            : %,d%n", renamed);
        printf(" already correct    : %,d%n", alreadyCorrect);
        printf(" unique applied funcs: %,d%n", appliedFunctionSites.size());
        printf(" native instructions : %,d%n", nativeInstructions);
        printf(" pseudo scan attempts: %,d%n", pseudoScanAttempts);
        printf(" native decode fails : %,d%n", nativeDecodeFailures);
        printf(" native call flows   : %,d%n", nativeCallFlows);
        printf(" native tail flows   : %,d%n", nativeTailFlows);
        printf(" native candidates   : %,d%n", discoveredSources.size());
        printf(" reference candidates: %,d%n", countDiscoveredSource(SOURCE_REFERENCE));
        printf(" relocation candidates: %,d%n", countDiscoveredSource(SOURCE_RELOCATION));
        printf(" exact data reloc ptrs: %,d%n",
            countDiscoveredSource(SOURCE_DATA_RELOCATION_POINTER));
        printf(" exact data reloc cells: %,d%n", dataRelocationPointerCellCount());
        printf(" typed ptr candidates: %,d%n", countDiscoveredSource(SOURCE_TYPED_POINTER));
        printf(" pointer slots scanned: %,d%n", pointerSlotsScanned);
        printf(" pointer-table cands : %,d%n", countDiscoveredSource(SOURCE_POINTER_TABLE));
        printf(" flow candidates     : %,d%n", flowCandidates);
        printf(" boundary candidates : %,d%n", boundaryCandidates);
        printf(" boundary matches    : %,d%n", boundaryMatches);
        printf(" native tested       : %,d%n", nativeTested);
        printf(" native sig matches  : %,d%n", nativeSigMatches);
        printf(" accepted strong    : %,d%n", acceptedStrong);
        printf(" accepted CRC/tail  : %,d%n", acceptedCrcTail);
        printf(" accepted reference : %,d%n", acceptedReference);
        printf(" accepted structure : %,d%n", acceptedStructure);
        printf(" data-reloc structure: %,d%n", dataRelocationStructureAccepted);
        printf(" structure resolved : %,d%n", structuralIdentitiesResolved);
        printf(" data-reloc resolved: %,d%n", dataRelocationIdentitiesResolved);
        printf(" weak sig rejected  : %,d%n", weakRejected);
        printf(" ambiguous rejected : %,d%n", ambiguousRejected);
        printf(" fanout rejected    : %,d%n", fanoutRejected);
        printf(" ambiguous func made: %,d%n", ambiguousFunctionsCreated);
        printf(" function-only tries: %,d%n", functionOnlyAttempts);
        printf(" function-only proofs: %,d%n", functionOnlyProofs);
        printf(" function-only created: %,d%n", functionOnlyCreated);
        printf(" padding CFG proofs  : %,d%n", paddingCfgProofs);
        printf(" natural CFG proofs  : %,d%n", naturalCfgProofs);
        printf(" explicit body made  : %,d%n", explicitBodyCreated);
        printf(" noncontig body made : %,d%n", nonContiguousBodyCreated);
        printf(" layout pruned      : %,d%n", layoutCandidatesPruned);
        printf(" layout narrowed    : %,d%n", layoutSitesNarrowed);
        printf(" layout resolved    : %,d%n", layoutIdentitiesResolved);
        printf(" SIG graph rounds   : %,d%n", sigGraphRounds);
        printf(" SIG graph checks   : %,d%n", sigGraphConstraints);
        printf(" SIG graph pruned   : %,d%n", sigGraphCandidatesPruned);
        printf(" SIG graph narrowed : %,d%n", sigGraphSitesNarrowed);
        printf(" SIG graph resolved : %,d%n", sigGraphIdentitiesResolved);
        printf(" SIG graph conflicts: %,d%n", sigGraphConflicts);
        printf(" computed CFG sites : %,d%n", computedCfgSites);
        printf(" computed CFG solved: %,d%n", computedCfgResolved);
        printf(" computed CFG reject: %,d%n", computedCfgRejected);
        printf(" ambiguous annotated: %,d%n", ambiguousAnnotated);
        printf(" logical consensus  : %,d%n", logicalConsensusSymbols);
        printf(" semantic aliases   : %,d%n", semanticAliases);
        printf(" semantic existing  : %,d%n", semanticExisting);
        printf(" semantic name skips: %,d%n", semanticNameSkips);
        printf(" semantic no func   : %,d%n", semanticNoFunction);
        printf(" semantic labels    : %,d%n", semanticLabels);
        printf(" semantic labels old: %,d%n", semanticLabelsExisting);
        printf(" semantic label skip: %,d  (inside function)%n", semanticLabelsContainingSkipped);
        printf(" semantic label errs: %,d%n", semanticLabelErrors);
        printf(" operation consensus: %,d%n", operationConsensusSites);
        printf(" operation labels   : %,d%n", operationLabels);
        printf(" operation labels old: %,d%n", operationLabelsExisting);
        printf(" operation label skip: %,d%n", operationLabelSkips);
        printf(" operation label errs: %,d%n", operationLabelErrors);
        printf(" CFG decode cache hit: %,d%n", structuralDecodeCacheHits);
        printf(" CFG decode cache miss: %,d%n", structuralDecodeCacheMisses);
        printf(" subroutine cache hit: %,d%n", validSubroutineCacheHits);
        printf(" subroutine cache miss: %,d%n", validSubroutineCacheMisses);
        printf(" skipped user names : %,d%n", skippedUserNames);
        printf(" rust names restored: %,d%n", rustNamesRestored);
        printf(" rust names demangled: %,d%n", rustNamesDemangled);
        printf(" rust demangle failed: %,d%n", rustDemangleFailed);
        printf(" raw names preserved: %,d%n", rawNamesPreserved);
        printf(" namespace errors   : %,d%n", namespaceErrors);
        printf(" errors             : %,d%n", errors);
        printf(" parse seconds      : %.3f%n", seconds(parseNanos));
        printf(" snapshot seconds   : %.3f%n", seconds(snapshotNanos));
        printf(" anchor index secs  : %.3f%n", seconds(anchorIndexNanos));
        printf(" anchor scan secs   : %.3f%n", seconds(anchorScanNanos));
        printf(" initial match secs : %.3f%n", seconds(initialMatchNanos));
        printf(" native find seconds: %.3f%n", seconds(discoveryNanos));
        printf(" native probe secs  : %.3f%n", seconds(probeNanos));
        printf(" apply seconds      : %.3f%n", seconds(applyNanos));
        printf(" elapsed seconds    : %.3f%n", elapsed);
        printSemanticDiagnosticSummary();
        if (reportPath != null) println(" JSON report        : " + reportPath);
    }

    private void printSemanticDiagnosticSummary() {
        Map<String, Integer> noFunctionReasons = new TreeMap<>();
        for (SemanticDiagnostic item : semanticDiagnostics) {
            if (item.kind.equals("no_function"))
                noFunctionReasons.merge(item.reason, 1, Integer::sum);
        }
        for (Map.Entry<String, Integer> entry : noFunctionReasons.entrySet())
            printf(" no-function reason : %,d x %s%n", entry.getValue(), entry.getKey());
        for (Map.Entry<String, Long> entry : functionOnlyFailureReasons.entrySet())
            printf(" function-only reject: %,d x %s%n", entry.getValue(), entry.getKey());
        for (SemanticDiagnostic item : semanticDiagnostics) {
            if (!item.kind.equals("protected_name")) continue;
            printf(" protected detail   : %s existing=%s [%s]%n",
                item.address, item.existingName, item.existingSource);
            printf("   proposed alias   : %s%n", item.proposedAlias);
            for (String candidate : item.candidates)
                printf("   matched candidate: %s%n", candidate);
        }
    }

    private void writeJsonReport(Path path) throws Exception {
        double elapsed = (System.nanoTime() - startedNanos) / 1_000_000_000.0;
        String json = "{\n" +
            "  \"schema_version\": \"1.5\",\n" +
            "  \"tool_version\": \"" + jsonEscape(TOOL_VERSION) + "\",\n" +
            "  \"signature\": \"" + jsonEscape(signaturePath.toString()) + "\",\n" +
            "  \"signature_sha256\": \"" + fileSha256(signaturePath) + "\",\n" +
            "  \"program\": \"" + jsonEscape(currentProgram.getName()) + "\",\n" +
            "  \"mode\": \"" + (dryRun ? "dry-run" : "apply") + "\",\n" +
            "  \"functions_matched\": " + functionsMatched + ",\n" +
            "  \"created_functions\": " + functionsCreated + ",\n" +
            "  \"renamed\": " + renamed + ",\n" +
            "  \"unique_applied_function_sites\": " + appliedFunctionSites.size() + ",\n" +
            "  \"executable_snapshot_blocks\": " + executableSnapshotBlocks + ",\n" +
            "  \"executable_snapshot_bytes\": " + executableSnapshotBytes + ",\n" +
            "  \"executable_snapshot_read_hits\": " + executableSnapshotReads + ",\n" +
            "  \"executable_snapshot_fallbacks\": " + executableSnapshotFallbacks + ",\n" +
            "  \"sig_anchor_leaf_paths\": " + sigAnchorLeafPaths + ",\n" +
            "  \"sig_anchor_anchored_paths\": " + sigAnchorAnchoredPaths + ",\n" +
            "  \"sig_anchor_index_size\": " + rareAnchorIndex.size() + ",\n" +
            "  \"sig_anchor_fanout_skipped\": " + sigAnchorFanoutSkipped + ",\n" +
            "  \"sig_anchor_fixed_windows\": " + sigAnchorFixedWindows + ",\n" +
            "  \"sig_anchor_secondary_paths\": " + sigAnchorSecondaryPaths + ",\n" +
            "  \"sig_anchor_secondary_checks\": " + sigAnchorSecondaryChecks + ",\n" +
            "  \"sig_anchor_secondary_rejected\": " + sigAnchorSecondaryRejected + ",\n" +
            "  \"sig_anchor_bytes_scanned\": " + sigAnchorBytesScanned + ",\n" +
            "  \"sig_anchor_raw_hits\": " + sigAnchorRawHits + ",\n" +
            "  \"sig_anchor_candidates_found\": " + sigAnchorCandidates + ",\n" +
            "  \"sig_anchor_signature_hits\": " + sigAnchorSignatureHits + ",\n" +
            "  \"sig_anchor_cfg_rejected\": " + sigAnchorCfgRejected + ",\n" +
            "  \"native_instructions\": " + nativeInstructions + ",\n" +
            "  \"pseudo_scan_attempts\": " + pseudoScanAttempts + ",\n" +
            "  \"native_candidates\": " + discoveredSources.size() + ",\n" +
            "  \"exact_data_relocation_pointer_candidates\": " +
                countDiscoveredSource(SOURCE_DATA_RELOCATION_POINTER) + ",\n" +
            "  \"exact_data_relocation_pointer_cells\": " +
                dataRelocationPointerCellCount() + ",\n" +
            "  \"native_signature_matches\": " + nativeSigMatches + ",\n" +
            "  \"data_relocation_structure_accepted\": " +
                dataRelocationStructureAccepted + ",\n" +
            "  \"structural_identities_resolved\": " +
                structuralIdentitiesResolved + ",\n" +
            "  \"structural_resolved_sites\": " +
                longAddressListJson(structuralResolvedSites) + ",\n" +
            "  \"data_relocation_identities_resolved\": " +
                dataRelocationIdentitiesResolved + ",\n" +
            "  \"data_relocation_identity_resolved_sites\": " +
                longAddressListJson(dataRelocationIdentityResolvedSites) + ",\n" +
            "  \"data_relocation_name_proofs\": " +
                dataRelocationNameDiagnosticsJson() + ",\n" +
            "  \"ambiguous_rejected\": " + ambiguousRejected + ",\n" +
            "  \"ambiguous_functions_created\": " + ambiguousFunctionsCreated + ",\n" +
            "  \"function_only_attempts\": " + functionOnlyAttempts + ",\n" +
            "  \"function_only_proofs\": " + functionOnlyProofs + ",\n" +
            "  \"function_only_created\": " + functionOnlyCreated + ",\n" +
            "  \"padding_cfg_proofs\": " + paddingCfgProofs + ",\n" +
            "  \"natural_cfg_proofs\": " + naturalCfgProofs + ",\n" +
            "  \"explicit_body_functions_created\": " + explicitBodyCreated + ",\n" +
            "  \"noncontiguous_body_functions_created\": " + nonContiguousBodyCreated + ",\n" +
            "  \"function_only_failure_reasons\": " + stringLongMapJson(functionOnlyFailureReasons) + ",\n" +
            "  \"function_only_proofs_detail\": " + functionProofDiagnosticsJson() + ",\n" +
            "  \"layout_candidates_pruned\": " + layoutCandidatesPruned + ",\n" +
            "  \"layout_sites_narrowed\": " + layoutSitesNarrowed + ",\n" +
            "  \"layout_identities_resolved\": " + layoutIdentitiesResolved + ",\n" +
            "  \"sig_graph_rounds\": " + sigGraphRounds + ",\n" +
            "  \"sig_graph_constraints_checked\": " + sigGraphConstraints + ",\n" +
            "  \"sig_graph_candidates_pruned\": " + sigGraphCandidatesPruned + ",\n" +
            "  \"sig_graph_sites_narrowed\": " + sigGraphSitesNarrowed + ",\n" +
            "  \"sig_graph_identities_resolved\": " + sigGraphIdentitiesResolved + ",\n" +
            "  \"sig_graph_conflicts\": " + sigGraphConflicts + ",\n" +
            "  \"sig_graph_resolved_sites\": " + longAddressListJson(sigGraphResolvedSites) + ",\n" +
            "  \"computed_cfg_sites\": " + computedCfgSites + ",\n" +
            "  \"computed_cfg_resolved\": " + computedCfgResolved + ",\n" +
            "  \"computed_cfg_rejected\": " + computedCfgRejected + ",\n" +
            "  \"ambiguous_annotated\": " + ambiguousAnnotated + ",\n" +
            "  \"logical_consensus_symbols\": " + logicalConsensusSymbols + ",\n" +
            "  \"semantic_aliases\": " + semanticAliases + ",\n" +
            "  \"semantic_no_function\": " + semanticNoFunction + ",\n" +
            "  \"semantic_name_skips\": " + semanticNameSkips + ",\n" +
            "  \"semantic_labels_created\": " + semanticLabels + ",\n" +
            "  \"semantic_labels_existing\": " + semanticLabelsExisting + ",\n" +
            "  \"semantic_labels_inside_function_skipped\": " + semanticLabelsContainingSkipped + ",\n" +
            "  \"semantic_label_errors\": " + semanticLabelErrors + ",\n" +
            "  \"operation_consensus_sites\": " + operationConsensusSites + ",\n" +
            "  \"operation_labels_created\": " + operationLabels + ",\n" +
            "  \"operation_labels_existing\": " + operationLabelsExisting + ",\n" +
            "  \"operation_label_skips\": " + operationLabelSkips + ",\n" +
            "  \"operation_label_errors\": " + operationLabelErrors + ",\n" +
            "  \"structural_decode_cache_hits\": " + structuralDecodeCacheHits + ",\n" +
            "  \"structural_decode_cache_misses\": " + structuralDecodeCacheMisses + ",\n" +
            "  \"valid_subroutine_cache_hits\": " + validSubroutineCacheHits + ",\n" +
            "  \"valid_subroutine_cache_misses\": " + validSubroutineCacheMisses + ",\n" +
            "  \"snapshot_seconds\": " + String.format(Locale.ROOT, "%.6f", seconds(snapshotNanos)) + ",\n" +
            "  \"anchor_index_seconds\": " + String.format(Locale.ROOT, "%.6f", seconds(anchorIndexNanos)) + ",\n" +
            "  \"anchor_scan_seconds\": " + String.format(Locale.ROOT, "%.6f", seconds(anchorScanNanos)) + ",\n" +
            "  \"semantic_diagnostics\": " + semanticDiagnosticsJson() + ",\n" +
            "  \"errors\": " + errors + ",\n" +
            "  \"elapsed_seconds\": " + String.format(Locale.ROOT, "%.6f", elapsed) + "\n" +
            "}\n";
        Path temporary = path.resolveSibling(path.getFileName().toString() + ".tmp");
        Files.writeString(temporary, json, StandardCharsets.UTF_8);
        try {
            Files.move(temporary, path, java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        }
        catch (java.nio.file.AtomicMoveNotSupportedException exception) {
            Files.move(temporary, path, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private String semanticDiagnosticsJson() {
        StringBuilder json = new StringBuilder("[\n");
        for (int index = 0; index < semanticDiagnostics.size(); index++) {
            SemanticDiagnostic item = semanticDiagnostics.get(index);
            if (index != 0) json.append(",\n");
            json.append("    {\"kind\": \"").append(jsonEscape(item.kind))
                .append("\", \"address\": \"").append(jsonEscape(item.address.toString()))
                .append("\", \"reason\": \"").append(jsonEscape(item.reason)).append("\"");
            if (item.existingName != null)
                json.append(", \"existing_name\": \"")
                    .append(jsonEscape(item.existingName)).append("\"");
            if (item.existingSource != null)
                json.append(", \"existing_source\": \"")
                    .append(jsonEscape(item.existingSource)).append("\"");
            json.append(", \"semantic_consensus\": \"")
                .append(jsonEscape(item.semantic)).append("\"")
                .append(", \"proposed_alias\": \"")
                .append(jsonEscape(item.proposedAlias)).append("\"")
                .append(", \"candidate_count\": ").append(item.candidates.size())
                .append(", \"semantic_label_applied\": ").append(item.labelApplied)
                .append(", \"matched_candidates\": [");
            for (int candidate = 0; candidate < item.candidates.size(); candidate++) {
                if (candidate != 0) json.append(',');
                json.append("\"").append(jsonEscape(item.candidates.get(candidate))).append("\"");
            }
            json.append("]}");
        }
        return json.append("\n  ]").toString();
    }

    private static String stringLongMapJson(Map<String, Long> values) {
        StringBuilder json = new StringBuilder("{");
        int index = 0;
        for (Map.Entry<String, Long> entry : values.entrySet()) {
            if (index++ != 0) json.append(',');
            json.append("\"").append(jsonEscape(entry.getKey())).append("\": ")
                .append(entry.getValue());
        }
        return json.append('}').toString();
    }

    private static String longAddressListJson(List<Long> values) {
        List<Long> sorted = new ArrayList<>(values);
        Collections.sort(sorted);
        StringBuilder json = new StringBuilder("[");
        for (int index = 0; index < sorted.size(); index++) {
            if (index != 0) json.append(',');
            json.append('"').append(String.format(Locale.ROOT, "%08x", sorted.get(index)))
                .append('"');
        }
        return json.append(']').toString();
    }

    private String functionProofDiagnosticsJson() {
        StringBuilder json = new StringBuilder("[");
        for (int index = 0; index < functionProofDiagnostics.size(); index++) {
            FunctionProofDiagnostic item = functionProofDiagnostics.get(index);
            if (index != 0) json.append(',');
            json.append("{\"address\":\"").append(jsonEscape(item.address.toString()))
                .append("\",\"proof\":\"").append(jsonEscape(item.proofKind))
                .append("\",\"sources\":\"")
                .append(String.format(Locale.ROOT, "0x%X", item.sources))
                .append("\",\"body_ranges\":").append(item.bodyRanges)
                .append(",\"body_bytes\":").append(item.bodyBytes)
                .append(",\"data_relocation_pointers\":")
                .append(item.dataRelocationPointers)
                .append(",\"semantic\":\"").append(jsonEscape(item.semantic))
                .append("\",\"signature_lengths\":[");
            for (int length = 0; length < item.signatureLengths.size(); length++) {
                if (length != 0) json.append(',');
                json.append(item.signatureLengths.get(length));
            }
            json.append("]}");
        }
        return json.append(']').toString();
    }

    private String dataRelocationNameDiagnosticsJson() {
        StringBuilder json = new StringBuilder("[");
        for (int index = 0; index < dataRelocationNameDiagnostics.size(); index++) {
            DataRelocationNameDiagnostic item = dataRelocationNameDiagnostics.get(index);
            if (index != 0) json.append(',');
            json.append("{\"address\":\"").append(jsonEscape(item.address.toString()))
                .append("\",\"identity\":\"").append(jsonEscape(item.identity))
                .append("\",\"pointer_sources\":").append(item.pointerSources)
                .append(",\"fixed_bytes\":").append(item.fixedBytes)
                .append(",\"crc_bytes\":").append(item.crcBytes)
                .append(",\"leaf_candidates\":").append(item.leafCandidates)
                .append(",\"name_fanout\":").append(item.nameFanout)
                .append(",\"module_length\":").append(item.moduleLength)
                .append(",\"body_bytes\":").append(item.bodyBytes).append('}');
        }
        return json.append(']').toString();
    }

    private static String fileSha256(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (java.io.InputStream input = Files.newInputStream(path)) {
            byte[] buffer = new byte[1024 * 1024];
            for (;;) {
                int count = input.read(buffer);
                if (count < 0) break;
                digest.update(buffer, 0, count);
            }
        }
        return hex(digest.digest());
    }

    private static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) result.append(String.format("%02X", b & 0xff));
        return result.toString();
    }

    private static String jsonEscape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
            .replace("\r", "\\r").replace("\n", "\\n");
    }

    private static double seconds(long nanos) { return nanos / 1_000_000_000.0; }

    private long countDiscoveredSource(int source) {
        long count = 0;
        for (int mask : discoveredSources.values()) if ((mask & source) != 0) count++;
        return count;
    }

    private int dataRelocationPointerSourceCount(Address target) {
        Set<Long> sources = dataRelocationPointerSources.get(target.getOffset());
        return sources == null ? 0 : sources.size();
    }

    private long dataRelocationPointerCellCount() {
        long count = 0;
        for (Set<Long> sources : dataRelocationPointerSources.values()) count += sources.size();
        return count;
    }
}
