mod atomic_output;
use binaryninja::background_task::BackgroundTask;
use binaryninja::binary_view::{BinaryView, BinaryViewBase, StringType};
use binaryninja::command::register_command;
use binaryninja::function::Function;
use binaryninja::interaction;
use binaryninja::logger::{BnLogLevel, Logger};
use binaryninja::Endianness;

use arrow::array::{Float64Array, StringArray};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowWriter;
use parquet::file::properties::WriterProperties;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;

const DANGEROUS_FUNCTIONS: &[&str] = &[
    "system",
    "execve",
    "execle",
    "execvp",
    "execlp",
    "doSystemCmd",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SegmentInfo {
    start: u64,
    end: u64,
    readable: bool,
    writable: bool,
    executable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct XrefInfo {
    function_name: String,
    function_start: String,
    xref_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BinaryAnalysisResult {
    binary: String,
    file_hash: String,
    architecture: String,
    endianness: String,
    average_cyclomatic_complexity: f64,
    entropy: f64,
    functions: Vec<(String, String)>,
    strings: Vec<(String, String)>,
    segments: Vec<SegmentInfo>,
    xrefs_to_system: Vec<XrefInfo>,
}

fn get_file_name(path: &Path) -> String {
    path.file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("unknown")
        .to_string()
}

fn get_architecture(bv: &BinaryView) -> String {
    bv.default_arch()
        .map(|arch| arch.name().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn get_endianness(bv: &BinaryView) -> String {
    match bv.default_endianness() {
        Endianness::LittleEndian => "Little".to_string(),
        Endianness::BigEndian => "Big".to_string(),
    }
}

fn get_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

fn calculate_cyclomatic_complexity(function: &Function) -> u32 {
    let basic_blocks = function.basic_blocks();
    let edges: u64 = basic_blocks
        .iter()
        .map(|block| block.outgoing_edges().len() as u64)
        .sum();
    let nodes = basic_blocks.len() as u64;

    if nodes == 0 {
        return 1;
    }

    complexity_from_counts(edges, nodes)
}

fn complexity_from_counts(edges: u64, nodes: u64) -> u32 {
    let complexity = (i128::from(edges) - i128::from(nodes) + 2).clamp(1, i128::from(u32::MAX));
    complexity as u32
}

fn compute_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut byte_count = [0u64; 256];
    for &byte in data {
        byte_count[usize::from(byte)] += 1;
    }

    let data_length = data.len() as f64;
    let mut entropy = 0.0;

    for &count in byte_count.iter().filter(|&&count| count != 0) {
        let probability = count as f64 / data_length;
        entropy -= probability * probability.log2();
    }

    entropy
}

fn decode_string(bv: &BinaryView, start: u64, length: usize, ty: StringType) -> String {
    let data = bv.read_vec(start, length);
    let little_endian = matches!(bv.default_endianness(), Endianness::LittleEndian);
    match ty {
        StringType::Utf16String => {
            let units = data
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&chunk| {
                    if little_endian {
                        u16::from_le_bytes(chunk)
                    } else {
                        u16::from_be_bytes(chunk)
                    }
                })
                .take_while(|unit| *unit != 0)
                .collect::<Vec<_>>();
            String::from_utf16_lossy(&units)
        }
        StringType::Utf32String => data
            .as_chunks::<4>()
            .0
            .iter()
            .map(|&chunk| {
                if little_endian {
                    u32::from_le_bytes(chunk)
                } else {
                    u32::from_be_bytes(chunk)
                }
            })
            .take_while(|value| *value != 0)
            .filter_map(char::from_u32)
            .collect(),
        _ => String::from_utf8_lossy(&data)
            .trim_end_matches('\0')
            .to_string(),
    }
}

fn get_segments(bv: &BinaryView) -> Vec<SegmentInfo> {
    bv.segments()
        .iter()
        .map(|segment| {
            let range = segment.address_range();
            SegmentInfo {
                start: range.start,
                end: range.end,
                readable: segment.readable(),
                writable: segment.writable(),
                executable: segment.executable(),
            }
        })
        .collect()
}

fn find_xrefs_to_dangerous_functions(bv: &BinaryView) -> Vec<XrefInfo> {
    let mut xref_info = Vec::new();

    for &func_name in DANGEROUS_FUNCTIONS {
        // Mach-O and 32-bit Windows symbols carry a leading underscore. An
        // import usually has several symbols under one name (the PLT or stub
        // function and the external symbol), and calls reference the stub, so
        // collect every match rather than one arbitrary symbol.
        let mut addresses = Vec::new();
        for name in [func_name.to_string(), format!("_{func_name}")] {
            for symbol in bv.symbols_by_name(name.as_str()).iter() {
                if !addresses.contains(&symbol.address()) {
                    addresses.push(symbol.address());
                }
            }
        }
        for address in addresses {
            let xrefs = bv.code_refs_to_addr(address);
            for xref in &xrefs {
                // Functions actually covering this xref address.
                let containing = bv.functions_containing(xref.address);

                if containing.is_empty() {
                    xref_info.push(XrefInfo {
                        function_name: func_name.to_string(),
                        function_start: "unknown".to_string(),
                        xref_address: format!("0x{:x}", xref.address),
                    });
                } else {
                    for function in containing.iter() {
                        xref_info.push(XrefInfo {
                            function_name: func_name.to_string(),
                            function_start: format!("0x{:x}", function.start()),
                            xref_address: format!("0x{:x}", xref.address),
                        });
                    }
                }
            }
        }
    }

    xref_info
}

fn analyse_binary(path: &Path) -> Option<BinaryAnalysisResult> {
    // Hash and entropy describe the original input file, not Binary Ninja's
    // potentially sparse or synthesized virtual address space.
    let file_bytes = fs::read(path).ok()?;
    let bv = binaryninja::load(path)?;

    let functions = bv.functions();
    let mut complexities = Vec::new();
    let mut function_info = Vec::new();

    for function in &functions {
        let cc = calculate_cyclomatic_complexity(&function);
        complexities.push(cc);
        // Debug formatting escaped quotes, backslashes, and control
        // characters in the exported name.
        function_info.push((
            function
                .symbol()
                .short_name()
                .to_string_lossy()
                .into_owned(),
            format!("0x{:x}", function.start()),
        ));
    }

    let avg_cc = average_complexity(&complexities);

    let filename = get_file_name(path);
    let file_hash = get_hash(&file_bytes);
    let architecture = get_architecture(&bv);
    let endianness = get_endianness(&bv);

    let strings: Vec<(String, String)> = bv
        .strings()
        .iter()
        .map(|s| {
            (
                decode_string(&bv, s.start, s.length, s.ty),
                format!("0x{:x}", s.start),
            )
        })
        .collect();

    let segment_info = get_segments(&bv);
    let xrefs = find_xrefs_to_dangerous_functions(&bv);

    let entropy = compute_entropy(&file_bytes);
    // Views parented to an open FileMetadata are not freed on drop.
    bv.file().close();

    Some(BinaryAnalysisResult {
        binary: filename,
        file_hash,
        architecture,
        endianness,
        average_cyclomatic_complexity: avg_cc,
        entropy,
        functions: function_info,
        strings,
        segments: segment_info,
        xrefs_to_system: xrefs,
    })
}

fn average_complexity(complexities: &[u32]) -> f64 {
    if complexities.is_empty() {
        return 0.0;
    }
    complexities
        .iter()
        .map(|&value| f64::from(value))
        .sum::<f64>()
        / complexities.len() as f64
}

/// Skip the results file (written into the scanned directory) and hidden
/// files such as .DS_Store, which Binary Ninja would otherwise open as raw views.
fn is_excluded_input(path: &Path, output_file: &Path) -> bool {
    let hidden = path
        .file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| name.starts_with('.'));
    let is_output = match (fs::canonicalize(path), fs::canonicalize(output_file)) {
        (Ok(input), Ok(output)) => input == output,
        _ => path == output_file,
    };
    hidden || is_output
}

/// `results.parquet` -> `results.cancelled.parquet`, so a cancelled run never
/// replaces the last complete report.
fn cancelled_output_path(path: &Path) -> PathBuf {
    let stem = path
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_else(|| "binary_analysis_results".to_string());
    let name = match path.extension() {
        Some(extension) => format!("{stem}.cancelled.{}", extension.to_string_lossy()),
        None => format!("{stem}.cancelled"),
    };
    path.with_file_name(name)
}

/// Files to analyse, in sorted order so report rows are stable across runs.
/// Both reports this plugin writes into the directory are left out.
fn collect_inputs(directory: &Path, output_file: &Path) -> std::io::Result<Vec<PathBuf>> {
    let partial_output = cancelled_output_path(output_file);
    let mut paths = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_file()
            && !is_excluded_input(&path, output_file)
            && !is_excluded_input(&path, &partial_output)
        {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

struct DirectoryOutcome {
    analysed: usize,
    failed: Vec<String>,
    cancelled: bool,
    report: PathBuf,
}

/// Analyse every input in `directory`. `on_file(index, total, path)` runs
/// before each file and returns false to cancel; results gathered until then
/// are written to the `.cancelled` report.
fn analyse_directory(
    directory: &Path,
    output_file: &Path,
    on_file: &dyn Fn(usize, usize, &Path) -> bool,
) -> Result<DirectoryOutcome, Box<dyn std::error::Error>> {
    let binary_paths = collect_inputs(directory, output_file)?;

    let mut results = Vec::new();
    let mut failed = Vec::new();
    let mut cancelled = false;
    for (index, path) in binary_paths.iter().enumerate() {
        if !on_file(index, binary_paths.len(), path) {
            cancelled = true;
            break;
        }
        match analyse_binary(path) {
            Some(result) => results.push(result),
            None => failed.push(get_file_name(path)),
        }
    }

    let report = if cancelled {
        cancelled_output_path(output_file)
    } else {
        output_file.to_path_buf()
    };
    write_results_to_parquet(&results, &report)?;

    Ok(DirectoryOutcome {
        analysed: results.len(),
        failed,
        cancelled,
        report,
    })
}

fn write_results_to_parquet(
    results: &[BinaryAnalysisResult],
    output_file: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let schema = Schema::new(vec![
        Field::new("Binary", DataType::Utf8, false),
        Field::new("File_Hash", DataType::Utf8, false),
        Field::new("Architecture", DataType::Utf8, false),
        Field::new("Endianness", DataType::Utf8, false),
        Field::new("Average_Cyclomatic_Complexity", DataType::Float64, false),
        Field::new("Entropy", DataType::Float64, false),
        Field::new("Functions", DataType::Utf8, false), // Simplified as JSON string
        Field::new("Strings", DataType::Utf8, false),   // Simplified as JSON string
        Field::new("Segments", DataType::Utf8, false),  // Simplified as JSON string
        Field::new("Xrefs_to_System", DataType::Utf8, false), // Simplified as JSON string
    ]);

    let mut binary_names = Vec::new();
    let mut file_hashes = Vec::new();
    let mut architectures = Vec::new();
    let mut endiannesses = Vec::new();
    let mut avg_complexities = Vec::new();
    let mut entropies = Vec::new();
    let mut functions_json = Vec::new();
    let mut strings_json = Vec::new();
    let mut segments_json = Vec::new();
    let mut xrefs_json = Vec::new();

    for result in results {
        binary_names.push(result.binary.clone());
        file_hashes.push(result.file_hash.clone());
        architectures.push(result.architecture.clone());
        endiannesses.push(result.endianness.clone());
        avg_complexities.push(result.average_cyclomatic_complexity);
        entropies.push(result.entropy);
        functions_json.push(serde_json::to_string(&result.functions)?);
        strings_json.push(serde_json::to_string(&result.strings)?);
        segments_json.push(serde_json::to_string(&result.segments)?);
        xrefs_json.push(serde_json::to_string(&result.xrefs_to_system)?);
    }

    let batch = RecordBatch::try_new(
        std::sync::Arc::new(schema),
        vec![
            std::sync::Arc::new(StringArray::from(binary_names)),
            std::sync::Arc::new(StringArray::from(file_hashes)),
            std::sync::Arc::new(StringArray::from(architectures)),
            std::sync::Arc::new(StringArray::from(endiannesses)),
            std::sync::Arc::new(Float64Array::from(avg_complexities)),
            std::sync::Arc::new(Float64Array::from(entropies)),
            std::sync::Arc::new(StringArray::from(functions_json)),
            std::sync::Arc::new(StringArray::from(strings_json)),
            std::sync::Arc::new(StringArray::from(segments_json)),
            std::sync::Arc::new(StringArray::from(xrefs_json)),
        ],
    )?;

    let mut output = atomic_output::AtomicOutput::new(output_file)?;
    let props = WriterProperties::builder().build();
    let mut writer = ArrowWriter::try_new(&mut output.file, batch.schema(), Some(props))?;

    writer.write(&batch)?;
    writer.close()?;
    output.commit()?;

    Ok(())
}

fn outcome_message(outcome: &DirectoryOutcome) -> String {
    let mut message = format!(
        "Analysed {} binaries.\nResults saved to {:?}",
        outcome.analysed, outcome.report
    );
    if outcome.cancelled {
        message.push_str("\nThe scan was cancelled; the previous complete report was kept.");
    }
    if !outcome.failed.is_empty() {
        message.push_str(&format!(
            "\n{} file(s) could not be loaded: {}",
            outcome.failed.len(),
            outcome.failed.join(", ")
        ));
    }
    message
}

fn analyse_directory_callback(_bv: &BinaryView) {
    if let Some(directory) =
        interaction::get_directory_name_input("Select directory of binaries to analyse", "")
    {
        let directory_path = directory;
        let output_file = directory_path.join("binary_analysis_results.parquet");
        thread::spawn(move || {
            let logger = Logger::new("rust_binary_analysis");
            let task = BackgroundTask::new("Analysing binaries", true);
            let _guard = task.enter();
            let outcome =
                analyse_directory(&directory_path, &output_file, &|index, total, path| {
                    if task.is_cancelled() {
                        return false;
                    }
                    let name = get_file_name(path);
                    task.set_progress_text(&format!("Analysing {}/{}: {}", index + 1, total, name));
                    logger.log(
                        BnLogLevel::InfoLog,
                        &format!("Analysing {}/{}: {}", index + 1, total, name),
                    );
                    true
                })
                .map(|outcome| {
                    let message = outcome_message(&outcome);
                    let partial = outcome.cancelled || !outcome.failed.is_empty();
                    logger.log(
                        if partial {
                            BnLogLevel::WarningLog
                        } else {
                            BnLogLevel::InfoLog
                        },
                        &message.replace('\n', " "),
                    );
                    (
                        if outcome.cancelled {
                            "Analysis Cancelled".to_string()
                        } else {
                            "Analysis Complete".to_string()
                        },
                        message,
                        if partial {
                            binaryninjacore_sys::BNMessageBoxIcon::WarningIcon
                        } else {
                            binaryninjacore_sys::BNMessageBoxIcon::InformationIcon
                        },
                    )
                })
                .unwrap_or_else(|error| {
                    let message = format!("Error during analysis: {}", error);
                    logger.log(BnLogLevel::ErrorLog, &message);
                    (
                        "Error".to_string(),
                        message,
                        binaryninjacore_sys::BNMessageBoxIcon::ErrorIcon,
                    )
                });
            binaryninja::main_thread::execute_on_main_thread(move || {
                interaction::show_message_box(
                    &outcome.0,
                    &outcome.1,
                    binaryninjacore_sys::BNMessageBoxButtonSet::OKButtonSet,
                    outcome.2,
                );
            });
        });
    }
}

#[no_mangle]
pub extern "C" fn CorePluginInit() -> bool {
    register_command(
        "Binary Analysis Tool\\Analyse Directory",
        "Analyse binaries in a directory and save results to a parquet file",
        analyse_directory_callback,
    );
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complexity_handles_acyclic_and_branching_graphs_without_underflow() {
        assert_eq!(complexity_from_counts(0, 1), 1);
        assert_eq!(complexity_from_counts(1099, 1100), 1);
        assert_eq!(complexity_from_counts(4, 4), 2);
        assert_eq!(complexity_from_counts(u64::MAX, 1), u32::MAX);
    }

    #[test]
    fn entropy_matches_shannon_bounds() {
        assert_eq!(compute_entropy(&[]), 0.0);
        assert_eq!(compute_entropy(&[0x41; 64]), 0.0);
        assert!((compute_entropy(&[0, 1, 0, 1]) - 1.0).abs() < 1e-12);
        let every_byte: Vec<u8> = (0..=u8::MAX).collect();
        assert!((compute_entropy(&every_byte) - 8.0).abs() < 1e-12);
    }

    #[test]
    fn directory_scan_excludes_its_output_and_hidden_files() {
        let directory = std::env::temp_dir().join(format!(
            "rust_binary_analysis_{}_exclusions",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        let output = directory.join("binary_analysis_results.parquet");
        let binary = directory.join("sample.bin");
        let hidden = directory.join(".DS_Store");
        for path in [&output, &binary, &hidden] {
            fs::write(path, b"x").unwrap();
        }
        assert!(is_excluded_input(&output, &output));
        assert!(is_excluded_input(&hidden, &output));
        assert!(!is_excluded_input(&binary, &output));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn inputs_are_sorted_and_skip_both_reports() {
        let directory = std::env::temp_dir().join(format!(
            "rust_binary_analysis_{}_inputs",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        let output = directory.join("binary_analysis_results.parquet");
        let partial = cancelled_output_path(&output);
        assert_eq!(
            partial,
            directory.join("binary_analysis_results.cancelled.parquet")
        );
        assert_eq!(
            cancelled_output_path(Path::new("/out/report")),
            Path::new("/out/report.cancelled")
        );
        for name in ["zeta.bin", "alpha.bin", ".hidden", "mid.so"] {
            fs::write(directory.join(name), b"x").unwrap();
        }
        fs::write(&output, b"x").unwrap();
        fs::write(&partial, b"x").unwrap();
        fs::create_dir_all(directory.join("subdirectory")).unwrap();
        let inputs = collect_inputs(&directory, &output).unwrap();
        let names: Vec<_> = inputs.iter().map(|path| get_file_name(path)).collect();
        assert_eq!(names, ["alpha.bin", "mid.so", "zeta.bin"]);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn cancelled_scan_keeps_the_complete_report_and_lists_failures() {
        let directory = std::env::temp_dir().join(format!(
            "rust_binary_analysis_{}_cancelled",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        let output = directory.join("binary_analysis_results.parquet");
        fs::write(&output, b"previous complete report").unwrap();
        fs::write(directory.join("sample.bin"), b"x").unwrap();
        // Cancel before the first file, so no Binary Ninja load is attempted.
        let outcome = analyse_directory(&directory, &output, &|_, total, _| {
            assert_eq!(total, 1);
            false
        })
        .unwrap();
        assert!(outcome.cancelled);
        assert_eq!(outcome.analysed, 0);
        assert_eq!(outcome.report, cancelled_output_path(&output));
        assert_eq!(fs::read(&output).unwrap(), b"previous complete report");
        assert!(fs::metadata(&outcome.report).unwrap().len() > 0);
        let message = outcome_message(&DirectoryOutcome {
            analysed: 2,
            failed: vec!["broken.bin".to_string()],
            cancelled: true,
            report: outcome.report.clone(),
        });
        assert!(message.contains("Analysed 2 binaries"));
        assert!(message.contains("cancelled"));
        assert!(message.contains("1 file(s) could not be loaded: broken.bin"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn average_complexity_does_not_overflow_u32_total() {
        assert_eq!(average_complexity(&[]), 0.0);
        assert_eq!(average_complexity(&[1, 3]), 2.0);
        assert_eq!(
            average_complexity(&[u32::MAX, u32::MAX]),
            f64::from(u32::MAX)
        );
    }

    #[test]
    fn non_empty_parquet_export_has_consistent_column_lengths() {
        let result = BinaryAnalysisResult {
            binary: "sample.bin".to_string(),
            file_hash: get_hash(b"sample"),
            architecture: "test".to_string(),
            endianness: "Little".to_string(),
            average_cyclomatic_complexity: 1.0,
            entropy: compute_entropy(b"sample"),
            functions: vec![],
            strings: vec![],
            segments: vec![],
            xrefs_to_system: vec![],
        };
        let output = std::env::temp_dir().join(format!(
            "rust_binary_analysis_{}_column_lengths.parquet",
            std::process::id()
        ));
        write_results_to_parquet(&[result], &output).unwrap();
        assert!(fs::metadata(&output).unwrap().len() > 0);
        fs::remove_file(output).unwrap();
    }
}
