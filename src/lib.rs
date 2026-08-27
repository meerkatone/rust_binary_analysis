use binaryninja::binary_view::{BinaryView, BinaryViewBase, StringType};
use binaryninja::command::register_command;
use binaryninja::function::Function;
use binaryninja::interaction;
use binaryninja::Endianness;

use arrow::array::{Float64Array, StringArray};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowWriter;
use parquet::file::properties::WriterProperties;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::path::Path;
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
    let edges: u32 = basic_blocks
        .iter()
        .map(|block| block.outgoing_edges().len() as u32)
        .sum();
    let nodes = basic_blocks.len() as u32;

    if nodes == 0 {
        return 1;
    }

    edges - nodes + 2
}

fn compute_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut byte_count = HashMap::new();
    for &byte in data {
        *byte_count.entry(byte).or_insert(0) += 1;
    }

    let data_length = data.len() as f64;
    let mut entropy = 0.0;

    for &count in byte_count.values() {
        let probability = count as f64 / data_length;
        entropy -= probability * probability.log2();
    }

    entropy
}

fn decode_string(bv: &BinaryView, start: u64, length: usize, ty: StringType) -> String {
    let data = bv.read_vec(start, length);
    match ty {
        StringType::Utf16String => {
            let units = data
                .chunks_exact(2)
                .map(|chunk| match bv.default_endianness() {
                    Endianness::LittleEndian => u16::from_le_bytes([chunk[0], chunk[1]]),
                    Endianness::BigEndian => u16::from_be_bytes([chunk[0], chunk[1]]),
                })
                .take_while(|unit| *unit != 0)
                .collect::<Vec<_>>();
            String::from_utf16_lossy(&units)
        }
        StringType::Utf32String => data
            .chunks_exact(4)
            .map(|chunk| match bv.default_endianness() {
                Endianness::LittleEndian => {
                    u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
                }
                Endianness::BigEndian => {
                    u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
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
        if let Some(symbol) = bv.symbol_by_raw_name(func_name) {
            let xrefs = bv.code_refs_to_addr(symbol.address());
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
        function_info.push((
            format!("{:?}", function.symbol().short_name())
                .trim_matches('"')
                .to_string(),
            format!("0x{:x}", function.start()),
        ));
    }

    let avg_cc = if complexities.is_empty() {
        0.0
    } else {
        complexities.iter().sum::<u32>() as f64 / complexities.len() as f64
    };

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

fn analyse_directory(
    directory: &Path,
    output_file: &Path,
) -> Result<usize, Box<dyn std::error::Error>> {
    let entries = fs::read_dir(directory)?;
    let mut binary_paths = Vec::new();

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            binary_paths.push(path);
        }
    }

    println!("Analysing {} binaries...", binary_paths.len());

    let mut results = Vec::new();
    for path in &binary_paths {
        println!("Analysing {:?}...", path);
        if let Some(result) = analyse_binary(path) {
            results.push(result);
        }
    }

    println!("Processed {} valid binaries", results.len());
    println!("Writing results to {:?}", output_file);

    write_results_to_parquet(&results, output_file)?;

    Ok(results.len())
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

    let file = fs::File::create(output_file)?;
    let props = WriterProperties::builder().build();
    let mut writer = ArrowWriter::try_new(file, batch.schema(), Some(props))?;

    writer.write(&batch)?;
    writer.close()?;

    Ok(())
}

fn analyse_directory_callback(_bv: &BinaryView) {
    if let Some(directory) =
        interaction::get_directory_name_input("Select directory of binaries to analyse", "")
    {
        let directory_path = directory;
        let output_file = directory_path.join("binary_analysis_results.parquet");
        thread::spawn(move || {
            let outcome = analyse_directory(&directory_path, &output_file)
                .map(|count| {
                    (
                        "Analysis Complete".to_string(),
                        format!(
                            "Analysed {} binaries.\nResults saved to {:?}",
                            count, output_file
                        ),
                        binaryninjacore_sys::BNMessageBoxIcon::InformationIcon,
                    )
                })
                .unwrap_or_else(|error| {
                    (
                        "Error".to_string(),
                        format!("Error during analysis: {}", error),
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
