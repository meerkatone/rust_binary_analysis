# Binary Ninja Security Analysis Plugin

A Binary Ninja plugin written in Rust that performs comprehensive security-focused analysis of binary files. This plugin extracts security-relevant metrics and identifies potential risks by analyzing dangerous function usage, code complexity, and binary entropy.

## Features

- **Dangerous Function Detection**: Identifies cross-references to security-critical functions like `system()`, `execve()`, and other exec family functions
- **Cyclomatic Complexity Analysis**: Calculates complexity metrics for all functions to identify potentially problematic code
- **Entropy Analysis**: Computes binary entropy to detect packed or obfuscated executables
- **Architecture & Metadata Extraction**: Captures target architecture, endianness, and file hashing
- **Batch Processing**: Analyze entire directories on a worker thread without blocking Binary Ninja's UI
- **Structured Output**: Results exported to Parquet format for data analysis and reporting

## Installation

### Prerequisites

- [Binary Ninja](https://binary.ninja/) (Commercial or Personal license latest dev build)
- [Rust toolchain](https://rustup.rs/) (latest stable)
- Binary Ninja API development headers

### Build and Install

1. Clone this repository:
   ```bash
   git clone https://github.com/meerkatone/rust_binary_analysis.git
   cd rust_binary_analysis
   ```

2. Set up Binary Ninja environment (if needed):
   ```bash
   export BINJA_DIR="/path/to/your/binaryninja/installation"
   ```

3. Build the plugin:
   ```bash
   cargo build --locked --release
   ```

   If Binary Ninja reports that the plugin was built for an outdated core ABI, update the lockfile deliberately and rebuild:

   ```bash
   cargo update
   cargo build --locked --release
   ```

4. Copy the compiled plugin to Binary Ninja's plugin directory:
   ```bash
   # macOS
   cp target/release/libbinary_analysis_plugin.dylib ~/Library/Application\ Support/Binary\ Ninja/plugins/
   
   # Linux
   cp target/release/libbinary_analysis_plugin.so ~/.binaryninja/plugins/
   
   # Windows
   copy target\release\binary_analysis_plugin.dll %APPDATA%\Binary Ninja\plugins\
   ```

5. Restart Binary Ninja to load the plugin

## Usage

1. Open Binary Ninja with any binary file loaded
2. Navigate to the menu: **Binary Analysis Tool → Analyse Directory**
3. Select a directory containing the binary files you want to analyze
4. The plugin processes the directory in the background and saves results to `binary_analysis_results.parquet`; the completion dialog is shown on Binary Ninja's main thread

## Output Format

The plugin generates a Parquet file with the following structure:

| Field | Type | Description |
|-------|------|-------------|
| `Binary` | String | Original filename |
| `File_Hash` | String | SHA-256 hash of the binary |
| `Architecture` | String | Target architecture (x86, x64, ARM, etc.) |
| `Endianness` | String | Byte order (Little/Big) |
| `Average_Cyclomatic_Complexity` | Float | Mean complexity across all functions |
| `Entropy` | Float | Binary entropy (0-8, higher = more random/packed) |
| `Functions` | JSON String | Array of function names and addresses |
| `Strings` | JSON String | Array of decoded string contents and addresses (ASCII/UTF-8, UTF-16, and UTF-32) |
| `Segments` | JSON String | Memory segment information |
| `Xrefs_to_System` | JSON String | Cross-references to dangerous functions |

## Security Analysis Details

### Dangerous Functions Monitored
The plugin specifically tracks usage of:
- `system` - Command execution
- `execve`, `execle`, `execvp`, `execlp` - Process execution
- `doSystemCmd` - Custom system command functions

### Complexity Analysis
- Calculates cyclomatic complexity using the formula: E - N + 2P (edges - nodes + 2 * connected components)
- Higher complexity indicates more complex control flow and potential maintenance issues
- Can help identify overly complex functions that may contain bugs

### Entropy Analysis
- Measures randomness in the binary data
- Low entropy (~1-3): Likely plain text or simple executable
- Medium entropy (~4-6): Normal compiled code
- High entropy (~7-8): Possibly packed, encrypted, or obfuscated

## Development

### Build Commands
```bash
# Development build
cargo build --locked

# Release build
cargo build --locked --release

# Check code without building
cargo check --locked

# Clean build artifacts
cargo clean
```

### Dependencies
- `binaryninja`: Official Binary Ninja API bindings
- `arrow`/`parquet`: Data serialization and export
- `serde`: JSON serialization
- `sha2`: Cryptographic hashing

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.
