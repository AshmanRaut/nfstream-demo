# NFStream Demonstration

Examples for extracting, extending, benchmarking, and visualizing network-flow
features with [NFStream](https://github.com/nfstream/nfstream).

The project uses PCAP captures as input and produces CSV files containing
flow-level features. The included visualization tool converts those CSV files
into presentation-ready PNG charts.

## What this project demonstrates

This repository contains five progressively more advanced demonstrations:

1. **Standard flow extraction** - extracts bidirectional network flows and
   statistical features from a PCAP file.
2. **Custom NFStream plugin** - adds a `udps.tcp_syn_count` feature that counts
   TCP SYN packets in each flow.
3. **SPLT early-packet analysis** - records packet directions, packet sizes, and
   inter-arrival times for the first packets of each flow.
4. **Feature benchmark** - compares baseline extraction with statistical and
   SPLT feature extraction.
5. **SPLT experiment** - measures how different early-packet limits affect
   extracted information and processing time.

## Repository structure

| File or directory | Purpose |
| --- | --- |
| `demo.py` | Basic NFStream flow extraction from `sample.pcap` |
| `plugin_demo.py` | Demonstrates the custom TCP SYN counter plugin |
| `splt_demo.py` | Prints early packet sequence features |
| `benchmark_features.py` | Benchmarks baseline and extended extraction |
| `splt_experiment.py` | Runs the SPLT packet-limit experiment |
| `visualize_results.py` | Generates charts from result CSV files |
| `sample.pcap` | Small capture used by the functional demonstrations |
| `benchmark.pcap` | Capture used by the performance benchmark |
| `results/` | Generated flow, benchmark, and experiment CSV files |
| `visualizations/` | Generated PNG charts |
| `requirements-current.txt` | Recorded Python environment dependencies |

## Requirements

- Python 3.14 or a compatible Python version supported by the installed
  NFStream release
- NFStream and the packages listed in `requirements-current.txt`
- A classic PCAP capture for the demonstration scripts

## Installation

Clone the repository and create a virtual environment:

```bash
git clone https://github.com/AshmanRaut/nfstream-demo.git
cd nfstream-demo

python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-current.txt
```

On Windows, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
```

## Run the demonstrations

Run these commands from the repository root:

```bash
python demo.py
python plugin_demo.py
python splt_demo.py
python benchmark_features.py
python splt_experiment.py
```

The scripts expect `sample.pcap` and `benchmark.pcap` in the project
directory. They create or update CSV files in `results/`.

### Generated CSV files

- `network_flows.csv` - standard NFStream flow features
- `network_flows_with_plugin.csv` - standard features plus
  `udps.tcp_syn_count`
- `feature_benchmark_results.csv` - benchmark timing and throughput results
- `splt_experiment_summary.csv` - summary for each SPLT packet limit
- `splt_experiment_details.csv` - per-flow SPLT measurements

## Generate visualizations

After generating the result CSV files, run:

```bash
python visualize_results.py
```

By default, the script:

- Reads CSV files from `results/`
- Writes PNG files to `visualizations/`
- Skips result types whose CSV files are missing
- Reports a clear error if no non-empty result CSV files are available

To use a different input or output directory:

```bash
python visualize_results.py \
  --input-dir "old results" \
  --output-dir visualizations
```

### Generated charts

| Chart | What it shows |
| --- | --- |
| `dashboard.png` | Combined overview of all available experiment charts |
| `network_flows.png` | Application categories and flow duration versus bytes |
| `network_flows_with_plugin.png` | TCP SYN-count distribution and SYN count versus flow packets |
| `feature_benchmark_results.png` | Median processing time and packet throughput |
| `splt_experiment_summary.png` | Extracted early-packet counts and processing time by SPLT limit |
| `splt_experiment_details.png` | Per-flow distribution of extracted SPLT packet values |

## Interpreting the experiments

### Flow extraction

NFStream converts packets into bidirectional flow records. Each record can
include addresses, ports, protocol information, packet counts, byte counts,
durations, packet-size statistics, inter-arrival-time statistics, TCP flags,
and application classification fields.

### Custom plugin

`plugin_demo.py` defines a `TCPSynCounter` plugin. It initializes a counter
when a flow is created and increments it when subsequent packets contain the
TCP SYN flag. The exported custom field is:

```text
udps.tcp_syn_count
```

### SPLT analysis

SPLT records the early packet sequence of a flow. The experiment varies the
configured packet limit across several values and records:

- Packet directions
- Packet sizes
- Inter-arrival times
- Median processing time

Flows that end before reaching the configured limit can contain fewer recorded
values than the requested maximum.

### Benchmarking

The benchmark compares a baseline configuration against an extended
configuration with statistical analysis and SPLT enabled. It reports median
runtime and input packets per second. Results can vary with machine load,
Python version, capture size, and the number of repetitions.

## Reproducibility notes

- Run commands from the repository root so relative PCAP and output paths
  resolve correctly.
- The benchmark scripts perform repeated measurements, but small captures can
  still produce timing variation.
- Existing CSV files in `results/` are overwritten by the corresponding demo.
- Generated charts are deterministic for the same CSV inputs, apart from
  plotting-library rendering differences.

## License

No license has been assigned to this repository yet. Add a license before
redistributing or reusing the project.
