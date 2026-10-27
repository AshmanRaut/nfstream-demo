# NFStream Demonstration

This project demonstrates NFStream network-flow extraction and feature analysis
from PCAP captures.

## Demonstrations

- `demo.py` extracts standard NFStream flow features from `sample.pcap`.
- `plugin_demo.py` adds a custom TCP SYN counter to each flow.
- `splt_demo.py` displays early packet sequence features.
- `benchmark_features.py` compares baseline and extended feature extraction.
- `splt_experiment.py` measures the effect of different SPLT packet limits.
- `visualize_results.py` turns generated CSV results into PNG charts.

## Setup

Create and activate a virtual environment, then install the recorded
dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-current.txt
```

## Run the demonstrations

```bash
python demo.py
python plugin_demo.py
python splt_demo.py
python benchmark_features.py
python splt_experiment.py
```

The scripts write CSV files to `results/`.

## Generate visualizations

After generating the result CSVs:

```bash
python visualize_results.py
```

The charts are written to `visualizations/`. To use another result directory:

```bash
python visualize_results.py \
  --input-dir "old results" \
  --output-dir visualizations
```

## Included data

The repository includes the sample and benchmark PCAP captures used by the
demonstrations, along with `NFStream.pdf`, the project reference document.
