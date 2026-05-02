# Autoforensiq – Execution Layer (P3)

## Overview
This module runs forensic tools via wrappers, logs execution, and outputs structured JSON for downstream analysis.

## Tools Integrated
- Volatility3 (memory)
- Tshark (network) working with real PCAP
- Sleuthkit (TSK) (disk)
- RegRipper (registry) basic output working
- Plaso (timeline)

## How to Run
```bash
python3 -m src.orchestrator
