# RCR_Payload_Jitter
## Description
This simple tool measures Range Coverage Ratio (RCR) - a custom measurement to potentially detect the introduction of payload/data jitter in host pair communication. It is an accompaniment to the [following blog article](https://www.activecountermeasures.com/measuring-data-jitter-using-rcr/), which fully details its conceptualization, development, and intended use. 

## Installation
To install the necessary dependencies via `conda` run:

```bash
conda env create -f environment.yml
conda activate rcr_payload_jitter
```

Alternatively for `pip` use:

```bash
pip install -r requirements.txt
```

## Usage 
### Logs
Sample logs are provided in `./input`. If desired to use own logs (Zeek `conn.log` only):
1. Place them in this same directory
2. 