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
1. Place them in this same directory.
2. Rename them from the generic `conn.log` to a more descriptive label use as reference in `config.json`.

### Configuration - Analysis Parameters
As described in the [blog article](https://www.activecountermeasures.com/measuring-data-jitter-using-rcr/), a number of parameters need to be configured as part of RCR. These can be set in `config.json`, and are currently populated with sensible default values, however the user is encouraged to fine-tune these to their liking, especially if custom logs are introduced.

`z_threshold`
- Description: Number of standard deviations for initial outlier detection
- Default value: 2.5

`min_cluster_size`
- Description: Minimum number of points to be considered a valid cluster
- Default value: 10

`cluster_width`
- Description: Maximum width (in bytes) for points to be considered part of the same cluster
- Default value: 20

`bucket_size`
- Description: Size of buckets for histogram calculation
- Default value: 10

`min_bucket_count`
- Description: Minimum number of values needed for a bucket to be considered filled
- Default value: 3

### Configuration - Input Data
All sample data is currently mapped in `config.json`, however if the user introduces their own data the specific IPs to be analyzed have to be specified here.

- For example
```json
        "sample.log": {
            "69.198.73.116": "C2_Traffic"
        }
```

Where:
- `sample.log` is the exact name of the file located in `./input`.
- `69.198.73.116` is the destination host IP to be analyzed.
- `C2_Traffic` is the desired label used in the results output. 


### Generating Results
To run the actual script and analyze all destination host IPs simply run
```bash
python main.py
```

Output report is generated in root folder as `results.html`.

## License
This project is licensed under the MIT License - see the [LICENSE](https://github.com/faanross/RCR_payload_jitter/blob/main/LICENSE) file for details.