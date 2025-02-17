import numpy as np
from scipy import stats
import json
import pandas as pd
from pathlib import Path
from tqdm import tqdm
import logging
from typing import Dict, List, Tuple, Any, Union, TypedDict
from numpy.typing import NDArray
from utils.html_generator import generate_html_report

# set up basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# define log file result data class
class LogFileResult(TypedDict):
    ip: str
    label: str
    log_file: str
    data: NDArray[np.float64]

# define RCR data class
class RCRResult(TypedDict):
    rcr: float
    original_range: Tuple[float, float]
    adjusted_range: Tuple[float, float]
    total_buckets: int
    filled_buckets: int
    removed_outlier_count: int
    outlier_mask: NDArray[np.bool_]
    data: NDArray[np.float64]

# function to ID outliers using our hybrid approach - Z-score plus determining whether is a cluster based on values chosen in config.json
def identify_outliers_hybrid(
        data: NDArray[np.float64],
        z_threshold: float = 3.0,
        min_cluster_size: int = 5,
        cluster_width: float = 10
) -> Tuple[NDArray[np.bool_], Tuple[float, float]]:

    z_scores = np.abs(stats.zscore(data))
    potential_outliers = z_scores >= z_threshold

    # Initialize all points as outliers
    is_outlier = potential_outliers.copy()

    if np.sum(potential_outliers) > 0:
        sorted_data = np.sort(data[potential_outliers])

        i = 0
        while i < len(sorted_data):
            cluster_points = sorted_data[
                (sorted_data >= sorted_data[i]) &
                (sorted_data <= sorted_data[i] + cluster_width)
                ]

            if len(cluster_points) >= min_cluster_size:
                for point in cluster_points:
                    is_outlier[data == point] = False
                i += len(cluster_points)
            else:
                i += 1

    valid_data = data[~is_outlier]
    if len(valid_data) > 0:
        valid_range = (float(np.min(valid_data)), float(np.max(valid_data)))
    else:
        valid_range = (float(np.min(data)), float(np.max(data)))

    return ~is_outlier, valid_range


# performs actual RCR calculation
def calculate_rcr(data: NDArray[np.float64], params: Dict[str, Dict[str, Any]]) -> RCRResult:

    # Find range of dataset
    original_min, original_max = float(min(data)), float(max(data))

   # call function to determine outliers
    non_outlier_mask, (adjusted_min, adjusted_max) = identify_outliers_hybrid(
        data,
        z_threshold=params['z_threshold']['value'],
        min_cluster_size=params['min_cluster_size']['value'],
        cluster_width=params['cluster_width']['value']
    )

    bucket_size = params['bucket_size']['value']
    min_bucket_count = params['min_bucket_count']['value']

    # creates buckets based on size
    total_adjusted_buckets = int(np.ceil((adjusted_max - adjusted_min) / bucket_size))

    adjusted_hist, _ = np.histogram(data[non_outlier_mask],
                                    bins=total_adjusted_buckets,
                                    range=(adjusted_min, adjusted_max))

    # determine which buckets are considered filled
    filled_buckets = int(np.sum(adjusted_hist >= min_bucket_count))

    # determine RCR
    rcr = (filled_buckets / total_adjusted_buckets) * 100 if total_adjusted_buckets > 0 else 0

    return {
        'rcr': float(rcr),
        'original_range': (original_min, original_max),
        'adjusted_range': (adjusted_min, adjusted_max),
        'total_buckets': total_adjusted_buckets,
        'filled_buckets': filled_buckets,
        'removed_outlier_count': int(np.sum(~non_outlier_mask)),
        'outlier_mask': non_outlier_mask,
        'data': data
    }

# processes our zeek conn.logs
def process_log_file(
        file_path: Path,
        ip_configs: Dict[str, str]
) -> List[LogFileResult]:
    # Process a single log file and extract orig_ip_bytes data for specified IPs.

    logger.info(f"Processing log file: {file_path}")

    try:
        columns = [
            "ts", "uid", "id_orig_h", "id_orig_p", "id_resp_h", "id_resp_p",
            "proto", "service", "duration", "orig_bytes", "resp_bytes",
            "conn_state", "local_orig", "local_resp", "missed_bytes",
            "history", "orig_pkts", "orig_ip_bytes", "resp_pkts",
            "resp_ip_bytes", "tunnel_parents"
        ]

        df = pd.read_csv(file_path, sep='\t', comment='#', names=columns, low_memory=False)

        results = []

        for ip, label in tqdm(ip_configs.items(), desc="Processing IPs"):
            ip_data = df[df['id_resp_h'] == ip] # filter only for the rows containing ip of interest
            ip_data = ip_data[ip_data['orig_ip_bytes'] != '-'] # filter out rows with no value for bytes
            ip_data = ip_data['orig_ip_bytes'].dropna().astype(float).values # convert into np array only containing orig_ip_bytes

            if len(ip_data) == 0:
                logger.warning(f"No valid data found for IP {ip} in {file_path}")
                continue

            logger.info(f"Found {len(ip_data)} connections for IP {ip}")
            results.append({
                'ip': ip,
                'label': label,
                'log_file': file_path.name,
                'data': ip_data
            })

        return results

    except Exception as e:
        logger.error(f"Error processing {file_path}: {str(e)}")
        raise


def main() -> None:
    # load json.config
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
    except Exception as e:
        logger.error(f"Error loading config.json: {str(e)}")
        return

    # where to look for Zeek log files
    input_path = Path('./input')

    # final results will be a list of dictionaries
    analysis_results = []

    # process our log files to extract only orig_ip_bytes of IPs defined in config.json
    for log_file, ip_configs in config['input_data'].items():
        file_path = input_path / log_file

        if not file_path.exists():
            logger.error(f"Log file not found: {file_path}")
            continue

        try:
            results = process_log_file(file_path, ip_configs) # list with ip, label, path, array of orig_ip_bytes values

            for result in results:
                rcr_result = calculate_rcr(result['data'], config['analysis_params'])
                result.update(rcr_result)
                analysis_results.append(result)

        except Exception as e:
            logger.error(f"Error processing {log_file}: {str(e)}")
            continue

    # finally, generate our report as results.html
    if analysis_results:
        try:
            html_report = generate_html_report(analysis_results, config['analysis_params'])
            with open('results.html', 'w') as f:
                f.write(html_report)
            logger.info("Report generated successfully: results.html")
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
    else:
        logger.error("No results to generate report")

if __name__ == "__main__":
    main()