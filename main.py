import numpy as np
from scipy import stats
import json
import pandas as pd
from pathlib import Path
from tqdm import tqdm
import logging
from utils.html_generator import generate_html_report

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def identify_outliers_hybrid(data, z_threshold=3.0, min_cluster_size=5, cluster_width=10):
    """
    Identify outliers using both z-score and cluster size information.
    """
    z_scores = np.abs(stats.zscore(data))
    potential_outliers = z_scores >= z_threshold

    # Initialize all points as outliers
    is_outlier = potential_outliers.copy()

    if np.sum(potential_outliers) > 0:
        # Sort the data for cluster detection
        sorted_data = np.sort(data[potential_outliers])

        # Find clusters using sliding window
        i = 0
        while i < len(sorted_data):
            # Look at points within cluster_width of current point
            cluster_points = sorted_data[
                (sorted_data >= sorted_data[i]) &
                (sorted_data <= sorted_data[i] + cluster_width)
                ]

            # If we found a valid cluster
            if len(cluster_points) >= min_cluster_size:
                # Mark all points in this cluster as non-outliers
                for point in cluster_points:
                    is_outlier[data == point] = False
                i += len(cluster_points)
            else:
                i += 1

    # Get valid range from non-outlier points
    valid_data = data[~is_outlier]
    if len(valid_data) > 0:
        valid_range = (np.min(valid_data), np.max(valid_data))
    else:
        valid_range = (np.min(data), np.max(data))

    return ~is_outlier, valid_range


def calculate_mrcr(data, params):
    """Calculate Modified Range Coverage Ratio using improved hybrid outlier detection"""
    original_min, original_max = min(data), max(data)

    # Identify outliers using hybrid method
    non_outlier_mask, (adjusted_min, adjusted_max) = identify_outliers_hybrid(
        data,
        z_threshold=params['z_threshold']['value'],
        min_cluster_size=params['min_cluster_size']['value'],
        cluster_width=params['cluster_width']['value']
    )

    bucket_size = params['bucket_size']['value']
    min_bucket_count = params['min_bucket_count']['value']

    # Create histograms for both original and adjusted ranges
    total_initial_buckets = int(np.ceil((original_max - original_min) / bucket_size))
    total_adjusted_buckets = int(np.ceil((adjusted_max - adjusted_min) / bucket_size))

    # Create histogram for adjusted range
    adjusted_hist, _ = np.histogram(data[non_outlier_mask],
                                    bins=total_adjusted_buckets,
                                    range=(adjusted_min, adjusted_max))

    # Count filled buckets (meeting minimum count requirement)
    filled_buckets = np.sum(adjusted_hist >= min_bucket_count)

    # Calculate MRCR
    mrcr = (filled_buckets / total_adjusted_buckets) * 100 if total_adjusted_buckets > 0 else 0

    return {
        'mrcr': mrcr,
        'original_range': (original_min, original_max),
        'adjusted_range': (adjusted_min, adjusted_max),
        'total_buckets': total_adjusted_buckets,
        'filled_buckets': filled_buckets,
        'removed_outlier_count': np.sum(~non_outlier_mask),
        'outlier_mask': non_outlier_mask,
        'data': data
    }


def process_log_file(file_path, ip_configs):
    """Process a single log file and extract data for specified IPs"""
    logger.info(f"Processing log file: {file_path}")

    try:
        # Define columns for Zeek log format
        columns = [
            "ts", "uid", "id_orig_h", "id_orig_p", "id_resp_h", "id_resp_p",
            "proto", "service", "duration", "orig_bytes", "resp_bytes",
            "conn_state", "local_orig", "local_resp", "missed_bytes",
            "history", "orig_pkts", "orig_ip_bytes", "resp_pkts",
            "resp_ip_bytes", "tunnel_parents"
        ]

        # Read the log file with proper column names
        df = pd.read_csv(file_path, sep='\t', comment='#', names=columns, low_memory=False)

        results = []
        for ip, label in tqdm(ip_configs.items(), desc="Processing IPs"):
            # Filter for specific IP and valid orig_ip_bytes
            ip_data = df[df['id_resp_h'] == ip]
            ip_data = ip_data[ip_data['orig_ip_bytes'] != '-']
            ip_data = ip_data['orig_ip_bytes'].dropna().astype(float).values

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


def main():
    # Load configuration
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
    except Exception as e:
        logger.error(f"Error loading config.json: {str(e)}")
        return

    input_path = Path('./input')
    analysis_results = []

    # Process each log file
    for log_file, ip_configs in config['input_data'].items():
        file_path = input_path / log_file

        if not file_path.exists():
            logger.error(f"Log file not found: {file_path}")
            continue

        # Process the log file
        try:
            results = process_log_file(file_path, ip_configs)

            # Calculate MRCR for each result
            for result in results:
                mrcr_result = calculate_mrcr(result['data'], config['analysis_params'])
                result.update(mrcr_result)
                analysis_results.append(result)

        except Exception as e:
            logger.error(f"Error processing {log_file}: {str(e)}")
            continue

    # Generate report
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