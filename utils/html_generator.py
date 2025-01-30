import base64
import io
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt

def plot_to_base64(data, title, adjusted_range=None, outlier_mask=None):
    """Generate plot and convert to base64 string"""
    plt.figure(figsize=(12, 6))
    sns.set_style("whitegrid")
    
    if outlier_mask is not None:
        sns.histplot(data=data[outlier_mask], bins=50, color='skyblue', alpha=0.6, label='Normal Values')
        if np.sum(~outlier_mask) > 0:
            sns.histplot(data=data[~outlier_mask], bins=50, color='red', alpha=0.3, label='Outliers')
            plt.legend()
    else:
        sns.histplot(data=data, bins=50, color='skyblue', alpha=0.6)
    
    plt.title(title)
    plt.xlabel("Bytes")
    plt.ylabel("Connection Count")
    
    if adjusted_range:
        plt.axvline(x=adjusted_range[0], color='red', linestyle='--', label='Adjusted Range')
        plt.axvline(x=adjusted_range[1], color='red', linestyle='--')
        if outlier_mask is None:
            plt.legend()
    
    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight', dpi=100)
    plt.close()
    buf.seek(0)
    return base64.b64encode(buf.getvalue()).decode('utf-8')

def generate_html_report(results, analysis_params):
    """Generate HTML report with all results"""
    css = """
body { font-family: Arial; margin: 20px auto; max-width: 1200px; padding: 20px; }
table { border-collapse: collapse; width: 100%; margin: 20px 0; }
th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
th { background-color: #f5f5f5; }
tr:nth-child(even) { background-color: #f9f9f9; }
.plot-container { margin: 20px 0; background: white; padding: 20px; }
.dataset-section { margin: 40px 0; border-top: 2px solid #eee; padding-top: 20px; }
img { max-width: 100%; height: auto; }
.params-section { background-color: #f8f9fa; padding: 15px; margin: 20px 0; }
"""

    # Generate summary rows
    summary_rows = "".join([
        f"""<tr>
            <td>{result['log_file']}</td>
            <td>{result['ip']}</td>
            <td>{result['label']}</td>
            <td>{result['mrcr']:.2f}%</td>
            <td>{result['removed_outlier_count']}</td>
            <td>{len(result['data'])}</td>
        </tr>""" for result in results
    ])

    # Generate parameters rows
    params_rows = "".join([
        f"""<tr>
            <td>{param}</td>
            <td>{details['value']}</td>
            <td>{details['description']}</td>
        </tr>""" for param, details in analysis_params.items()
    ])

    # Generate detailed sections
    detailed_sections = "".join([
        f"""<div class="dataset-section">
            <h3>{result['label']} ({result['ip']})</h3>
            <p>Log File: {result['log_file']}</p>
            <p>MRCR Score: {result['mrcr']:.2f}%</p>
            <p>Original Range: {result['original_range'][0]:.1f} - {result['original_range'][1]:.1f} bytes</p>
            <p>Adjusted Range: {result['adjusted_range'][0]:.1f} - {result['adjusted_range'][1]:.1f} bytes</p>
            <p>Outliers Removed: {result['removed_outlier_count']}</p>
            <div class="plot-container">
                <h4>Before Outlier Removal</h4>
                <img src="data:image/png;base64,{plot_to_base64(result['data'], 
                    f"Bytes Distribution - {result['label']} ({result['ip']}")}">
            </div>
            <div class="plot-container">
                <h4>After Outlier Removal (Red = Outliers)</h4>
                <img src="data:image/png;base64,{plot_to_base64(result['data'], 
                    f"Bytes Distribution with Outliers - {result['label']} ({result['ip']})", 
                    result['adjusted_range'], 
                    result['outlier_mask'])}">
            </div>
        </div>""" for result in results
    ])

    # Construct the final HTML
    html = f"""<!DOCTYPE html>
<html>
<head>
    <style>{css}</style>
</head>
<body>
    <h1>Network Traffic Analysis Report</h1>
    
    <h2>Summary Results</h2>
    <table>
        <tr>
            <th>Log File</th>
            <th>IP Address</th>
            <th>Label</th>
            <th>MRCR Score</th>
            <th>Outliers Found</th>
            <th>Total Connections</th>
        </tr>
        {summary_rows}
    </table>

    <div class="params-section">
        <h3>Analysis Parameters</h3>
        <table>
            <tr>
                <th>Parameter</th>
                <th>Value</th>
                <th>Description</th>
            </tr>
            {params_rows}
        </table>
    </div>

    <h2>Detailed Analysis</h2>
    {detailed_sections}
</body>
</html>"""

    return html