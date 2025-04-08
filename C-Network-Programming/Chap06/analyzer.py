# Import required libraries


import matplotlib.pyplot as plt
import pandas as pd
import plotly.express as px


# Load the CSV file into a DataFrame
def load_data(file_path="analyzer.csv"):
    """Load the CSV log file into a pandas DataFrame."""
    df = pd.read_csv(file_path)
    print("First 5 rows of the DataFrame:")
    print(df.head(5))
    return df


# 4.1.1 Basic Analysis
def analyze_by_protocol(df):
    """Count events by protocol (analyzer_name) and plot a bar graph."""
    analyzer_counts = df['analyzer_name'].value_counts()
    print("Event counts by analyzer_name:")
    print(analyzer_counts)

    # Plot horizontal bar graph
    analyzer_counts.plot(kind='barh', color='skyblue', title='Events by Protocol')
    plt.xlabel('Count')
    plt.ylabel('Protocol')
    plt.show()


def analyze_by_source_ip(df, specific_ip='10.164.94.120'):
    """Count events by source IP and analyze a specific IP."""
    source_ip_counts = df['id.orig_h'].value_counts()
    print("Event counts by Source IP:")
    print(source_ip_counts)

    # Filter for a specific IP
    specific_ip_data = df[df['id.orig_h'] == specific_ip]
    print(f"Details for IP {specific_ip}:")
    print(specific_ip_data[['ts', 'id.resp_h', 'failure_reason']].head())


def analyze_by_dest_ip(df):
    """Count events by destination IP and plot a bar graph."""
    dest_ip_counts = df['id.resp_h'].value_counts()
    print("Event counts by Destination IP:")
    print(dest_ip_counts)

    # Plot horizontal bar graph
    dest_ip_counts.plot(kind='barh', color='lightgreen', title='Events by Destination IP')
    plt.xlabel('Count')
    plt.ylabel('Destination IP')
    plt.show()


# 4.1.2 Time-Based Analysis
def time_based_analysis(df):
    """Analyze event frequency by hour and plot a bar graph."""
    df['ts'] = pd.to_datetime(df['ts'])  # Convert timestamp to datetime
    df['hour'] = df['ts'].dt.hour  # Extract hour
    hourly_counts = df.groupby('hour').size()
    print("Events by Hour:")
    print(hourly_counts)

    # Plot bar graph
    hourly_counts.plot(kind='bar', color='salmon', title='Events by Hour')
    plt.xlabel('Hour of Day')
    plt.ylabel('Event Count')
    plt.show()


# 4.1.3 Failure Reason Breakdown
def failure_reason_analysis(df):
    """Count events by failure reason and plot a bar graph."""
    failure_counts = df['failure_reason'].value_counts()
    print("Event Counts by Failure Reason:")
    print(failure_counts)

    # Plot horizontal bar graph
    failure_counts.plot(kind='barh', color='lightcoral', title='Events by Failure Reason')
    plt.xlabel('Count')
    plt.ylabel('Failure Reason')
    plt.show()


# 4.1.4 Source-to-Destination Connections
def connection_analysis(df):
    """Analyze source-to-destination pairs and plot a bar graph."""
    df['connection'] = df['id.orig_h'] + ' -> ' + df['id.resp_h']
    connection_counts = df['connection'].value_counts()
    print("Event Counts by Connection:")
    print(connection_counts)

    # Plot horizontal bar graph (top 10 for readability)
    connection_counts.head(10).plot(kind='barh', color='orchid', title='Top 10 Source-to-Destination Connections')
    plt.xlabel('Count')
    plt.ylabel('Connection')
    plt.show()


# 4.1.5 Port Analysis
def port_analysis(df):
    """Analyze destination and source ports and plot a bar graph."""
    dest_port_counts = df['id.resp_p'].value_counts()
    print("Violations by Destination Port:")
    print(dest_port_counts)

    unique_source_ports = df['id.orig_p'].nunique()
    print(f"Number of unique source ports: {unique_source_ports}")

    # Plot horizontal bar graph for destination ports
    dest_port_counts.plot(kind='barh', color='lightblue', title='Events by Destination Port')
    plt.xlabel('Count')
    plt.ylabel('Destination Port')
    plt.show()


# 4.2.1 Port Analysis for RDP Events (Port 3389)
def rdp_port_analysis(df):
    """Analyze RDP events on port 3389 and plot with matplotlib and plotly."""
    rdp_events = df[df['id.resp_p'] == 3389]
    dest_ip_counts = rdp_events['id.resp_h'].value_counts().reset_index()
    dest_ip_counts.columns = ['Destination IP', 'Connection Count']
    print("RDP Connections by Destination IP:")
    print(dest_ip_counts)

    # Matplotlib plot
    dest_ip_counts.plot(kind='barh', x='Destination IP', y='Connection Count',
                        color='teal', title='RDP Connections by Destination IP')
    plt.xlabel('Connection Count')
    plt.ylabel('Destination IP')
    plt.show()

    # Plotly plot (top 10)
    fig = px.bar(dest_ip_counts.head(10),
                 x='Connection Count', y='Destination IP', orientation='h',
                 title='Top 10 RDP Target IPs by Connection Count')
    fig.update_layout(plot_bgcolor='white', xaxis_title='Number of RDP Connections',
                      yaxis_title='Destination IP')
    fig.show()


# 4.2.2 Source-Destination Pairs for RDP Events
def analyze_rdp_ip_pairs():
    # 08_rdp_ip_pairs_analysis.py
    # Phân tích cặp IP nguồn-đích cho sự kiện RDP (4.2.2)

    # Tải dữ liệu
    df = pd.read_csv("analyzer.csv")

    # Lọc các sự kiện RDP (port đích = 3389)
    rdp_events = df[df['id.resp_p'] == 3389]

    # Tạo cặp nguồn-đích và đếm số lần xuất hiện
    rdp_events['IP_Pair'] = rdp_events['id.orig_h'] + ' → ' + rdp_events['id.resp_h']
    ip_pair_counts = rdp_events.groupby(['id.orig_h', 'id.resp_h']).size().reset_index()
    ip_pair_counts.columns = ['Source IP', 'Destination IP', 'Connection Count']

    # Sắp xếp theo số lần kết nối giảm dần
    ip_pair_counts = ip_pair_counts.sort_values('Connection Count', ascending=False)

    # Hiển thị top 15 cặp IP
    print("Top 15 RDP Source-Destination IP Pairs:")
    print(ip_pair_counts.head(15))

    # Tạo nhãn cho trực quan hóa
    ip_pair_counts['IP Pair'] = ip_pair_counts['Source IP'] + ' → ' + ip_pair_counts['Destination IP']

    # 2. Biểu đồ cột ngang với Matplotlib
    plt.figure(figsize=(12, 8))
    plt.barh(ip_pair_counts['IP Pair'].head(10), ip_pair_counts['Connection Count'].head(10), color='salmon')
    plt.title('Top 10 RDP Source-Destination IP Pairs (Matplotlib)')
    plt.xlabel('Number of RDP Connections')
    plt.ylabel('Source → Destination IP')
    plt.tight_layout()
    plt.show()

    # 4. Biểu đồ tròn (Pie Chart) với Matplotlib
    plt.figure(figsize=(10, 8))
    plt.pie(ip_pair_counts['Connection Count'].head(10), labels=ip_pair_counts['IP Pair'].head(10), autopct='%1.1f%%',
            startangle=140, colors=plt.cm.Paired.colors)
    plt.title('Distribution of Top 10 RDP Source-Destination IP Pairs (Pie Chart)')
    plt.tight_layout()
    plt.show()


# Main execution
if __name__ == "__main__":
    # Load the data
    df = load_data("analyzer.csv")

    # Run basic analysis
    analyze_by_protocol(df)
    analyze_by_source_ip(df)
    analyze_by_dest_ip(df)

    # Run time-based analysis
    time_based_analysis(df)

    # Run failure reason analysis
    failure_reason_analysis(df)

    # Run connection analysis
    connection_analysis(df)

    # Run port analysis
    port_analysis(df)

    
    # Sau đó, run RDP source-destination pair analysis
    analyze_rdp_ip_pairs()
    
    # Run advanced RDP analysis first
    rdp_port_analysis(df)

    

