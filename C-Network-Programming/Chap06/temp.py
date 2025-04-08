# 08_rdp_ip_pairs_analysis.py
# Phân tích cặp IP nguồn-đích cho sự kiện RDP (4.2.2)
import matplotlib.pyplot as plt
import pandas as pd

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
