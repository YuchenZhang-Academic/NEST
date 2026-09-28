import os
import dpkt
import pickle
from multiprocessing import Pool

def extract_unique_ips_from_pcap(file_path):
    unique_ips = set()
    print(file_path)
    with open(file_path, 'rb') as f:
        try:
            pcap = dpkt.pcap.Reader(f)  # 先按.pcap格式解析，若解析不了，则按pcapng格式解析
        except:
            f.seek(0,0)
            pcap = dpkt.pcapng.Reader(f)

        for timestamp, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                unique_ips.add(ip.src)
                unique_ips.add(ip.dst)

    return unique_ips

def process_file(file_path, output_folder):
    try:
        unique_ips = extract_unique_ips_from_pcap(file_path)

        # Save unique IPs to a .pkl file
        output_file = os.path.join(output_folder, f"{os.path.splitext(os.path.basename(file_path))[0]}.pkl")
        with open(output_file, 'wb') as f:
            pickle.dump(unique_ips, f)
    except:
        pass

def process_pcap_files(input_folder, output_folder):
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    files_to_process = []
    for root, dirs, files in os.walk(input_folder):
        for file in files:
            if file.endswith(('.pcap', '.pcapng')):
                files_to_process.append(os.path.join(root, file))

    with Pool(24) as pool:
        pool.starmap(process_file, [(file_path, output_folder) for file_path in files_to_process])


if __name__ == "__main__":
    src_folder = '/data/qj/LLM_traffic2/think/plan1_view/trace/code_128k/trace_dataset_pre1_1MB' #'./pcap_dataset_test'
    dest_folder = './pkl_dataset'
    process_pcap_files(src_folder, dest_folder)





