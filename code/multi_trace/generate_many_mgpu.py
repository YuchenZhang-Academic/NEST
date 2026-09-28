from dataset import pcaplinktype_decoder_class
from model import get_model
import torch
import torch.nn as nn
import random

from scapy.all import *
import struct

import os
import pickle
import multiprocessing

from generate_lib import generate


def analyze_pcap(file_path):
    # 读取pcap文件
    packets = rdpcap(file_path)
    
    # 获取第一个数据包的时间戳
    first_packet_timestamp = packets[0].time
    
    # 获取所有的IP地址
    ip_addresses = set()
    for pkt in packets:
        if 'IP' in pkt:
            ip_addresses.add(pkt['IP'].src)
            ip_addresses.add(pkt['IP'].dst)
    
    # 获取数据包总数
    total_packets = len(packets)
    
    return first_packet_timestamp, list(ip_addresses), total_packets

def process_file(model, device, outputfile, start_time, ip_list, packet_num):

    print('len(ip_list)', len(ip_list), 'packet_num', packet_num, outputfile)

    packet_list = generate(model, ip_list, start_time, max_packet_num = packet_num, device = device)
    wrpcap(outputfile, packet_list)

        
def test_many_gpu(gpu_id):
    vocab_size = 260
    max_len = 12032
    model_path = '/home/zyc/project/NEST/new/code/multi_trace/parameters/test_111.pt'
    device = f'cuda:{gpu_id}'
    torch.cuda.set_device(device)  # 设置当前进程可见的 GPU 设备
    
    # 指定目录路径
    directory = '/home/zyc/project/NEST/old/graph/code_12k/trace_dataset_pre1_1MB_100'

    # 创建模型实例
    model = get_model(num_tokens = vocab_size, max_len = max_len).to(device)
    model.load_state_dict(torch.load(model_path, map_location=device))
    model.eval()
    
    # 遍历目录中的文件
    file_list = os.listdir(directory)
    random.shuffle(file_list)
    for filename in file_list:
        if filename.endswith(".pcap"): 
            pcappath = os.path.join(directory, filename)
            start_time, ip_list, packet_num = analyze_pcap(pcappath)


            outputpath = '/home/zyc/project/NEST/new/experiments/multi_trace/output'
            os.makedirs(outputpath, exist_ok = True)
            outputfile = outputpath + '/' + filename.split('.')[0] + '.pcap'
            if os.path.exists(outputfile):
                continue

            process_file(model, device, outputfile, start_time, ip_list, packet_num = min(packet_num, 1000))


def main():
    num_gpus = torch.cuda.device_count()
    pool = multiprocessing.Pool(processes=num_gpus)
    pool.map(test_many_gpu, range(num_gpus))
    pool.close()
    pool.join()


if __name__ == "__main__":
    multiprocessing.set_start_method('spawn')
    main()












