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


def restore_pcap_from_bytes(packet_bytes, file_path):
    packets = []
    current_packet = b''
    start_time = 0
    last_time = None
    linktype_num = None

    i = 0
    while (i < len(packet_bytes)):
        byte = packet_bytes[i]
        if i == 0 and byte == 256:
            i += 1
            continue

        if byte == 257:
            break
        elif byte == 256:
            packets.append((last_time + start_time, current_packet, linktype_num))
            current_packet = b''
            start_time += last_time
            last_time = None
            linktype_num = None
        else: 
            if linktype_num is None:
                linktype_num = pcaplinktype_decoder_class(byte)
                i += 1
                continue
            elif last_time is None:
                content = packet_bytes[i:i+8]
                if len(content) < 8:
                    last_time = 0
                    break
                content = [min(c, 255) for c in content]
                last_time = struct.unpack('>d', bytes(content))[0]
                i += 8
                continue
            else:
                byte = min(byte, 255)
                current_packet += bytes([byte])

        i += 1

    # 残缺包追加
    packets.append((last_time + start_time, current_packet, linktype_num))

    packet_list = []
    for ts, pyaload, linktype_num_packet_class in packets:
        try:
            packet = linktype_num_packet_class(pyaload)
            packet.time = ts
            packet_list.append(packet)
        except:
            print('error packet')

    wrpcap(file_path, packet_list)
    

def process_file(filepath, model, device, max_len, outputfile):
    with open(filepath, 'rb') as file:
        data = pickle.load(file)

    while (True):
        try:
            # 计算头部信息
            start_time = data[0]
            all_ips = [data[1]] + data[2]
            # 限制最大头数目, 最多为2000个ip地址
            all_ips = all_ips[:64]
            header = [259]
            header.extend(list(struct.pack('>d', start_time)))
            for ip in all_ips:
                header.append(259)
                for i in ip.split('.'):
                    header.append(int(i))
            header.append(256)

            inp = torch.tensor(header).long().to(device)
            GENERATE_LENGTH = max_len
            with torch.no_grad():
                sample = model.module.generate(inp, GENERATE_LENGTH, eos_token = 257)

            restore_pcap_from_bytes(sample, outputfile)
            break
        except Exception as e:
            # 捕获异常并打印异常信息
            print("发生异常:", e)

def test_many_gpu(gpu_id):
    vocab_size = 260
    max_len = 12032
    model_path = '/home/zyc/project/NEST/new/code/single_trace/parameters/single_trace.pt'
    device = f'cuda:{gpu_id}'
    torch.cuda.set_device(device)  # 设置当前进程可见的 GPU 设备
    # 指定目录路径
    directory = '/home/zyc/project/NEST/old/trace/code_128k/trace_dataset_pre2_1MB_1000/data'

    # 创建模型实例
    model = get_model(num_tokens = vocab_size, max_len = max_len).to(device)
    model.load_state_dict(torch.load(model_path, map_location=device))
    model.eval()
    
    # 遍历目录中的文件
    file_list = os.listdir(directory)
    random.shuffle(file_list)
    for filename in file_list:
        if filename.endswith(".pkl"):  # 确保文件是.pkl文件
            filepath = os.path.join(directory, filename)

            outputpath = '/home/zyc/project/NEST/new/experiments/single_trace/output'
            os.makedirs(outputpath, exist_ok = True)
            outputfile = outputpath + '/' + filename.split('.')[0] + '.pcap'
            if os.path.exists(outputfile):
                continue

            process_file(filepath, model, device, max_len, outputfile)
        input("continue")

def main():
    num_gpus = torch.cuda.device_count()
    pool = multiprocessing.Pool(processes=num_gpus)
    pool.map(test_many_gpu, range(num_gpus))
    pool.close()
    pool.join()

if __name__ == "__main__":
    multiprocessing.set_start_method('spawn')
    main()










