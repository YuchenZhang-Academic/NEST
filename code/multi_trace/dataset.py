import os
from scapy.all import *
import torch
import random
import struct
from torch.utils.data import Dataset, DataLoader
from torch.nn.utils.rnn import pad_sequence
import pickle

def pcaplinktype_decoder_class(num):
    if num == 1:
        return scapy.layers.l2.Loopback
    elif num == 2:
        return scapy.layers.l2.Dot3
    elif num == 3:
        return scapy.layers.l2.Ether
    elif num == 4:
        return scapy.layers.ppp
    elif num == 5:
        return scapy.layers.inet6.IPv46
    elif num == 6:
        return scapy.layers.inet6.IPv6
    elif num == 7:
        return scapy.layers.l2.HDLC
    elif num == 8:
        return scapy.layers.dot11
    elif num == 9:
        return scapy.layers.l2.CookedLinux
    elif num == 10:
        return scapy.layers.dot11.PrismHeader
    elif num == 11:
        return scapy.layers.dot11.RadioTap
    elif num == 12:
        return scapy.layers.ppi
    elif num == 13:
        return scapy.layers.dot15d4
    elif num == 14:
        return scapy.layers.bluetooth
    elif num == 15:
        return scapy.layers.l2.DIR_PPP
    elif num == 16:
        return scapy.layers.dot15d4
    elif num == 17:
        return scapy.layers.bluetooth4LE
    elif num == 18:
        return scapy.layers.bluetooth4LE
    elif num == 19:
        return scapy.layers.l2.MPacketPreamble
    elif num == 20:
        return scapy.layers.l2.CookedLinuxV2
    elif num == 21:
        return scapy.layers.inet.IP
    
    return scapy.layers.l2.CookedLinux


def pcaplinktype_encoder(pkt):
    if type(pkt) is scapy.layers.l2.Loopback:
        return  1
    elif type(pkt) is scapy.layers.l2.Dot3:
        return 2
    elif type(pkt) is scapy.layers.l2.Ether:
        return 3
    elif type(pkt) is scapy.layers.ppp:
        return 4
    elif type(pkt) is scapy.layers.inet6.IPv46:
        return 5
    elif type(pkt) is scapy.layers.inet6.IPv6:
        return 6
    # elif type(pkt) is scapy.layers.l2.HDLC:
    #     return 7
    elif type(pkt) is scapy.layers.dot11:
        return 8
    elif type(pkt) is scapy.layers.l2.CookedLinux:
        return 9
    elif type(pkt) is scapy.layers.dot11.PrismHeader:
        return 10
    elif type(pkt) is scapy.layers.dot11.RadioTap:
        return 11
    elif type(pkt) is scapy.layers.ppi:
        return 12
    elif type(pkt) is scapy.layers.dot15d4:
        return 13
    elif type(pkt) is scapy.layers.bluetooth:
        return 14
    # elif type(pkt) is scapy.layers.l2.DIR_PPP:
    #     return 15
    elif type(pkt) is scapy.layers.dot15d4:
        return 16
    elif type(pkt) is scapy.layers.bluetooth4LE:
        return 17
    # elif type(pkt) is scapy.layers.l2.BTLE_RF:
    #     return 18
    elif type(pkt) is scapy.layers.l2.MPacketPreamble:
        return 19
    elif type(pkt) is scapy.layers.l2.CookedLinuxV2:
        return 20
    elif type(pkt) is scapy.layers.inet.IP:
        return 21


def replace_last_folder(path, new_folder_name):
    # 将路径分割为目录部分和文件名部分
    directory, file_name = os.path.split(path)

    # 将目录部分分割为文件夹列表
    folders = directory.split(os.sep)

    # 用新的文件夹名字替换倒数第一个文件夹名字
    folders[-1] = new_folder_name

    # 组合成新的路径
    new_directory = os.path.join(*folders)

    # 最终的新路径
    new_path = os.path.join(new_directory, file_name)

    return new_path

def modify_file_extension(file_path, new_extension):
    file_name, file_extension = os.path.splitext(file_path)
    new_file_name = file_name + new_extension
    return new_file_name

class PcapDataset(Dataset):
    def __init__(self, path, max_length, sample_rate = 0.001):
        self.pcap_path = os.path.join(path,'pcap')
        self.data_path = os.path.join(path,'data')
        self.pcap_files = [os.path.join(self.pcap_path, file) for file in os.listdir(self.pcap_path) if file.endswith('.pcap') or file.endswith('.pcapng')]
        #print('self.pcap_files ',self.pcap_files )
        print('random.shuffle dataset start...')
        random.shuffle(self.pcap_files)
        print('random.shuffle dataset finish...')
        self.max_length = max_length
        self.sample_rate = sample_rate

        self.dg = self.data_generator()

    def __len__(self):
        # 如果生成器无法提供数据集长度信息，可以返回一个较大的数字
        return int(len(self.pcap_files) * 3 * self.sample_rate)

    # 定义一个生成器来读取数据
    def data_generator(self):
        if len(self.pcap_files) == 0:
            raise ValueError("No pcap files found in the specified path.")

        for index in range(len(self.pcap_files)):
            if random.random()>self.sample_rate:
                continue

            file_path = self.pcap_files[index]
            pkl_path = replace_last_folder(file_path, "data")
            pkl_path = modify_file_extension(pkl_path, '.pkl')
            with open(pkl_path, 'rb') as file:
                data = pickle.load(file)

            # 计算头部信息
            start_time = data[0]
            all_ips = [data[1]] + data[2]
            # 限制最大头数目, 最多k个ip地址
            all_ips = all_ips[:64]
            header = [259]
            header.extend(list(struct.pack('>d', start_time)))
            for ip in all_ips:
                header.append(259)
                for i in ip.split('.'):
                    header.append(int(i))
            header.append(256)

            # Read packets from the selected file
            packets = []
            last_time = None
            d_time = None
            with PcapReader(file_path) as pcap_reader:
                for pkt_data in pcap_reader:

                    ts = pkt_data.time
                    data = bytes(pkt_data)

                    if last_time is None:
                        d_time = ts - start_time
                        last_time = ts
                    else:
                        d_time = ts - last_time
                        last_time = ts

                    time_encoded = struct.pack('>d', d_time)
                    
                    vectors = list(time_encoded + data)
                    head = 256
                    vectors.insert(0,head)
                    vectors.insert(1,pcaplinktype_encoder(pkt_data))
                    
                    packets.extend(vectors)

                    if len(packets) > self.max_length:
                        output = header + packets
                        output = output[:self.max_length]
                        yield torch.tensor(output).long()

                        # 防止一直学习一个大文件
                        if random.random() < 0.1:
                            break

                        randstart = random.randint(0,len(packets) -1)
                        packets = packets[randstart:]

            end = 257
            packets.append(end)

            output = header + packets
            output = output[:self.max_length]
            yield torch.tensor(output).long()

    def __getitem__(self, index):
        # 从生成器中获取数据
        return next(self.dg)


def collate_fn(batch):
    batch = pad_sequence(batch, batch_first=True, padding_value=258)
    return batch


if __name__ == "__main__":
    # Example usage
    max_len = 256
    dataset = PcapDataset('./trace_dataset', max_length=max_len, sample_rate = 1)

    batch_size = 1
    dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True, collate_fn=collate_fn)

    for batch in dataloader:
        print('batch')
        print(batch.shape)
        print(batch[:50])
        #break




