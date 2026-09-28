import os
import torch
import random
import struct
from torch.utils.data import Dataset, DataLoader
import socket
from torch.nn.utils.rnn import pad_sequence

from scapy.all import *
import pickle


def ip_to_four_numbers(ip):
    return tuple(map(int, ip.split('.')))

class PcapDataset(Dataset):
    def __init__(self, path, max_len = 256, sample_rate =1):
        self.max_len = max_len
        self.sample_rate = sample_rate

        self.files = [os.path.join(path, file) for file in os.listdir(path) if file.endswith('.pkl')]
        print('random.shuffle dataset start...')
        random.shuffle(self.files)
        print('random.shuffle dataset finish...')
        self.dg = self.data_generator()
        

    def __len__(self):
        # 如果生成器无法提供数据集长度信息，可以返回一个较大的数字
        return int(len(self.files) * self.sample_rate)

    # 定义一个生成器来读取数据
    def data_generator(self):
        if len(self.files) == 0:
            raise ValueError("No pcap files found in the specified path.")

        for index in range(len(self.files)):
            if random.random()>self.sample_rate:
                continue

            file_path = self.files[index]

            with open(file_path, 'rb') as file:
                ip_list = pickle.load(file)

            if len(ip_list) == 0:
                continue

            data = []
            for ip in ip_list:
                data.append(259)
                for i in range(4):
                    data.append(ip[i])
            data.append(256)

            data = data[:self.max_len]

            yield torch.tensor(data).long()
        


    def __getitem__(self, index):
        # 从生成器中获取数据
        return next(self.dg)


def collate_fn(batch):
    batch = pad_sequence(batch, batch_first=True, padding_value=258)
    return batch


if __name__ == "__main__":
    # Example usage
    dataset = PcapDataset('./pkl_dataset')

    batch_size = 1
    dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=False, collate_fn=collate_fn)

    for batch in dataloader:
        print('batch')
        print(batch.shape)
        print(batch)
        #break

    



