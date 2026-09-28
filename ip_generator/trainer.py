
import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F
from torch.optim import lr_scheduler
import time
import os
from tqdm import tqdm
import random

from torch.utils.data import DataLoader
from dataset import PcapDataset, collate_fn
import re

def create_folder_if_not_exists(folder_path):
    if not os.path.exists(folder_path):
        try:
            os.makedirs(folder_path)
            print(f"Folder created at {folder_path}")
        except OSError as e:
            print(f"Failed to create directory! Error: {e}")
    else:
        print(f"Folder already exists at {folder_path}")

# 定义稀疏卷积神经网络
class Trainer():
    def __init__(self, model, device, dataset_path, batch_size, max_len, max_round, output_folder = './output/'):
        # paras
        self.learning_rate = 1e-4
        self.batch_size = batch_size
        self.max_len = max_len
        self.max_round = max_round
        self.dataset_path = dataset_path

        self.output_folder = output_folder

        # 模型
        self.model = model
        self.device = device
        self.model.to(self.device)

        # 选择优化器
        self.optimizer = optim.AdamW(self.model.parameters(), lr=self.learning_rate)

        # 设置余弦学习率调度
        self.scheduler = lr_scheduler.CosineAnnealingLR(self.optimizer, T_max=1000)  # T_max是调度周期的长度

    def train_one_epoch(self, round = 0):
        self.model.train()
        dataset = PcapDataset(self.dataset_path, max_len=self.max_len)
        self.dataloader = DataLoader(dataset, batch_size=self.batch_size, shuffle=False, collate_fn=collate_fn)

        running_loss = 0.0
        i_time = 0
        total_batches = len(self.dataloader)

        
        with tqdm(total=total_batches) as pbar:
            for batch in self.dataloader:
                i_time += 1
                
                self.optimizer.zero_grad()

                batch = batch.to(self.device)
                loss = self.model(batch)
                
                loss.mean().backward()  # Backpropagation
                self.optimizer.step()  # Update model parameters

                running_loss += loss.mean().item()

                pbar.set_description(f'Round {round}, Batch {i_time}, Loss: {loss.mean().item():.4f}')
                pbar.update(1)

        return running_loss


    def train(self):
        create_folder_if_not_exists(self.output_folder)
        para_filename = os.path.join(self.output_folder, 'test')

        # 尝试从断点开始执行
        now_r = self.find_max_roundn(self.output_folder)
        if now_r >= 0: # 找到历史记录
            with open(para_filename+'.txt',"a") as txt_file:
                txt_file.writelines('find history and loading'+','+str(now_r)+'\n')
            self.model.load_state_dict(torch.load(para_filename+'_'+str(now_r)+'.pt',map_location=self.device))
        else:
            with open(para_filename+'.txt',"a") as txt_file:
                txt_file.writelines('round'+','+'train_loss'+'\n')

        # 开始训练
        for round in range(now_r+1, self.max_round):
            print("round",round)
            train_loss = self.train_one_epoch(round)

            torch.save(self.model.state_dict(), para_filename+'_'+str(round)+'.pt')
            
            # 记录参数数据、训练过程
            with open(para_filename+'.txt',"a") as txt_file:
                txt_file.writelines(str(round)+','+str(train_loss)+'\n')

            # 更新学习率
            self.scheduler.step()
            
        # 读取模型参数
        #self.model.load_state_dict(torch.load(para_filename+'_best'+'.pt',map_location=self.device))


    def find_max_roundn(self, folder_path):
        max_n = -1

        # 遍历文件夹下的文件
        for file_name in os.listdir(folder_path):
            # 使用正则表达式匹配文件名
            match = re.match(r'test_(\d+)\.pt', file_name)
            if match:
                n = int(match.group(1))
                max_n = max(max_n, n)

        return max_n










