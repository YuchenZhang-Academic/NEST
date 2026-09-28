import torch
from trainer import Trainer
from model import get_model

def main():
    batch_size = 2
    vocab_size = 260
    max_len = 12032

    device = 'cuda:0' if torch.cuda.is_available() else 'cpu'

    # 创建模型实例
    model = get_model(num_tokens = vocab_size, max_len = max_len).to(device)
    
    dataset_path = './pcap_dataset_test'
    
    trainer = Trainer(model, device, dataset_path, batch_size, max_len, max_round = 100, output_folder = './output/test/')
    trainer.train()

    return 

if __name__ == "__main__":
    main()










