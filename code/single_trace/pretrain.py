import torch
from trainer import Trainer
from model import get_model

def main():
    batch_size = 1
    vocab_size = 260
    max_len = 12032

    device = 'cuda:0' if torch.cuda.is_available() else 'cpu'

    # 创建模型实例
    model = get_model(num_tokens = vocab_size, max_len = max_len).to(device)
    
    dataset_path = '../code_128k/trace_dataset_pre2_1MB' #'./trace_dataset'
    
    trainer = Trainer(model, device, dataset_path, batch_size, max_len, max_round = 1000, output_folder = './output/20240407/')
    trainer.train()

    return 

if __name__ == "__main__":
    main()










