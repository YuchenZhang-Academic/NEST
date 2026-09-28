import torch
from collections import OrderedDict
import pickle

from model import get_model
from scapy.all import *

def remove_duplicates_with_order(lst):
    # 使用OrderedDict来保持原始顺序并去重
    return list(OrderedDict.fromkeys(lst))

def restore_ip_from_bytes(sample):
    sample = sample.cpu().numpy()

    ips = []
    ip = []
    for num in sample:
        if num == 256:
            break

        if 0 <= num <= 255:
            ip.append(num)
            if len(ip) == 4:
                ips.append(".".join(map(str, ip)))
                ip = []
        else:
            if len(ip) == 4:
                ips.append(".".join(map(str, ip)))
            ip = []

    return remove_duplicates_with_order(ips)



def main():
    vocab_size = 260
    max_len = 12032
    model_path = '/home/zyc/project/NEST/new/code/ip_generator/parameters/ip_generator.pt'
    device = 'cuda:0' if torch.cuda.is_available() else 'cpu'

    # Create the output folder if it doesn't exist
    output_folder = '/home/zyc/project/NEST/new/experiments/ip_generator/output'
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Create the model instance
    model = get_model(num_tokens=vocab_size, max_len=max_len)

    model.load_state_dict(torch.load(model_path, map_location=device))
    model = model.to(device)
    model.eval()

    # Generate and save 1000 results
    for i in range(1):
        inp = [256]
        inp = torch.tensor(inp).long().to(device)
        GENERATE_LENGTH = max_len
        sample = model.module.generate(inp, GENERATE_LENGTH, eos_token=256)

        # Restore IPs from bytes
        ips = restore_ip_from_bytes(sample)

        # Save the result as a .pkl file
        filename = os.path.join(output_folder, f'result_{i}.pkl')
        with open(filename, 'wb') as f:
            print(ips)
            pickle.dump(ips, f)

        print(f"Generated and saved result {i}")

    return


if __name__ == "__main__":
    main()