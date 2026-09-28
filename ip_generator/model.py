import torch
import torch.nn as nn
from dataset import PcapDataset,collate_fn
from torch.utils.data import Dataset, DataLoader
import random
import numpy as np
from torch.autograd import Variable
import math
import torch.nn.functional as F
from linear_attention_transformer import LinearAttentionTransformerLM
from myautowrapper import AutoregressiveWrapper



def get_model(num_tokens, max_len):

    model = LinearAttentionTransformerLM(
        num_tokens = num_tokens,
        dim = 256,
        heads = 8,
        depth = 32,
        max_seq_len = max_len,
        causal = True,                  # auto-regressive or not
        ff_dropout = 0.1,               # dropout for feedforward
        attn_layer_dropout = 0.1,       # dropout right after self-attention layer
        attn_dropout = 0.1,             # dropout post-attention
        emb_dim = 256,                  # embedding factorization, to save on memory
        dim_head = 64,                 # be able to fix the dimension of each head, making it independent of the embedding dimension and the number of heads
        blindspot_size = 64,            # this gives the q(kv) attention a blindspot of 64 tokens back in the causal case, but gives back an order of magnitude return in memory savings. should be paired with local attention of at least a window size of this setting. setting this to 1 will allow for full q(kv) attention of past
        n_local_attn_heads = 8,         # number of local attention heads for (qk)v attention. this can be a tuple specifying the exact number of local attention heads at that depth
        local_attn_window_size = 128,   # receptive field of the local attention
        reversible = True,              # use reversible nets, from Reformer paper
        ff_chunks = 2,                  # feedforward chunking, from Reformer paper
        ff_glu = True,                  # use GLU variant for feedforward
        attend_axially = True,         # will fold the sequence by the local attention window size, and do an extra strided attention followed by a feedforward with the cheap q(kv) attention
        shift_tokens = True             # add single token shifting, for great improved convergence
    )

    model = AutoregressiveWrapper(model)

    model = nn.DataParallel(model)

    return model



def test():
    device = 'cuda:0' if torch.cuda.is_available() else 'cpu'

    max_len = 256
    x = [256 for _ in range(max_len)]
    x = torch.tensor(x).long().to(device)
    x = x[None,:]
    print('x.shape', x.shape)

     # 创建模型实例
    model = get_model(num_tokens = 260, max_len = max_len).to(device)

    loss = model(x)
    loss.mean().backward()
    print(loss.mean().item())



def main():
    max_len = 256
    dataset = PcapDataset('./flow_output', max_length=max_len)

    batch_size = 1
    dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True, collate_fn=collate_fn)

     # 创建模型实例
    model = get_model(num_tokens = 260, max_len = max_len)

    for batch in dataloader:
        batch = batch[:,:128]
        print('batch',batch.shape)
        loss = model(batch)
        loss.mean().backward()
        print(loss.mean().item())
        break



if __name__ == "__main__":
    test()
    #main()

    
    














