from functools import partial
import torch
from torch import nn
import torch.nn.functional as F
from torch.nn.utils.rnn import pad_sequence
from tqdm import tqdm

from linear_attention_transformer.autopadder import Autopadder

def top_p(logits, thres = 0.9):
    sorted_logits, sorted_indices = torch.sort(logits, descending=True)
    cum_probs = torch.cumsum(F.softmax(sorted_logits, dim=-1), dim=-1)

    sorted_indices_to_remove = cum_probs > (1 - thres)
    sorted_indices_to_remove[:, 1:] = sorted_indices_to_remove[:, :-1].clone()
    sorted_indices_to_remove[:, 0] = 0

    sorted_logits[sorted_indices_to_remove] = float('-inf')
    return sorted_logits.scatter(1, sorted_indices, sorted_logits)

def top_k(logits, thres = 0.9):
    k = int((1 - thres) * logits.shape[-1])
    val, ind = torch.topk(logits, k)
    probs = torch.full_like(logits, float('-inf'))
    probs.scatter_(1, ind, val)
    return probs

def split_and_concat_withhead(x, max_seq_len):
    # 获取batch和length
    batch_size, length = x.size()

    if length < max_seq_len:
        return x
        
    # 计算切割长度
    split_length = length - max_seq_len 

    # 创建一个列表来存储切割后的tensor
    split_tensors = []

    for batch_idx in range(batch_size):
        # 找到切割起始点和结束点的索引
        start_idx = None
        end_idx = None
        for i in range(length-1, -1, -1):
            if x[batch_idx, i] == 259:
                start_idx = i + 1
                break
        if start_idx is None:
            start_idx = 0

        for i in range(start_idx, length):
            if x[batch_idx, i] == 256:
                end_idx = i
                break
        if end_idx is None:
            end_idx = length

        # 切割tensor并拼接
        split_tensor = torch.cat([x[batch_idx, :end_idx+1], x[batch_idx, end_idx +1+ split_length:]], dim=0)

        split_tensors.append(split_tensor)

    # 将切割后的tensor拼接成一个tensor
    return torch.stack(split_tensors, dim=0).to(x.device)

class AutoregressiveWrapper(nn.Module):
    def __init__(self, net, ignore_index = 258, pad_value = 258):
        super().__init__()
        self.pad_value = pad_value
        self.ignore_index = ignore_index

        self.net = Autopadder(net)
        self.max_seq_len = net.max_seq_len

    @torch.no_grad()
    def generate(self, start_tokens, seq_len, eos_token = None, temperature = 1., filter_logits_fn = top_k, filter_thres = 0.9, **kwargs):
        was_training = self.net.training
        num_dims = len(start_tokens.shape)

        if num_dims == 1:
            start_tokens = start_tokens[None, :]

        b, t = start_tokens.shape

        self.net.eval()
        out = start_tokens

        desc = 'Generating' + str(start_tokens.device)
        for _ in tqdm(range(seq_len), desc=desc):
            x = split_and_concat_withhead(out, self.max_seq_len)
            logits = self.net(x, **kwargs)
            logits = logits[:,:x.shape[1],:]
            logits = logits[:, -1, :]
            filtered_logits = filter_logits_fn(logits, thres = filter_thres)
            probs = F.softmax(filtered_logits / temperature, dim=-1)
            sample = torch.multinomial(probs, 1)

            out = torch.cat((out, sample), dim=-1)

            if eos_token is not None and (sample == eos_token).all():
                break

        out = out[:, t:]

        if num_dims == 1:
            out = out.squeeze(0)

        self.net.train(was_training)
        return out

    def forward(self, x, return_loss = True, **kwargs):
        pad = partial(pad_sequence, batch_first = True, padding_value = self.pad_value)

        if not return_loss:
            if not isinstance(x, torch.Tensor):
                x = pad(x)
            return self.net(x, **kwargs)

        if isinstance(x, torch.Tensor):
            xi = x[:, :-1]
            xo = x[:, 1:]

            # help auto-solve an area of confusion around input masks in auto-regressive
            # if user supplies a mask that is only off by one from the source sequence, resolve it for them
            mask = kwargs.pop('input_mask', None)
            if mask is not None and mask.shape[1] == x.shape[1]:
                mask = mask[:, :-1]
                kwargs.update(input_mask = mask)
        else:
            xi = pad(list(map(lambda t: t[:-1], x)))
            xo = pad(list(map(lambda t: t[1:], x)))

        out = self.net(xi, **kwargs)

        # 找出开始点, 遍历每个批次
        loss = 0
        for i_batch in range(xo.shape[0]):
            idx = (xo[i_batch] == 256).nonzero(as_tuple=False)
            if len(idx) == 0:
                print('error loss', xo.shape, xo[i_batch][-10:])
                idx = [xo.shape[1]-1]
            idx = idx[0]
            loss += F.cross_entropy(out[i_batch][idx:], xo[i_batch][idx:], ignore_index = self.ignore_index, reduction='sum') / xo.shape[0] / self.max_seq_len

        return loss




