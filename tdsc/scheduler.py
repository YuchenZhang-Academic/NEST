
from dataset import pcaplinktype_decoder_class
from model import get_model
import torch
import torch.nn as nn

from scapy.all import *
import struct
import ipaddress
import copy
import math


def closest_ip(ip_list, target_ip):
    target_ip = ipaddress.ip_address(target_ip)
    closest = None
    min_distance = float('inf')

    for ip in ip_list:
        ip = ipaddress.ip_address(ip)
        distance = abs(int(ip) - int(target_ip))
        if distance < min_distance:
            min_distance = distance
            closest = ip

    return str(closest)

def cal_header(iplist, myip, start_time):
    header = [259]
    header.extend(list(struct.pack('>d', start_time)))

    ip_nome = [ip for ip in iplist if not ip == myip][:200]
    ip_all = [myip] + ip_nome

    for ip in ip_all:
        header.append(259)
        for i in ip.split('.'):
            header.append(int(i))
    header.append(256)

    return header


def get_time_and_ip_from_ptoken(token_list):
    if len(token_list) < 20:
        print('error nextk', token_list)
        return None, None, None
    
    if token_list[0] == 256:
        token_list = token_list[1:]
    
    link_type = token_list[0]
    packet_class = pcaplinktype_decoder_class(link_type)
    token_list = token_list[1:]

    content = token_list[:8]
    content = [min(c, 255) for c in content]
    dt = struct.unpack('>d', bytes(content))[0]
    dt = max(dt, 0)
    token_list = token_list[8:]

    current_packet = b''
    for byte in token_list:
        byte = min(byte, 255)
        current_packet += bytes([byte])

    try:
        packet = packet_class(current_packet)
    except:
        print('error nextk', token_list)
        return None, None, None

    if IP in packet:
        src = packet['IP'].src
        dst = packet['IP'].dst
    else:
        print('error nextk', token_list)
        return None, None, None

    return dt, src, dst



def change_token_ip(token_list, src, dst):
    if token_list[0] == 256:
        token_list = token_list[1:]
    
    link_type = token_list[0]
    packet_class = pcaplinktype_decoder_class(link_type)
    token_list = token_list[1:]

    time_content = token_list[:8]
    time_content = [min(c, 255) for c in time_content]
    token_list = token_list[8:]

    current_packet = b''
    for byte in token_list:
        byte = min(byte, 255)
        current_packet += bytes([byte])

    packet = packet_class(current_packet)
    
    packet['IP'].src = src
    packet['IP'].dst = dst
    print('src', src, 'dst', dst)

    # 变回token list
    rtlist = [256]
    rtlist.append(link_type)
    rtlist = rtlist + time_content
    rtlist = rtlist + list(bytes(packet))
    return rtlist



def gen_next_k_token(model, inp, k, device = 'cpu', eos_token = 257, eos_token2 = 257):
    inp = torch.tensor(inp).long().to(device)
    sample = model.module.generate(inp, k, eos_token = eos_token, eos_token2 = eos_token2)
    return sample.cpu().numpy()


def match_time(P, dt):
    outP = copy.deepcopy(P)
    outP = copy.deepcopy(P)
    if outP[0] == 256:
        outP = outP[1:]

    time_encoded = struct.pack('>d', dt)
    time_encoded = list(time_encoded)

    outP[1:9] = time_encoded
    return outP


def generate(model, ip_list, start_time, max_packet_num = 2, device = 'cpu', update_receiver=True, max_attempts=1000, events=None, on_packet=None):
    packet_list = []

    ip_content_dict = {}
    ip_last_time_dict = {}
    global_time = start_time
    for ip in ip_list:
        header = cal_header(ip_list, ip, start_time)
        ip_content_dict[ip] = header
        ip_last_time_dict[ip] = start_time

    '''
    对于每个ip地址，预测下面的8位（dT），以及通信的IP双方（后面k位）。
    对通信的IP双方取ip list的最近邻桶，确保不会生成奇怪的ip地址。
    然后根据dT的优先级排序，
    计算出最优先的ipx，对ipx进行数据包生成，记数据包为P。
    将P追加到ipx和ipx的通信对方   和  输出列表。
    然后重复上述过程。
    '''

    ip_next_content_dict = {}
    ip_next_dt_dict = {}
    sd_ip_dict = {}
    packet_num = 0
    attempts = 0
    while(True):
        if packet_num>=max_packet_num:
            break
        attempts += 1
        if attempts > max_attempts:
            raise RuntimeError('No complete output within scheduling attempt budget')
        #print('ip_next_content_dict.keys()',ip_next_content_dict.keys())
        #print('ip_next_dt_dict.keys()',ip_next_dt_dict.keys())
        print(packet_num, max_packet_num, '进度：', packet_num/max_packet_num)

        for key in ip_content_dict.keys():
            if key in ip_next_content_dict.keys():   # 没有受到干扰的节点不需要重新计算
                continue

            nextk = gen_next_k_token(model, inp = ip_content_dict[key], k = 38 +1 +8, device = device)
            dt, sip, dip = get_time_and_ip_from_ptoken(copy.deepcopy(nextk))
            if dt is None or not math.isfinite(dt) or sip is None or dip is None:
                # 忽略本ip地址的本次生成
                continue
            
            # 入桶，将ip和提供的输入ip进行对齐
            closekey = closest_ip([sip,dip], key)
            if str(closekey) == str(sip):
                sip = key
                ip_list_nome = [i for i in ip_list if not i == key]
                dip = closest_ip(ip_list_nome, dip)
            else:
                dip = key
                ip_list_nome = [i for i in ip_list if not i == key]
                sip = closest_ip(ip_list_nome, sip)
            # 将对齐后的ip替换nextk
            nextk = change_token_ip(copy.deepcopy(nextk), sip, dip)
            ip_next_content_dict[key] = nextk
            #print(key, nextk)
            sd_ip_dict[key] = [sip, dip]
            
            # 忽略src 不等于 IP视角的数据包。
            if key == sip:
                ip_next_dt_dict[key] = dt

        if len(ip_next_dt_dict.keys()) == 0:
            ip_next_content_dict = {}
            ip_next_dt_dict = {}
            continue  

        # 然后根据dT的优先级排序，
        def sort_by_dt(item):
            return item[1]  # 假设值 dt 在元组中是第二个元素
        # 按照值 dt 的优先级排序字典
        sorted_ip_next_dt = sorted(ip_next_dt_dict.items(), key=sort_by_dt)
        # 打印排序后的结果
        pkey = sorted_ip_next_dt[0][0]
        print('pkey', pkey)
        
        # 计算出最优先的pkey，对pkey进行数据包生成，记数据包为P。
        P = gen_next_k_token(model, inp = ip_content_dict[pkey] + ip_next_content_dict[pkey], k = 1600 , device = device,  eos_token = 256, eos_token2 = 257)
        if len(P) == 0 or P[-1] not in (256, 257):
            raise RuntimeError('Packet continuation reached token cap without a terminator')
        P = list(ip_next_content_dict[pkey]) + list(P)
        P[-1] = 256 # 拒绝257
        global_time += sorted_ip_next_dt[0][1]

        token_list = copy.deepcopy(P)
        if token_list[0] == 256:
            token_list = token_list[1:]
        link_type = token_list[0]
        packet_class = pcaplinktype_decoder_class(link_type)
        token_list = token_list[1 + 8:-1] # type token + time token : end token]

        try:
            packet = packet_class(bytes(token_list))
            packet.time = global_time
            packet_list.append(packet)
        except:
            print('error packet', P)
            print(token_list)
            sip = sd_ip_dict[pkey][0]
            dip = sd_ip_dict[pkey][1]
            # 错误包删了，从头开始
            if sip in ip_next_content_dict.keys():
                del ip_next_content_dict[sip] 
            if dip in ip_next_content_dict.keys():
                del ip_next_content_dict[dip] 
            if sip in ip_next_dt_dict.keys():
                del ip_next_dt_dict[sip] 
            if dip in ip_next_dt_dict.keys():
                del ip_next_dt_dict[dip]
            continue

        # 将P追加到ipx和ipx的通信对方   和  输出列表。注意对齐时间
        sip = sd_ip_dict[pkey][0]
        dip = sd_ip_dict[pkey][1]
        P_sip = match_time(P, global_time - ip_last_time_dict[sip])
        P_dip = match_time(P, global_time - ip_last_time_dict[dip])
        ip_content_dict[sip] = ip_content_dict[sip] + P_sip
        if update_receiver:
            ip_content_dict[dip] = ip_content_dict[dip] + P_dip
        if events is not None:
            events.append(dict(packet=packet_num, time=float(global_time), src=sip, dst=dip,
                               sender_tokens=len(ip_content_dict[sip]), receiver_tokens=len(ip_content_dict[dip]),
                               receiver_updated=update_receiver))

        if sip in ip_next_content_dict.keys():
            del ip_next_content_dict[sip] 
        if update_receiver and dip in ip_next_content_dict.keys():
            del ip_next_content_dict[dip] 

        if sip in ip_next_dt_dict.keys():
            del ip_next_dt_dict[sip] 
        if update_receiver and dip in ip_next_dt_dict.keys():
            del ip_next_dt_dict[dip]

        # 对齐时间2
        for key in ip_next_dt_dict:
            ip_next_dt_dict[key] -= sorted_ip_next_dt[0][1]

        ip_last_time_dict[sip] = global_time
        if update_receiver:
            ip_last_time_dict[dip] = global_time
        if on_packet is not None:
            on_packet(packet)
        
        packet_num += 1

    return packet_list



def main():
    ip_list = ['192.168.137.5', '8.8.8.8', '1.2.3.4','10.181.9.1']
    start_time = 1605012765.3969844 # 随便写

    vocab_size = 260
    max_len = 128* 1000
    model_path = '../../trace/code_128k/output/test_27.pt'
    device = 'cuda:0' if torch.cuda.is_available() else 'cpu'
    # 创建模型实例
    model = get_model(num_tokens = vocab_size, max_len = max_len)
    model.load_state_dict(torch.load(model_path, map_location=device))
    model.eval()

    packet_list = generate(model, ip_list, start_time, max_packet_num = 3, device = device)
    wrpcap('test.pcap', packet_list)


if __name__ == "__main__":
    main()











