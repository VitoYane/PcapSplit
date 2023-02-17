from scapy.all import *
from fire import Fire
from os import walk, path, makedirs
import string
import re
from collections import defaultdict

def walk_dir(root_dir, ext_list = ['.pcap', '.pcapng']):
    # root_dir = f"\\\?\\{root_dir}".replace('/','\\')  # 解决长路径报错

    for root, dirs, files in walk(root_dir):
        # root 表示当前正在访问的文件夹路径
        # dirs 表示该文件夹下的子目录名list
        # files 表示该文件夹下的文件list

        # 遍历文件
        for f in files:
            if path.splitext(f)[-1] in ext_list:
                yield path.join(root, f)

        # 遍历所有的文件夹
        for d in dirs:
            walk_dir(path.join(root, d))    # 子目录

def extract_printable_data(pcap_file, output_file):
    # 从 Pcap 文件中读取数据包
    packets = rdpcap(pcap_file)

    # 获取 ASCII 可打印字符集
    printable_chars = set(string.printable)

    # 打开输出文件，准备写入 printable 内容
    with open(output_file, "w") as f:
        # 遍历每个数据包
        for packet in packets:
            # 检查数据包是否为 TCP 协议，并且包含 Raw 层
            if TCP in packet and Raw in packet:
                # 检查端口号是否为 HTTP
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    try:
                        # 提取 HTTP 报文的 printable 内容
                        http_data = packet[Raw].load.decode("utf-8")
                        printable_data = ''.join(filter(lambda x: x in printable_chars, http_data))
                        
                        # 替换连续的两个换行符为一个
                        printable_data = re.sub('[\r\n]{1,3}', '\n', printable_data)

                        # 将 printable 内容写入输出文件
                        f.write(printable_data + "\n\n\n")
                    except:
                        # 如果无法解码为 utf-8，则跳过此数据包
                        continue




def main(out_dir = 'pcap_split'):
    # split_pcap_by_session_A(pcap_file, output_dir=out_dir)
    for rf in walk_dir(out_dir):
        rftxt = rf.replace('.pcap', '.txt')
        print(f"deal {rf} to {rftxt}")
        extract_printable_data(rf, rftxt)
    
    # extract_printable_data("stream5.pcap", "result-5.txt")





if __name__ == '__main__':
    Fire(main)