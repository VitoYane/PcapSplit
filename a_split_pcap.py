import os, re
from threadpool import ThreadPool, makeRequests
import time, random



def deal_result(request, result):
    print('.', end='', flush=1)
    
def split_pcap_by_session_D(pcap_file, output_dir, max_streams, thread_pool_num=32):
    # Make sure the output directory exists
    os.makedirs(output_dir, exist_ok=True)
    print('start split')
    
    pool = ThreadPool(thread_pool_num)
    # Execute the tshark command for each stream and write the results to a new pcap file
    cmd_list = []
    for stream in range(max_streams):
        max_len = len(str(abs(max_streams)))
        output_file = os.path.join(output_dir, f"tcp.stream eq {stream:0{max_len}}.pcap")
        cmd = f"tshark -2 -R 'tcp.stream eq {stream}' -r {pcap_file} -w '{output_file}'"
        cmd_list.append(([cmd], None))
    reqs = makeRequests(RunCmd, cmd_list, deal_result)
    [pool.putRequest(req) for req in reqs]
    pool.wait()

def RunCmd(command, pattern = ''):
    '''运行cmd命令,没有pattern返回命令行返回内容，有pattern返回数组
    [+] command：要执行的命令
    [-] pattern：提取关键内容
    '''
    ret = os.popen(command).read()
    if pattern != '' :
        ret = re.findall(pattern,ret,re.I|re.S)
    return ret

def get_max_stream_num(pcap_file):
    # 使用 tshark 获取最大会话数
    cmd = f"tshark -r '{pcap_file}' -T fields -e tcp.stream | sort -n | tail -1"
    ret = RunCmd(cmd, '\d+')
    if ret:return int(ret[0])
    else: return 999999

def main(pcap_file, output_dir='pcaps'):
    max_stream = get_max_stream_num(pcap_file)
    print(f"max_stream => |{max_stream}| {type(max_stream)}")
    split_pcap_by_session_D(pcap_file, output_dir, max_stream)

from fire import Fire
if __name__ == '__main__':
    Fire(main)
    
