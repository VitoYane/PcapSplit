

from glob import glob
import openai, sys
from time import localtime, strftime
from threadpool import ThreadPool, makeRequests

all_req = 0
sign_req = 0


import openai
openai.api_key = "sk-Bew1dsFo3YX*****************1AkBHmY48ijxu" # 需要修改api_key
def get_answer(prompt, max_tokens):
    try:
        response = openai.Completion.create(
            model = "text-davinci-003",     # 模型名称
            prompt = prompt,                # 问题
            temperature = 0.7,              # 什么系数吧
            max_tokens = max_tokens,        # 返回内容的长度限制
            stream = False,                 # False就是一次性返回, True 就是一个个打出来像打字机, 返回的是迭代器, 需要后面代码处理. 此处没有处理 所以用False
            top_p = 1,                      # 未知
            frequency_penalty = 0,          # 频率限制?
            presence_penalty = 0            # 字数限制? 
        )
        return 0, response['choices'][0]['text'].strip()    # 获取返回值关键返回内容
    except Exception as e:                  # 异常处理
        return str(e), None

def anyone_in_str(_list, _str):
    '''判断列表中任意一个元素在不在字符串中'''
    return any(_one in _str for _one in _list)

def str_in_anyone(_str, _list):
    '''判断字符串在不在列表中任意一个元素中'''
    return any(_str in _one for _one in _list)

def all_in_str(_list, _str):
    '''判断列表中全部元素是否都在字符串中'''
    return all(_one in _str for _one in _list)

def str_in_all(_str, _list):
    '''判断字符串在所有元素中'''
    return all(_str in _one for _one in _list)



def err_retry(func=None, *args, **kwds):
    '''第一个参数必须是err, 本函数根据err判断重试'''
    in_type_listA = lambda data, type_list: any(isinstance(data, t) for t in type_list)
    n = kwds.pop('n', 3)
    try:
        for _ in range(n):
            ret = func(*args, **kwds)
            if in_type_listA(ret, [list, tuple]): err = ret[0] if ret else 1
            elif in_type_listA(ret, [dict]): err = ret.get('err', 1)
            else: err = ret
            if not err: break
    except Exception as e:
        print(e)
    return ret

from os import walk, path
def walk_dir(root_dir, ext_list = ['.txt']):
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


def read_fileA(filePath, ret_type = 'list'):
    '''无错读文件，返回可选list,str '''
    from chardet import detect
    with open(filePath, 'ab+') as f:
        f.seek(0, 0); content = f.read()
        code = detect(content)['encoding']
        code = code or 'latin1'
        ret = content.decode(code, 'ignore')
        if ret_type == 'list':
            f.seek(0, 0)
            ret = list(map(lambda x: x.decode(code, 'ignore').strip(), f.readlines()))
        return ret

def read_fileB(file_obj, ret_type = 'list'):
    '''无错读文件，输入文件对象, 返回可选list,str '''
    from chardet import detect
    file_obj.seek(0, 0); content = file_obj.read()
    code = detect(content)['encoding']
    code = code or 'latin1'
    ret = content.decode(code, 'ignore')
    if ret_type == 'list':
        file_obj.seek(0, 0)
        ret = list(map(lambda x: x.decode(code, 'ignore').strip(), file_obj.readlines()))
    return ret

def judge_attack(key_content, rf_rst):
    try:
        # Does this request contain any attacks?
        No = ['不存在攻击行为','未发现', '没有可疑的攻击行为', 'does not contain any attacks']
        Yes = ['存在攻击行为', '有可能存在攻击行为','是的','this request contains an attack']
        
        question = f'这个请求存在攻击行为吗?\n{key_content}'
        # print(f"\n\nquestion => |{question}|")
        answer_len = 4000 - len(question)
        err, response = err_retry(get_answer, question, answer_len, n=3)
        # print(f"\nresponse => |{response}|")
        if len(response) > 5:
            with open(rf_rst, 'w', encoding='utf-8') as wf:
                wf.writelines(response)
    
            if anyone_in_str(No, response):
                return 0, 0, response[:response.find('，')]
            elif anyone_in_str(Yes, response):
                return 0, 1, response[:response.find('，')]
            else:
                return 0, 0, response[:response.find('，')]
        else:
            return 1, 0, ''
    
    except Exception as e:
        print(e)
        return 1, 0, ''
    

def deal_result(request, result):
    global sign_req, all_req
    err, sign, disc = result
    if sign: sign_req += 1
    print(f"\r检出率: {sign_req/all_req:0.2%}")


def main(read_dir = 'pcap_split', thread_pool_num = 1, f = 0):
    args = []
    global sign_req, all_req
    pool = ThreadPool(thread_pool_num)
    for rf in walk_dir(read_dir, ['.txt']):
        if '-result.txt' in rf: continue
        all_req += 1
        rf_rst = rf.replace('.txt', '-result.txt')
        content = read_fileA(rf, 'str')[:2048]
        key_content = content.split('\r\n\r\n\r\n')[0][:1024]
        if len(key_content) < 10: continue
        
        err, sign, disc = judge_attack(key_content, rf_rst)
        if sign: sign_req += 1

        print('\r' + f' 已检测 {all_req: 4} 个报文, 识别到攻击 {sign_req} 个, 检出率: {sign_req/all_req:0.2%}', end='', flush=True)
        
    #     args.append(([key_content, rf_rst], None))
    #     all_req += 1
    #     reqs = makeRequests(judge_attack, args, deal_result)
    
    # [pool.putRequest(req) for req in reqs]
    # pool.wait()


from fire import Fire
if __name__ == '__main__':
    Fire(main)

