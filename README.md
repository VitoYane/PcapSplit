# PcapSplit
PcapSplit

### 依赖库
``` pip install -r requirements.txt ```

### 解包
``` python3 a_split_pcap.py 原始pcap文件 解包目录 ```

可以将大的pcap文件, 使用tshark命令按照会话提取为单个pcap文件.
因为调用的tshark程序, 速度较慢


### 提取明文
``` python3 b_get_http.py 待提取的pcap文件目录 ```

会遍历目录下所有pcap文件, 转化成明文txt文件

### 提取明文
``` python3 c_get_result.py 待判断的pcap文件目录 ```

会遍历目录下所有txt文件, 提交到ChatGPT的接口进行攻击判断

![image](https://user-images.githubusercontent.com/17432059/221515617-df2ab5d8-d862-489a-b509-81c0e495cf0f.png)
