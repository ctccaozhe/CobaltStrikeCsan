import os
import re
import time

import requests
import threading
from queue import Queue


get_ip_regex = r"((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}"  # 获取ip的正则
cs_port = "50050"

regCount = 0  # 队列最大容量
workQueue = Queue(maxsize=regCount)
threads = 230  # 线程个数
bots = []  # 线程对象

queueLock = threading.Lock()

class ScanCsThread(threading.Thread):
    def __init__(self, type):
        threading.Thread.__init__(self)
        print("启动线程%s" % type)
        self.type = type

    def run(self):
        while True:
            if workQueue.qsize() != 0:
                queueLock.acquire()
                ip = workQueue.get()
                queueLock.release()
                # print("线程%s开始扫描,IP: %s！" % (self.type, ip))
                cmd = "nmap -p %s --script ssl-cert %s" % (cs_port, ip)
                r = os.popen(cmd)
                text = str(r.read())
                if "Cobalt".upper() in text.upper():
                    print("疑似CS服务器IP: %s！" % ip)
                    with open('cs_server', 'a') as f:
                        f.write("疑似CS服务器IP: %s！\n" % ip)
                else:
                    ssl_ports = ["80", "443", "8080", "8443", "6666"]
                    for port in ssl_ports:
                        agreements = ["http", "https"]
                        for agreement in agreements:
                            cmd = "python3.9 ./CobaltStrikeParser/parse_beacon_config.py %s://%s:%s/" % (agreement, ip, port)
                            r = os.popen(cmd)
                            text = str(r.read())
                            if "PublicKey_MD5" in text:
                                with open('cs_server', 'a') as f:
                                    f.write("发现配置文件，疑似CS服务器IP: %s！\n" % ip)
                                print("发现配置文件疑似CS服务器IP: %s://%s:%s/" % (agreement, ip, port))
                            print(text)
                print("线程%s结束扫描,剩余%s,IP: %s！" % (self.type, workQueue.qsize(), ip))
            else:
                print("队列无数据，扫描完成，退出线程！")
                break
        exit(0)


if __name__ == '__main__':
    print("准备开始扫描!")
    type_page = 0
    with open("./scan9.txt", 'r+') as f:
        first_line = f.readlines()
    for ip_list in first_line:
        matches = re.search(get_ip_regex, ip_list)
        if matches:
            tmp_ip = matches.group()
            workQueue.put(tmp_ip)
    del tmp_ip, first_line, ip_list
    print("队列入库完成!")
    print("正在启动线程!")
    with open('cs_server', 'w') as f:
        f.write('run_cs_scan\n')

    for i in range(0, threads):
        thread = ScanCsThread(str(i))
        bots.append(thread)
        thread.start()
        # time.sleep(0.5)

    # 线程保护
    # i = i + 1
    # while True:
    #     # time.sleep(10)
    #     if workQueue.qsize() == 0:
    #         print("扫描完成，退出程序")
    #         break
    #     elif len(threading.enumerate()) != threads + 4:
    #         print("有线程挂了，补充线程")
    #         thread = ScanCsThread(str(i+1))
    #         bots.append(thread)
    #         thread.start()
