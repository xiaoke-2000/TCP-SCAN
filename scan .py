# -*- coding: utf-8 -*-
import threading  # 导入threading包
import datetime
from socket import *
import re

thread = []#线程列表
openNum = 0#处于开放状态的端口数，默认为0
A_port = []#主机存活的端口列表

#TCP connecct()扫描
def PortScaner(host,port):
    global openNum
    s = socket(AF_INET, SOCK_STREAM)  # 创建套接字
    s.settimeout(0.1)#设置socket连接超时，避免socket重复操作
    try:
        s.connect((host,port))
        print('[+]The port %s is open\n' % (port))
        openNum += 1#如果socket连接成功，openNum加1
        A_port.append(port)#讲该端口号添加到主机存活的端口列表中
    except:
        pass   #连接失败
    s.close()

# 利用正则表达式匹配host，判断是否符合IP地址的格式 同时输入不能为空
def ChecK_Host(host):  
    compile_ip = re.compile(
        '^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$')
    if compile_ip.match(host) and len(host) != 0:  # host符合IP地址的格式且不为空值返回True，否则返回False
        return True
    else:
        return False

 #保存扫描结果
def Save_Data(): 
    for i in range(len(A_port)):
        d =str(A_port[i])
        data = open('Active_Port.txt', 'a')
        data.write(d+'\n')
        data.close()

def main():
    hostname = input('please input a valid IP address:')
    host = gethostbyname(hostname)#将给定的主机名解释为一个IP地址
    start = int(input('input start port:'))#起始端口
    end = int(input('input end port:'))#结束端口
    if ChecK_Host(host) and len(host) != 0:
        # 获取开始时间
        Start_Time = datetime.datetime.now()  
        print('*' * 12 + '%s' % Start_Time + '*' * 12)
        print("   <===============Scanning start==============>")
        for port in range(start, end):
            # 创建一个线程，target为线程需要执行的函数，args为函数的参数
            t = threading.Thread(target=PortScaner, args=(host, port))  
            thread.append(t)  # 把线程保存到线程列表
        for t in range(len(thread)):  # 先获取thread线程列表的长度，遍历线程列表
            thread[t].start()  # 运行一个线程，即运行target指定的函数
        for t in range(len(thread)):
            thread[t].join()  # 表示当主进程中断时，所有的线程也会停止执行
        End_Time = datetime.datetime.now()  # 获取结束时间
        Time = End_Time - Start_Time  #得出扫描过程花费的时间
        print("   <===============Scanning start==============>")
        #输出端口扫描结束后的相关结果信息
        print('*' * 12 + '%s' % End_Time + '*' * 12)
        print('[*]The scanning process consumed %s second' % Time)
        print('[*]Scan results:'+'>'*10+'the target host %s opened %s ports in total'%(host,openNum))
        print('[*]%s is opening\n'%A_port)
        print('The scan results are saved to the Active_Port.txt!')
        try:
            Save_Data()
            print('>>>>Save Done!!!')#保存成功
        except:
            print('Save failed!!!')#保存失败
    else:
        #输入IP地址为空或不符合格式
        print('The IP address is invalid,Please input again!!!')
        main()#重新执行main()函数，实现输入错误则重新输入


if __name__ == '__main__':
    main()
