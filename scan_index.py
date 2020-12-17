#coding:utf-8
#用作masscan+nmap扫描
#author: the_dawn
#git: https://github.com/dawn0207/python_masscan_nmap

import masscan
import threading
import nmap
import xlwt
    
class Scan:
    def __init__(self):
        self.sem = threading.Semaphore(10) # 限制线程的最大数量为100个
        self.res=[]     #标记表格计数
        self.workbook = xlwt.Workbook(encoding='utf-8') # 创建一个workbook 设置编码
        self.worksheet = self.workbook.add_sheet('结果', cell_overwrite_ok=True) # 创建一个worksheet
        self.worksheet.write(0,0,"IP地址")
        self.worksheet.write(0, 1, "端口")
        self.worksheet.write(0, 2, "协议")
        self.worksheet.write(0, 3, "版本")
        host_list_ip=[] #获取扫描IP地址
        ip=open('ip.txt','r')
        for i in ip:
            i=i.replace("\n","")
            if i=="":
                pass
            else:
                host_list_ip.append(i.replace("\n",""))
        t=[]  #线程保存数组
        for ip in host_list_ip: #将扫描加入masscan线程中
            thread=threading.Thread(target=self.server_scan, args=(ip,))
            t.append(thread)
        for x in t:
            x.start()
        for x in t:
            x.join()
        self.workbook.save('Result.xls') #结果保存表
        
    def server_scan(self,ip):
        result={}
        with self.sem:
            try: #masscan扫描
                mas = masscan.PortScanner()
                mas.scan(ip,ports='1-65535',arguments='--max-rate 100')#masscan发包率设置为1000
                result=mas.scan_result['scan']
            except Exception as e:
                print("错误信息: "+str(e))
                return
            
            try: #处理扫描结果
                p=''
                for resu in result.values():
                    for port in resu['tcp'].keys():
                        p=p+str(port)+','
                if port=="":
                    return
                else:
                	self.nmap_scan(ip,p)
            except Exception as e:
                print(str(e))
                return
    def nmap_scan(self,ip,port): #nmap扫描
        try:
            nm = nmap.PortScanner()
            scan_result = nm.scan(hosts=ip, arguments='-sV -p '+port) #使用nmap扫描
            try:
                for result in scan_result['scan'].values():
                    for port in result['tcp'].keys():
                        if result['tcp'][port]['state']=='filtered': #消除过滤端口信息
                            pass
                        elif result['tcp'][port]['state']=='closed': #消除关闭端口信息
                            pass
                        else:
                            self.res.append(str(ip))
                            self.worksheet.write(len(self.res),0,str(ip))
                            self.worksheet.write(len(self.res),1,str(port))
                            self.worksheet.write(len(self.res),2,result['tcp'][port]['name'])
                            self.worksheet.write(len(self.res),3,result['tcp'][port]['version'])
            except Exception as e:
                print(str(e))
        except Exception as e:
            print(str(e))
if __name__=='__main__':
    Scan()