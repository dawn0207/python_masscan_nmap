# python_masscan_nmap
通过python调取masscan扫描开放端口，然后通过nmap对端口服务和版本进行确认，最终输出表格

脚本运行之前，确保安装了masscan,nmap并存在于系统环境中。

通过pip install -r requirement.txt安装脚本运行需要模块。

将需要扫描IP保存到ip.txt文件中，运行python scan_index.py，最终获得Result.xls结果表。
