import nmap
def easyscan(ip):
    try:
        print("WAİTİNG >>>>>>>>>")
        nm = nmap.PortScanner()
        scane =nm.scan(ip+"/24", '22-443')
        ips = nm.all_hosts()
        for i in ips:
            print("ip : " + i+"\tmac: "+scane["scan"][i]['addresses']['mac'])
    except KeyError:
        pass
def portscan(ip2):
    nm = nmap.PortScanner()
    nm.scan(ip2)
    protocols = nm[ip2].all_protocols()

    unique_ports = set()
    print("Opened ports: ")

    for protocol in protocols:
        ports = list(nm[ip2][protocol].keys())
        for p in ports:
            keys = nm[ip2][protocol][p]

            key_value_pairs = [f"{k}: {v}" for k, v in keys.items()]
            key_value_str = ", ".join(key_value_pairs)  # Listeyi birleştir


            unique_ports.add((p, protocol, key_value_str))

    for p, proto, kv_str in unique_ports:
        print(f"port: {p} | protocol: {proto} | details: {kv_str}")

try :
    while True :
        print("""
        WHAT DO YOU WANT
        1) LAN SCAN
        2) PORT SCAN
        3) EXİT
        """)
        chs = input("I want:")
        if chs == "1" or chs == "lan scan" or chs == "LAN SCAN" or chs == "lanscan" :
            md = input("give me ip: ")
            easyscan(md)
        elif chs == "2" or chs == "port scan" or chs == "PORT SCAN" or chs == "portscan" or chs == "porscan":
            di = input("give target İP: ")
            portscan(di)
        elif chs == "3" or chs == "exit" or chs == "exıt" or chs == "EXİT" or chs == "EXIT":
            exit()
        else:
            print("wtf bro")
except KeyboardInterrupt:
    print("\nSEE YOU LATER BRO")