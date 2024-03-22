import doipsimu.doipserver as doipserver
from doipsimu.doipclient import DoIPSocket, UdsOverDoIP

def my_callback(code, seq, buf, cur, block_len):
    if code == 0:
        print(f"[+] 第 {seq} 轮写入成功")
    else:
        print(f"[+] 第 {seq} 轮写入失败")

# 创建doip网关
gw = doipserver.DoIPGateway(protocol_version=2)

# 在doip网关中添加ecu节点, 设置逻辑地址以及PINCODE
ecu1 = doipserver.DoIPNode(logical_address=0x0e80, pincode=b"2345")
ecu2 = doipserver.DoIPNode(logical_address=0x1010, pincode=b"4321")
gw.add_node(ecu1)
gw.add_node(ecu2)

# 启动网关仿真
gw.start()


# 开始尝试诊断仿真的网关
ds = DoIPSocket(source_address=0x1010, target_address=0x0e80)
uds = UdsOverDoIP(ds)

# 进入扩展会话
uds.open_extended_session(diagnostic_session_type=2)

# 请求种子
o = uds.request_seed()
while o is None:
    o = uds.request_seed()
seed, code = o
print("[+]请求到种子", seed)
key = doipserver.DoIPNode.calc_key(seed, b"2345")
print("[+]根据种子计算密钥", key)
if uds.send_key(key=key) == 0:
    print("[+]成功进入27服务")
    
    if (code := uds.erase_memory(0x1000, 0x3000)) == 0:
        print("[+] 成功擦除内存 0x1000 - 0x3000 的内存")
    else:
        print("[+] 擦除内存失败", uds.negativeResponseCodes[code])

    
    if (code := uds.reprogramming(0x1000, 0x3000, b"\x00" * 0x2000, my_callback)) == 0:
        print("[+] 向0x1000 - 0x3000刷写全0成功")
    else:
        print("[+] 向0x1000 - 0x3000刷写全0失败")

    if (code := uds.reset(1)) == 0:
        print("[+] 重置ECU成功")
    else:
        print("[+] 重置ECU失败")

    ret = uds.get_flash(0x1000, 0x2000)
    if isinstance(ret, bytes) and all(b == 0 for b in ret):
        print("[+] 成功读取0x1000 - 0x3000内存, 且为全0, 证明成功刷写")
    else:
        print("[-] 内存写入失败或读取失败")


else:
    print("[-]进入27服务失败")

# 退出扩展会话
uds.exit_extended_session()

# 停止网关仿真
gw.stop()