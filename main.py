import doipsimu.doipserver as doipserver
from doipsimu.doipclient import DoIPSocket, UdsOverDoIP

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
uds.open_extended_session()

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
    if uds.write_did(0x1234, b"HELLO, WORLD!") == 0:
        print("[+]成功通过$2E服务在0x1234写入HELLO WORLD")
        print("[+]通过$22服务读取0x1234", uds.read_did(0x1234))
    else:
        print("[+]$2E服务写入失败")
else:
    print("[-]进入27服务失败")

# 退出扩展会话
uds.exit_extended_session()

# 停止网关仿真
gw.stop()