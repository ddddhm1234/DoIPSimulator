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

uds.open_extended_session()

for i in range(4):
    seed, code = uds.request_seed()
    if code == 0:
        print("第 %d 次请求成功, %s" % (i, str(seed)))
    else:
        print("第 %d 次请求失败, %s" % (i, uds.negativeResponseCodes[code]))

uds.exit_extended_session()


# 停止网关仿真
gw.stop()


