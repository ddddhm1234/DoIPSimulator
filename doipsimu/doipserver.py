import threading
import random
import time
import socketserver
import logging
import socket
from scapy.contrib.automotive import doip, uds
from scapy.all import StreamSocket
from typing import Literal, Callable, Dict


class DoIPNode:
    """
    DoIP节点
    """
    @staticmethod
    def mk_nr(pkt: doip.DoIP, nr_code: int) -> doip.DoIP:
        """
        根据doip数据包产生NegativeRespone响应
        """
        sa = pkt.source_address
        ta = pkt.target_address
        resp = doip.DoIP(payload_type=0x8001, source_address=ta, target_address=sa) / uds.UDS() / uds.UDS_NR(
            requestServiceId=pkt[1].service,
            negativeResponseCode=nr_code
        )
        return resp

    @staticmethod
    def mk_pr(pkt: doip.DoIP, pr_payload) -> doip.DoIP:
        """
        根据doip数据包产生PositiveRespone响应,
        pr_payload需要根据不同的UDS Service产生, 由用户传入
        """
        sa = pkt.source_address
        ta = pkt.target_address
        resp = doip.DoIP(payload_type=0x8001, source_address=ta,
                         target_address=sa) / uds.UDS() / pr_payload
        return resp

    @staticmethod
    def calc_key(seed: bytes, pincode: bytes) -> bytes:
        key = []
        for i in range(4):
            key.append((seed[i] ^ pincode[i] + 32) % 0xFF)

        return bytes(key)

    def __init__(self, logical_address=0x0e80, data: Dict = None, key_algorithm: Callable = None, pincode: bytes = b"1234",
                 seed_len=4) -> None:
        # 节点逻辑地址
        self.addr = logical_address
        # 节点DID数据项
        if isinstance(data, dict):
            self.data = data
        elif data is None:
            self.data = {
                0xF190: b"VIN_CHENGRUI_HACK",
                0x0001: b"Hu.Jiacheng",
                0x0002: b"Wang.Zhiyi",
                0x0003: b"Zhang.Chengao",
                0x0004: b"Cheng.Rui",
                0x0005: b"Lian.Xiaowu"
            }
        else:
            raise ValueError("data must be a dict")

        # 安全访问算法, PINCODE, 随机种子长度
        if key_algorithm is None:
            key_algorithm = DoIPNode.calc_key

        self.key_algorithm = key_algorithm
        self.pincode = pincode
        self.seed_len = seed_len

        self.uds_handler = {}
        self.add_uds_handler(uds.UDS_RDBI, self.read_did)
        self.add_uds_handler(uds.UDS_SA, self.security_access)
        self.add_uds_handler(uds.UDS_DSC, self.diagnostic_session_control)
        self.add_uds_handler(uds.UDS_TP, self.tester_present)
        self.add_uds_handler(uds.UDS_WDBI, self.write_did)

        self.add_uds_handler(uds.UDS_CC, self.comm_control)

    def add_uds_handler(self, uds_service: uds.Packet, handler: Callable):
        self.uds_handler[uds_service] = handler

    def remove_uds_handler(self, uds_service: uds.Packet):
        if uds_service in self.uds_handler.keys():
            del self.uds_handler[uds_service]

    def comm_control(self, pkt: doip.DoIP, session: Dict) -> doip.DoIP:
        # 一直返回PositiveRespone
        resp = self.mk_pr(pkt, uds.UDS_CCPR(controlType=pkt[2].controlType))
        return resp

    def routing_control(self, pkt: doip.DoIP, session: Dict) -> doip.DoIP:
        sf = pkt[2].subFunction

    def tester_present(self, pkt: doip.DoIP, session: Dict) -> doip.DoIP:
        sf = pkt[2].subFunction
        if sf == 0x80:
            if "session_type" in session.keys():
                if session["session_deadline"] < time.time():
                    # 如果当前会话已经结束, 返回0x7E subFunctionNotSupportedInActiveSession
                    resp = self.mk_nr(pkt, 0x7E)
                else:
                    # 延长当前会话1s
                    session["session_deadline"] = time.time() + 1
                    resp = self.mk_pr(pkt, uds.UDS_TPPR())
            else:
                # 如果当前尚未进入扩展会话, 返回0x12 subFunctionNotSupported
                resp = self.mk_nr(pkt, 0x12)
        else:
            resp = self.mk_nr(pkt, 0x7E)

        return resp

    def diagnostic_session_control(self, pkt: doip.DoIP, session: Dict) -> doip.DoIP:
        # 扩展会话类型
        stype = pkt[2].diagnosticSessionType

        # 当前扩展会话类型
        session["session_type"] = stype
        # 当前扩展会话结束时间, 发送TP可以延长扩展会话时间
        session["session_deadline"] = time.time() + 3

        resp = self.mk_pr(pkt, uds.UDS_DSCPR(
            diagnosticSessionType=pkt[2].diagnosticSessionType
        ))
        return resp

    def security_access(self, pkt: doip.DoIP, session: Dict) -> doip.DoIP:
        sat = pkt.securityAccessType

        calc_key = self.key_algorithm
        pincode = self.pincode

        if session.get("session_type", 0) != 3 or session.get("session_deadline", 0) < time.time():
            # 如果当前未进入扩展会话或扩展会话已经过期, 返回0x7F serviceNotSupportedInActiveSession
            resp = self.mk_nr(pkt, 0x7F)
            return resp

        if sat % 2 == 1:
            # 如果是请求种子
            # 产生随机数种子
            session["seed"] = random.randbytes(self.seed_len)

            # 返回种子

            resp = self.mk_pr(pkt, uds.UDS_SAPR(
                securityAccessType=pkt[2].securityAccessType,
                securitySeed=session["seed"]
            ))
        else:
            # 如果是发送key
            if "seed" not in session.keys():
                # 如果seed字段不在session上下文中, 说明没有请求种子就发送key了, 返回0x35 invalidkey
                resp = self.mk_nr(pkt, 0x35)
            else:
                key = calc_key(session["seed"], pincode)
                if key == pkt[2].securityKey:
                    # 如果key正确, 成功进入27服务
                    resp = self.mk_pr(pkt, uds.UDS_SAPR(
                        securityAccessType=pkt[2].securityAccessType
                    ))
                    # 记录成功通过安全访问
                    session["sa_type"] = pkt[2].securityAccessType
                else:
                    # 如果key不正确, 返回0x35 invalidkey
                    resp = self.mk_nr(pkt, 0x35)

        return resp

    def write_did(self, pkt: doip.DoIP, session: Dict) -> doip.DoIP:
        # 对$2e服务的封装, WriteDataByIdentifier
        data = self.data
        if session.get("sa_type", -1) != -1 and session.get("session_deadline", 0) >= time.time():
            # 只有成功通过安全访问并且安全访问会话没有过期才有权限写入
            did = pkt[2].dataIdentifier
            raw = pkt[3]
            data[did] = raw
            resp = self.mk_pr(pkt, uds.UDS_WDBIPR(dataIdentifier=did))
        else:
            # 否则, 返回 0x7F ServiceNotSupportedInActiveSession
            resp = self.mk_nr(pkt, 0x7F)

        return resp

    def read_did(self, pkt: doip.DoIP, session: Dict) -> doip.DoIP:
        # 对$22服务的封装, ReadDataByIdentifier
        data = self.data
        dids = pkt.identifiers

        if len(dids) > 0:
            did = dids[0]
        else:
            # 如果payload中没有请求读取的did, 返回0x13 incorrectMessageLengthOrInvalidFormat
            resp = self.mk_nr(pkt, 0x13)
            return resp

        if did in data.keys():
            resp = self.mk_pr(pkt, uds.UDS_RDBIPR(
                dataIdentifier=did) / data[did])
        else:
            # 如果did不在data中, 返回 RequestOutOfRange
            resp = self.mk_nr(pkt, 0x31)
        return resp


class DoIPGateway:
    """
    DoIP网关
    """

    def __init__(self, protocol_version: Literal[2, 3] = 2, bind_port: int = 13400,
                 bind_address: str = "0.0.0.0",
                 log_level=logging.WARNING) -> None:
        # 设置DoIP协议版本号
        self.version = protocol_version
        # payload的处理handler
        self.payload_handlers = {
            "tcp": {},
            "udp": {}
        }

        # 添加路由激活处理handler
        self.add_payload_handler(0x5, self.routing_activate, "tcp")
        # 添加诊断消息处理handler
        self.add_payload_handler(0x8001, self.diagnostic_message, "tcp")

        # DoIP网关绑定端口, 地址
        self.bind_port = bind_port
        self.bind_address = bind_address

        # 设置logger
        logger = logging.getLogger(__name__)
        c_handler = logging.StreamHandler()
        c_handler.setLevel(log_level)
        c_format = logging.Formatter('%(name)s : %(levelname)s : %(message)s')
        c_handler.setFormatter(c_format)
        logger.addHandler(c_handler)
        self.logger = logger

        # doip节点
        self.nodes = {}

    def start(self):
        class MyTCPHandler(socketserver.StreamRequestHandler):
            def setup(o) -> None:
                return super().setup()

            def handle(o) -> None:
                o.request: socket.socket
                o.request.settimeout(0.5)
                sock = StreamSocket(o.request, doip.DoIP)
                # 当前连接上下文集合
                session = {}
                # 初始化当前连接与各个节点的session
                for node_addr, node in self.nodes.items():
                    session[node_addr] = {}

                while not self.stop_flag:
                    try:
                        pkt = sock.recv()
                    except TimeoutError:
                        continue
                    if pkt is None:
                        break
                    # 如果是DoIP数据包
                    if pkt.haslayer(doip.DoIP):
                        payload_type = pkt[doip.DoIP].fields["payload_type"]
                        self.logger.info(
                            "RECV a DoIP message with payload_type == %d" % (payload_type, ))
                        if payload_type in self.payload_handlers["tcp"].keys():
                            # 调用payload对应的payload
                            self.logger.info("Call payload handler %s" % (
                                self.payload_handlers["tcp"][payload_type].__name__))
                            resp = self.payload_handlers["tcp"][payload_type](
                                pkt, session)
                            resp: doip.DoIP
                            # 发送返回数据包
                            self.logger.info("ANSWER with %s" %
                                             (resp.summary(), ))
                            sock.send(resp)

            def finish(o) -> None:
                return super().finish()

        socketserver.ThreadingTCPServer.allow_reuse_address = True
        tcp_server = socketserver.ThreadingTCPServer(
            (self.bind_address, self.bind_port), MyTCPHandler)
        self.tcp_server = tcp_server
        th = threading.Thread(target=tcp_server.serve_forever, daemon=True)
        self.stop_flag = False
        th.start()

    def stop(self):
        self.stop_flag = True
        self.tcp_server.shutdown()

    def add_node(self, node: DoIPNode):
        self.nodes[node.addr] = node

    def diagnostic_message(self, pkt: doip.DoIP, session: Dict) -> doip.DoIP:
        if session.get("active", False):
            # 如果已经完成路由激活
            ta = pkt.fields["target_address"]
            sa = pkt.fields["source_address"]
            # 如果目标地址不在doip网络中
            if ta not in self.nodes.keys():
                # 返回未知目标地址 NACK_CODE
                resp = doip.DoIP(payload_type=0x8003,
                                 nack_code=0x03, target_address=sa)
                return resp

            node = self.nodes[ta]
            node: DoIPNode
            # DoIP -> UDS -> UDS服务, 因此取第2层
            uds_clz = pkt.layers()[2]
            if uds_clz in node.uds_handler.keys():
                # 如果存在处理该UDS服务的handler
                handler = node.uds_handler[uds_clz]
                resp = handler(pkt, session[ta])
            else:
                # 如果不存在处理该UDS服务的handler
                # 返回serviceNotSupported
                resp = doip.DoIP(payload_type=0x8003, nack_code=0x03, target_address=sa, source_address=ta) / uds.UDS() / uds.UDS_NR(negativeResponseCode=0x11,
                                                                                                                                     requestServiceId=0x0)

        else:
            # 没有完成路由激活返回不合法的来源地址 NACK_CODE
            resp = doip.DoIP(payload_type=0x8003, nack_code=0x02)

        return resp

    def routing_activate(self, pkt: doip.DoIP, session: Dict) -> doip.DoIP:
        sa = pkt.fields["source_address"]
        # 如果源地址在DoIP网络节点中
        if sa in self.nodes.keys():
            resp = doip.DoIP(payload_type=6, target_address=sa,
                             routing_activation_response=0x10)
            # 设置当前连接会话状态, 已经成功完成路由激活
            session["active"] = True

        else:
            resp = doip.DoIP(payload_type=6, routing_activation_response=0x0)
            session["active"] = False

        return resp

    def add_payload_handler(self, payload_type: int, handler: Callable,
                            protocol: Literal["tcp", "udp", "all"]):
        if protocol == "tcp":
            self.payload_handlers["tcp"][payload_type] = handler
        elif protocol == "udp":
            self.payload_handlers["udp"][payload_type] = handler
        elif protocol == "all":
            self.payload_handlers["tcp"][payload_type] = handler
            self.payload_handlers["udp"][payload_type] = handler

    def remove_payload_handler(self, payload_type: int):
        if payload_type in self.payload_handlers["udp"].keys():
            del self.payload_handlers["udp"][payload_type]

        if payload_type in self.payload_handlers["tcp"].keys():
            del self.payload_handlers["tcp"][payload_type]
