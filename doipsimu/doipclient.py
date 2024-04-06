import socket
import time
from typing import Tuple, Callable, Optional
import scapy.contrib.automotive.doip
from scapy.supersocket import StreamSocket
from scapy.contrib.automotive import doip
from scapy.contrib.automotive import uds
import threading

class DoIPSocket(scapy.contrib.automotive.doip.DoIPSocket):
    def __init__(
        self,
        ip: str = "127.0.0.1",
        port: int = 13400,
        activate_routing: bool = True,
        source_address: int = 3712,
        target_address: int = 0,
        activation_type: int = 0,
        reserved_oem: bytes = b"",
        timeout: float = 0.05,
    ) -> None:
        """
        创建DoIP会话
        :param ip: doip服务ip
        :param port: doip服务端口
        :param activate_routing: 是否路由激活
        :param source_address: 源地址
        :param target_address: 目的地址
        :param activation_type: 激活类型
        :param reserved_oem: 厂商保留
        :param timeout: 超时时间
        """
        self.cr_my_timeout = timeout
        super().__init__(
            ip,
            port,
            activate_routing,
            source_address,
            target_address,
            activation_type,
            reserved_oem,
        )

    def _init_socket(self, sock_family=socket.AF_INET):
        """
        覆盖scapy doip类的初始化socket的方法, 在此设置socket超时时间
        :param sock_family:
        :return:
        """
        s = socket.socket(sock_family, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(self.cr_my_timeout)

        s.connect((self.ip, self.port))
        StreamSocket.__init__(self, s, doip.DoIP)

    def activate_routing(
        self,
        source_address: int,
        target_address: int,
        activation_type: int = 0,
        reserved_oem: bytes = b"",
    ) -> int:
        """
        激活路由
        :param source_address: 来源逻辑地址
        :param target_address: 目标逻辑地址
        :param activation_type: 激活类型
        :param reserved_oem: 厂商预留数据
        :return:
        """
        resp = self.sr1(
            doip.DoIP(
                payload_type=0x5,
                activation_type=activation_type,
                source_address=source_address,
                reserved_oem=reserved_oem,
            ),
            verbose=False,
            timeout=1,
        )
        if (
            resp
            and resp.payload_type == 0x6
            and resp.routing_activation_response == 0x10
        ):
            self.target_address = target_address or resp.logical_address_doip_entity
            # 激活成功
            return True
        else:
            return False


class UdsOverDoIP:
    def __init__(self, doip_socket: DoIPSocket):
        """
        基于DoIPSocket构建一个Uds会话
        :param doip_socket:
        """
        self.socket = doip_socket
        # 是否进入扩展会话
        self._extended = False
        # socket锁, 防止扩展会话维持的后台线程与主线程产生冲突
        self._sock_lock = threading.Lock()
        self._daemon = None

        self.negativeResponseCodes = {
            0x00: "positiveResponse",
            0x10: "generalReject",
            0x11: "serviceNotSupported",
            0x12: "subFunctionNotSupported",
            0x13: "incorrectMessageLengthOrInvalidFormat",
            0x14: "responseTooLong",
            0x20: "ISOSAEReserved",
            0x21: "busyRepeatRequest",
            0x22: "conditionsNotCorrect",
            0x23: "ISOSAEReserved",
            0x24: "requestSequenceError",
            0x25: "noResponseFromSubnetComponent",
            0x26: "failurePreventsExecutionOfRequestedAction",
            0x31: "requestOutOfRange",
            0x33: "securityAccessDenied",
            0x35: "invalidKey",
            0x36: "exceedNumberOfAttempts",
            0x37: "requiredTimeDelayNotExpired",
            0x3A: "secureDataVerificationFailed",
            0x70: "uploadDownloadNotAccepted",
            0x71: "transferDataSuspended",
            0x72: "generalProgrammingFailure",
            0x73: "wrongBlockSequenceCounter",
            0x78: "requestCorrectlyReceived-ResponsePending",
            0x7E: "subFunctionNotSupportedInActiveSession",
            0x7F: "serviceNotSupportedInActiveSession",
            0x80: "ISOSAEReserved",
            0x81: "rpmTooHigh",
            0x82: "rpmTooLow",
            0x83: "engineIsRunning",
            0x84: "engineIsNotRunning",
            0x85: "engineRunTimeTooLow",
            0x86: "temperatureTooHigh",
            0x87: "temperatureTooLow",
            0x88: "vehicleSpeedTooHigh",
            0x89: "vehicleSpeedTooLow",
            0x8A: "throttle/PedalTooHigh",
            0x8B: "throttle/PedalTooLow",
            0x8C: "transmissionRangeNotInNeutral",
            0x8D: "transmissionRangeNotInGear",
            0x8E: "ISOSAEReserved",
            0x8F: "brakeSwitch(es)NotClosed",
            0x90: "shifterLeverNotInPark",
            0x91: "torqueConverterClutchLocked",
            0x92: "voltageTooHigh",
            0x93: "voltageTooLow",
        }

        # uds诊断消息的doip头部包
        self._uds_base_pkt = doip.DoIP(
            payload_type=0x8001,
            source_address=self.socket.source_address,
            target_address=self.socket.target_address,
        )

    def __del__(self):
        # 退出扩展会话, 结束后台线程
        self._extended = False

    def __atomic_send(self, pkt):
        self._sock_lock.acquire()
        self.socket.send(pkt)
        self._sock_lock.release()

    def open_extended_session(
        self, diagnostic_session_type: int = 3
    ) -> Optional[int]:
        """
        进入并维持扩展会话
        :param diagnostic_session_type: 诊断会话类型
        :return: 返回0成功打开扩展会话, 返回非0打开失败
        """
        def __test_presenter():
            while self._extended:
                self.__atomic_send(self._uds_base_pkt / uds.UDS() / uds.UDS_TP(subFunction=0x80))
                time.sleep(0.2)

        # 如果已经进入扩展会话
        if self._extended:
            # 关闭现有的扩展会话线程, 重新分配线程锁
            self._extended = False
            self._daemon.join(timeout=3)
            self._sock_lock = threading.Lock()

        # 发送扩展会话进入请求
        pkt_extend = (
            self._uds_base_pkt
            / uds.UDS()
            / uds.UDS_DSC(diagnosticSessionType=diagnostic_session_type)
        )
        self.__atomic_send(pkt_extend)

        deadline = time.time() + 2
        while deadline >= time.time():
            resp = self.socket.recv()
            # resp.show()
            if resp is None:
                continue

            # 如果收到积极回复, 说明成功进入扩展会话
            if resp.haslayer(uds.UDS_DSCPR):
                # 开始后台扩展会话维持线程
                self._daemon = threading.Thread(
                    target=__test_presenter
                )
                self._extended = True
                self._daemon.start()
                return 0x0
            # 如果收到UDS消极回复, 回报错误原因
            elif (
                resp.haslayer(uds.UDS_NR) and resp[uds.UDS_NR].requestServiceId == 0x10
            ):
                return resp[uds.UDS_NR].negativeResponseCode

        return None

    def exit_extended_session(self) -> None:
        """退出扩展会话
        """
        self._extended = False
        self._daemon.join()

    def request_seed(self, security_access_type: int = 0x05) -> Optional[Tuple[bytes, int]]:
        """$27服务封装, 安全访问, 请求种子

        :param security_access_type: 安全访问类型, 该参数应该与调用send_key方法时的参数相同
        :return: (seed(bytes), error_code(int)) 或者 None, 为 None时表示超时未回复
        * 当error_code为0时, seed是请求所得种子
        * 当error_code为非0时, seed是b"", error_code取值含义见negativeResponseCode
        """
        pkt = self._uds_base_pkt / uds.UDS() / uds.UDS_SA(securityAccessType = security_access_type)
        
        self.__atomic_send(pkt)
        
        deadline = time.time() + 5

        while deadline >= time.time():
            
            try:
                resp = self.socket.recv()
            except TimeoutError:
                pass
            

            if resp is None:
                continue

            if resp.haslayer(uds.UDS_SAPR):
                if "securitySeed" in resp[uds.UDS_SAPR].fields.keys():
                    return resp[uds.UDS_SAPR].fields["securitySeed"], 0x0
            elif resp.haslayer(uds.UDS_NR):
                return b"", resp.negativeResponseCode
        
        return None

    def send_key(self, security_access_type: int = 0x05, key: bytes = b"") -> Optional[int]:
        """$27服务封装, 安全访问, 发送密钥

        :param security_access_type: 安全访问类型, 该参数应该与调用send_key方法时的参数相同
        :param key: 密钥, defaults to b""
        :return: 返回0时表示成功通过$27服务, 返回非0时表示失败, 具体含义见negativeResponseCode, 返回None表示超时未回复
        """
        pkt = self._uds_base_pkt / uds.UDS() / uds.UDS_SA(securityAccessType=security_access_type + 1, securityKey=key)
        
        self.__atomic_send(pkt)

        deadline = time.time() + 5
        while deadline >= time.time():
            
            try:
                resp = self.socket.recv()
            except TimeoutError:
                pass
            

            if resp is None:
                continue

            if resp.haslayer(uds.UDS_SAPR):
                if "securitySeed" not in resp[uds.UDS_SAPR].fields.keys():
                    return 0x0
            elif resp.haslayer(uds.UDS_NR):
                return resp.negativeResponseCode
        
        return None


    def read_did(self, did: int = 0xF190) -> Optional[Tuple[bytes, int]]:
        """$22服务的封装, ReadDataByIdentifier

        :param did: did
        :return: 当收到回复时, 返回(payload(bytes), error_code(int)), 当超时未收到回复时, 返回None
        * 当 error_code 为 0 时, 代表成功读取did
        * 当 error_code 为 非0 时, 代表出现错误, error_code定义见UDS协议的negativeResponseCode
        """

        pkt = self._uds_base_pkt / uds.UDS() / uds.UDS_RDBI(identifiers=[did])
        
        self.__atomic_send(pkt)
        

        deadline = time.time() + 5
        while deadline >= time.time():
            
            try:
                resp = self.socket.recv()
            except TimeoutError:
                pass
            

            if resp is None:
                continue
            
            if resp.haslayer(uds.UDS_RDBIPR):
                if resp[uds.UDS_RDBIPR].dataIdentifier == did:
                    # 成功读取, 0x0: Positive Response
                    return resp.getlayer(uds.UDS_RDBIPR).payload.original, 0x0
            elif resp.haslayer(uds.UDS_NR):
                if resp[uds.UDS_NR].requestServiceId == 0x22:
                    return b"", resp.negativeResponseCode

        return None

    def reset(self, reset_type: int = 0x1) -> Optional[int]:
        """$11服务封装, ECUReset

        :param reset_type: 重置类型, defaults to 0x1. 0x1是硬重置, 0x3是软重置
        :return: 
        * 为 0 , 表示重置成功
        * 非0 时, 表示重置失败, 取值含义见 negativeResponseCode
        * 为None时, 表示超时未回复
        """
        pkt = self._uds_base_pkt / uds.UDS() / uds.UDS_ER(resetType=reset_type)
        
        self.__atomic_send(pkt)
        

        deadline = time.time() + 5
        while deadline >= time.time():
            
            try:
                resp = self.socket.recv()
            except TimeoutError:
                pass
            

            if resp is None:
                continue

            if resp.haslayer(uds.UDS_ERPR):
                return 0x0
            elif resp.haslayer(uds.UDS_NR):
                return resp.negativeResponseCode
            

    def write_did(self, did: int = 0xF190, payload: bytes = b"") -> Optional[int]:
        """$2e服务的封装, WriteDataByIdentifier

        :param did: did
        :param payload: 写入数据
        :return: 当收到回复时, 返回 error_code(int), 当超时未收到回复时, 返回None
        * 当 error_code 为 0 时, 代表成功写入did
        * 当 error_code 为 非0 时, 代表出现错误, error_code定义见UDS协议的negativeResponseCode
        """

        pkt = self._uds_base_pkt / uds.UDS() / uds.UDS_WDBI(dataIdentifier=did)
        pkt.add_payload(payload)
        
        self.__atomic_send(pkt)
        

        deadline = time.time() + 5
        while deadline >= time.time():
            
            try:
                resp = self.socket.recv()
            except TimeoutError:
                pass
            

            if resp is None:
                continue

            uds.UDS_WDBIPR
            if resp.haslayer(uds.UDS_WDBIPR):
                if resp[uds.UDS_WDBIPR].dataIdentifier == did:
                    # 成功读取, 0x0: Positive Response
                    return 0x0
            elif resp.haslayer(uds.UDS_NR):
                if resp[uds.UDS_NR].requestServiceId == 0x2E:
                    return resp.negativeResponseCode

        return None

    
    def routing_control(self, rid: int, rc_type: int = 0x1, payload: bytes = b"") -> Optional[int]:
        """$31服务封装, RoutingControl

        :param rid: routing identifier
        :param rc_type: 控制类型, 1表示开启, 2表示停止, 3表示请求结果, defaults to 0x1
        :return: 为 0 时表示成功, 非 0 时表示失败, 具体含义见negativeResponseCode, 为None时表示超时未收到回复
        """
        pkt = self._uds_base_pkt / uds.UDS() / uds.UDS_RC(routineControlType=rc_type, routineIdentifier=rid) / payload
        
        self.__atomic_send(pkt)
        
        deadline = time.time() + 5
        while deadline >= time.time():
            
            try:
                resp = self.socket.recv()
            except TimeoutError:
                pass
            
            if resp is None:
                continue
            
            if resp.haslayer(uds.UDS_RCPR):
                return 0x0
            elif resp.haslayer(uds.UDS_NR):
                return resp.negativeResponseCode
        
        return None
    
    def erase_memory(self, addr: int, size: int, addr_len: int = 4, size_len: int = 4) -> Optional[int]:
        """擦除内存, 通过0xFF00 Routing完成
        
        :param addr: 内存地址
        :param size: 内存长度
        :param addr_len: 编码内存地址的字节数
        :param size_len: 编码内存长度的字节数
        :return: 为 0 时表示成功, 非 0 时表示失败, 为None表示超时未收到回复
        """
        return self.routing_control(0xFF00, 1, payload=addr.to_bytes(addr_len, "big") + size.to_bytes(size_len, "big"))
    
    def reprogramming(self, addr: int, size: int, data: bytes, callback: Callable, data_formatter: int = 0, addr_len: int = 4, size_len: int = 4):
        rd_layer = uds.UDS_RD(dataFormatIdentifier=data_formatter, memorySizeLen=size_len, memoryAddressLen=addr_len)
        if addr_len == 1:
            rd_layer.memoryAddress1 = addr
        elif addr_len == 2:
            rd_layer.memoryAddress2 = addr
        elif addr_len == 3:
            rd_layer.memoryAddress3 = addr
        elif addr_len == 4:
            rd_layer.memoryAddress4 = addr

        if size_len == 1:
            rd_layer.memorySize1 = size
        elif size_len == 2:
            rd_layer.memorySize2 = size
        elif size_len == 3:
            rd_layer.memorySize3 = size
        elif size_len == 4:
            rd_layer.memorySize4 = size
        
        pkt = self._uds_base_pkt / uds.UDS() / rd_layer
        self.__atomic_send(pkt)

        block_len = -1

        deadline = time.time() + 5
        while deadline >= time.time():
            
            try:
                resp = self.socket.recv()
            except TimeoutError:
                pass
            

            if resp is None:
                continue
            
            if resp.haslayer(uds.UDS_RDPR):
                block_len = int.from_bytes(resp[uds.UDS_RDPR].maxNumberOfBlockLength, "big")
                break
            elif resp.haslayer(uds.UDS_NR):
                return resp.negativeResponseCode
        
        if time.time() > deadline:
            return None
        # 进入下载请求
        seq = 1

        for i in range(0, len(data), block_len):
            buf = data[i : min(i + block_len, len(data))]
            pkt = self._uds_base_pkt / uds.UDS() / uds.UDS_TD(blockSequenceCounter=seq, transferRequestParameterRecord=buf)
            self.__atomic_send(pkt)

            deadline = time.time() + 5
            while deadline >= time.time():
                
                try:
                    resp = self.socket.recv()
                except TimeoutError:
                    pass
                
                if resp is None:
                    continue
                
                if resp.haslayer(uds.UDS_TDPR):
                    callback(0, seq, buf, i, block_len)

                    seq += 1
                    seq %= 0xFF

                    break
                elif resp.haslayer(uds.UDS_NR):
                    callback(resp.negativeResponseCode, seq, buf, i, block_len)
                    return resp.negativeResponseCode
            
            if time.time() >= deadline:
                return None
        
        pkt = self._uds_base_pkt / uds.UDS() / uds.UDS_RTE()
        self.__atomic_send(pkt)

        deadline = time.time() + 5
        while deadline >= time.time():
            
            try:
                resp = self.socket.recv()
            except TimeoutError:
                pass
            

            if resp is None:
                continue
            
            if resp.haslayer(uds.UDS_RTEPR) or resp[uds.UDS].service == 0x77:
                return 0
            elif resp.haslayer(uds.UDS_NR):
                return resp.negativeResponseCode

        return None
    
    def get_flash(self, addr: int, size: int, callback: Callable = None, data_formatter: int = 0, addr_len: int = 4, size_len: int = 4):
        rd_layer = uds.UDS_RU(dataFormatIdentifier=data_formatter, memorySizeLen=size_len, memoryAddressLen=addr_len)
        if addr_len == 1:
            rd_layer.memoryAddress1 = addr
        elif addr_len == 2:
            rd_layer.memoryAddress2 = addr
        elif addr_len == 3:
            rd_layer.memoryAddress3 = addr
        elif addr_len == 4:
            rd_layer.memoryAddress4 = addr

        if size_len == 1:
            rd_layer.memorySize1 = size
        elif size_len == 2:
            rd_layer.memorySize2 = size
        elif size_len == 3:
            rd_layer.memorySize3 = size
        elif size_len == 4:
            rd_layer.memorySize4 = size
        
        pkt = self._uds_base_pkt / uds.UDS() / rd_layer
        self.__atomic_send(pkt)

        block_len = -1

        deadline = time.time() + 5
        while deadline >= time.time():
            
            try:
                resp = self.socket.recv()
            except TimeoutError:
                pass
            

            if resp is None:
                continue
            
            if resp.haslayer(uds.UDS_RUPR):
                block_len = int.from_bytes(resp[uds.UDS_RUPR].maxNumberOfBlockLength, "big")
                break
            elif resp.haslayer(uds.UDS_NR):
                return resp.negativeResponseCode
        if time.time() > deadline:
            return None
        # 进入上传请求
        seq = 1

        read_buf = b""

        flag = True
        while flag:
            # 不断读取block, 直到request out of range
            
            pkt = self._uds_base_pkt / uds.UDS() / uds.UDS_TD(blockSequenceCounter=seq)

            self.__atomic_send(pkt)

            deadline = time.time() + 5
            while deadline >= time.time():
                try:
                    resp = self.socket.recv()
                except TimeoutError:
                    pass
                

                if resp is None:
                    continue
                
                if resp.haslayer(uds.UDS_TDPR):
                    if callback is not None:
                        callback(0, seq, resp[uds.UDS_TDPR].transferResponseParameterRecord, len(read_buf), block_len)
                    
                    read_buf += resp[uds.UDS_TDPR].transferResponseParameterRecord
                    break
                elif resp.haslayer(uds.UDS_NR):
                    
                    flag = False
                    break

            seq += 1
            seq %= 0xFF

        # 如果正确读取完所有内存
        if len(read_buf) == size and resp.negativeResponseCode == 0x31:
            return read_buf
        else:
            return resp.negativeResponseCode
        