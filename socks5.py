# -*- coding:utf-8 -*-

import logging
import select
import socket
import struct
import sys
import random
from socketserver import StreamRequestHandler, ThreadingTCPServer

Log_Format = "%(levelname)s %(asctime)s - %(message)s"
logging.basicConfig(filename = "/root/log.log",filemode = "w", format = Log_Format, level=logging.DEBUG)
SOCKS_VERSION = 5
ips = []

class SocksProxy(StreamRequestHandler):
    username = sys.argv[2].split(":")[0]
    password = sys.argv[2].split(":")[1]
    def handle(self):
        logging.info('Accepting connection from %s:%s' % self.client_address)
        # 协商
        # 从客户端读取并解包两个字节的数据
        header = self.connection.recv(2)
        version, nmethods = struct.unpack("!BB", header)
        # 设置socks5协议，METHODS字段的数目大于0
        assert version == SOCKS_VERSION
        assert nmethods > 0
        # 接受支持的方法
        methods = self.get_available_methods(nmethods)
        # 检查是否支持用户名/密码认证方式，不支持则断开连接
        if 2 not in set(methods):
            self.server.close_request(self.request)
            return
        # 发送协商响应数据包
        self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 2))
        # 校验用户名和密码
        if not self.verify_credentials():
            return
        # 请求
        version, cmd, _, address_type = struct.unpack("!BBBB", self.connection.recv(4))
        assert version == SOCKS_VERSION
        if address_type == 1:  # IPv4
            address = socket.inet_ntoa(self.connection.recv(4))
        elif address_type == 3:  # 域名
            domain_length = self.connection.recv(1)[0]
            address = self.connection.recv(domain_length)
        elif address_type == 4: # IPv6
            addr_ip = self.connection.recv(16)
            address = socket.inet_ntop(socket.AF_INET6, addr_ip)
        else:
            self.server.close_request(self.request)
            return
        port = struct.unpack('!H', self.connection.recv(2))[0]
        # 响应，只支持CONNECT请求
        try:
            if cmd == 1:  # CONNECT
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ip = random.choice(ips)
                logging.info('Choice ip %s' % ip)
                remote.bind((ip,0))
                remote.connect((address, port))
                bind_address = remote.getsockname()
                logging.info('Connected to %s %s' % (address, port))
            else:
                self.server.close_request(self.request)
            addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
            port = bind_address[1]
            reply = struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, 1, addr, port)
        except Exception as err:
            logging.error(err)
            # 响应拒绝连接的错误
            reply = self.generate_failed_reply(address_type, 5)
        self.connection.sendall(reply)
        # 建立连接成功，开始交换数据
        if reply[1] == 0 and cmd == 1:
            self.exchange_loop(self.connection, remote)
        self.server.close_request(self.request)
    def get_available_methods(self, n):
        methods = []
        for i in range(n):
            methods.append(ord(self.connection.recv(1)))
        return methods
    def verify_credentials(self):
        """校验用户名和密码"""
        version = ord(self.connection.recv(1))
        assert version == 1
        username_len = ord(self.connection.recv(1))
        username = self.connection.recv(username_len).decode('utf-8')
        password_len = ord(self.connection.recv(1))
        password = self.connection.recv(password_len).decode('utf-8')
        if username == self.username and password == self.password:
            # 验证成功, status = 0
            response = struct.pack("!BB", version, 0)
            self.connection.sendall(response)
            return True
        # 验证失败, status != 0
        response = struct.pack("!BB", version, 0xFF)
        self.connection.sendall(response)
        self.server.close_request(self.request)
        return False
    def generate_failed_reply(self, address_type, error_number):
        return struct.pack("!BBBBIH", SOCKS_VERSION, error_number, 0, address_type, 0, 0)
    def exchange_loop(self, client, remote):
        while True:
            # 等待数据
            r, w, e = select.select([client, remote], [], [])
            if client in r:
                data = client.recv(4096)
                if remote.send(data) <= 0:
                    break
            if remote in r:
                data = remote.recv(4096)
                if client.send(data) <= 0:
                    break

if __name__ == '__main__':
    port = int(sys.argv[1])
    ips = sys.argv[3].split(",")
    # 使用socketserver库的多线程服务器ThreadingTCPServer启动代理
    with ThreadingTCPServer(('0.0.0.0', port), SocksProxy) as server:
        server.serve_forever()