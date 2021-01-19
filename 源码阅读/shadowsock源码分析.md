##　说明
用于分析shadowsocksr的源码

##　local服务器分析
初始化阶段
``` py
# 入口函数
if __name__ == '__main__':
    main()

# 读取配置
shell.get_config(True)
# 根据local值判断是读取的本机的配置信息，还是远程server的配置信息
shortopts = 'hd:s:b:p:k:l:m:O:o:G:g:c:t:vq'　# 本机的opt
shortopts = 'hd:s:p:k:m:O:o:G:g:c:t:vq' #　远程server的opt
``` 

前置配置阶段基本完成，起daemon，判断当前服务是否唯一
``` py
# 根据配置执行daemon
daemon.daemon_exec(config)

# 注册处理函数
signal.signal(signal.SIGINT, handle_exit)
signal.signal(signal.SIGTERM, handle_exit)

# 检查lock信息
fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 0, 0, os.SEEK_SET)
```

正式起tcp服务
``` py
# 传入config，开启tcp监听
tcp_server = tcprelay.TCPRelay(config, dns_resolver, True)

#　判断是local server
listen_addr = config['local_address']
listen_port = config['local_port']

# 开启本地监听
server_socket = socket.socket(af, socktype, proto)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind(sa)
server_socket.listen(config.get('max_connect', 1024))

## 保存socket信息
self._server_socket = server_socket　　　               # 保存socket
self._server_socket_fd = server_socket.fileno()        # 保存文件描述符
```

完成本地socket监听后，将其放在select里面共同监听，本质上实现跨平台的一步
``` py
# 加入loop
tcp_server.add_to_loop(loop)

# 保存本地loop，并将socket加入loop的select监听
self._eventloop = loop
self._eventloop.add(self._server_socket,eventloop.POLL_IN | eventloop.POLL_ERR, self)

fd = f.fileno()                     
self._fdmap[fd] = (f, handler)  # 保存本地为handler，方便后期调用TCPRelay::handle_event
self._impl.register(fd, mode)   # 跨平台的关键步骤

# 实际的跨平台是因为采用了不同的select
        if hasattr(select, 'epoll'):
            self._impl = select.epoll()
            model = 'epoll'
        elif hasattr(select, 'kqueue'):
            self._impl = KqueueLoop()
            model = 'kqueue'
        elif hasattr(select, 'select'):
            self._impl = SelectLoop()
            model = 'select'

# 可以看到SelectLoop::register，将fd添加到select监听列表
    def register(self, fd, mode):
        if mode & POLL_IN:
            self._r_list.add(fd)
        if mode & POLL_OUT:
            self._w_list.add(fd)
        if mode & POLL_ERR:
            self._x_list.add(fd)
```

完成上述操作后，已经在本地监听了本地的local端口，接下来处理监听信息
``` py
# 设置进程为user
daemon.set_user(config.get('user', None))
pwrec = pwd.getpwnam(username)
os.setuid(uid)

# 配置完成之后，启动run
loop.run()

# 开始poll查看是否有socket返回
events = self.poll(TIMEOUT_PRECISION)

# 取得event信息，调用回调函数TCPRelay::handle_event
for sock, fd, event in events:
    handle = handler.handle_event(sock, fd, event) or handle

# 对返回的socket比对处理，当前分析流程为_server_socket，即local server监听接口到网络信息流
# accept socket
conn = self._server_socket.accept()
# 创建remote server连接
handler = TCPRelayHandler(self, self._fd_to_handlers,self._eventloop, conn[0], self._config,self._dns_resolver, self._is_local) 
self._server = server                                            # 保存TCPRelay为一个server
self._fd_to_handlers = fd_to_handlers                            # 保存handler
self._local_sock = local_sock                                    # 本地accept socket
self._client_address = local_sock.getpeername()[:2]              # 本地发出访问的端口的socket信息
self._accept_address = local_sock.getsockname()[:2]              # 本地监听端口的socket信息
self._update_tcp_mss(local_sock)                                 # 调整报文mtu

server_info.host = config['server']                              # 远程代理服务器host
server_info.port = server._listen_port                           # 远程代理服务器端口
server_info.client = self._client_address[0]                     # 本地发出访问的端口的ip信息
server_info.client_port = self._client_address[1]                # 本地发出访问的端口的端口信息
self._redir_list = config.get('redirect', ["*#0.0.0.0:0"])       # 未知
self._protocol.set_server_info(server_info)                      # 用于加解密头
self._chosen_server = self._get_a_server()                       # 如果是local则获取一个server
self._update_activity()                                          # 暂时不管
local_sock.setblocking(False)                                    # 设置不阻塞
local_sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)     # 设置不使用Nagle
self._local_sock_fd = local_sock.fileno()                        # 保存文件描述符
fd_to_handlers[self._local_sock_fd] = self                       # 将自己保存到handler字典
loop.add(local_sock, eventloop.POLL_IN | eventloop.POLL_ERR, self._server)  　# 保存local_sock到loop，注册事件处理函数为TCPRelay::handle_event
```

处理accept socket的返回
``` py
# 处理accept socket回调函数
handler = self._fd_to_handlers.get(fd, None)                     # 从_fd_to_handlers保存的accept socket取出保存的TCPRelayHandler
handle = handler.handle_event(sock, fd, event)                   # 调用TCPRelayHandler::handle_event
elif fd == self._local_sock_fd:                                  # 指定为accept socket
elif event & (eventloop.POLL_IN | eventloop.POLL_HUP):           # 本地为监听本地信息到达
self._on_local_read()                                            # 读取本地data
data = self._local_sock.recv(recv_buffer_size)                   # 读取accept socket信息
ogn_data = data　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　# 保存data
elif is_local and self._stage == STAGE_INIT:
self._write_to_sock(b'\x05\00', self._local_sock)
self._stage = STAGE_ADDR
```

回写local socket
``` py
if data:
l = len(data)
s = sock.send(data)                                              # 发送'\x05\00'回本地


```



obfs解析
``` py
# 创建TCPRelayHandler::obfs
self._obfs = obfs.obfs(config['obfs'])
self._protocol = obfs.obfs(config['protocol'])

# 从method_support的map中读取method_info
self.method = method
self._method_info = self.get_method_info(method)                 # 例如返回class http_simple(plain.plain):
self.obfs = self.get_obfs(method)                                # 如果存在多个method，取出第一个
self._protocol.set_server_info(server_info)                      # 保存server_info值，方法在基类plain中

# 字典
method_supported = {}
method_supported.update(plain.obfs_map)
method_supported.update(http_simple.obfs_map)
method_supported.update(obfs_tls.obfs_map)
method_supported.update(verify.obfs_map)
method_supported.update(auth.obfs_map)
method_supported.update(auth_chain.obfs_map)

# 以http_simple为例
obfs_map = {
        'http_simple': (create_http_simple_obfs,),
        'http_simple_compatible': (create_http_simple_obfs,),
        'http_post': (create_http_post_obfs,),
        'http_post_compatible': (create_http_post_obfs,),
        'random_head': (create_random_head_obfs,),
        'random_head_compatible': (create_random_head_obfs,),
}

# 返回http_simple头文件加密类
def create_http_simple_obfs(method):
    return http_simple(method)

```