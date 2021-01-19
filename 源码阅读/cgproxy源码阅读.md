## 背景
用于记录cgproxy源码

## 阅读过程
``` cpp
// 进入主函数，以daemon启动为例
int main(int argc, char *argv[])
if (as_cgproxyd) ::CGPROXY::CGPROXYD::main(argc, argv);

// 检查uid是否为root启动
  if (getuid() != 0) {
    error("permission denied, need root");
    exit(EXIT_FAILURE);
  }

// 启动cgproxy进程
cgproxyd d
d.start()

// 判断是否为唯一进程
lock()

// 注册信号处理函数
    signal(SIGINT, &signalHandler);
    signal(SIGTERM, &signalHandler);
    signal(SIGHUP, &signalHandler);


// 指定全局instance为cgproxyd->this
assignStaticInstance()

// 读取config
config.loadFromFile(DEFAULT_CONFIG_FILE)
ifstream ifs(f)
string js = to_str(ifs.rdbuf())
loadFromJsonStr(js)
json j = json::parse(js)

// 读取使用代理和使用代理的应用名称
#define tryassign(v)                                                                     \
  try {                                                                                  \
    j.at(#v).get_to(v);                                                                  \
  } catch (exception & e) {}
#define merge(v)                                                                         \
  {                                                                                      \
    v.erase(std::remove(v.begin(), v.end(), v##_preserved), v.end());                    \
    v.insert(v.begin(), v##_preserved);                                                  \
  }
tryassign(program_proxy);


// 设置iptables信息
applyConfig()
// 清除自己的iptables
#define TPROXY_IPTABLS_CLEAN "@CMAKE_INSTALL_FULL_DATADIR@/cgproxy/scripts/cgroup-tproxy.sh stop"
system(TPROXY_IPTABLS_CLEAN)

// 设置环境变量
config.toEnv();
setenv("program_proxy", join2str(program_proxy, ':').c_str(), 1);
setenv("cgroup_proxy", join2str(cgroup_proxy, ':').c_str(), 1);

// 开启监听
if (enable_socketserver) startSocketListeningThread()
promise<void> status;
future<void> status_f = status.get_future();
// 起一个进程
thread th(SOCKET::startThread, handle_msg_static, move(status));


// 查看SocketServer::startThread函数
void SocketServer::socketListening(function<int(char *)> callback, promise<void> status)
sfd = socket(AF_UNIX, SOCK_STREAM, 0);
// 定义本机交互local socket
memset(&unix_socket, '\0', sizeof(struct sockaddr_un));
// 定义本机socket地址，并监听
strncpy(unix_socket.sun_path, SOCKET_PATH, sizeof(unix_socket.sun_path) - 1);
bind(sfd, (struct sockaddr *)&unix_socket, sizeof(struct sockaddr_un));
listen(sfd, LISTEN_BACKLOG);
chmod(SOCKET_PATH, S_IRWXU | S_IRWXG | S_IRWXO);

// 通知status.get_future()，不阻塞执行
status.set_value();

// 判断是否超时
future_status fstatus = status_f.wait_for(chrono::seconds(THREAD_TIMEOUT));

// 进入while监听消息
cfd = accept(sfd, NULL, NULL);
// 读取accept socket信息
flag = read(cfd, &msg_len, sizeof(int));

// 回调handle_msg_static，传入接收到accept socket消息，此处用socket实现进程间通信，执行各种操作，并将结果返回原进程
int status = callback(msg);
flag = write(cfd, &status, sizeof(int));
```

继续分析handle_msg_static代码
``` cpp
// 查看handle_msg_static代码，调用了cgproxyd::handle_msg，可知传入的信息为json格式的消息
instance->handle_msg(msg);
j = json::parse(msg);
// 判断类型
type = j.at("type").get<int>();
// 为config类型
case MSG_TYPE_CONFIG_JSON:
status = config.loadFromJsonStr(j.at("data").dump());          // 设置当前config，并设置环境变量
// 与上同，只不过是读取的文件
case MSG_TYPE_CONFIG_PATH:　
// 
case MSG_TYPE_PROXY_PID:
pid = j.at("data").get<int>();                                 // 获取pid
```

绑定pid的cgroup信息到指定cgroup
``` cpp
// 用于pid纳管cgroup信息
status = attach(pid, config.cgroup_proxy_preserved)
int attach(const string pid, const string cgroup_target)
if (!validate(pid, cgroup_target)) return_error;               // 判断当前是否pid是否为数字
// CGROUP_PROXY_PRESVERED定义为"/proxy.slice"
const string cgroup_proxy_preserved = CGROUP_PROXY_PRESVERED

// 查看mount point是否为空 CGROUP2_MOUNT_POINT "/var/run/cgproxy/cgroup2"
if (cgroup2_mount_point.empty()) return_error;
// 拼接字符串
string cgroup_target_path = cgroup2_mount_point + cgroup_target;
string cgroup_target_procs = cgroup_target_path + "/cgroup.procs";  // /var/run/cgproxy/cgroup2/proxy.slice/cgroup.procs
// 如果不存在 /var/run/cgproxy/cgroup2/proxy.slice"　则创建目录
mkdir(cgroup_target_path.c_str(),
              S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)


// cgroup限制
cg = getCgroup(pid)
string getCgroup(const string &pid)
ifstream ifs(cgroup_f);
if (line[0] == '0') 
// 获取用于纳管的slice模块　　/system.slice/NetworkManager.service
cgroup = line.substr(3);
// 检查pid的cgroup是否为输入的group
if (cg == cgroup_target) 
// 如果不存在则加入
if (write2procs(pid, cgroup_target_procs) != 0)
```

添加proxy_program列表
``` cpp
int write2procs(string pid, string procspath)
// 每次输入都输入到文件结尾
ofstream procs(procspath, ofstream::app);
// 将pid添加到/var/run/cgproxy/cgroup2/proxy.slice/cgroup.procs
procs << pid.c_str() << endl;
```

``` cpp
// 设置 no_proxy　列表，一样的方式
case MSG_TYPE_NOPROXY_PID:
#define CGROUP_NOPROXY_PRESVERED "/noproxy.slice"
```

执行监听转发
``` cpp
if (enable_execsnoop) startExecsnoopThread()

// 等待status
promise<void> status
future<void> status_f = status.get_future()

// 起线程
thread th(EXECSNOOP::startThread, handle_pid_static, move(status))
int execsnoop()
```

bpf内核代码注入函数块
``` cpp
auto init_res = bpf.init(BPF_PROGRAM)
// 建立一个系统调用
string execve_fnname = bpf.get_syscall_fnname("execve");
// 绑定系统调用
auto attach_res =
      bpf.attach_kprobe(execve_fnname, "ret_syscall_execve", 0, BPF_PROBE_RETURN)
// 注册回调函数从内核返回用户空间pid
auto open_res = bpf.open_perf_buffer("events", &handle_events)
// 释放空间
bpf.free_bcc_memory()
// 循环监听events
while (true) bpf.poll_perf_buffer("events")
```

查看当前CPU进程pid返回后做的事情
``` cpp
// 放开线程
status.set_value()
// 返回pid后，调用handle_pid_static,handle_pid_static调用cgproxyd::handle_pid
instance->handle_pid(pid);
// 获取proc路径
unique_ptr<char[], decltype(&free)> path(
        realpath(to_str("/proc/", pid, "/exe").c_str(), NULL), &free);
// 进入判断program_noproxy,获取pid的cgroup信息
string cg = getCgroup(pid)
// 下面还以proxy_program作为源码阅读，判断是否存在于
if (!belongToCgroup(cg, config.cgroup_proxy))
// 不存在则attach，函数上述已经描述过
int res = attach(pid, config.cgroup_proxy_preserved)
```

join线程
``` cpp
    if (socketserver_thread.joinable()) socketserver_thread.join();
    if (execsnoop_thread.joinable()) execsnoop_thread.join();
```
至此execsnoop-bcc和src目录源码全部读取完成
-----------------

## 接下来分析cgroup-tproxy.sh脚本
前置准备操作
``` sh
# 检查是否为root
[ ! $(id -u) -eq 0 ] && { >&2 echo "iptables: need root to modify iptables";exit -1; }
# 赋值cgroup_proxy为默认值
if [ -z ${cgroup_proxy+x} ]; then  
    cgroup_proxy="/proxy.slice"
# 指定默认端口为12345
[ -z ${port+x} ] && port=12345
# 默认gateway为false
enable_gateway=false
# 指定cgroup目录，默认为/sys/fs/cgroup/unified，此处可能是/var/run/cgproxy/cgroup2/
[ -z ${cgroup_mount_point+x} ] && cgroup_mount_point=$(findmnt -t cgroup2 -n -o TARGET | head -n 1)
# 检查长度是否为空
[ -z $cgroup_mount_point ] && { >&2 echo "iptables: no cgroup2 mount point available"; exit -1; }
# 检查是否/sys/fs/cgroup/unified存在，不存在则创建
[ ! -d $cgroup_mount_point ] && mkdir -p $cgroup_mount_point
# 检查/sys/fs/cgroup/unified/proxy.slice检查文件是否存在，不存在则创建，创建失败则结束
test -d $cgroup_mount_point$cgroup_proxy    || mkdir $cgroup_mount_point$cgroup_proxy   || exit -1; 
# 设置cgroup_proxy
_cgroup_proxy=()
for cg in ${cgroup_proxy[@]}; do         # 遍历/proxy.slice.../proxy1.slice:/proxy2.slice等
# 判断/sys/fs/cgroup/unified/proxy.slice是否存在，如果存在则添加/proxy.slice到_cgroup_proxy
test -d $cgroup_mount_point$cg && _cgroup_proxy+=($cg) || { >&2 echo "iptables: $cg not exist, ignore";}
# 确保目录都存在
unset cgroup_proxy && cgroup_proxy=${_cgroup_proxy[@]}
```

正式进入iptables配置
``` sh
# ip配置
ip rule add fwmark $fwmark_tproxy table $table_tproxy       # 标记了fwmark_tproxy0x9973的走路由表10007
ip route add local default dev lo table $table_tproxy       # table10007的回环到本地

# iptable新增Enter链　(PREROUTING)
iptables -w 60 -t mangle -N TPROXY_ENT
iptables -w 60 -t mangle -A TPROXY_ENT -m socket -j MARK --set-mark $fwmark_tproxy  # socket流量打上fwmark_tproxy0x9973标记
iptables -w 60 -t mangle -A TPROXY_ENT -m socket -j ACCEPT                          # socket
iptables -w 60 -t mangle -A TPROXY_ENT -p tcp -j TPROXY --on-ip 127.0.0.1 --on-port $port --tproxy-mark $fwmark_tproxy   # tcp流量转发到本地127.0.0.1:12345　并打上tproxy-mark0x9973
iptables -w 60 -t mangle -A TPROXY_ENT -p udp -j TPROXY --on-ip 127.0.0.1 --on-port $port --tproxy-mark $fwmark_tproxy   # udp流量转发到本地127.0.0.1:12345　并打上tproxy-mark0x9973

# iptables新增PRE链　(PREROUTING)
iptables -w 60 -t mangle -N TPROXY_PRE
iptables -w 60 -t mangle -A TPROXY_PRE -m addrtype --dst-type LOCAL -j RETURN       # 目标是本地的不处理，返回上个链
iptables -w 60 -t mangle -A TPROXY_PRE -m addrtype ! --dst-type UNICAST -j RETURN   # 广播的不处理
# gateway暂时忽略,转发DNS53端口和udp tcp数据到Enter，再被转发到本机端口
iptables -w 60 -t mangle -A TPROXY_PRE -p udp --dport 53 -j TPROXY_ENT 
$enable_udp && iptables -w 60 -t mangle -A TPROXY_PRE -p udp -j TPROXY_ENT
$enable_tcp && iptables -w 60 -t mangle -A TPROXY_PRE -p tcp -j TPROXY_ENT
# 将PRE链添加进PREROUTING链
iptables -w 60 -t mangle -A PREROUTING -j TPROXY_PRE

## mangle output,默认相等，暂不考虑
if [ $fwmark_reroute != $fwmark_tproxy ]; then
ip rule add fwmark $fwmark_reroute table $table_reroute
ip route add local default dev lo table $table_reroute

# iptables新增MARK链  (OUTPUT)
iptables -w 60 -t mangle -A TPROXY_MARK -m addrtype ! --dst-type UNICAST -j RETURN
$enable_dns && iptables -w 60 -t mangle -A TPROXY_MARK -p udp --dport 53 -j MARK --set-mark $fwmark_reroute
$enable_udp && iptables -w 60 -t mangle -A TPROXY_MARK -p udp -j MARK --set-mark $fwmark_reroute
$enable_tcp && iptables -w 60 -t mangle -A TPROXY_MARK -p tcp -j MARK --set-mark $fwmark_reroute
```

至此源码阅读完毕，剩下execsnoop-kernel另外分析
--------------------------