using System;
using System.Net;
using System.Threading;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace TCPUDP.Helper
{
    /// <summary>
    /// UDP帮助类，构造函数有示例调用
    /// </summary>
    public class UdpHelper
    {
        #region Field Area
        private UdpClient _udpClient { get; set; } = null;

        #region System parameter set
        /// <summary>
        /// 获取从网络接收的可读取的数据量。
        /// </summary>
        public int Available { get => _udpClient.Available; }
        /// <summary>
        /// 获取或设置一个 Boolean 值，该值指定是否可以 UdpClient 发送广播数据包。
        /// </summary>
        public bool EnableBroadcast { get => _udpClient.EnableBroadcast; set => _udpClient.EnableBroadcast = value; }
        /// <summary>
        /// 获取或设置 Boolean 值，指定 UdpClient 是否只允许一个客户端使用端口。
        /// </summary>
        public bool ExclusiveAddressUse { get => _udpClient.ExclusiveAddressUse; set => _udpClient.ExclusiveAddressUse = value; }
        /// <summary>
        /// 获取或设置 Boolean 值，该值指定是否将输出多播数据包传递给发送应用程序。
        /// </summary>
        public bool MulticastLoopback { get => _udpClient.MulticastLoopback; set => _udpClient.MulticastLoopback = value; }
        /// <summary>
        /// 获取或设置一个值，它指定由 UdpClient 发送的 Internet 协议 (IP) 数据包的生存时间 (TTL)。
        /// </summary>
        public short Ttl { get => _udpClient.Ttl; set => _udpClient.Ttl = value; }
        #endregion

        #region Ctor parameter set
        private UdpModel _udpModel { get; set; } = null;
        #endregion
        #endregion

        #region ctor
        /// <summary>
        /// 调用示例
        /// CancellationTokenSource cancellationToken = new CancellationTokenSource();
        /// UdpHelper udpClient = new UdpHelper(udp =>
        /// {
        ///     //本地端口
        ///     udp.LocalIpEndPoint = new IPEndPoint(IPAddress.Parse("192.168.0.159"), 5010);
        ///     //发送端口
        ///     udp.SendIpEndPoint = new IPEndPoint(IPAddress.Parse("192.168.0.159"), 5011);
        ///     //绑定对方端口
        ///     udp.RemoteIpEndPoint = new IPEndPoint(IPAddress.Parse("192.168.0.159"), 5011);
        ///
        ///     //取消接收Token
        ///     udp.ReceiveCancellationToken = cancellationToken.Token;
        ///
        ///     //接收回调
        ///     udp.ReceiveIPPortCallBack = (ip,port, bytes) =>
        ///     {
        ///         Console.WriteLine(ip);
        ///         Console.WriteLine(port);
        ///         Console.WriteLine(Encoding.ASCII.GetString(bytes));
        ///     };
        ///     
        ///     设置永久重连，2秒尝试一次
        ///     udp.ReConnectCount = -1;
        ///     udp.ReConnectTime = 2000;
        ///
        ///     //开启发送和接收日志,默认关闭
        ///     udp.OpenSendLog = true;
        ///     udp.OpenReceiveLog = true;
        ///
        ///     udp.OpenErrorLog = true;
        ///     udp.OpenOtherLog = true;
        ///
        ///     //异常日志
        ///     udp.ErrorLogCallBack = (exception, suggestMsg) => 
        ///                     Console.WriteLine($"{exception.Message}{exception.StackTrace}{suggestMsg}");
        ///     //收发消息 普通日志
        ///     udp.LogInfoWithIPCallBack = (ipEndPoint, logMsg) => 
        ///                     Console.WriteLine($"{ipEndPoint.Address},{ipEndPoint.Port},{logMsg}");
        /// });
        /// </summary>
        /// <param name="udpConfigInfo"></param>
        public UdpHelper(Action<UdpModel> udpConfigInfo)
        {
            _udpModel = new UdpModel();
            udpConfigInfo(_udpModel);
            InitUdp();
        }
        #endregion

        #region Method

        #region 接收数据
        /// <summary>
        /// 返回由远程主机发送的 UDP 数据报。
        /// </summary>
        /// <param name="remoteEP">一个 IPEndPoint，它表示从其发送数据的远程主机。</param>
        /// <returns></returns>
        public byte[] Receive(ref IPEndPoint? remoteEP) => _udpClient.Receive(ref remoteEP);

        /// <summary>
        /// 异步返回由远程主机发送的 UDP 数据报。
        /// </summary>
        /// <returns></returns>
        public Task<UdpReceiveResult> ReceiveAsync() => _udpClient.ReceiveAsync();

        public byte[] CustomeReceive(Func<UdpClient, byte[]> func) => func(_udpClient);
        #endregion

        #region 连接
        /// <summary>
        /// 使用指定的 IP 地址和端口号建立默认远程主机。
        /// </summary>
        /// <param name="addr">要将数据发送到的远程主机的 IPAddress</param>
        /// <param name="port">要将数据发送到的端口号</param>
        public void Connect(IPAddress addr, int port) => _udpClient.Connect(addr, port);

        /// <summary>
        /// 使用指定的网络终结点建立默认远程主机。
        /// </summary>
        /// <param name="endPoint">一个 IPEndPoint，它指定要将数据发送到的网络终结点</param>
        public void Connect(IPEndPoint endPoint) => _udpClient.Connect(endPoint);

        /// <summary>
        /// 使用指定的主机名和端口号建立默认远程主机
        /// </summary>
        /// <param name="hostname">要将数据发送到的远程主机的 DNS 名称。</param>
        /// <param name="port">要将数据发送到的远程主机上的端口号。</param>
        public void Connect(string hostname, int port) => _udpClient?.Connect(hostname, port);

        #endregion

        #region 发送
        /// <summary>
        /// 将 UDP 数据报发送到远程主机。
        /// </summary>
        /// <param name="dgram">一个 Byte 类型的数组，它指定你打算以字节数组形式发送的 UDP 数据报。</param>
        /// <returns>已发送的字节数。</returns>
        public int Send(byte[] dgram) => Send(dgram, dgram.Length);
        /// <summary>
        /// 将 UDP 数据报发送到远程主机。
        /// </summary>
        /// <param name="dgram">一个 Byte 类型的数组，它指定你打算以字节数组形式发送的 UDP 数据报。</param>
        /// <param name="bytes">数据报中的字节数。</param>
        /// <returns>已发送的字节数。</returns>
        public int Send(byte[] dgram, int bytes) => Send(dgram, bytes, null);
        /// <summary>
        /// 将 UDP 数据报发送到远程主机。
        /// </summary>
        /// <param name="dgram">一个 Byte 类型的数组，它指定你打算以字节数组形式发送的 UDP 数据报。</param>
        /// <param name="endPoint">一个 IPEndPoint，表示要将数据报发送到的主机和端口。</param>
        /// <returns></returns>
        public int Send(byte[] dgram, IPEndPoint endPoint) => Send(dgram, dgram.Length, endPoint);
        /// <summary>
        /// 将 UDP 数据报发送到位于指定远程终结点的主机。
        /// </summary>
        /// <param name="dgram">一个 Byte 类型的数组，它指定你打算以字节数组形式发送的 UDP 数据报。</param>
        /// <param name="bytes">数据报中的字节数。</param>
        /// <param name="endPoint">一个 IPEndPoint，表示要将数据报发送到的主机和端口。</param>
        /// <returns>已发送的字节数。</returns>
        public int Send(byte[] dgram, int bytes, IPEndPoint? endPoint) => CustomSend(u => u.Send(dgram, bytes, endPoint), endPoint);
        /// <summary>
        /// 自定义发送处理逻辑
        /// </summary>
        /// <param name="func"></param>
        /// <returns></returns>
        public int CustomSend(Func<UdpClient, int> func, IPEndPoint sendIpEndPoint)
        {
            if (_udpModel.BeforeSendCallBack != null)
            {
                _udpModel.BeforeSendCallBack();
            }
            int res = 0;
            try
            {
                res = func(_udpClient);
                LogInfo($"消息发送成功", sendIpEndPoint, _udpModel.OpenSendLog);
            }
            catch (Exception e)
            {
                ErrorLog("消息发送异常", e, sendIpEndPoint);
            }
            if (_udpModel.AfterSendCallBack != null)
            {
                _udpModel.AfterSendCallBack();
            }
            return res;
        }



        /// <summary>
        /// 将 UDP 数据报发送到远程主机。
        /// </summary>
        /// <param name="dgram">一个 Byte 类型的数组，它指定你打算以字节数组形式发送的 UDP 数据报。</param>
        /// <returns>已发送的字节数。</returns>
        public Task<int> SendAsync(byte[] dgram) => SendAsync(dgram, dgram.Length);
        /// <summary>
        /// 将 UDP 数据报发送到远程主机。
        /// </summary>
        /// <param name="dgram">一个 Byte 类型的数组，它指定你打算以字节数组形式发送的 UDP 数据报。</param>
        /// <param name="bytes">数据报中的字节数。</param>
        /// <returns>已发送的字节数。</returns>
        public Task<int> SendAsync(byte[] dgram, int bytes) => SendAsync(dgram, bytes, null);
        /// <summary>
        /// 将 UDP 数据报发送到远程主机。
        /// </summary>
        /// <param name="dgram">一个 Byte 类型的数组，它指定你打算以字节数组形式发送的 UDP 数据报。</param>
        /// <param name="endPoint">一个 IPEndPoint，表示要将数据报发送到的主机和端口。</param>
        /// <returns></returns>
        public Task<int> SendAsync(byte[] dgram, IPEndPoint endPoint) => SendAsync(dgram, dgram.Length, null);
        /// <summary>
        /// 将 UDP 数据报异步发送到远程主机。
        /// </summary>
        /// <param name="dgram">一个 Byte 类型的数组，它指定你打算以字节数组形式发送的 UDP 数据报。</param>
        /// <param name="bytes">数据报中的字节数。</param>
        /// <param name="endPoint">一个 IPEndPoint，表示要将数据报发送到的主机和端口。</param>
        /// <returns>已发送的字节数</returns>
        public Task<int> SendAsync(byte[] datagram, int bytes, IPEndPoint endPoint) => CustomSendAsync(u => u.SendAsync(datagram, bytes, endPoint), endPoint);
        /// <summary>
        /// 自定义异步发送处理逻辑
        /// </summary>
        /// <param name="func"></param>
        /// <returns></returns>
        public Task<int> CustomSendAsync(Func<UdpClient, Task<int>> func, IPEndPoint sendIpEndPoint)
        {
            if (_udpModel.BeforeSendCallBack != null)
            {
                _udpModel.BeforeSendCallBack();
            }
            try
            {
                Task<int> res = func(_udpClient);
                LogInfo($"异步消息发送成功", sendIpEndPoint, _udpModel.OpenSendLog);
                try
                {
                    if (_udpModel.AfterSendCallBack != null)
                    {
                        _udpModel.AfterSendCallBack();
                    }
                }
                catch (Exception e)
                {
                    ErrorLog("AfterSendCallBack异常", e, sendIpEndPoint);
                }
                return res;
            }
            catch (Exception e)
            {
                ErrorLog("异步消息发送异常", e, sendIpEndPoint);
            }
            return default;
        }
        #endregion

        #region Close
        /// <summary>
        /// 关闭 UDP 连接。
        /// </summary>
        public void Close()
        {
            try
            {
                _udpClient.Close();
                LogInfo("Udp端口已关闭", _udpModel.LocalIpEndPoint, _udpModel.OpenOtherLog);
            }
            catch (Exception e)
            {
                ErrorLog("Udp端口关闭异常", e, _udpModel.LocalIpEndPoint);
            }
        }
        #endregion

        #region Dispose
        /// <summary>
        /// 释放由 UdpClient 占用的托管和非托管资源。
        /// </summary>
        public void Dispose()
        {
            try
            {
                _udpClient.Dispose();
                LogInfo("Udp端口已释放Dispose", _udpModel.LocalIpEndPoint, _udpModel.OpenOtherLog);
                if (_udpModel.DisposeCallBack != null)
                {
                    _udpModel.DisposeCallBack(_udpModel.LocalIpEndPoint);
                }
            }
            catch (Exception e)
            {
                ErrorLog("Udp端口释放Dispose异常", e, _udpModel.LocalIpEndPoint);
            }
        }
        #endregion

        #endregion

        #region Custom Method
        /// <summary>
        /// 初始化Udp
        /// </summary>
        /// <exception cref="ArgumentException">参数异常</exception>
        /// <exception cref="ArgumentNullException">参数异常</exception>
        private void InitUdp()
        {
            if (_udpModel.ReConnectCount < -1)
            {
                throw new ArgumentException("请设置正确的重连次数");
            }
            try
            {
                #region 初始化对象
                _udpClient = _udpModel.LocalIpEndPoint is null
                                    ? new UdpClient()
                                    : new UdpClient(_udpModel.LocalIpEndPoint)
                                    ;
                #endregion

                #region 限制绑定连接 
                if (_udpModel.RemoteIpEndPoint != null)//也可以不做绑定
                {
                    _udpClient.Connect(_udpModel.RemoteIpEndPoint);
                }
                #endregion

                #region 接收回调设置
                if (_udpModel.ReceiveByteCallBack != null)
                {
                    TaskRecive(ipEndPoint =>
                    {
                        _udpModel.ReceiveByteCallBack(Receive(ref ipEndPoint));
                        LogInfo($"消息接收成功", ipEndPoint, _udpModel.OpenReceiveLog);
                    });
                }
                else if (_udpModel.ReceiveIPEndPointCallBack != null)
                {
                    TaskRecive(ipEndPoint =>
                    {
                        byte[] bytes = Receive(ref ipEndPoint);
                        LogInfo($"消息接收成功", ipEndPoint, _udpModel.OpenReceiveLog);
                        _udpModel.ReceiveIPEndPointCallBack(ipEndPoint, bytes);
                    });
                }
                else if (_udpModel.ReceiveIPPortCallBack != null)
                {
                    TaskRecive(ipEndPoint =>
                    {
                        byte[] bytes = Receive(ref ipEndPoint);
                        LogInfo($"消息接收成功", ipEndPoint, _udpModel.OpenReceiveLog);
                        _udpModel.ReceiveIPPortCallBack(ipEndPoint.Address.ToString(),
                                                           ipEndPoint.Port,
                                                           bytes);
                    });
                }
                else
                {
                    LogInfo("没有接收消息回调注册", _udpModel.LocalIpEndPoint, _udpModel.OpenOtherLog);
                }
                #endregion
                LogInfo("初始化UDP成功", _udpModel.LocalIpEndPoint, _udpModel.OpenOtherLog);
            }
            catch (Exception e)
            {
                ErrorLog("初始化异常，请检查必要配置。", e, _udpModel.RemoteIpEndPoint);
            }


        }
        /// <summary>
        /// 异步接收对象（非阻塞当前线程）
        /// </summary>
        /// <param name="action"></param>
        private void TaskRecive( Action<IPEndPoint>  action)
        {
            Task.Run(() =>
            {
                IPEndPoint ipEndPoint = _udpModel.RemoteIpEndPoint is null ? new IPEndPoint(IPAddress.Any, 0) : _udpModel.RemoteIpEndPoint;
                int reTryCount = 0;
                while (!_udpModel.ReceiveCancelToken.IsCancellationRequested)
                {
                    try
                    {
                        action(ipEndPoint);
                        reTryCount = 0;
                        if (_udpModel.AfterReceiveCallBack != null)
                        {
                            Task.Run(() => _udpModel.AfterReceiveCallBack());
                        }
                    }
                    catch (SocketException e)
                    {
                        reTryCount++;
                        ErrorLog($"对方可能已挂起，正在尝试重连...当前重连次数:{reTryCount}.", e, _udpModel.LocalIpEndPoint);
                        Task.Delay(_udpModel.ReConnectTime).Wait();
                        //-1无限重连
                        if (_udpModel.ReConnectCount == -1)
                        {
                            continue;
                        }
                        if (reTryCount > _udpModel.ReConnectCount)
                        {
                            ErrorLog($"当前重连次数:{reTryCount}.重连次数已满，取消监听", e, _udpModel.LocalIpEndPoint);
                            break;
                        }
                        
                    }
                    catch (ObjectDisposedException e)
                    {
                        ///访问对象已被释放，需要重新初始化赋值连接
                        InitUdp();
                    }
                }
            });
        }
        /// <summary>
        /// 异常日志处理中心
        /// </summary>
        /// <param name="errorMsg">异常提示内容</param>
        /// <param name="exception">捕捉到的异常</param>
        /// <param name="iPEndPoint">异常发生的端口号信息</param>
        private void ErrorLog(string errorMsg, Exception exception, IPEndPoint iPEndPoint)
        {
            if (_udpModel.OpenErrorLog)
            {
                if (_udpModel.ErrorLogWithIPPortCallBack != null)
                {
                    _udpModel.ErrorLogWithIPPortCallBack(iPEndPoint.Address.ToString(), iPEndPoint.Port, exception, errorMsg);
                }
                if (_udpModel.ErrorLogWithIPEndPointCallBack != null)
                {
                    _udpModel.ErrorLogWithIPEndPointCallBack(iPEndPoint, exception, errorMsg);
                }
                if (_udpModel.ErrorLogCallBack != null)
                {
                    _udpModel.ErrorLogCallBack(exception, errorMsg);
                }
            }
        }
        /// <summary>
        /// 日志处理中心
        /// </summary>
        /// <param name="logMsg">日志内容</param>
        /// <param name="iPEndPoint">日志发生的端口号信息</param>
        /// <param name="writeLog">日志种类</param>
        private void LogInfo(string logMsg, IPEndPoint iPEndPoint, bool writeLog)
        {
            if (writeLog)
            {
                if (_udpModel.LogInfoCallBack != null)
                {
                    _udpModel.LogInfoCallBack(logMsg);
                }
                if (_udpModel.LogInfoWithIPCallBack != null)
                {
                    _udpModel.LogInfoWithIPCallBack(iPEndPoint, logMsg);
                }
                if (_udpModel.LogInfoWithIPPortCallBack != null)
                {
                    _udpModel.LogInfoWithIPPortCallBack(iPEndPoint.Address.ToString(), iPEndPoint.Port, logMsg);
                }
            }
        }
        #endregion
    }
    /// <summary>
    /// UDP 配置中心
    /// </summary>
    public class UdpModel
    {
        /// <summary>
        /// 本地IPEndPoint（ip，端口）
        /// </summary>
        public IPEndPoint LocalIpEndPoint { get; set; }

        /// <summary>
        /// 失败重连次数，默认10次，设置-1 为永久尝试连接
        /// </summary>
        public int ReConnectCount { get; set; } = 10;
        /// <summary>
        /// 失败重连间隔（毫秒），默认3000毫秒
        /// </summary>
        public int ReConnectTime { get; set; } = 3000;

        /// <summary>
        /// 绑定远程【对方】端（ip，端口）
        /// ====【警告】======
        /// 非绑定可收发来自任意IP端口消息，绑定后只能收发来自绑定IP端口远程信息
        /// </summary>
        public IPEndPoint RemoteIpEndPoint { get; set; }

        /// <summary>
        /// 接收消息Token
        /// </summary>
        public CancellationToken ReceiveCancelToken = default(CancellationToken);

        #region 开关控制
        /// <summary>
        /// 控制开启 接收消息 日志回调，默认关闭
        /// </summary>
        public bool OpenReceiveLog = false;
        /// <summary>
        /// 控制开启 发送消息 日志回调，默认关闭
        /// </summary>
        public bool OpenSendLog = false;
        /// <summary>
        /// 控制开启 接收异常 日志回调，默认开启
        /// </summary>
        public bool OpenErrorLog = true;
        /// <summary>
        /// 控制开启 接收其他【开启/关闭连接，释放连接等】 日志回调，默认开启
        /// </summary>
        public bool OpenOtherLog = true;
        #endregion

        #region RecvCallback
        /// <summary>
        /// 接收回调，返回 IP 端口 和接收字节数组
        /// </summary>
        public Action<string, int, byte[]> ReceiveIPPortCallBack { get; set; }
        /// <summary>
        /// 接收回调，返回 IPEndPoint 和接收字节数组
        /// </summary>
        public Action<IPEndPoint?, byte[]> ReceiveIPEndPointCallBack { get; set; }
        /// <summary>
        /// 接收回调，返回 字节数组
        /// </summary>
        public Action<byte[]> ReceiveByteCallBack { get; set; }
        #endregion

        #region 异常回调
        /// <summary>
        /// Error 开头回调注册其一即可
        /// 异常回调，返回 产生异常IP 端口 异常 错误消息提示（非系统） 
        /// </summary>
        public Action<string, int, Exception, string> ErrorLogWithIPPortCallBack { get; set; }
        /// <summary>
        /// Error 开头回调注册其一即可
        /// 异常回调，返回 产生异常IPEndPoint 异常 错误消息提示（非系统） 
        /// </summary>
        public Action<IPEndPoint?, Exception, string> ErrorLogWithIPEndPointCallBack { get; set; }
        /// <summary>
        /// Error 开头回调注册其一即可
        /// 异常回调，返回 异常 错误消息提示（非系统） 
        /// </summary>
        public Action<Exception, string> ErrorLogCallBack { get; set; }
        #endregion

        #region 日志回调
        /// <summary>
        /// LogInfo 开头回调注册其一即可
        /// 普通日志回调，返回 产生日志IP 端口  消息
        /// </summary>
        public Action<string, int, string> LogInfoWithIPPortCallBack { get; set; }
        /// <summary>
        /// LogInfo 开头回调注册其一即可
        /// 普通日志回调，返回 产生日志IPEndPoint  消息 
        /// </summary>
        public Action<IPEndPoint?, string> LogInfoWithIPCallBack { get; set; }
        /// LogInfo 开头回调注册其一即可
        /// 普通日志回调，返回 日志消息 
        /// </summary>
        public Action<string> LogInfoCallBack { get; set; }
        #endregion

        #region 发送消息回调
        /// <summary>
        /// 发送消息前回调
        /// </summary>
        public Action BeforeSendCallBack { get; set; }
        /// <summary>
        /// 发送消息后回调
        /// </summary>
        public Action AfterSendCallBack { get; set; }
        #endregion

        #region 接收消息回调
        /// <summary>
        /// 接收数据后会 新开线程回调 且立即触发
        /// </summary>
        public Action AfterReceiveCallBack  { get; set; }
        #endregion

        #region 释放资源回调
        /// <summary>
        /// 释放资源回调,IPEndPoint为远程连接端IP
        /// </summary>
        public Action<IPEndPoint> DisposeCallBack { get; set; } = null;
        #endregion
    }
}
