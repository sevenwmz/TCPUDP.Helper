using System;
using System.Net;
using System.Threading;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace TCPUDP.Helper
{
    /// <summary>
    /// TCPClient 帮助类，构造函数有示例调用
    /// </summary>
    public class TcpClientHelper
    {
        #region Field Area

        /// <summary>
        /// TcpClient
        /// </summary>
        private TcpClient _tcpClient { get; set; } = null;
        /// <summary>
        /// TcpClient Config
        /// </summary>
        private TcpClientModel _tcpModel { get; set; } = null;
        /// <summary>
        /// 获取一个值，该值指示 Socket 的基础 TcpClient 是否已连接到远程主机。
        /// </summary>
        public bool Connected { get => _tcpClient.Connected; }
        /// <summary>
        /// 获取或设置 Boolean 值，指定 TcpClient 是否只允许一个客户端使用端口。
        /// </summary>
        public bool ExclusiveAddressUse { get => _tcpClient.ExclusiveAddressUse; set => _tcpClient.ExclusiveAddressUse = value; }
        /// <summary>
        /// 获取或设置一个值，该值在发送或接收缓冲区未满时禁用延迟。
        /// </summary>
        public bool NoDelay { get => _tcpClient.NoDelay; set => _tcpClient.NoDelay = value; }
        /// <summary>
        /// 获取或设置接收缓冲区的大小。
        /// </summary>
        public int ReceiveBufferSize { get => _tcpClient.ReceiveBufferSize; set => _tcpClient.ReceiveBufferSize = value; }
        /// <summary>
        /// 获取或设置在初始化一个读取操作以后 TcpClient 等待接收数据的时间量。连接的超时值（以毫秒为单位）默认值为 0。
        /// </summary>
        public int ReceiveTimeout { get => _tcpClient.ReceiveTimeout; set => _tcpClient.ReceiveTimeout = value; }
        /// <summary>
        /// 获取或设置发送缓冲区的大小。
        /// </summary>
        public int SendBufferSize { get => _tcpClient.SendBufferSize; set => _tcpClient.SendBufferSize = value; }
        /// <summary>
        /// 获取或设置 TcpClient 等待发送操作成功完成的时间量。发送超时值（以毫秒为单位） 默认值为 0。
        /// </summary>
        public int SendTimeout { get => _tcpClient.SendTimeout; set => _tcpClient.SendTimeout = value; }
        /// <summary>
        /// 获取当前连接状态
        /// </summary>
        public bool CurrentStatus
        {
            get
            {
                try
                {
                    bool curStatus = !(_tcpClient.Client.Poll(1000, SelectMode.SelectRead)
                    && _tcpClient.Client.Available == 0 || !_tcpClient.Client.Connected);
                    if (curStatus)
                    {
                        reTryCount = 0;
                    }
                    return curStatus;
                }
                catch (Exception)
                {
                    if (_tcpModel.ConnectFailedCallBack != null)
                    {
                        _tcpModel.ConnectFailedCallBack(_tcpModel.RemoteIpEndPoint);
                    }
                    return false;
                }
            }
        }
        /// <summary>
        /// 重连标记，True为重连
        /// </summary>
        private bool _hasReTryConne = false;
        /// <summary>
        /// 当前重连次数
        /// </summary>
        private int reTryCount = 0;
        /// <summary>
        /// 异步取消判断标记
        /// </summary>
        private CancellationTokenSource _recvCancelTokenSource { get; set; } = new CancellationTokenSource();
        /// <summary>
        /// 异步取消判断标记
        /// </summary>
        private CancellationToken _cancelToken { get; set; }

        #endregion

        #region Ctor
        /// <summary>
        /// 调用示例
        /// TcpClientHelper tcp = new TcpClientHelper(tcp =>
        /// {
        ///     ///本地/远程IP
        ///     tcp.LocalIpEndPoint = new IPEndPoint(IPAddress.Parse("192.168.0.159"), 5010);
        ///     tcp.RemoteIpEndPoint = new IPEndPoint(IPAddress.Parse("192.168.0.159"), 5011);
        ///
        ///     ///是否开启自动连接
        ///     tcp.AutoConnect = true;
        ///     ///接收回调
        ///     tcp.ReceiveIPPortCallBack = (ip, port, bytes) => Console.WriteLine($"Receive {ip},{port} {Encoding.ASCII.GetString(bytes)}");
        ///     ///重连次数， -1无限重连
        ///     tcp.ReConnectCount = 5;
        ///     tcp.ReConnectTime = 3000;///重连间隔（毫秒）
        ///
        ///     //开启接收和发送日志回调开关
        ///     tcp.OpenReceiveLog = true;
        ///     tcp.OpenSendLog = true;
        ///     
        ///     //开启普通和异常日志回调
        ///     tcp.LogInfoWithIPPortCallBack = (ip, port, msg) => Console.WriteLine($"Log:{msg},{ip},{port}");
        ///     tcp.ErrorLogWithIPPortCallBack = (ip, port, exception, msg) => Console.WriteLine($"Error:{msg},{ip},{port}");
        /// });
        /// </summary>
        /// <param name="clientConfig">配置项</param>
        public TcpClientHelper(Action<TcpClientModel> clientConfig)
        {
            _tcpModel = new TcpClientModel();
            clientConfig(_tcpModel);
            InitTcpClient();
        }
        #endregion

        #region Method

        #region 连接
        /// <summary>
        /// 使用指定的 IP 地址和端口号建立默认远程主机。
        /// </summary>
        /// <param name="addr">要将数据发送到的远程主机的 IPAddress</param>
        /// <param name="port">要将数据发送到的端口号</param>
        public void Connect(IPAddress addr, int port) => Connect(new IPEndPoint(addr, port));
        /// <summary>
        /// 使用指定的网络终结点建立默认远程主机。
        /// </summary>
        /// <param name="endPoint">一个 IPEndPoint，它指定要将数据发送到的网络终结点</param>
        public void Connect(IPEndPoint endPoint)
        {
            _tcpClient.Connect(endPoint);
            ConnectSuccessCallback();
        }

        /// <summary>
        /// 使用指定的主机名和端口号建立默认远程主机
        /// </summary>
        /// <param name="hostname">要将数据发送到的远程主机的 DNS 名称。</param>
        /// <param name="port">要将数据发送到的远程主机上的端口号。</param>
        public void Connect(string hostname, int port) => Connect(new IPEndPoint(IPAddress.Parse(hostname), port));


        /// <summary>
        /// 使用指定的主机名和端口号建立默认远程主机
        /// </summary>
        /// <param name="hostname">要将数据发送到的远程主机的 DNS 名称。</param>
        /// <param name="port">要将数据发送到的远程主机上的端口号。</param>
        /// <returns>表示异步连接操作的任务</returns>
        public async Task ConnectAsync(string hostname, int port)
        {
            await _tcpClient?.ConnectAsync(hostname, port);
            ConnectSuccessCallback();
        }
        /// <summary>
        /// 使用指定的 IP 地址和端口号建立默认远程主机。
        /// </summary>
        /// <param name="addr">要将数据发送到的远程主机的 IPAddress</param>
        /// <param name="port">要将数据发送到的端口号</param>
        /// <returns>表示异步连接操作的任务</returns>
        public async Task ConnectAsync(IPAddress addr, int port) => ConnectAsync(addr.ToString(), port);

        /// <summary>
        /// 使用指定的主机名和端口号建立默认远程主机
        /// </summary>
        /// <param name="endPoint"></param>
        /// <returns>表示异步连接操作的任务</returns>
        public async Task ConnectAsync(IPEndPoint endPoint) => ConnectAsync(endPoint.Address, endPoint.Port);
        /// <summary>
        /// 重连设置
        /// </summary>
        /// <param name="e"></param>
        /// <returns></returns>
        public void ReTryConnect(Exception e)
        {
            if (_hasReTryConne)
            {
                return;
            }
            _hasReTryConne = true;
            while (_tcpModel.ReConnectCount == -1 || reTryCount < _tcpModel.ReConnectCount)//-1无限重连
            {
                if (CurrentStatus)
                {
                    LogInfo("已建立连接，当前连接状态为True", _tcpModel.RemoteIpEndPoint, _tcpModel.OpenOtherLog);
                    _hasReTryConne = false;
                    break;
                }
                reTryCount++;
                Task.Delay(_tcpModel.ReConnectTime).Wait();
                ErrorLog($"对方可能已挂起，正在尝试重连...当前重连次数:{reTryCount}.", e, _tcpModel.LocalIpEndPoint);
                Dispose();
                InitTcpClient();
            }
            if (reTryCount >= _tcpModel.ReConnectCount)
            {
                _recvCancelTokenSource.Cancel();
                ErrorLog($"当前重连次数:{reTryCount}.重连次数已满，取消监听", e, _tcpModel.LocalIpEndPoint);
            }
        }
        /// <summary>
        /// 连接成功回调
        /// </summary>
        private void ConnectSuccessCallback()
        {
            if (_tcpModel.ConnectSuccessCallBack != null)
            {
                _tcpModel.ConnectSuccessCallBack(_tcpModel.RemoteIpEndPoint);
            }
        }
        #endregion

        #region 接收数据
        /// <summary>
        /// 返回由远程主机发送的 TCP 数据报。 
        /// 非阻塞，有消息才会读，没消息会返回null
        /// </summary>
        /// <returns></returns>
        public byte[] Receive() => CustomeReceive(stream =>
        {
            byte[] receiveBuffer = new byte[_tcpModel.ReceiveBufferSize];
            int bytesReceived = stream.Read(receiveBuffer);
            if (!CurrentStatus)
            {
                ReTryConnect(new Exception("接收数据时发现连接断开，需要重连"));
                return new byte[0];
            }
            return receiveBuffer;
        });

        /// <summary>
        /// 异步返回由远程主机发送的 TCP 数据报。
        /// 非阻塞，有消息才会读，没消息会返回null
        /// </summary>
        /// <returns></returns>
        public async Task<byte[]> ReceiveAsync(CancellationToken asyncReceiveCancelToken)
        {
            if (!CurrentStatus)
            {
                ReTryConnect(new Exception("接收数据时发现连接断开，需要重连"));
                return new byte[0];
            }
            Memory<byte> by = by = new Memory<byte>();
            var stream = _tcpClient.GetStream();
            await stream.ReadAsync(by, asyncReceiveCancelToken);
            return by.ToArray();
        }

        public byte[] CustomeReceive(Func<NetworkStream, byte[]> func) => func(_tcpClient.GetStream());//关闭连接这里会异常，增加_tcpClient验证
        #endregion

        #region 发送
        /// <summary>
        /// 将 TCP 数据报发送到远程主机。
        /// </summary>
        /// <param name="buffer">一个 Byte 类型的数组，该数组包含要写入 NetworkStream 的数据。</param>
        /// <returns>已发送的字节数。</returns>
        public IPEndPoint Send(byte[] buffer) => Send(buffer, 0, buffer.Length);
        /// <summary>
        /// 将 TCP 数据报发送到远程主机。
        /// </summary>
        /// <param name="buffer">一个 Byte 类型的数组，该数组包含要写入 NetworkStream 的数据。</param>
        /// <param name="offSet">buffer 中开始写入数据的位置。</param>
        /// <param name="count">要写入 NetworkStream 的字节数。</param>
        /// <returns>返回当前发送到的远程主机IPEndPoint</returns>
        public IPEndPoint Send(byte[] buffer, int offSet, int count) => CustomSend(t =>
        {
            t.Write(buffer, offSet, count);
            return _tcpModel.RemoteIpEndPoint;
        });
        /// <summary>
        /// 自定义发送处理逻辑
        /// </summary>
        /// <param name="func"></param>
        /// <returns></returns>
        public IPEndPoint CustomSend(Func<NetworkStream, IPEndPoint> func)
        {
            if (_tcpModel.BeforeSendCallBack != null)
            {
                _tcpModel.BeforeSendCallBack();
            }
            try
            {
                var ipend = func(_tcpClient.GetStream());
                LogInfo($"消息发送成功", _tcpModel.RemoteIpEndPoint, _tcpModel.OpenSendLog);
                if (_tcpModel.AfterSendCallBack != null)
                {
                    _tcpModel.AfterSendCallBack();
                }
                return ipend;
            }
            catch (Exception e)
            {
                ReTryConnect(e);
                ErrorLog("消息发送异常", e, _tcpModel.RemoteIpEndPoint);
                return _tcpModel.RemoteIpEndPoint;
            }
        }



        /// <summary>
        /// 将 TCP 数据报异步发送到远程主机。
        /// 以异步操作形式，将指定字节数组范围内的数据写入 NetworkStream。
        /// </summary>
        /// <param name="buffer">一个包含要写入 NetworkStream 的数据的字节数组。</param>
        /// <param name="cancellationToken">要监视取消请求的标记。</param>
        /// <returns>表示异步写入操作的任务。</returns>
        public async Task<IPEndPoint> SendAsync(byte[] buffer, CancellationToken cancellationToken)
                                    => await SendAsync(buffer, 0, buffer.Length, cancellationToken);
        /// <summary>
        /// 将 TCP 数据报异步发送到远程主机。
        /// 以异步操作形式，将指定字节数组范围内的数据写入 NetworkStream。
        /// </summary>
        /// <param name="buffer">一个包含要写入 NetworkStream 的数据的字节数组。</param>
        /// <param name="offSet">buffer 中开始写入数据的位置。</param>
        /// <param name="count">要写入 NetworkStream 的字节数。</param>
        /// <param name="cancellationToken">要监视取消请求的标记。</param>
        /// <returns>表示异步写入操作的任务。</returns>
        public async Task<IPEndPoint> SendAsync(byte[] buffer, int offSet, int count, CancellationToken cancellationToken)
            => await CustomSendAsync(t =>
        {
            t.WriteAsync(buffer, offSet, count, cancellationToken);
            return _tcpModel.RemoteIpEndPoint;
        });

        /// <summary>
        /// 自定义异步发送处理逻辑
        /// </summary>
        /// <param name="func"></param>
        /// <returns></returns>
        public async Task<IPEndPoint> CustomSendAsync(Func<NetworkStream, IPEndPoint> func)
        {
            if (_tcpModel.BeforeSendCallBack != null)
            {
                _tcpModel.BeforeSendCallBack();
            }
            try
            {
                var res = func(_tcpClient.GetStream());
                LogInfo($"异步消息发送成功", _tcpModel.RemoteIpEndPoint, _tcpModel.OpenSendLog);
                if (_tcpModel.AfterSendCallBack != null)
                {
                    _tcpModel.AfterSendCallBack();
                }
                return res;
            }
            catch (Exception e)
            {
                _tcpClient.GetStream().Dispose();
                ErrorLog("异步消息发送异常", e, _tcpModel.RemoteIpEndPoint);
                ReTryConnect(e);
                return _tcpModel.RemoteIpEndPoint;
            }
        }
        #endregion

        #region Close
        /// <summary>
        /// 关闭 Tcp 连接。
        /// </summary>
        public void Close()
        {
            try
            {
                _tcpClient.Close();
                LogInfo("Tcp端口已关闭", _tcpModel.LocalIpEndPoint, _tcpModel.OpenOtherLog);
            }
            catch (Exception e)
            {
                ErrorLog("Tcp端口关闭异常", e, _tcpModel.LocalIpEndPoint);
            }
        }
        #endregion

        #region Dispose
        /// <summary>
        /// 释放由 TcpClient 占用的托管和非托管资源。
        /// </summary>
        public void Dispose()
        {
            try
            {
                _tcpClient.Dispose();
                if (_tcpModel.DisposeCallBack != null)
                {
                    _tcpModel.DisposeCallBack(_tcpModel.RemoteIpEndPoint);
                }
                LogInfo("Tcp端口已释放Dispose", _tcpModel.LocalIpEndPoint, _tcpModel.OpenOtherLog);
            }
            catch (Exception e)
            {
                ErrorLog("Tcp端口释放Dispose异常", e, _tcpModel.LocalIpEndPoint);
            }
        }
        #endregion

        #endregion

        #region Custom Method
        /// <summary>
        /// 初始化TCP
        /// </summary>
        /// <exception cref="ArgumentException">参数异常</exception>
        /// <exception cref="ArgumentNullException">参数异常</exception>
        private void InitTcpClient()
        {
            #region Verify
            if (_tcpModel.ReConnectCount < -1)
            {
                throw new ArgumentException("请设置正确的重连次数");
            }
            if (_tcpModel.LocalIpEndPoint is null)
            {
                throw new ArgumentException("请设置本地IP和端口号");
            }
            if (_tcpModel.RemoteIpEndPoint is null)
            {
                throw new ArgumentException("请设置远程IP和端口号");
            }
            #endregion

            try
            {
                _tcpClient = new TcpClient(_tcpModel.LocalIpEndPoint);
                if (_tcpModel.AutoConnect)//也可以不做绑定
                {
                    Connect(_tcpModel.RemoteIpEndPoint);
                }
                if (_cancelToken != _recvCancelTokenSource.Token)
                {
                    _cancelToken = _recvCancelTokenSource.Token;
                }
                #region 接收回调设置
                if (_hasReTryConne)
                {
                    return;
                }
                if (_tcpModel.ReceiveByteCallBack != null)
                {
                    TaskRecive(ipEndPoint =>
                    {
                        byte[] bytes = Receive();
                        if (bytes.Length > 1)
                        {
                            LogInfo($"消息接收成功", ipEndPoint, _tcpModel.OpenReceiveLog);
                            _tcpModel.ReceiveByteCallBack(bytes);
                        }
                    });
                }
                else if (_tcpModel.ReceiveIPEndPointCallBack != null)
                {
                    TaskRecive(ipEndPoint =>
                    {
                        byte[] bytes = Receive();
                        if (bytes.Length > 1)
                        {
                            LogInfo($"消息接收成功", ipEndPoint, _tcpModel.OpenReceiveLog);
                            _tcpModel.ReceiveIPEndPointCallBack(ipEndPoint, bytes);
                        }
                    });
                }
                else if (_tcpModel.ReceiveIPPortCallBack != null)
                {
                    TaskRecive(ipEndPoint =>
                    {
                        byte[] bytes = Receive();
                        if (bytes.Length > 1)
                        {
                            LogInfo($"消息接收成功", ipEndPoint, _tcpModel.OpenReceiveLog);
                            _tcpModel.ReceiveIPPortCallBack(ipEndPoint.Address.ToString(),
                                                               ipEndPoint.Port,
                                                               bytes);
                        }

                    });
                }
                else
                {
                    LogInfo("没有接收消息回调注册", _tcpModel.LocalIpEndPoint, _tcpModel.OpenOtherLog);
                }
                #endregion
                LogInfo("初始化TCP成功", _tcpModel.LocalIpEndPoint, _tcpModel.OpenOtherLog);
            }
            catch (Exception e)
            {
                Dispose();
                ErrorLog(_hasReTryConne ? e.Message : "初始化异常，请检查必要配置。", e, _tcpModel.RemoteIpEndPoint);
            }


        }
        /// <summary>
        /// 异步接收对象（非阻塞当前线程）
        /// </summary>
        /// <param name="action"></param>
        private void TaskRecive(Action<IPEndPoint> action)
        {
            Task.Run(() =>
            {
                while (!_tcpModel.ReceiveCanceToken.IsCancellationRequested && !_cancelToken.IsCancellationRequested)
                {
                    try
                    {
                        action(_tcpModel.RemoteIpEndPoint);
                        if (_tcpModel.AfterReceiveCallBack != null)
                        {
                            Task.Run(() => _tcpModel.AfterReceiveCallBack());
                        }
                    }

                    catch (Exception e)
                    {
                        ErrorLog($"{e.Message}", e, _tcpModel.RemoteIpEndPoint);
                        ReTryConnect(e);
                        Task.Delay(_tcpModel.ReConnectTime).Wait();
                    }

                }
            }, _cancelToken);
        }

        /// <summary>
        /// 异常日志处理中心
        /// </summary>
        /// <param name="errorMsg">异常提示内容</param>
        /// <param name="exception">捕捉到的异常</param>
        /// <param name="iPEndPoint">异常发生的端口号信息</param>
        private void ErrorLog(string errorMsg, Exception exception, IPEndPoint iPEndPoint)
        {
            if (_tcpModel.OpenErrorLog)
            {
                if (_tcpModel.ErrorLogWithIPPortCallBack != null)
                {
                    _tcpModel.ErrorLogWithIPPortCallBack(iPEndPoint.Address.ToString(), iPEndPoint.Port, exception, errorMsg);
                }
                if (_tcpModel.ErrorLogWithIPEndPointCallBack != null)
                {
                    _tcpModel.ErrorLogWithIPEndPointCallBack(iPEndPoint, exception, errorMsg);
                }
                if (_tcpModel.ErrorLogCallBack != null)
                {
                    _tcpModel.ErrorLogCallBack(exception, errorMsg);
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
                if (_tcpModel.LogInfoCallBack != null)
                {
                    _tcpModel.LogInfoCallBack(logMsg);
                }
                if (_tcpModel.LogInfoWithIPCallBack != null)
                {
                    _tcpModel.LogInfoWithIPCallBack(iPEndPoint, logMsg);
                }
                if (_tcpModel.LogInfoWithIPPortCallBack != null)
                {
                    _tcpModel.LogInfoWithIPPortCallBack(iPEndPoint.Address.ToString(), iPEndPoint.Port, logMsg);
                }
            }
        }
        #endregion
    }
    /// <summary>
    /// TcpClient 配置模块
    /// </summary>
    public class TcpClientModel
    {
        /// <summary>
        /// 本地IPEndPoint（ip，端口）
        /// </summary>
        public IPEndPoint LocalIpEndPoint = null;
        /// <summary>
        /// 绑定远程【对方】端（ip，端口）
        /// </summary>
        public IPEndPoint RemoteIpEndPoint = null;
        /// <summary>
        /// 接收字节大小，默认1024
        /// </summary>
        public int ReceiveBufferSize { get; set; } = 1024;
        /// <summary>
        /// 直接启动服务端
        /// </summary>
        public bool AutoConnect { get; set; } = false;
        /// <summary>
        /// 接收消息取消Token
        /// </summary>
        public CancellationToken ReceiveCanceToken = default;

        #region 重连
        /// <summary>
        /// 失败重连次数，默认10次，设置-1 为永久尝试连接
        /// </summary>
        public int ReConnectCount { get; set; } = 10;
        /// <summary>
        /// 失败重连间隔（毫秒），默认3000毫秒
        /// </summary>
        public int ReConnectTime { get; set; } = 3000;
        #endregion

        #region 日志异常控制开关
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

        #region 接收消息回调
        /// <summary>
        /// 接收回调，返回 IP 端口 和接收字节数组
        /// </summary>
        public Action<string, int, byte[]> ReceiveIPPortCallBack = null;
        /// <summary>
        /// 接收回调，返回 IPEndPoint 和接收字节数组
        /// </summary>
        public Action<IPEndPoint, byte[]> ReceiveIPEndPointCallBack = null;
        /// <summary>
        /// 接收回调，返回 字节数组
        /// </summary>
        public Action<byte[]> ReceiveByteCallBack = null;
        #endregion

        #region 日志回调
        /// <summary>
        /// LogInfo 开头回调注册其一即可
        /// 普通日志回调，返回 产生日志IP 端口  消息
        /// </summary>
        public Action<string, int, string> LogInfoWithIPPortCallBack = null;
        /// <summary>
        /// LogInfo 开头回调注册其一即可
        /// 普通日志回调，返回 产生日志IPEndPoint  消息 
        /// </summary>
        public Action<IPEndPoint, string> LogInfoWithIPCallBack = null;
        /// LogInfo 开头回调注册其一即可
        /// 普通日志回调，返回 日志消息 
        /// </summary>
        public Action<string> LogInfoCallBack = null;
        #endregion

        #region 异常回调
        /// <summary>
        /// Error 开头回调注册其一即可
        /// 异常回调，返回 产生异常IP 端口 异常 错误消息提示（非系统） 
        /// </summary>
        public Action<string, int, Exception, string> ErrorLogWithIPPortCallBack = null;
        /// <summary>
        /// Error 开头回调注册其一即可
        /// 异常回调，返回 产生异常IPEndPoint 异常 错误消息提示（非系统） 
        /// </summary>
        public Action<IPEndPoint, Exception, string> ErrorLogWithIPEndPointCallBack = null;
        /// <summary>
        /// Error 开头回调注册其一即可
        /// 异常回调，返回 异常 错误消息提示（非系统） 
        /// </summary>
        public Action<Exception, string> ErrorLogCallBack = null;
        #endregion

        #region 连接回调
        /// <summary>
        /// 连接成功回调,IPEndPoint为远程连接端IP
        /// </summary>
        public Action<IPEndPoint> ConnectSuccessCallBack = null;
        /// <summary>
        /// 断开连接回调,IPEndPoint为远程连接端IP
        /// </summary>
        public Action<IPEndPoint> ConnectFailedCallBack = null;
        #endregion

        #region 发送消息回调
        /// <summary>
        /// 发送消息前回调
        /// </summary>
        public Action BeforeSendCallBack = null;
        /// <summary>
        /// 发送消息后回调
        /// </summary>
        public Action AfterSendCallBack = null;
        #endregion

        #region 接收数据回调
        /// <summary>
        /// 接收数据后会 新开线程回调 且立即触发
        /// </summary>
        public Action AfterReceiveCallBack = null;
        #endregion

        #region 释放资源回调
        /// <summary>
        /// 释放资源回调,IPEndPoint为远程连接端IP
        /// </summary>
        public Action<IPEndPoint> DisposeCallBack = null;
        #endregion
    }
}