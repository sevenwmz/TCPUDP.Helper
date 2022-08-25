using System;
using System.Net;
using System.Linq;
using System.Threading;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace TCPUDP.Helper
{
    /// <summary>
    /// TCPServer 帮助类，构造函数有示例调用
    /// </summary>
    public class TcpServerHelper
    {
        #region Field Area

        /// <summary>
        /// TcpServer
        /// </summary>
        private TcpListener _tcpServer { get; set; } = null;
        /// <summary>
        /// TcpServer Config
        /// </summary>
        private TcpServerModel _tcpModel { get; set; } = null;
        /// <summary>
        /// 缓存所有连接服务中心的客户端
        /// </summary>
        private Dictionary<string, TcpClient> _tcpClientDictionary { get; set; } = new Dictionary<string, TcpClient>();

        /// <summary>
        /// 获取或设置一个 Boolean 值，该值指定 TcpListener 是否只允许一个基础套接字来侦听特定端口。
        /// </summary>
        public bool ExclusiveAddressUse { get => _tcpServer.ExclusiveAddressUse; set => _tcpServer.ExclusiveAddressUse = value; }

        /// <summary>
        /// 获取当前 EndPoint 的基础 TcpListener。
        /// </summary>
        public EndPoint LocalEndpoint { get => _tcpServer.LocalEndpoint; }

        /// <summary>
        /// 确定是否有挂起的连接请求。
        /// </summary>
        /// <returns>如果连接正挂起，则为 true；否则为 false</returns>
        public bool Pending { get => _tcpServer.Pending(); }

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
        /// TcpServerHelper tcpServer = new TcpServerHelper(s =>
        /// {
        ///     s.LocalIpEndPoint = new IPEndPoint(IPAddress.Parse("192.168.0.159"), 5011);
        ///     ///是否开启自动连接
        ///     s.AutoConnect = true;
        ///     ///接收回调
        ///     s.ReceiveIPPortCallBack = (ip, port, bytes, count) => Console.WriteLine($"ServerReceive {ip},{port} {Encoding.ASCII.GetString(bytes)}");
        ///
        ///     s.ClientConnectCallBack = ipInfo => Console.WriteLine($"有新的客户端连接进入 ip：{ipInfo.Address.ToString()},port:{ipInfo.Port}");
        ///     s.ClientDisConnectCallBack = ipInfo => Console.WriteLine($"有客户端断开连接 ip：{ipInfo.Address.ToString()},port:{ipInfo.Port}");
        ///
        ///     //开启接收和发送日志回调开关
        ///     s.OpenReceiveLog = true;
        ///     s.OpenSendLog = true;
        ///
        ///     //开启普通和异常日志回调
        ///     s.LogInfoWithIPPortCallBack = (ip, port, msg) => Console.WriteLine($"Log:{msg},{ip},{port}");
        ///     s.ErrorLogWithIPPortCallBack = (ip, port, exception, msg) => Console.WriteLine($"Error:{msg},{ip},{port}");
        /// });
        /// </summary>
        /// <param name="clientConfig">配置项</param>
        public TcpServerHelper(Action<TcpServerModel> serverConfig)
        {
            _tcpModel = new TcpServerModel();
            serverConfig(_tcpModel);
            InitTcpServer();
        }
        #endregion

        #region Method

        #region 连接
        /// <summary>
        /// 开始侦听传入的连接请求。
        /// </summary>
        public void Start()
        {
            _tcpServer.Start();
            ReceiveStartInit();
        }
        /// <summary>
        /// 启动对具有最大挂起连接数的传入连接请求的侦听。
        /// </summary>
        /// <param name="backlog">挂起连接队列的最大长度。</param>
        public void Start(int backlog)
        {
            _tcpServer.Start(backlog);
            ReceiveStartInit();
        }

        /// <summary>
        /// 创建一个新的侦听指定端口的 TcpListener 实例。
        /// </summary>
        /// <param name="port">用来侦听传入的连接尝试的端口。</param>
        /// <returns>一个新的用于侦听指定端口的 TcpListener 实例。</returns>
        public static TcpListener Create(int port) => TcpListener.Create(port);

        #endregion

        #region 接收数据
        /// <summary>
        /// 自定义接收方法
        /// </summary>
        /// <param name="func">自定义逻辑，放入连接的TcpClient</param>
        /// <returns>返回接收到的数据</returns>
        public byte[] CustomeReceive(Func<TcpClient, byte[]> func) => func(_tcpServer.AcceptTcpClient());

        #endregion

        #region 发送
        /// <summary>
        /// 将 TCP 数据报发送到远程客户端
        /// 默认选择一个已连接客户端发送。
        /// </summary>
        /// <param name = "buffer" > 一个 Byte 类型的数组，该数组包含要写入 NetworkStream 的数据。</param>
        public void Send(byte[] buffer)
        {
            if (_tcpClientDictionary.Count <= 0)
            {
                Exception exception = new Exception("当前没有连接的客户端，无法进行发送任务处理");
                ErrorLog("当前没有连接的客户端，无法进行发送任务处理", exception, _tcpModel.LocalIpEndPoint);
                return;
            }
            Send(_tcpClientDictionary.First().Key, buffer);
        }
        /// <summary>
        /// 将 TCP 数据报发送到远程客户端
        /// 默认选择一个发送。
        /// </summary>
        /// <param name = "ip" > 发送到的目标客户端地址 </param>
        /// <param name = "buffer" > 一个 Byte 类型的数组，该数组包含要写入 NetworkStream 的数据。</param>
        public void Send(string ip, byte[] buffer) => Send(ip, buffer, 0, buffer.Length);

        /// <summary>
        /// 将 TCP 数据报发送到远程主机。
        /// </summary>
        /// <param name = "ip" > 发送到的目标客户端地址 </param>
        /// <param name="buffer">一个 Byte 类型的数组，该数组包含要写入 NetworkStream 的数据。</param>
        /// <param name="offSet">buffer 中开始写入数据的位置。</param>
        /// <param name="count">要写入 NetworkStream 的字节数。</param>
        public void Send(string ip, byte[] buffer, int offSet, int count) => CustomSend(ip, tcpClient => tcpClient.GetStream().Write(buffer, offSet, count));
        /// <summary>
        /// 自定义发送处理逻辑
        /// </summary>
        /// <param name="ip">发送到的目标客户端地址</param>
        /// <param name="client">自定义处理逻辑，返回发送成功字节</param>
        public void CustomSend(string ip, Action<TcpClient> client)
        {
            if (_tcpModel.BeforeSendCallBack != null)
            {
                _tcpModel.BeforeSendCallBack();
            }
            try
            {
                if (!_tcpClientDictionary.ContainsKey(ip))
                {
                    ErrorLog("指定的IP客户端已断开连接，请确认后再次尝试发送", new Exception("指定的IP客户端尚未连接，无法进行发送任务处理"), new IPEndPoint(IPAddress.Parse(ip), 0));
                    return;
                }
                client(_tcpClientDictionary[ip]);
                LogInfo($"消息发送成功", _tcpModel.LocalIpEndPoint, _tcpModel.OpenSendLog);
                if (_tcpModel.AfterSendCallBack != null)
                {
                    _tcpModel.AfterSendCallBack();
                }
            }
            catch (Exception e)
            {
                ErrorLog("消息发送异常", e, _tcpModel.LocalIpEndPoint);
            }
        }



        /// <summary>
        /// 将 TCP 数据报异步发送到远程主机。
        /// 以异步操作形式，将指定字节数组范围内的数据写入 NetworkStream。
        /// </summary>
        /// <param name = "buffer" > 一个包含要写入 NetworkStream 的数据的字节数组。</param>
        /// <param name = "cancellationToken" > 要监视取消请求的标记。</param>
        /// <returns>表示异步写入操作的任务。</returns>
        public async Task SendAsync(byte[] buffer, CancellationToken cancellationToken)
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
        public async Task SendAsync(byte[] buffer, int offSet, int count, CancellationToken cancellationToken)
            => await CustomSendAsync(t => t.WriteAsync(buffer, offSet, count, cancellationToken));

        /// <summary>
        /// 自定义异步发送处理逻辑
        /// </summary>
        /// <param name="action"></param>
        /// <returns></returns>
        public async Task CustomSendAsync(Action<NetworkStream> action)
        {
            if (_tcpModel.BeforeSendCallBack != null)
            {
                _tcpModel.BeforeSendCallBack();
            }
            try
            {
                action(_tcpServer.AcceptTcpClientAsync().Result.GetStream());
                LogInfo($"异步消息发送成功", _tcpModel.LocalIpEndPoint, _tcpModel.OpenSendLog);
                if (_tcpModel.AfterSendCallBack != null)
                {
                    _tcpModel.AfterSendCallBack();
                }
            }
            catch (Exception e)
            {
                ErrorLog("异步消息发送异常", e, _tcpModel.LocalIpEndPoint);
            }
        }
        #endregion

        #region 客户端连接
        /// <summary>
        /// 获取当前所有已连接的客户端IP
        /// </summary>
        /// <returns></returns>
        public IList<string> GetConnectClint() => _tcpClientDictionary.Keys.ToList();

        #endregion

        #region Stop
        /// <summary>
        /// 释放由 TcpServer 占用的托管和非托管资源。
        /// </summary>
        public void Stop()
        {
            try
            {
                _tcpServer.Stop();
                if (_tcpModel.StopCallBack != null)
                {
                    _tcpModel.StopCallBack(_tcpModel.LocalIpEndPoint);
                }
                LogInfo("Tcp端口已Stop", _tcpModel.LocalIpEndPoint, _tcpModel.OpenOtherLog);
            }
            catch (Exception e)
            {
                ErrorLog("Tcp端口已Stop", e, _tcpModel.LocalIpEndPoint);
            }
        }
        #endregion

        #endregion

        #region Custom Method
        /// <summary>
        /// 初始化TCP Server
        /// </summary>
        /// <exception cref="ArgumentException">参数异常</exception>
        /// <exception cref="ArgumentNullException">参数异常</exception>
        private void InitTcpServer()
        {
            #region Verify
            if (_tcpModel.LocalIpEndPoint is null)
            {
                throw new ArgumentException("请设置本地IP和端口号");
            }
            #endregion

            try
            {
                _tcpServer = new TcpListener(_tcpModel.LocalIpEndPoint);
                _cancelToken = _recvCancelTokenSource.Token;

                if (_tcpModel.AutoConnect)//也可以不做绑定
                {
                    Start();
                }
            }
            catch (Exception e)
            {
                Stop();
                ErrorLog(e.Message, e, _tcpModel.LocalIpEndPoint);
            }
        }

        /// <summary>
        /// 接收数据的处理方法
        /// </summary>
        private void ReceiveStartInit()
        {
            if (_tcpModel.ReceiveByteCallBack == null &&
                _tcpModel.ReceiveIPEndPointCallBack == null &&
                _tcpModel.ReceiveIPPortCallBack == null)
            {
                LogInfo("没有接收消息回调注册，请进行自定义的接收回调处理，推荐使用_tcpServer.CustomeReceive()", _tcpModel.LocalIpEndPoint, _tcpModel.OpenOtherLog);
                return;
            }
            #region 接收回调设置
            Task.Run(() =>
            {
                while (!_tcpModel.ReceiveCanceToken.IsCancellationRequested && !_cancelToken.IsCancellationRequested)
                {
                    if (!Pending)
                    {
                        Thread.Sleep(1000);
                        continue;
                    }
                    Task.Run(() =>
                    {
                        TcpClient client = _tcpServer.AcceptTcpClient();
                        IPEndPoint recIPInfo = ((IPEndPoint)client.Client.RemoteEndPoint);
                        _tcpClientDictionary.Add(recIPInfo.Address.ToString(), client);
                        try
                        {
                            LogInfo("新的连接进入", recIPInfo, _tcpModel.OpenOtherLog);
                            if (_tcpModel.ClientConnectCallBack != null)
                            {
                                _tcpModel.ClientConnectCallBack(recIPInfo);
                            }
                            byte[] receiveBuffer = new byte[_tcpModel.ReceiveBufferSize];
                            NetworkStream stream = client.GetStream();
                            while (!_tcpModel.ReceiveCanceToken.IsCancellationRequested && !_cancelToken.IsCancellationRequested)
                            {
                                if (stream is null)
                                {
                                    Thread.Sleep(1000);
                                    continue;
                                }
                                int recvByteLength = stream.Read(receiveBuffer, 0, receiveBuffer.Length);
                                ///出现异常，客户端断开连接，释放这个Client
                                if (recvByteLength == 0)
                                {
                                    _tcpClientDictionary.Remove(recIPInfo.Address.ToString());
                                    stream.Dispose();
                                    stream = null;
                                    client.Dispose();
                                    client = null;
                                    LogInfo($"客户端断开连接，服务端已释放连接", recIPInfo, _tcpModel.OpenOtherLog);
                                    if (_tcpModel.ClientDisConnectCallBack != null)
                                    {
                                        _tcpModel.ClientDisConnectCallBack(recIPInfo);
                                    }
                                    break;
                                }
                                #region Receive CallBack
                                if (_tcpModel.AfterReceiveCallBack != null)
                                {
                                    _tcpModel.AfterReceiveCallBack();
                                }
                                if (_tcpModel.ReceiveByteCallBack != null)
                                {
                                    _tcpModel.ReceiveByteCallBack(receiveBuffer);
                                }
                                if (_tcpModel.ReceiveByteWithLengthCallBack != null)
                                {
                                    _tcpModel.ReceiveByteWithLengthCallBack(receiveBuffer, recvByteLength);
                                }
                                if (_tcpModel.ReceiveIPEndPointCallBack != null)
                                {
                                    _tcpModel.ReceiveIPEndPointCallBack(recIPInfo, receiveBuffer, recvByteLength);
                                }
                                if (_tcpModel.ReceiveIPPortCallBack != null)
                                {
                                    _tcpModel.ReceiveIPPortCallBack(recIPInfo.Address.ToString(), recIPInfo.Port, receiveBuffer, recvByteLength);
                                }

                                LogInfo($"消息接收成功", recIPInfo, _tcpModel.OpenReceiveLog);
                                #endregion
                            }
                        }
                        catch (Exception e)
                        {
                            ErrorLog("接收线程产生异常", e, recIPInfo);
                        }
                    }, _tcpModel.ReceiveCanceToken);
                }
            });
            LogInfo("初始化TCP成功", _tcpModel.LocalIpEndPoint, _tcpModel.OpenOtherLog);
            #endregion
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
    /// 服务于TCP Server的配置Model
    /// </summary>
    public class TcpServerModel
    {
        /// <summary>
        /// 本地IPEndPoint（ip，端口）
        /// </summary>
        public IPEndPoint LocalIpEndPoint = null;

        /// <summary>
        /// 是否自动开启连接
        /// </summary>
        public bool AutoConnect { get; set; } = false;

        /// <summary>
        /// 接收字节大小，默认1024
        /// </summary>
        public int ReceiveBufferSize { get; set; } = 1024;

        /// <summary>
        /// 接收消息取消Token
        /// </summary>
        public CancellationToken ReceiveCanceToken { get; set; } = default;

        #region 日志开关
        /// <summary>
        /// 控制开启 接收消息 日志回调，默认关闭
        /// </summary>
        public bool OpenReceiveLog { get; set; } = false;
        /// <summary>
        /// 控制开启 发送消息 日志回调，默认关闭
        /// </summary>
        public bool OpenSendLog { get; set; } = false;
        /// <summary>
        /// 控制开启 接收异常 日志回调，默认开启
        /// </summary>
        public bool OpenErrorLog { get; set; } = true;
        /// <summary>
        /// 控制开启 接收其他【开启/关闭连接，释放连接等】 日志回调，默认开启
        /// </summary>
        public bool OpenOtherLog { get; set; } = true;
        #endregion

        #region 数据接收回调
        /// <summary>
        /// 接收回调，返回 IP 端口 和接收字节数组,本次接收的字节数长度
        /// </summary>
        public Action<string, int, byte[], int> ReceiveIPPortCallBack { get; set; } = null;
        /// <summary>
        /// 接收回调，返回 IPEndPoint 和接收字节数组,本次接收的字节数长度
        /// </summary>
        public Action<IPEndPoint, byte[], int> ReceiveIPEndPointCallBack { get; set; } = null;
        /// <summary>
        /// 接收回调，返回 字节数组,本次接收的字节数长度
        /// </summary>
        public Action<byte[], int> ReceiveByteWithLengthCallBack { get; set; } = null;
        /// <summary>
        /// 接收回调，返回 字节数组
        /// </summary>
        public Action<byte[]> ReceiveByteCallBack { get; set; } = null;
        #endregion

        #region 日志回调
        /// <summary>
        /// LogInfo 开头回调注册其一即可
        /// 普通日志回调，返回 产生日志IP 端口  消息
        /// </summary>
        public Action<string, int, string> LogInfoWithIPPortCallBack { get; set; } = null;
        /// <summary>
        /// LogInfo 开头回调注册其一即可
        /// 普通日志回调，返回 产生日志IPEndPoint  消息 
        /// </summary>
        public Action<IPEndPoint, string> LogInfoWithIPCallBack { get; set; } = null;
        /// LogInfo 开头回调注册其一即可
        /// 普通日志回调，返回 日志消息 
        /// </summary>
        public Action<string> LogInfoCallBack { get; set; } = null;
        #endregion

        #region 异常回调
        /// <summary>
        /// Error 开头回调注册其一即可
        /// 异常回调，返回 产生异常IP 端口 异常 错误消息提示（非系统） 
        /// </summary>
        public Action<string, int, Exception, string> ErrorLogWithIPPortCallBack { get; set; } = null;
        /// <summary>
        /// Error 开头回调注册其一即可
        /// 异常回调，返回 产生异常IPEndPoint 异常 错误消息提示（非系统） 
        /// </summary>
        public Action<IPEndPoint, Exception, string> ErrorLogWithIPEndPointCallBack { get; set; } = null;
        /// <summary>
        /// Error 开头回调注册其一即可
        /// 异常回调，返回 异常 错误消息提示（非系统） 
        /// </summary>
        public Action<Exception, string> ErrorLogCallBack { get; set; } = null;
        #endregion

        #region 客户端连接回调
        /// <summary>
        /// 客户端连接成功回调,IPEndPoint为远程连接端IP
        /// </summary>
        public Action<IPEndPoint> ClientConnectCallBack { get; set; } = null;
        /// <summary>
        /// 客户端断开连接回调,IPEndPoint为远程连接端IP
        /// </summary>
        public Action<IPEndPoint> ClientDisConnectCallBack { get; set; } = null;
        #endregion

        #region 发送消息回调
        /// <summary>
        /// 发送消息前回调
        /// </summary>
        public Action BeforeSendCallBack { get; set; } = null;
        /// <summary>
        /// 发送消息后回调
        /// </summary>
        public Action AfterSendCallBack { get; set; } = null;
        #endregion

        #region 接收消息回调
        /// <summary>
        /// 接收数据后会 新开线程回调 且立即触发
        /// </summary>
        public Action AfterReceiveCallBack { get; set; } = null;
        #endregion

        #region 释放资源回调
        /// <summary>
        /// 释放资源回调,IPEndPoint为远程连接端IP
        /// </summary>
        public Action<IPEndPoint> StopCallBack { get; set; } = null;
        #endregion
    }
}
