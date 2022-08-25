using System.IO;
using Microsoft.Extensions.Configuration;


namespace TCPUDP.Helper
{
    internal class Program
    {
        private static readonly IConfigurationRoot _configuration;
        static Program()
        {
            var builder = new ConfigurationBuilder()
                                .SetBasePath(Directory.GetCurrentDirectory())
                                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true);

            _configuration = builder.Build();
        }
        static void Main(string[] args)
        {
            #region TcpServer
            //TcpServerHelper tcpServer = new TcpServerHelper(s =>
            //{
            //    s.LocalIpEndPoint = new IPEndPoint(IPAddress.Parse(_configuration["TcpIP"]), Convert.ToInt32(_configuration["TcpPort"]));
            //    ///是否开启自动连接
            //    s.AutoConnect = true;
            //    ///接收回调
            //    s.ReceiveIPPortCallBack = (ip, port, bytes, count) => Console.WriteLine($"ServerReceive {ip},{port} {Encoding.ASCII.GetString(bytes)}");

            //    s.ClientConnectCallBack = ipInfo => Console.WriteLine($"有新的客户端连接进入 ip：{ipInfo.Address.ToString()},port:{ipInfo.Port}");
            //    s.ClientDisConnectCallBack = ipInfo => Console.WriteLine($"有客户端断开连接 ip：{ipInfo.Address.ToString()},port:{ipInfo.Port}");

            //    //开启接收和发送日志回调开关
            //    s.OpenReceiveLog = true;
            //    s.OpenSendLog = true;

            //    //开启普通和异常日志回调
            //    s.LogInfoWithIPPortCallBack = (ip, port, msg) => Console.WriteLine($"Log:{msg},{ip},{port}");
            //    s.ErrorLogWithIPPortCallBack = (ip, port, exception, msg) => Console.WriteLine($"Error:{msg},{ip},{port}");
            //});
            //while (true)
            //{
            //    tcpServer.Send("192.168.0.159", Encoding.ASCII.GetBytes("Hello tcp 屋里哇啦啊啊啊啊啊"));
            //    Thread.Sleep(1000);
            //}
            #endregion

            #region TCP CLient
            //TcpClientHelper tcp = new TcpClientHelper(tcp =>
            //{
            //    ///本地/远程IP
            //    tcp.LocalIpEndPoint = new IPEndPoint(IPAddress.Parse("192.168.0.159"), 5010);
            //    tcp.RemoteIpEndPoint = new IPEndPoint(IPAddress.Parse("192.168.0.159"), 5011);

            //    ///是否开启自动连接
            //    tcp.AutoConnect = true;
            //    ///接收回调
            //    tcp.ReceiveIPPortCallBack = (ip, port, bytes) => Console.WriteLine($"Receive {ip},{port} {Encoding.ASCII.GetString(bytes)}");
            //    ///重连次数， -1无限重连
            //    tcp.ReConnectCount = 5;
            //    tcp.ReConnectTime = 3000;///重连间隔（毫秒）

            //    //开启接收和发送日志回调开关
            //    tcp.OpenReceiveLog = true;
            //    tcp.OpenSendLog = true;

            //    //开启普通和异常日志回调
            //    tcp.LogInfoWithIPPortCallBack = (ip, port, msg) => Console.WriteLine($"Log:{msg},{ip},{port}");
            //    tcp.ErrorLogWithIPPortCallBack = (ip, port, exception, msg) => Console.WriteLine($"Error:{msg},{ip},{port}");
            //});

            //while (true)
            //{
            //    tcp.Send(Encoding.ASCII.GetBytes("Hello tcp hahahahaaha"));
            //    Thread.Sleep(1000);
            //}
            #endregion

            #region UDP
            //CancellationTokenSource cancellationToken = new CancellationTokenSource();
            //UdpHelper uDPClient = new UdpHelper(udp =>
            //{
            //    //本地端口
            //    udp.LocalIpEndPoint = new IPEndPoint(IPAddress.Parse("192.168.10.10"), 5010);
            //    //udp.RemoteIpEndPoint = new IPEndPoint(IPAddress.Parse("192.168.0.159"), 5011);

            //    //取消接收Token
            //    udp.ReceiveCancellationToken = cancellationToken.Token;

            //    //接收回调
            //    udp.ReceiveIPPortCallBack = (ip, port, bytes) =>
            //    {
            //        Console.WriteLine(ip);
            //        Console.WriteLine(port);
            //        Console.WriteLine(Encoding.ASCII.GetString(bytes));
            //    };

            //    udp.OpenErrorLog = true;
            //    udp.OpenOtherLog = true;

            //    ///设置永久重连，2秒尝试一次
            //    udp.ReConnectCount = -1;
            //    udp.ReConnectTime = 2000;

            //    //异常日志
            //    udp.ErrorLogCallBack = (exception, suggestMsg) =>
            //                    Console.WriteLine($"{suggestMsg}");
            //    //收发消息 普通日志
            //    udp.LogInfoWithIPCallBack = (ipEndPoint, logMsg) =>
            //                    Console.WriteLine($"{ipEndPoint.Address},{ipEndPoint.Port},{logMsg}");
            //});
            //while (true)
            //{
            //    uDPClient.Send(Encoding.ASCII.GetBytes("nihaowa"), new IPEndPoint(IPAddress.Parse("192.168.0.159"), 5013));

            //    Thread.Sleep(5000);
            //    //cancellationToken.Cancel();
            //    //Console.WriteLine("finish");
            //}
            #endregion
        }

    }
}
