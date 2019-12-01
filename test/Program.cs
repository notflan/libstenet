using System;
using EncryptedNetwork;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.IO;

namespace test
{
    class Program
    {
        static async Task client()
        {
            try
            {
                Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                await sock.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 24444));

                using (var ens = new EncryptedNetworkStream(sock))
                {
                    await ens.ExchangeAsync();

                    using(var read = await ens.ReadBlockAsync())
                    {
                        Console.WriteLine(await read.ReadStringAsync());


                        using (var write = read.WriteBlock())
                        {
                            write.WriteString("World.");
                        }
                    }
                }
            }
            catch(Exception ex)
            {
                Console.WriteLine("CLIENT: " + ex.Message);
            }
        }
        static Task server()
        {
            return Task.Run(async () =>
            {
                TcpListener listen = new TcpListener(24444);
                listen.Start();

                Task c = client();

                while(true)
                {
                    var sock = await listen.AcceptSocketAsync();

                    using(var ens = new EncryptedNetworkStream(sock))
                    {
                        await ens.ExchangeAsync();

                        using(var write = ens.WriteBlock())
                        {
                            write.WriteString("Hello");
                            using (var read = await write.ReadBlockAsync())
                            {
                                Console.WriteLine(await read.ReadStringAsync());
                            }
                        }
                    }

                    break;
                }
                listen.Stop();

                await c;
            });
        }
        static void Main(string[] args)
        {
            var serv = server();
            serv.Wait();
            if (serv.IsFaulted)
                Console.WriteLine("SERVER FAILED: " + serv.Exception.Message);
            Console.ReadKey();
        }
    }

    static class Extensions
    {
        public static void WriteString(this Stream stream, string str)
        {
            byte[] buf = System.Text.Encoding.UTF8.GetBytes(str);

            var l = buf.Length;
            var num = BitConverter.GetBytes(l);

            stream.Write(num, 0, sizeof(int));
            stream.Write(buf, 0, buf.Length);
        }

        public static async Task<string> ReadStringAsync(this Stream stream)
        {
            byte[] num = new byte[sizeof(int)];

            await stream.ReadAsync(num, 0, sizeof(int));

            int l = BitConverter.ToInt32(num, 0);
            if (l <= 0) throw new ArgumentException(l + " not valid length for string.");

            byte[] buf = new byte[l];
            await stream.ReadAsync(buf, 0, l);

            return System.Text.Encoding.UTF8.GetString(buf);
        }
    }
}
