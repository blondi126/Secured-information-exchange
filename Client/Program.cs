using Encoder;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Text;

const int port = 8005;
const string address = "127.0.0.1";

BigInteger K;

var publicKey = RSA.GetOpenKey();
var privateKey = RSA.GetCloseKey();
var ipPoint = new IPEndPoint(IPAddress.Parse(address), port);

try
{
    GetSharedSecret(ipPoint);
    DataExchange();
}
catch (Exception ex)
{
    Console.WriteLine(ex.Message);
}

void GetSharedSecret(EndPoint ip)
{
    var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
    s.Connect(ip);
    Console.WriteLine("Устанавливаем соединение.");

    var b = GetRandCount(128);
    Console.WriteLine($"Сгенерирован закрытый ключ b = {b}");

    var data = new byte[256];
    var builder = new StringBuilder();
    do
    {
        var bytes = s.Receive(data, data.Length, 0);
        builder.Append(Encoding.Unicode.GetString(data, 0, bytes));
    } while (s.Available > 0);

    var keys = builder.ToString().Split(',');
    var p = int.Parse(keys[0]);
    var g = int.Parse(keys[1]);
    var A = BigInteger.Parse(keys[2]);

    Console.WriteLine($"Получены ключи p = {p}, g = {g} и A = {A}.");

    var B = KeyGeneration(g, b, p);

    s.Send(Encoding.Unicode.GetBytes($"{B},{publicKey.Key1},{publicKey.Key2}"));
    Console.WriteLine($"Отправлен ключ B = {B}.");

    K = KeyGeneration(A, b, p);

    Console.WriteLine($"Посчитан общий секретный ключ K = {K}");
    Console.WriteLine("Канал готов к передаче данных.");
    Console.WriteLine($"Мой открытый ключ цифровой подписи: {{{publicKey.Key1} {publicKey.Key2}}}");

    s.Shutdown(SocketShutdown.Both);
    s.Close();
}

void DataExchange()
{
    while (true)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        socket.Connect(ipPoint!);

        Console.WriteLine("\nВведите сообщение:");
        var message = Console.ReadLine();

        if (!string.IsNullOrEmpty(message))
        {
            var text = Encoding.Unicode.GetBytes(message);

            var messageHash = Hash.Bob_faq6_hash(message);
            var messageHashBytes = BitConverter.GetBytes(messageHash);
            var sign = RSA.GenerateDigitalSign(messageHashBytes, privateKey);

            var data = sign.Concat(text).ToArray();

            var key = Encoding.Unicode.GetBytes($"{K}");
            var encoder = new RC4(key);

            var encryptedData = encoder.Encode(data);
            socket.Send(encryptedData);

            data = new byte[256];
            var builder = new StringBuilder();
            do
            {
                var bytes = socket.Receive(data, data.Length, 0);
                builder.Append(Encoding.Unicode.GetString(data, 0, bytes));
            } while (socket.Available > 0);

            Console.WriteLine("Ответ сервера: " + builder.ToString());
        }
        socket.Shutdown(SocketShutdown.Both);
        socket.Close();
    }
}

BigInteger GetRandCount(int bits)
{
    var random = new Random();
    var count = new byte[bits / 8];
    random.NextBytes(count);
    var result = new BigInteger(count);
    return result > 0 ? result : -result;
}

BigInteger KeyGeneration(BigInteger a, BigInteger b, BigInteger p)
{
    return BigInteger.ModPow(a, b, p);
}