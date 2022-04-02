using Server;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Text;

const int port = 8005;
const string address = "127.0.0.1";
BigInteger K;

var ipPoint = new IPEndPoint(IPAddress.Parse(address), port);

var listenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

try
{
    listenSocket.Bind(ipPoint);

    listenSocket.Listen(1);

    Console.WriteLine("Сервер запущен. Ожидание подключений...");

    var secretKey = GetSharedSecret();

    DataExchange();
}
catch (Exception ex)
{
    Console.WriteLine(ex.Message);
}


BigInteger GetSharedSecret()
{
    var p = PrimeNumbers.List[new Random().Next(PrimeNumbers.List.Count)];
    var g = PrimeNumbers.GetPRoot(p);
    var a = GetRandCount(128);
    Console.WriteLine($"Сгенерирован закрытый ключ a = {a}");

    var A = BigIntKeyGeneration(g, a, p);

    var handler = listenSocket!.Accept();
    Console.WriteLine("Соединение установлено.");

    handler.Send(Encoding.Unicode.GetBytes($"{p},{g},{A}"));
    Console.WriteLine($"Отправлены ключи p = {p}, g = {g} и A = {A}.");

    var data = new byte[256];
    var builder = new StringBuilder();

    do
    {
        var bytes = handler.Receive(data);
        builder.Append(Encoding.Unicode.GetString(data));
    } while (handler.Available > 0);

    var B = BigInteger.Parse(builder.ToString());
    Console.WriteLine($"Получен ключ B = {B}");

    K = BigIntKeyGeneration(B, a, p);
    Console.WriteLine($"Посчитан общий секретный ключ K = {K}");

    handler.Shutdown(SocketShutdown.Both);
    handler.Close();

    return K;

}

BigInteger GetRandCount(int bits)
{
    var random = new Random();
    var count = new byte[bits / 8];
    random.NextBytes(count);
    var result = new BigInteger(count);
    return result > 0 ? result : -result;
}

BigInteger BigIntKeyGeneration(BigInteger a, BigInteger b, BigInteger p)
{
    return BigInteger.ModPow(a, b, p);
}

void DataExchange()
{
    while (true)
    {
        var handler = listenSocket.Accept();

        var builder = new StringBuilder();
        var encryptedData = new byte[256];

        var key = Encoding.Unicode.GetBytes($"{K}");
        var decoder = new RC4(key);

        do
        {
            var bytes = handler.Receive(encryptedData);
            var decryptedData = decoder.Decode(encryptedData, bytes);

            builder.Append(Encoding.Unicode.GetString(decryptedData));
        }
        while (handler.Available > 0);

        Console.WriteLine(DateTime.Now.ToShortTimeString() + ": " + builder.ToString());

        const string message = "Ваше сообщение доставлено.";
        var data = Encoding.Unicode.GetBytes(message);
        handler.Send(data);

        handler.Shutdown(SocketShutdown.Both);
        handler.Close();
    }
}