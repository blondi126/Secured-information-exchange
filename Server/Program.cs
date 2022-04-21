using Encoder;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Text;

const int port = 8005;
const string address = "127.0.0.1";

BigInteger K;

var publicClientKey = new KeyPair();
var ipPoint = new IPEndPoint(IPAddress.Parse(address), port);
var listenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

try
{
    listenSocket.Bind(ipPoint);
    listenSocket.Listen(1);
    Console.WriteLine("Сервер запущен. Ожидание подключений...");

    GetSharedSecret();
    DataExchange();
}
catch (Exception ex)
{
    Console.WriteLine(ex.Message);
}

void GetSharedSecret()
{
    var p = PrimeNumbers.GetRandomNum();
    var g = PrimeNumbers.GetPRoot(p);
    var a = GetRandCount(128);
    Console.WriteLine($"Сгенерирован закрытый ключ a = {a}");

    var A = BigIntKeyGeneration(g, a, p);

    var handler = listenSocket!.Accept();
    Console.WriteLine("Устанавливаем соединение.");

    handler.Send(Encoding.Unicode.GetBytes($"{p},{g},{A}"));
    Console.WriteLine($"Отправлены ключи p = {p}, g = {g} и A = {A}.");

    var data = new byte[256];
    var builder = new StringBuilder();

    do
    {
        var bytes = handler.Receive(data);
        builder.Append(Encoding.Unicode.GetString(data));
    } while (handler.Available > 0);

    var keys = builder.ToString().Split(',');
    var B = BigInteger.Parse(keys[0]);
    publicClientKey.Key1 = long.Parse(keys[1]);
    publicClientKey.Key2 = long.Parse(keys[2]);

    Console.WriteLine($"Получен ключ B = {B}");

    K = BigIntKeyGeneration(B, a, p);
    Console.WriteLine($"Посчитан общий секретный ключ K = {K}");
    Console.WriteLine("Канал готов к передаче данных.\n");

    handler.Shutdown(SocketShutdown.Both);
    handler.Close();
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

        byte[] sign;
        do
        {
            var bytes = handler.Receive(encryptedData);
            var decryptedData = decoder.Decode(encryptedData, bytes);

            var signSize = decryptedData.First();

            sign = decryptedData.Skip(1).Take(signSize).ToArray();

            var text = decryptedData.Skip(signSize + 1).ToArray();
            builder.Append(Encoding.Unicode.GetString(text));
        }
        while (handler.Available > 0);

        var receivedMessage = builder.ToString();
        var messageHash = Hash.Bob_faq6_hash(receivedMessage);
        var messageHashBytes = BitConverter.GetBytes(messageHash);

        if (VerifySignature(sign, messageHashBytes, publicClientKey))
            Console.WriteLine(DateTime.Now.ToShortTimeString() + ": " + receivedMessage);
        else
            Console.WriteLine("The digital signature has been violated.");

        const string message = "Ваше сообщение доставлено.";
        var data = Encoding.Unicode.GetBytes(message);
        handler.Send(data);

        handler.Shutdown(SocketShutdown.Both);
        handler.Close();
    }
}

bool VerifySignature(byte[] signature, byte[] messageHash, KeyPair keyPair)
{
    var sign = new BigInteger(signature);

    var messagePrototype = BigInteger.ModPow(sign, keyPair.Key1, keyPair.Key2);

    return messagePrototype == new BigInteger(messageHash);
}