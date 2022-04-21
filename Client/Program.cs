using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Text;
using Encoder;

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

    var B = BigIntKeyGeneration(g, b, p);

    s.Send(Encoding.Unicode.GetBytes($"{B},{publicKey.Key1},{publicKey.Key2}"));
    Console.WriteLine($"Отправлен ключ B = {B}.");

    K = BigIntKeyGeneration(A, b, p);

    Console.WriteLine($"Посчитан общий секретный ключ K = {K}");
    Console.WriteLine("Канал готов к передаче данных.");
    Console.WriteLine($"Мой открытый ключ цифровой подписи: {{{publicKey.Key1} {publicKey.Key2}}}");
  //  Console.WriteLine($"Мой закрытый ключ цифровой подписи: {{{privateKey.Key1} {privateKey.Key2}}}");

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
            var messageHash = Hash.Bob_faq6_hash(message);
            var messageHashBytes = BitConverter.GetBytes(messageHash);
            var text = Encoding.Unicode.GetBytes(message);

            var sign = GenerateDigitalSign(messageHashBytes, privateKey);
            //Console.WriteLine("Подпись в хексах: " + BitConverter.ToString(sign));
            //Console.WriteLine("Сообщение в хексах: " + BitConverter.ToString(text));
            //Console.WriteLine("Хэш сообщения в хексах: " + BitConverter.ToString(messageHashBytes));
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

BigInteger BigIntKeyGeneration(BigInteger a, BigInteger b, BigInteger p)
{
    return BigInteger.ModPow(a, b, p);
}

byte[] GenerateDigitalSign(byte[] data, KeyPair keyPair)
{
    var message = new BigInteger(data);
  //  Console.WriteLine("Хэш сообщения в числовом виде:" + message);
    var num = BigInteger.ModPow(message, keyPair.Key1, keyPair.Key2);
  // Console.WriteLine($"Подпись в числовом виде: {message} ^ {keyPair.Key1} mod {keyPair.Key2} = {num}");
    var numBytes = num.ToByteArray();
    var size = BitConverter.GetBytes(numBytes.Length).ToArray()[0];
   // Console.WriteLine($"Размер подписи: {size}");
    var result = new byte[numBytes.Length + 1];
    numBytes.CopyTo(result, 1);
    result[0] = size;
   // Console.WriteLine(BitConverter.ToString(result));
    return result;
}