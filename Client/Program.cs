using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

class Client {
	static void Main() {
		// Create TCP Client, Connect to server
		using var client = new TcpClient();
		client.Connect(IPAddress.Loopback, 8000);
		Console.WriteLine("Server connected!");

		// Create read, write stream
		using var stream = client.GetStream();
		using var reader = new BinaryReader(stream);
		using var writer = new BinaryWriter(stream);

		// Create RSA providers for server, client
		using var serverRSA = new RSACryptoServiceProvider();
		using var clientRSA = new RSACryptoServiceProvider();

		// Read server's public key
		{
			var publicKeyLength = reader.ReadInt32();
			var publicKeyBytes = reader.ReadBytes(publicKeyLength);
			serverRSA.ImportRSAPublicKey(publicKeyBytes, out _);
		}

		// Send client's public key
		{
			var publicKeyBytes = clientRSA.ExportRSAPublicKey();
			writer.Write(publicKeyBytes.Length);
			writer.Write(publicKeyBytes);
		}

		while (true) {
			// Read input from user
			Console.Write("Input:");
			var message = Console.ReadLine() ?? throw new Exception("Please input the message");
			var messageBytes = Encoding.UTF8.GetBytes(message);

			// Encrypt input using server's public key
			var encryptedData = serverRSA.Encrypt(messageBytes, true);

			// Send encrypted data with it's length to server
			writer.Write(encryptedData.Length);
			writer.Write(encryptedData);
			Console.WriteLine($"Sent:{message}");

			// Receive echo data
			var receivedDataLength = reader.ReadInt32();
			var receivedData = reader.ReadBytes(receivedDataLength);
			var decryptedReceivedData = clientRSA.Decrypt(receivedData, true);
			var decrypted = Encoding.UTF8.GetString(decryptedReceivedData);
			Console.WriteLine($"Received:{decrypted}");
		}
	}
}
