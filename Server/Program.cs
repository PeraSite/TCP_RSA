using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

class Server {
	private static void Main() {
		// Create TCP Server, listen on port 8000
		var listener = new TcpListener(IPAddress.Any, 8000);
		listener.Start();
		Console.WriteLine("Server started!");

		while (true) {
			// Accept client connection
			using var client = listener.AcceptTcpClient();
			Console.WriteLine("Client connected!");

			// Create read/write streams
			using var stream = client.GetStream();
			using var reader = new BinaryReader(stream);
			using var writer = new BinaryWriter(stream);

			// Create RSA providers for client and server
			using RSACryptoServiceProvider clientRSA = new RSACryptoServiceProvider();
			using RSACryptoServiceProvider serverRSA = new RSACryptoServiceProvider();

			// Send server's public key to client
			{
				var publicKeyBytes = serverRSA.ExportRSAPublicKey();
				writer.Write(publicKeyBytes.Length);
				writer.Write(publicKeyBytes);
			}

			// Receive client's public key
			{
				var publicKeyLength = reader.ReadInt32();
				var publicKeyBytes = reader.ReadBytes(publicKeyLength);
				clientRSA.ImportRSAPublicKey(publicKeyBytes, out _);
			}

			while (client.Connected) {
				// Receive encrypted data from client
				var encryptedDataLength = reader.ReadInt32();
				var encryptedData = reader.ReadBytes(encryptedDataLength);

				// Decrypt data using server's private key
				var decryptedData = serverRSA.Decrypt(encryptedData, true);
				var message = Encoding.UTF8.GetString(decryptedData);
				Console.WriteLine("Received: " + message);

				// Echo message back to client
				var encryptedMessage = clientRSA.Encrypt(Encoding.UTF8.GetBytes($"ECHO_{message}"), true);
				writer.Write(encryptedMessage.Length);
				writer.Write(encryptedMessage);
			}
		}
	}
}
