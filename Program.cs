using Konscious.Security.Cryptography;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TextFileEncrypter
{
    static class Program
    {
        const string FILE_HEADER = "// 42f42f39-ff6f-4f1d-a905-c44be4ba26e6";

        static int Main(string[] args)
        {
            try
            {
                Run(args);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}\n\nDetails:\n{ex}");
                Console.ReadLine();

                return 1;
            }

            return 0;
        }

        static void Run(string[] args)
        {
            if (args.Length != 1)
            {
                throw new Exception($"Expecting exactly one argument (a file path), but found {args.Length} arguments.");
            }

            var filePath = args[0];

            if (!File.Exists(filePath))
            {
                throw new Exception($"File '{filePath}' not found.");
            }

            var fileContents = File.ReadAllText(filePath);

            if (ShouldDecrypt(fileContents))
            {
                Decrypt(filePath, fileContents);
            }
            else
            {
                Encrypt(filePath, fileContents);
            }
        }

        static bool ShouldDecrypt(string fileContents)
        {
            return fileContents.StartsWith(FILE_HEADER);
        }

        static void Encrypt(string filePath, string fileContents)
        {
            Console.WriteLine($"Encrypting '{filePath}'...");
            var password = GetPassword("a");
            var iterationCount = GetNumber("iteration count");
            var memorySize = GetNumber("memory size in megabytes");
            var salt = GetSalt();
            var encryptionKey = GetEncryptionKey(salt, iterationCount, memorySize, password);
            Encrypt(filePath, fileContents, encryptionKey, salt, iterationCount, memorySize);
            Console.WriteLine($"Successfully encrypted the contents of the file.");
            PrintClosingMessage();
        }

        static string GetPassword(string article)
        {
            Console.WriteLine($"Please enter {article} password:");
            var password = ReadLine();
            Console.Clear();

            return password.Length == 0 ? " " : password;
        }

        static string ReadLine()
        {
            return Console.ReadLine() ?? throw new Exception($"Unexpected end of stream.");
        }

        static int GetNumber(string name)
        {
            while (true)
            {
                Console.WriteLine($"Please enter the {name} to use in the key stretching algorithm:");
                var text = ReadLine();

                if (text.Length == 0)
                {
                    return 1;
                }

                if (int.TryParse(text, out var value) && value >= 1)
                {
                    return value;
                }

                Console.WriteLine($"Invalid value '{text}' found.");
            }
        }

        static byte[] GetSalt()
        {
            var salt = new byte[32];
            using var random = new RNGCryptoServiceProvider();
            random.GetBytes(salt);

            return salt;
        }

        static byte[] GetEncryptionKey(byte[] salt, int iterationCount, int memorySize, string password)
        {
            Console.WriteLine($"Stretching password using {iterationCount:N0} iteration(s) and {memorySize:N0} megabyte(s)...");
            var stopwatch = Stopwatch.StartNew();
            var argon2 = new Argon2d(Encoding.UTF8.GetBytes(password))
            {
                MemorySize = 1024 * memorySize,
                DegreeOfParallelism = 8,
                Iterations = iterationCount,
                Salt = salt,
            };
            var encryptionKey = argon2.GetBytes(32);
            Console.WriteLine($"Stretching password took {stopwatch.ElapsedMilliseconds:N0} ms.");

            return encryptionKey;
        }

        static void Encrypt(
            string filePath,
            string fileContents,
            byte[] encryptionKey,
            byte[] salt,
            int iterationCount,
            int memorySize)
        {
            using var aes = new AesGcm(encryptionKey);
            var nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
            using var random = new RNGCryptoServiceProvider();
            random.GetBytes(nonce);
            var plaintext = Encoding.UTF8.GetBytes(fileContents);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[AesGcm.TagByteSizes.MaxSize];
            aes.Encrypt(nonce, plaintext, ciphertext, tag);
            var state = new State(salt, iterationCount, memorySize, nonce, tag, ciphertext);
            var json = JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(filePath, FILE_HEADER + Environment.NewLine + json);
        }

        static void PrintClosingMessage()
        {
            Console.WriteLine("Press any key to exit the program...");
            Console.ReadLine();
        }

        static void Decrypt(string filePath, string fileContents)
        {
            Console.WriteLine($"Decrypting '{filePath}'...");
            var state = GetState(fileContents);
            var password = GetPassword("the");
            var encryptionKey = GetEncryptionKey(state.Salt, state.IterationCount, state.MemorySize, password);
            var plaintext = Decrypt(state, encryptionKey);
            var text = Encoding.UTF8.GetString(plaintext);
            Console.WriteLine("File contents:");
            Console.WriteLine(text);
            PrintClosingMessage();
            Console.Clear();
        }

        static State GetState(string fileContents)
        {
            var options = new JsonSerializerOptions { ReadCommentHandling = JsonCommentHandling.Skip };

            return JsonSerializer.Deserialize<State>(fileContents, options) ?? throw new Exception("JSON deserialization returned null.");
        }

        static byte[] Decrypt(State state, byte[] encryptionKey)
        {
            using var aes = new AesGcm(encryptionKey);
            var plaintext = new byte[state.Ciphertext.Length];
            aes.Decrypt(state.Nonce, state.Ciphertext, state.Tag, plaintext);

            return plaintext;
        }

        record State(byte[] Salt, int IterationCount, int MemorySize, byte[] Nonce, byte[] Tag, byte[] Ciphertext);
    }
}
