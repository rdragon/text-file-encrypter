# Text File Encrypter
Encrypt or decrypt a single text file using AES-256-GCM with a key that is stretched using [Argon2](https://en.wikipedia.org/wiki/Argon2).

# Quick start
- Install [.NET 7.0 SDK](https://dotnet.microsoft.com/download/dotnet/7.0)
- Encrypt `README.md`: Run `dotnet run -- README.md`. You will be asked to provide a password, an iteration count and a memory size. This will encrypt the contents of `README.md` (the file is modified).
- Decrypt `README.md`: Run `dotnet run -- README.md`. You will be asked to provide a password. If the password is correct, then the original contents of the file are written to stdout.

# Notes
- The application uses the first line of the input file to determine whether to encrypt or decrypt the contents.
- If you generate an executable of the program then you can drag & drop a file on the executable to start the encryption/decryption of that file.
- This application does not perform well on large text files because it uses string and byte arrays instead of streams and spans, and because it uses JSON to store the ciphertext.
- This application does not provide protection against [side-channel attacks](https://en.wikipedia.org/wiki/Side-channel_attack). If you need protection against such attacks, then use the class `Argon2i` or `Argon2id` instead of the class `Argon2d` (see `Program.cs`).
