using System;
using System.IO;
using System.Security.Cryptography;

namespace Encryptico
{
    public class DRMValidator
    {
        private string Key, Password, FilePath;
        private int Iterations, RandomSaltLength;

        // Unique salt will ensure unique validity
        private const string UniqueSalt = "gAHhKOmwUty8ZJb1gYbQOQ==";

        public DRMValidator(string key, string password, int iterations, int randomSaltLength)
        {
            if (string.IsNullOrEmpty(key) || string.IsNullOrEmpty(password) || iterations < 1 || randomSaltLength < 1) { throw new ArgumentNullException(); }

            Key = key;
            Password = password;
            Iterations = iterations;
            RandomSaltLength = randomSaltLength;
        }
        public DRMValidator(string filePath)
        {
            if (string.IsNullOrEmpty(filePath)) { throw new ArgumentNullException(); }
            FilePath = filePath;
        }
        public bool IsValid()
        {
            // Convert the key provided into a byte array
            byte[] hashBytes;  
            try
            {
                hashBytes = Convert.FromBase64String(Key);
            } 
            catch
            {
                return false;
            }

            // Initialize a byte array for our random salt.
            byte[] salt = new byte[RandomSaltLength];

            // Parse the salt out of the key hash
            Array.Copy(hashBytes, 0, salt, 0, RandomSaltLength);
          
            // Calculate the hash
            byte[] hash = new Rfc2898DeriveBytes(Password, salt, Iterations).GetBytes(hashBytes.Length - salt.Length);

            // Verify the hash
            for (int i = 0; i < hash.Length; i++)
            {
                if (hashBytes[i + salt.Length] != hash[i])
                {
                    return false;
                }
            }
            return true;
        }

        public static string GenerateKey(string password, int iterations, int saltLength)
        {
            byte[] salt = GenerateRandomSalt(saltLength);
            byte[] hash = new Rfc2898DeriveBytes(password, salt, iterations).GetBytes(saltLength);
            byte[] hashBytes = new byte[saltLength * 2];

            Array.Copy(salt, 0, hashBytes, 0, saltLength);
            Array.Copy(hash, 0, hashBytes, saltLength, saltLength);

            return Convert.ToBase64String(hashBytes);
        }
        private static byte[] GenerateRandomSalt(int length)
        {
            var key = new byte[length];
            using (var provider = new RNGCryptoServiceProvider())
            {
                provider.GetBytes(key);
            }
            return key;
        }
        private bool IsValid(SecureLicense license)
        {
            byte[] hashBytes = Convert.FromBase64String(license.Key);
            byte[] salt = new byte[license.RandomSaltLength];

            Array.Copy(hashBytes, 0, salt, 0, license.RandomSaltLength);
            
            byte[] hash = new Rfc2898DeriveBytes(license.Password, salt, license.Iterations).GetBytes(hashBytes.Length - salt.Length);
            
            for (int i = 0; i < hash.Length; i++)
            {
                if (hashBytes[i + salt.Length] != hash[i])
                {
                    return false;
                }
            }
            return true;
        }
        public bool IsLocalLicenseValid()
        {
            string licensePath = FilePath;

            if (string.IsNullOrEmpty(licensePath)) { throw new ArgumentNullException(); }
            if (!File.Exists(licensePath)) { return false; }

            var license = ReadFromBinaryFile<SecureLicense>(licensePath);

            return IsValid(license);
        }
        public void GenerateLicense(string filePath)
        {
            var license = new SecureLicense(Key, Password, Iterations, RandomSaltLength);
            string directory = Path.GetDirectoryName(filePath);

            // If file name not specified, give a default file name
            string fileName = (!string.IsNullOrEmpty(Path.GetFileName(filePath)) ? Path.GetFileName(filePath) : "license.lic");

            // Create the directory if it does not exist
            if (!Directory.Exists(directory)) { Directory.CreateDirectory(directory); }

            // Combine the directories, for a full write path
            directory = Path.Combine(directory, fileName);

            // Write our license file
            WriteToBinaryFile(directory, license);
        }
        private void WriteToBinaryFile<T>(string filePath, T objectToWrite, bool append = false)
        {
            using (Stream stream = File.Open(filePath, append ? FileMode.Append : FileMode.Create))
            {
                var binaryFormatter = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
                binaryFormatter.Serialize(stream, objectToWrite);
            }
        }
        private T ReadFromBinaryFile<T>(string filePath)
        {
            using (Stream stream = File.Open(filePath, FileMode.Open))
            {
                var binaryFormatter = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
                return (T)binaryFormatter.Deserialize(stream);
            }
        }
    }
}
