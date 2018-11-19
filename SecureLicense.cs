using System;
using System.Collections.Generic;
using System.Text;

namespace Encryptico
{
    [Serializable]
    internal class SecureLicense
    {
        internal string Key { get; }
        internal string Password { get; }
        internal int Iterations { get; }
        internal int RandomSaltLength { get; }

        internal SecureLicense(string key, string password, int iterations, int randomSaltLength)
        {
            Key = key;
            Password = password;
            Iterations = iterations;
            RandomSaltLength = randomSaltLength;
        }
    }
}
