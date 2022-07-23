using System.Security.Cryptography;

namespace EmulateFormsAuthentication
{
    internal class SHA1HashProvider : HashProvider
    {
        const int Sha1HashSize = 20;
        const int Sha1KeySize = 64;

        public SHA1HashProvider(byte[] validationKey)
            : base(validationKey, Sha1HashSize, Sha1KeySize)
        {
        }

        protected override HMAC CreateHasher(byte[] key)
        {
            return new HMACSHA1(key);
        }
    }
}