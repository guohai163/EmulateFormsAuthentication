using System;
using System.Security.Cryptography;
/// <summary>
/// 参考源码 https://github.com/microsoft/referencesource/blob/master/System.Web/Security/FormsAuthentication.cs
/// 这是.net4。5的源码，可能会和2。0有所区别，我这里尽量还原
/// </summary>
namespace EmulateFormsAuthentication
{
    public class FormsAuthentication
    {
        private const int MAX_TICKET_LENGTH = 4096;


        private HashProvider _hasher;

        private SymmetricAlgorithm _symmetric;

        /// <summary>
        /// 构造方法
        /// </summary>
        /// <param name="decryptionKey">加密解密KEy</param>
        /// <param name="validationKey">验证的KEY</param>
        /// <param name="encryptMethod">加密方法，默认3DES</param>
        /// <param name="validationMethod">验证方法默认sha1</param>
        public FormsAuthentication(string decryptionKey, string validationKey, EncryptMethodEnumeration encryptMethod = EncryptMethodEnumeration.TripleDES,
            ValidationMethodEnumeration validationMethod = ValidationMethodEnumeration.SHA1)
        {
            byte[] descriptionKeyBytes = CryptoUtil.HexToBinary(decryptionKey);
            byte[] validationKeyBytes = CryptoUtil.HexToBinary(validationKey);

            _hasher = HashProvider.Create(validationKeyBytes, validationMethod);

            _symmetric = GetSymmetric(encryptMethod);

            _symmetric.Key = descriptionKeyBytes;

        }

        private SymmetricAlgorithm GetSymmetric(EncryptMethodEnumeration encryptMethod)
        {
            switch (encryptMethod)
            {
                case EncryptMethodEnumeration.TripleDES:
                    return TripleDES.Create();
                case EncryptMethodEnumeration.AES:
                    return Aes.Create();
                default:
                    return TripleDES.Create();
            }
        }

        /// <devdoc>
        ///    <para>Given an encrypted authenitcation ticket as
        ///       obtained from an HTTP cookie, this method returns an instance of a
        ///       FormsAuthenticationTicket class.</para>
        /// </devdoc>
        public FormsAuthenticationTicket Decrypt(string encryptedTicket)
        {
            if (String.IsNullOrEmpty(encryptedTicket) || encryptedTicket.Length > MAX_TICKET_LENGTH)
                throw new Exception("encryptedTicket");

            byte[] bBlob = null;

            if ((encryptedTicket.Length % 2) == 0)
            { // Could be a hex string
                try
                {
                    bBlob = CryptoUtil.HexToBinary(encryptedTicket);
                }
                catch { }
            }
            if (bBlob == null || bBlob.Length < 1)
                throw new Exception("encryptedTicket");


            // TODO: 
            byte[] decryptedCookie = MachineKeySection.EncryptOrDecryptData(false, bBlob, _hasher, true, _symmetric);

            int ticketLength = decryptedCookie.Length - _hasher.HashSize;


            bool validHash = _hasher.CheckHash(decryptedCookie, ticketLength);

            if (!validHash)
            {
                throw new Exception("Invalid Hash");
            }


            return FormsAuthenticationTicketSerializer.Deserialize(decryptedCookie, ticketLength);
        }


        /// <devdoc>
        ///    Given a FormsAuthenticationTicket, this
        ///    method produces a string containing an encrypted authentication ticket suitable
        ///    for use in an HTTP cookie.
        /// </devdoc>
        public String Encrypt(FormsAuthenticationTicket ticket)
        {
            if (ticket == null)
                throw new ArgumentNullException("ticket");

            byte[] bBlob = FormsAuthenticationTicketSerializer.Serialize(ticket);

            if (bBlob == null)
                return null;

            byte[] hashBlob = _hasher.GetHMACSHAHash(bBlob, null, 0, bBlob.Length);
            if (hashBlob == null)
            {
                throw new Exception("Unable to get HMACSHAHash");
            }

            // create a new byte array big enough to store the ticket data, and the hash data which is appended to the end.
            byte[]  cookieBlob = new byte[hashBlob.Length + bBlob.Length];
            Buffer.BlockCopy(bBlob, 0, cookieBlob, 0, bBlob.Length);
            Buffer.BlockCopy(hashBlob, 0, cookieBlob, bBlob.Length, hashBlob.Length);

            byte[] encryptedCookieBlob = MachineKeySection.EncryptOrDecryptData(true, cookieBlob, _hasher, true, _symmetric);

            if (encryptedCookieBlob == null)
            {
                throw new Exception("Unable to encrypt cookie");
            }

            // sign the encrypted blob 

                hashBlob = _hasher.GetHMACSHAHash(encryptedCookieBlob, null, 0, encryptedCookieBlob.Length);

                if (hashBlob == null)
                {
                    throw new Exception("Unable to sign cookie");
                }

                // create a new byte array big enough to store the cookie data, and the hash which is appended to the end.
                cookieBlob = new byte[hashBlob.Length + encryptedCookieBlob.Length];
                Buffer.BlockCopy(encryptedCookieBlob, 0, cookieBlob, 0, encryptedCookieBlob.Length);
                Buffer.BlockCopy(hashBlob, 0, cookieBlob, encryptedCookieBlob.Length, hashBlob.Length);
            

            // now convert the binary encrypted cookie data and return hex value.
            return CryptoUtil.BinaryToHex(cookieBlob);
        }
    }
}

