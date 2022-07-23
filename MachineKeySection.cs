using System;
using System.Security.Cryptography;

namespace EmulateFormsAuthentication
{
    public sealed class MachineKeySection
    {

        /// <summary>
        /// 对cookies里的数据进行加密和解密
        /// </summary>
        /// <param name="fEncrypt">true加密，false解密</param>
        /// <param name="buf">数据</param>
        /// <param name="hasher">sha校验</param>
        /// <param name="isHashAppended">是否做HASH</param>
        /// <param name="symmetric">加密对象</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="CryptographicException"></exception>
        /// <exception cref="Exception"></exception>
        internal static byte[] EncryptOrDecryptData(bool fEncrypt, byte[] buf, HashProvider hasher, bool isHashAppended, SymmetricAlgorithm symmetric)
        {
            if (hasher == null)
            {
                throw new ArgumentNullException("hasher");
            }

            
            if (fEncrypt)
            {
                
                var encryptor = symmetric.CreateEncryptor();
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        bool createIv = true;
                        bool useRandomIv = true;

                        if (createIv)
                        {
                            int ivLength = RoundupNumBitsToNumBytes(symmetric.KeySize);
                            byte[] iv = null;

                            if (hasher != null)
                            {
                                iv = hasher.GetIVHash(buf, ivLength);
                            }
                            //else if (useRandomIv)
                            //{
                            //    iv = new byte[ivLength];
                            //    RandomNumberGenerator.GetBytes(iv);
                            //}

                            // first write the iv.
                            cs.Write(iv, 0, iv.Length);
                        }

                        cs.Write(buf, 0, buf.Length);
                        cs.FlushFinalBlock();

                        byte[] paddedDate = ms.ToArray();
                        cs.Close();

                        return paddedDate;
                    }
                }
            }
            else
            {
                #region  解密

                if (isHashAppended)
                {
                    // need to check the hash signature, and strip it off the end of the byte array.
                    buf = hasher.CheckHashAndRemove(buf);
                    if (buf == null)
                    {
                        // signature verification failed
                        throw new CryptographicException("Signature verification failed");
                    }
                }

                using (var ms = new MemoryStream())
                {
                    using (var decryptor = symmetric.CreateDecryptor())
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                        {
                            cs.Write(buf, 0, buf.Length);

                            cs.FlushFinalBlock();
                            byte[] paddedData = ms.ToArray();
                            cs.Close();

                            // The data contains some random bytes prepended at the start. Remove them.
                            int ivLength = RoundupNumBitsToNumBytes(symmetric.KeySize);
                            int dataLength = paddedData.Length - ivLength;
                            if (dataLength < 0)
                            {
                                throw new Exception($"Unexpected salt length: {ivLength}. Total: {paddedData.Length}");
                            }

                            byte[] decryptedData = new byte[dataLength];
                            Buffer.BlockCopy(paddedData, ivLength, decryptedData, 0, dataLength);
                            return decryptedData;
                        }
                    }
                }

                #endregion
            }



        }


        internal static int RoundupNumBitsToNumBytes(int numBits)
        {
            if (numBits < 0)
                return 0;
            return (numBits / 8) + (((numBits & 7) != 0) ? 1 : 0);
        }
    }
}

