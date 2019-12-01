using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace EncryptedNetwork
{
    public unsafe struct AESKey
    {
        public const int KeySize = 32;
        public const int IVSize = 16;

        internal fixed byte key[KeySize];
        internal fixed byte iv[IVSize];

        /// <summary>
        /// The Key (256 bit)
        /// </summary>
        public byte[] Key
        {
            get
            {
                byte[] bytes = new byte[KeySize];
                fixed (byte* k = key)
                {
                    Marshal.Copy((IntPtr)k, bytes, 0, KeySize);
                }
                return bytes;
            }
            set
            {
                if (value.Length != KeySize) throw new ArgumentException(nameof(value) + " must be exaclty " + KeySize + " bytes (not " + value.Length + ")");
                fixed (byte* k = key)
                {
                    Marshal.Copy(value, 0, (IntPtr)k, KeySize);
                }
            }
        }

        /// <summary>
        /// The IV (128 bits)
        /// </summary>
        public byte[] IV
        {
            get
            {
                byte[] bytes = new byte[IVSize];
                fixed (byte* k = iv)
                {
                    Marshal.Copy((IntPtr)k, bytes, 0, IVSize);
                }
                return bytes;
            }
            set
            {
                if (value.Length != IVSize) throw new ArgumentException(nameof(value) + " must be exaclty " + IVSize + " bytes (not " + value.Length + ")");
                fixed (byte* k = iv)
                {
                    Marshal.Copy(value, 0, (IntPtr)k, IVSize);
                }
            }
        }


        /// <summary>
        /// Binary serialisation of this key
        /// </summary>
        public byte[] BinaryData
        {
            get
            {
                return this.ToByteArrayUnmanaged();
            }
            set
            {
                if (value.Length < sizeof(AESKey)) throw new ArgumentException(nameof(value) + " must be at least " + sizeof(AESKey) + " bytes (not " + value.Length + ")");
                fixed (AESKey* k = &this)
                {
                    Marshal.Copy(value, 0, (IntPtr)k, sizeof(AESKey));
                }
            }
        }

        /// <summary>
        /// Create a new key
        /// </summary>
        /// <returns>The new AES Key</returns>
        public static AESKey NewKey()
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] buffer = new byte[sizeof(AESKey)];
            rng.GetBytes(buffer);
            rng.Dispose();
            return buffer.ToStructureUnmanaged<AESKey>();
        }

        /// <summary>
        /// Set the key and iv to an AesCryptoServiceProvider
        /// </summary>
        /// <param name="r">The CSP</param>
        public void ToCSP(AesCryptoServiceProvider r)
        {
            r.KeySize = 256;
            r.BlockSize = 128;

            r.Key = Key;
            r.IV = IV;
        }

        /// <summary>
        /// Get the key and iv from and AESCryptoServiceProvider
        /// </summary>
        /// <param name="r">The CSP</param>
        public void FromCSP(AesCryptoServiceProvider r)
        {
            Key = r.Key;
            IV = r.IV;
        }
        /// <summary>
        /// Initialise a new AESKey from an AESCryptoServiceProvider
        /// </summary>
        /// <param name="aes">The AES key</param>
        public AESKey(AesCryptoServiceProvider aes)
        {
            FromCSP(aes);
        }
    }
}
