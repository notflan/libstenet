using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace EncryptedNetwork
{
    public unsafe struct RSAPublicKey
    {
        public const int ModulusSize = 128;
        public const int ExponentSize = 3;

        internal fixed byte mod[ModulusSize];
        internal fixed byte exp[ExponentSize];

        /// <summary>
        /// The modulus of this key
        /// </summary>
        public byte[] Modulus
        {
            get
            {
                byte[] bytes = new byte[ModulusSize];
                fixed (byte* m = mod)
                {
                    Marshal.Copy((IntPtr)m, bytes, 0, ModulusSize);
                }
                return bytes;
            }
            set
            {
                if (value.Length != ModulusSize) throw new ArgumentException(nameof(value) + " must be exaclty " + ModulusSize + " bytes (not " + value.Length + ")");
                fixed (byte* m = mod)
                {
                    Marshal.Copy(value, 0, (IntPtr)m, ModulusSize);
                }
            }
        }
        /// <summary>
        /// The public exponent of this key
        /// </summary>
        public byte[] Exponent
        {
            get
            {
                byte[] bytes = new byte[ExponentSize];
                fixed (byte* m = exp)
                {
                    Marshal.Copy((IntPtr)m, bytes, 0, ExponentSize);
                }
                return bytes;
            }
            set
            {
                if (value.Length != ExponentSize) throw new ArgumentException(nameof(value) + " must be exaclty " + ExponentSize + " bytes (not " + value.Length + ")");
                fixed (byte* m = exp)
                {
                    Marshal.Copy(value, 0, (IntPtr)m, ExponentSize);
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
                if (value.Length < sizeof(RSAPublicKey)) throw new ArgumentException(nameof(value) + " must be at least " + sizeof(RSAPublicKey) + " bytes (not " + value.Length + ")");
                fixed (RSAPublicKey* k = &this)
                {
                    Marshal.Copy(value, 0, (IntPtr)k, sizeof(RSAPublicKey));
                }
            }
        }

        /// <summary>
        /// Set the public key to a RSACryptoServiceProvider
        /// </summary>
        /// <param name="csp">The CSP to set the key to</param>
        public void ToCSP(RSACryptoServiceProvider csp)
        {
            var p = csp.ExportParameters(false);
            p.Modulus = Modulus;
            p.Exponent = Exponent;
            csp.ImportParameters(p);
        }
        /// <summary>
        /// Get the public key information from an RSACryptoServiceProvider and return it in an RSAPublicKey struct
        /// </summary>
        /// <param name="csp">The CSP</param>
        /// <returns>A new RSAPublicKey struct</returns>
        public static RSAPublicKey FromCSP(RSACryptoServiceProvider csp)
        {
            RSAPublicKey rp = new RSAPublicKey();
            var p = csp.ExportParameters(false);
            rp.Modulus = p.Modulus;
            rp.Exponent = p.Exponent;
            return rp;
        }

        public static implicit operator byte[](RSAPublicKey rp)
        {
            return rp.ToByteArrayUnmanaged();
        }
        public static explicit operator RSAPublicKey(byte[] byt)
        {
            return byt.ToStructureUnmanaged<RSAPublicKey>();
        }
    }
}
