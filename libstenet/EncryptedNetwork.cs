using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Threading;

namespace EncryptedNetwork
{
    internal interface IEncryptedContainer
    {
        EncryptedNetworkStream Parent { get; }

        EncryptedNetworkStreamBlock WriteBlock();
        EncryptedNetworkStreamBlock ReadBlock();
        EncryptedNetworkStreamBlock ReadBlock(int msTimeout);
        Task<EncryptedNetworkStreamBlock> ReadBlockAsync(CancellationToken cancel);
        Task<EncryptedNetworkStreamBlock> ReadBlockAsync();
    }
    /// <summary>
    /// An encrypted block container for an <see cref="EncryptedNetworkStream"/>.
    /// </summary>
    public abstract class EncryptedNetworkStreamBlock : BackedStream, IEncryptedContainer
    {
        internal EncryptedNetworkStreamBlock(Stream back) : base(back) { }

        /// <summary>
        /// The EncryptedNetworkStream that owns this block.
        /// </summary>
        public abstract EncryptedNetworkStream Parent { get; }

        /// <summary>
        /// Start a Read block synchronously with a milisecond timeout.
        /// </summary>
        /// <param name="msTimeout">The timeout</param>
        /// <returns>The new Read block.</returns>
        public abstract EncryptedNetworkStreamBlock ReadBlock(int msTimeout);
        /// <summary>
        /// Start a Read block synchronously.
        /// </summary>
        /// <returns>The new Read block.</returns>
        public abstract EncryptedNetworkStreamBlock ReadBlock();
        /// <summary>
        /// Start a Write block.
        /// </summary>
        /// <returns></returns>
        public abstract EncryptedNetworkStreamBlock WriteBlock();

        /// <summary>
        /// Start a Read block asynchronously.
        /// </summary>
        /// <param name="cancel">Token for cancellation.</param>
        /// <returns>Awaitable Task for new Read block.</returns>
        public async virtual Task<EncryptedNetworkStreamBlock> ReadBlockAsync(CancellationToken cancel)
        {
            return await Task.Run(ReadBlock);
        }
        /// <summary>
        /// Start a Read block asynchronously.
        /// </summary>
        /// <returns>Awaitable Task for new Read block.</returns>
        public virtual Task<EncryptedNetworkStreamBlock> ReadBlockAsync() => ReadBlockAsync(CancellationToken.None);
    }
    /// <summary>
    /// Proveides RSA & AES cryptography wrapper over a <see cref="NetworkStream"/>.
    /// </summary>
    public class EncryptedNetworkStream : BackedStream, IEncryptedContainer
    {
        private class EncryptedReadBlock : EncryptedNetworkStreamBlock
        {
            private AesCryptoServiceProvider aes = null;
            EncryptedNetworkStream ens;
            public EncryptedReadBlock(BackedStream ens, IEncryptedContainer container)
                : base(ens)
            {
                KeepBackingStreamAlive = true;
                this.ens = container.Parent;
            }
            public override bool KeepBackingStreamAlive { get => true; set { if (!value) throw new NotSupportedException("Cannot set ReadBlock to dispose of its parent."); } }

            public override EncryptedNetworkStream Parent => ens;

            public async Task Initialise(CancellationToken cancel)
            {
                ens.ThrowIfNotExchanged();

                aes = new AesCryptoServiceProvider();
                try
                {
                    var len = (await backing.BlockingReadValueUnmanagedAsync<int>(cancel)).NetOrd();
                    if (len <= 0)
                        throw new ArgumentException("Invalid length read. ("+len+")");

                    byte[] by = new byte[len];
                    await backing.BlockingReadAsync(by, 0, len, cancel);

                    var decrypted = ens.you.Decrypt(by, false);

                    var key = decrypted.ToStructureUnmanaged<AESKey>();
                    key.ToCSP(aes);
                }
                catch(Exception ex)
                {
                    aes.Dispose();
                    aes = null;
                    throw ex;
                }
            }

            public override int Read(byte[] buffer, int offset, int count)
             => ReadAsync(buffer, offset, count, CancellationToken.None).Sync();
            public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            {
                static int roundUp(int numToRound, int multiple)
                {
                    if (multiple == 0)
                        return numToRound;

                    int remainder = Math.Abs(numToRound) % multiple;
                    if (remainder == 0)
                        return numToRound;
                    if (numToRound < 0)
                        return -(Math.Abs(numToRound) - remainder);
                    return numToRound + multiple - remainder;
                }

                if (aes == null)
                    return await backing.ReadAsync(buffer, offset, count, cancellationToken);
                else
                {
                    byte[] byr = new byte[count % 16 == 0 ? count + 16 : roundUp(count, 16)];
                    await backing.BlockingReadAsync(byr, 0, byr.Length, cancellationToken);
                    using (var dec = aes.CreateDecryptor())
                    {
                        Array.Copy(dec.TransformFinalBlock(byr, 0, byr.Length), 0, buffer, offset, count);
                        return count;
                    }
                }

            }

            public override void Write(byte[] buffer, int offset, int count)
                => backing.Write(buffer, offset, count);

            public override EncryptedNetworkStreamBlock WriteBlock()
            {
                var w =  new EncryptedWriteBlock(this, this);
                w.Initialise();
                return w;
            }

            public override EncryptedNetworkStreamBlock ReadBlock()
            {
                var r = new EncryptedReadBlock(this, this);
                r.Initialise(CancellationToken.None).Sync();
                return r;
            }
            public override EncryptedNetworkStreamBlock ReadBlock(int msTimeout)
            {
                var r = new EncryptedReadBlock(this, this);
                r.Initialise(CancellationToken.None).Sync(msTimeout);
                return r;
            }
            public async override Task<EncryptedNetworkStreamBlock> ReadBlockAsync(CancellationToken cancel)
            {
                var r = new EncryptedReadBlock(this, this);
                await r.Initialise(cancel);
                return r;
            }
            ~EncryptedReadBlock() { Dispose(false); aes = null; }
        }
        private class EncryptedWriteBlock : EncryptedNetworkStreamBlock
        {
            private AesCryptoServiceProvider aes = null;
            EncryptedNetworkStream ens;

            public override EncryptedNetworkStream Parent => ens;
            public override bool KeepBackingStreamAlive { get => true; set { if (!value) throw new NotSupportedException("Cannot set WriteBlock to dispose of its parent."); } }

            public EncryptedWriteBlock(BackedStream ens, IEncryptedContainer container)
                : base(ens)
            {
                KeepBackingStreamAlive = true;
                this.ens = container.Parent;
            }

            public void Initialise()
            {
                ens.ThrowIfNotExchanged();

                aes = new AesCryptoServiceProvider();

                try
                {
                    var key = AESKey.NewKey();
                    key.ToCSP(aes);

                    var encrypted = ens.them.Encrypt(key.ToByteArrayUnmanaged(), false);
                    var size = encrypted.Length.NetOrd();

                    backing.WriteValueUnmanaged(size);
                    backing.Write(encrypted, 0, encrypted.Length);
                }
                catch(Exception ex)
                {
                    aes.Dispose();
                    aes = null;
                    throw ex;
                }
            }

            protected override void Dispose(bool disposing)
            {
                base.Dispose(disposing);
                aes.Dispose();
            }

            public override int Read(byte[] buffer, int offset, int count)
               => backing.Read(buffer, offset, count);


            public override void Write(byte[] buffer, int offset, int count)
            {
                if (aes == null)
                    backing.Write(buffer, offset, count);
                else
                {
                    using(var enc = aes.CreateEncryptor())
                    {
                        var ebuf = enc.TransformFinalBlock(buffer, offset, count);
                        backing.Write(ebuf, 0, ebuf.Length);
                    }
                }
            }

            public override EncryptedNetworkStreamBlock WriteBlock()
            {
                var w = new EncryptedWriteBlock(this, this);
                w.Initialise();
                return w;
            }

            public override EncryptedNetworkStreamBlock ReadBlock()
            {
                var r = new EncryptedReadBlock(this, this);
                r.Initialise(CancellationToken.None).Sync();
                return r;
            }
            public override EncryptedNetworkStreamBlock ReadBlock(int msTimeout)
            {
                var r = new EncryptedReadBlock(this, this);
                r.Initialise(CancellationToken.None).Sync(msTimeout);
                return r;
            }
            public async override Task<EncryptedNetworkStreamBlock> ReadBlockAsync(CancellationToken cancel)
            {
                var r = new EncryptedReadBlock(this, this);
                await r.Initialise(cancel);
                return r;
            }
            ~EncryptedWriteBlock() { Dispose(false); aes = null; }
        }

        private readonly RSACryptoServiceProvider you;
        private RSACryptoServiceProvider them;

        /// <summary>
        /// Your local RSA CSP (with both public and private keys.)
        /// </summary>
        public RSACryptoServiceProvider PrivateCSP => you;
        /// <summary>
        /// Your local RSA public key.
        /// </summary>
        public RSAPublicKey LocalPublicKey => RSAPublicKey.FromCSP(you);
        /// <summary>
        /// Remote endpoint's RSA public key.
        /// </summary>
        /// <exception cref="ArgumentException">Thrown if RSA public keys have not been exchanged yet.</exception>
        public RSAPublicKey RemotePublicKey => them == null ? throw ThrowNotYetExchangedException() : RSAPublicKey.FromCSP(them);

        private static ArgumentException ThrowNotYetExchangedException() => throw new ArgumentException("Keys not yet exchanged.");
        private void ThrowIfNotExchanged() { if (!Exchanged) ThrowNotYetExchangedException(); }

        /// <summary>
        /// Have RSA public keys been exchanged yet?
        /// </summary>
        public bool Exchanged => them != null;

        EncryptedNetworkStream IEncryptedContainer.Parent => this;

        /// <summary>
        /// Initialise a new <see cref="EncryptedNetworkStream"/> from a <seealso cref="NetworkStream"/>
        /// </summary>
        /// <param name="stream">The Stream to set backing for.</param>
        /// <param name="key">Your local RSA CSP to use for private a public keys.</param>
        public EncryptedNetworkStream(NetworkStream stream, RSACryptoServiceProvider key)
            :base(stream)
        {
            you = key;
        }
        /// <summary>
        /// Initialise a new <see cref="EncryptedNetworkStream"/> from a <seealso cref="NetworkStream"/>
        /// </summary>
        /// <param name="stream">The Stream to set backing for.</param>
        public EncryptedNetworkStream(NetworkStream stream) : this(stream, new RSACryptoServiceProvider()) { }
        /// <summary>
        /// Initialise a new <see cref="EncryptedNetworkStream"/> from a <seealso cref="Socket"/>
        /// </summary>
        /// <param name="stream">The Socket to set backing for. (NOTE: Closes the socket on dispose)</param>
        /// <param name="key">Your local RSA CSP to use for private a public keys.</param>
        public EncryptedNetworkStream(Socket sock, RSACryptoServiceProvider key)
            : this(new NetworkStream(sock, true), key) { }
        /// <summary>
        /// Initialise a new <see cref="EncryptedNetworkStream"/> from a <seealso cref="Socket"/>
        /// </summary>
        /// <param name="stream">The Socket to set backing for. (NOTE: Closes the socket on dispose)</param>
        public EncryptedNetworkStream(Socket sock)
            : this(sock, new RSACryptoServiceProvider()) { }

        /// <summary>
        /// Exchange the RSA public keys asynchronously.
        /// </summary>
        /// <returns>Awaitable Task that completes when the operation is successful.</returns>
        public Task ExchangeAsync() => ExchangeAsync(CancellationToken.None);
        /// <summary>
        /// Exchange the RSA public keys asynchronously.
        /// </summary>
        /// <param name="cancel">Cancellation token.</param>
        /// <returns>Awaitable Task that completes when the operation is successful.</returns>
        public async Task ExchangeAsync(CancellationToken cancel)
        {
            backing.WriteValueUnmanaged(LocalPublicKey);

            try
            {
                var pub = await backing.BlockingReadValueUnmanagedAsync<RSAPublicKey>(cancel);

                them??= new RSACryptoServiceProvider();
                pub.ToCSP(them);
            }
            catch (Exception ex)
            {
                them?.Dispose();
                them = null;
                throw ex;
            }
        }
        /// <summary>
        /// Exchange RSA public keys synchronously with a milisecond timeout.
        /// </summary>
        /// <param name="msTimeout">The timout.</param>
        public void Exchange(int msTimeout)
        => ExchangeAsync().Sync(msTimeout);
        /// <summary>
        /// Exchange RSA public keys synchronously.
        /// </summary>
        public void Exchange()
        => ExchangeAsync().Sync();

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
        }

        /// <summary>
        /// Read unencrypted data from the backing stream.
        /// </summary>
        /// <param name="buffer">Buffer to read into.</param>
        /// <param name="offset">Offset of buffer.</param>
        /// <param name="count">Number of bytes to read into buffer.</param>
        /// <returns>The number of bytes successfully read.</returns>
        public override int Read(byte[] buffer, int offset, int count)
            => backing.Read(buffer, offset, count);
        /// <summary>
        /// Write unencrypted data to the backing stream.
        /// </summary>
        /// <param name="buffer">Buffer to write from.</param>
        /// <param name="offset">Offset of buffer.</param>
        /// <param name="count">Number of bytes to write from buffer.</param>
        public override void Write(byte[] buffer, int offset, int count)
            => backing.Write(buffer, offset, count);

        /// <summary>
        /// Create a new encrypted write block for this stream.
        /// </summary>
        /// <returns>The new WriteBlock.</returns>
        public EncryptedNetworkStreamBlock WriteBlock()
        {
            var w = new EncryptedWriteBlock(this, this);
            w.Initialise();
            return w;
        }

        /// <summary>
        /// Create a new encrypted read block for this stream synchronously.
        /// </summary>
        /// <returns>The new ReadBlock.</returns>
        public EncryptedNetworkStreamBlock ReadBlock()
        {
            var r = new EncryptedReadBlock(this, this);
            r.Initialise(CancellationToken.None).Sync();
            return r;
        }
        /// <summary>
        /// Create a new encrypted read block for this stream synchronously with a milisecond timeout.
        /// </summary>
        /// <param name="msTimeout">The timeout.</param>
        /// <returns>The new ReadBlock.</returns>
        public EncryptedNetworkStreamBlock ReadBlock(int msTimeout)
        {
            var r = new EncryptedReadBlock(this, this);
            r.Initialise(CancellationToken.None).Sync(msTimeout);
            return r;
        }

        /// <summary>
        /// Create a new encrypted read block for this stream asynchronously.
        /// </summary>
        /// <param name="cancel">Cancellation token.</param>
        /// <returns>Awaitable Task that completes and returns the new ReadBlock.</returns>
        public async Task<EncryptedNetworkStreamBlock> ReadBlockAsync(CancellationToken cancel)
        {
            var r = new EncryptedReadBlock(this, this);
            await r.Initialise(cancel);
            return r;
        }
        /// <summary>
        /// Create a new encrypted read block for this stream asynchronously.
        /// </summary>
        /// <returns>Awaitable Task that completes and returns the new ReadBlock.</returns>
        public Task<EncryptedNetworkStreamBlock> ReadBlockAsync() => ReadBlockAsync(CancellationToken.None);
    }
}
