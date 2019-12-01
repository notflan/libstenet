using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace EncryptedNetwork
{ 
    /// <summary>
    /// Provides a wrapper to override methods of a Stream
    /// </summary>
    public abstract class BackedStream : Stream
    {
        protected Stream backing;
        /// <summary>
        /// The Stream used as the backing
        /// </summary>
        public Stream Backing { get { return backing; } }
        /// <summary>
        /// Keep the backing stream alive after the class is disposed (default <c>false</c>)
        /// </summary>
        public virtual bool KeepBackingStreamAlive { get; set; } = false;
        /// <summary>
        /// Initialise an instance of the BackedStream class
        /// </summary>
        /// <param name="s">The initial Stream</param>
        public BackedStream(Stream s)
        {
            backing = s;
        }

        protected ObjectDisposedException ThrowIfDisposed()
        {
            if (Disposed)
                throw new ObjectDisposedException(GetType().Name + " object has been disposed.");
            else return null;
        }

        protected bool Disposed { get; private set; } = false;
        protected override void Dispose(bool disposing)
        {
            ThrowIfDisposed();

            Disposed = true;
            if (disposing)
            {
                if (!KeepBackingStreamAlive) backing.Dispose();
            }
            backing = null;
        }

        #region Stream Overrides
        public override bool CanRead
        {
            get { return Backing.CanRead; }
        }
        public override bool CanSeek
        {
            get { return Backing.CanSeek; }
        }
        public override bool CanWrite
        {
            get { return Backing.CanWrite; }
        }
        public override void Flush()
        {
            Backing.Flush();
        }
        public override long Length
        {
            get { return Backing.Length; }
        }
        public override long Position
        {
            get
            {
                return Backing.Position;
            }
            set
            {
                Backing.Position = value;
            }
        }
        public override long Seek(long offset, SeekOrigin origin)
        {
            return Backing.Seek(offset, origin);
        }
        public override void SetLength(long value)
        {
            Backing.SetLength(value);
        }
        #endregion
    }
    internal static class Extensions
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static unsafe void WriteValueUnmanaged<T>(this Stream s, T t) where T : unmanaged
        {
            byte[] buffer = new byte[sizeof(T)];
            fixed (byte* ptr = buffer)
            {
                *(T*)ptr = t;
            }
            s.Write(buffer, 0, buffer.Length);
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static unsafe T ReadValueUnmanaged<T>(this Stream s) where T : unmanaged
        {
            T output;
            byte[] buffer = new byte[sizeof(T)];
            s.Read(buffer, 0, buffer.Length);

            fixed (byte* ptr = buffer)
            {
                output = *(T*)ptr;
            }

            return output;
        }

        public static unsafe T SwapByteOrder<T>(this T v) where T: unmanaged
        {
            Span<byte> b = new Span<byte>(&v, sizeof(T));
            b.Reverse();
            return v;
        }

        /*public static unsafe T Little<T>(this T v) where T : unmanaged
        {
            if (BitConverter.IsLittleEndian) return v;
            else return v.SwapByteOrder();
        }*/
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static unsafe T NetOrd<T>(this T v) where T : unmanaged
        {
            if (!BitConverter.IsLittleEndian) return v;
            else return v.SwapByteOrder();
        }

        public static T Sync<T>(this Task<T> task, int timeout)
        {
            task.Wait(timeout);
            if (task.IsFaulted)
                throw task.Exception;
            return task.Result;
        }
        public static T Sync<T>(this Task<T> task)
        {
            task.Wait();
            if (task.IsFaulted)
                throw task.Exception;
            return task.Result;
        }
        public static void Sync(this Task task)
        {
            task.Wait();
            if (task.IsFaulted)
                throw task.Exception;
        }
        public static void Sync(this Task task, int msTimeout)
        {
            task.Wait(msTimeout);
            if (task.IsFaulted)
                throw task.Exception;
        }

        public static async Task<T> BlockingReadValueUnmanagedAsync<T>(this Stream s, System.Threading.CancellationToken? cancel) where T : unmanaged
        {
            int size;
            unsafe
            {
                size = sizeof(T);
            }
            byte[] buffer = new byte[size];
            await s.BlockingReadAsync(buffer, 0, size, cancel);

            return buffer.ToStructureUnmanaged<T>();
        }
        public static async Task BlockingReadAsync(this Stream s, byte[] to, int offset, int length, System.Threading.CancellationToken? cancel)
        {
            int read = 0;
            while ((read += await (cancel == null ? s.ReadAsync(to, offset + read, length - read) : s.ReadAsync(to, offset + read, length - read, cancel.Value))) < length) cancel?.ThrowIfCancellationRequested();
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static unsafe T ToStructureUnmanaged<T>(this byte[] bytes) where T : unmanaged
        {
            fixed (byte* ptr = bytes)
            {
                return *(T*)ptr;
            }
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static unsafe byte[] ToByteArrayUnmanaged<T>(this T t) where T : unmanaged
        {
            byte[] o = new byte[sizeof(T)];
            fixed (byte* ptr = o)
            {
                *(T*)ptr = t;
            }
            return o;
        }
    }
}
