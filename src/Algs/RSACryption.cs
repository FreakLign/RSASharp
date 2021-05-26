using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace SharedLib.Algs
{
    public class RSACryption : ICryptoTransform
    {
        private string _e;
        private string _d;
        private string _n;

        private BigInteger _ev;
        private BigInteger _dv;
        private BigInteger _nv;

        public string E => _e;
        public string D => _d;
        public string N => _n;

        public bool CanReuseTransform => throw new NotImplementedException();

        public bool CanTransformMultipleBlocks => false;

        public int InputBlockSize => 1048576;

        public int OutputBlockSize => 1048576;

        public RSACryption()
        {

        }

        public void LoadPrivateKey(string privateKey, string Nv)
        {
            _d = privateKey;
            _n = Nv;
            _nv = new BigInteger(Convert.FromBase64String(Nv));
            _dv = new BigInteger(Convert.FromBase64String(privateKey));
        }

        public void LoadPublicKey(string publicKey, string Nv)
        {
            _e = publicKey;
            _n = Nv;
            _nv = new BigInteger(Convert.FromBase64String(Nv));
            _ev = new BigInteger(Convert.FromBase64String(publicKey));
        }

        public static RSACryption Create()
        {
            RSACryption r = new RSACryption();
            var rand = new Random((int)DateTime.Now.ToFileTime());
            BigInteger p = PrimeFunctions.BigPrimeGroups[rand.Next(0, PrimeFunctions.BigPrimeGroups.Length)];
            BigInteger q = PrimeFunctions.BigPrimeGroups[rand.Next(0, PrimeFunctions.BigPrimeGroups.Length)];
            while (q == p)
            {
                q = PrimeFunctions.BigPrimeGroups[rand.Next(0, PrimeFunctions.BigPrimeGroups.Length)];
            }
            BigInteger phi = (p - 1) * (q - 1);
            BigInteger n = p * q;
            BigInteger k = rand.Next(10, 20);
            BigInteger e = 1;
            BigInteger d = -1;
            while (d == -1)
            {
                e = PrimeFunctions.MiddlePrimeGroups[rand.Next(0, PrimeFunctions.MiddlePrimeGroups.Length)];
                d = ExtendedEuclideanalgorithm.GetMultiplicativeInverseModule(e, 0 - phi);
            }
            r.LoadPublicKey(Convert.ToBase64String(e.ToByteArray()), Convert.ToBase64String(n.ToByteArray()));
            r.LoadPrivateKey(Convert.ToBase64String(d.ToByteArray()), Convert.ToBase64String(n.ToByteArray()));
            return r;
        }

        public byte[] SignData(byte[] data)
        {
            try
            {
                var value = new BigInteger(data);
                var rval = BigInteger.ModPow(value, _dv, _nv);
                var e = rval.ToString();
                return rval.ToByteArray();
                //var t1 = rval.ToByteArray();
                //var t2 = new BigInteger(t1);
                //return Encoding.ASCII.GetBytes(e);
            }
            catch (ArgumentException ex)
            {
                throw ex;
            }
        }

        public byte[] EncryptData(byte[] data)
        {
            try
            {
                var value = new BigInteger(data);
                //if(!BigInteger.TryParse(e, out var value))
                //{
                //    throw new ArgumentException("Argument error.");
                //}
                var v = BigInteger.ModPow(value, _ev, _nv);
                return v.ToByteArray();
            }
            catch (ArgumentException ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// 创建密钥对。
        /// </summary>
        /// <param name="n">N值</param>
        /// <param name="e">公钥</param>
        /// <param name="d">密钥</param>
        public static void Create(out byte[] n, out byte[] e, out byte[] d)
        {
            RSACryption r = new RSACryption();
            var rand = new Random((int)DateTime.Now.ToFileTime());
            BigInteger p = PrimeFunctions.BigPrimeGroups[rand.Next(0, PrimeFunctions.BigPrimeGroups.Length)];
            BigInteger q = PrimeFunctions.BigPrimeGroups[rand.Next(0, PrimeFunctions.BigPrimeGroups.Length)];
            while (q == p)
            {
                q = PrimeFunctions.BigPrimeGroups[rand.Next(0, PrimeFunctions.BigPrimeGroups.Length)];
            }
            BigInteger phi = (p - 1) * (q - 1);
            BigInteger nv = p * q;
            BigInteger k = rand.Next(10, 20);
            BigInteger ev = 1;
            BigInteger dv = -1;
            while (dv == -1)
            {
                ev = PrimeFunctions.MiddlePrimeGroups[rand.Next(0, PrimeFunctions.MiddlePrimeGroups.Length)];
                dv = ExtendedEuclideanalgorithm.GetMultiplicativeInverseModule(ev, 0 - phi);
            }
            n = nv.ToByteArray();
            e = ev.ToByteArray();
            d = dv.ToByteArray();
        }

        /// <summary>
        /// 加密数据。
        /// </summary>
        /// <param name="data">数据</param>
        /// <param name="n">N值</param>
        /// <param name="e">公（私）钥</param>
        /// <returns>加密后的数值。</returns>
        public static byte[] EncryptData(byte[] data, byte[] n, byte[] e)
        {
            var value = new BigInteger(data);
            var nv = new BigInteger(n);
            var ev = new BigInteger(e);
            var v = BigInteger.ModPow(value, ev, nv);
            return v.ToByteArray();
        }

        /// <summary>
        /// 解密数据。
        /// </summary>
        /// <param name="data">数据</param>
        /// <param name="n">N值</param>
        /// <param name="e">私（公）钥</param>
        /// <returns>解密后的数值。</returns>
        public static byte[] DecryptData(byte[] data, byte[] n, byte[] d)
        {
            var value = new BigInteger(data);
            var nv = new BigInteger(n);
            var dv = new BigInteger(d);
            var v = BigInteger.ModPow(value, dv, nv);
            return v.ToByteArray();
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            if (inputBuffer.Length <= inputCount + inputOffset)
            {
                throw new ArgumentOutOfRangeException("Input data length has been out of range.");
            }
            var value = new BigInteger(inputBuffer);
            outputBuffer = BigInteger.ModPow(value, _dv, _nv).ToByteArray();
            return 1;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (inputBuffer.Length <= inputCount + inputOffset)
            {
                throw new ArgumentOutOfRangeException("Input data length has been out of range.");
            }
            var newBuffer = new byte[inputCount];
            Array.Copy(inputBuffer, newBuffer, inputCount);
            var value = new BigInteger(inputBuffer);
            return BigInteger.ModPow(value, _dv, _nv).ToByteArray();
        }

        public void Dispose()
        {
            throw new NotImplementedException();
        }
    }
}
