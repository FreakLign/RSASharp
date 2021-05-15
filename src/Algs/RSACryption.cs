using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace SharedLib.Algs
{
    public class RSACryption:ICryptoTransform
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

        public bool CanTransformMultipleBlocks => throw new NotImplementedException();

        public int InputBlockSize => throw new NotImplementedException();

        public int OutputBlockSize => throw new NotImplementedException();

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
                return BigInteger.ModPow(value, _dv, _nv).ToByteArray();
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
                return BigInteger.ModPow(value, _ev, _nv).ToByteArray();
            }
            catch (ArgumentException ex)
            {
                throw ex;
            }
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            if(inputBuffer.Length <= inputCount + inputOffset)
            {
                throw new ArgumentOutOfRangeException("Input data length has been out of range.");
            }
            return 0;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            throw new NotImplementedException();
        }

        public void Dispose()
        {
            throw new NotImplementedException();
        }
    }
}
