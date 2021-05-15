using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace SharedLib.Algs
{
    public static class ExtendedEuclideanalgorithm
    {
        public static BigInteger DoExtendedEuclideanalgorithm(BigInteger a, BigInteger b, ref BigInteger x, ref BigInteger y)
        {
            if (a < b) return DoExtendedEuclideanalgorithm(b, a, ref y, ref x);
            BigInteger m = 0;
            BigInteger n = 1;
            x = 1;
            y = 1;
            while (b != 0)
            {
                BigInteger d = a / b, t;
                t = m; m = x - d * t; x = t;
                t = n; n = y - d * t; y = t;
                t = a % b; a = b; b = t;
            }
            return a;
        }

        public static BigInteger GetMultiplicativeInverseModule(BigInteger n, BigInteger p)
        {
            BigInteger x = 1, y = 1;
            if (DoExtendedEuclideanalgorithm(n, p, ref x, ref y) == 1)
            {
                x = x % p;
                return x >= 0 ? x : p + x;
            }
            else
            {
                return -1;
            }
        }
    }
}
