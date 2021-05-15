using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace SharedLib.Algs
{
    public static class FastPowerMod
    {
        public static BigInteger DoFastPowerMod(BigInteger a, BigInteger b, BigInteger mod)
        {
            BigInteger ans = 1;
            a = a % mod;
            while (b > 0)
            {
                if (b % 2 == 1)
                    ans = (ans * a) % mod;
                b = b / 2;
                a = (a * a) % mod;
            }
            return ans;
        }
    }
}
