using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Diagnostics;
using System.Windows;
using System.Numerics;
using System.Linq;

namespace SharedLib.Algs
{
    class MainClass
    {
        [STAThread]
        static void Main()
        {
            RSACryption rs = RSACryption.Create();

            string toDisplay = "Company Name: 123\n" +
                "Start Time: 2021/01/02\n" +
                "Start Time: 2021/01/02\n" +
                "Start Time: 2021/01/02\n" +
                "Start Time: 2021/01/02\n" +
                "Start Time: 2021/01/02\n";
            var bs = Encoding.UTF8.GetBytes(toDisplay);
            var oo = rs.SignData(bs);
            var va = Convert.ToBase64String(oo);
            Console.WriteLine(va);

            var da = rs.EncryptData(Convert.FromBase64String(va));
            var re = Encoding.UTF8.GetString(da);
            Console.WriteLine(re);
        }
    }
}
