using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.AES;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        /// 
        public static int ModPower(int num, int pow, int mod)
        {
            int res = 1;
            int i = 1;
            while (i <= pow)
            {
                res = (res * num) % mod;
                i++;
            }
            return res;
        }

        public static long ModInverse(int a, int m)
        {
            int m0 = m;
            int t, q;
            int x0 = 0, x1 = 1;

            if (m == 1)
            {
                return 0;
            }



            //extended Euclid Algorithm
            while (a > 1)
            {
                // q is quotient
                q = a / m;
                t = m;
                // x1 = new ExtendedEuclid().GetMultiplicativeInverse(t,q);
                //m:rem
                m = a % m;
                a = t;
                t = x0;
                x0 = x1 - q * x0;
                x1 = t;
            }
            if (x1 < 0)
            {
                x1 += m0;
            }

            return x1;
        }


        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            //throw new NotImplementedException();
            int a = (int)ModPower(alpha, k, q);
            int b = (int)(m * ModPower(y, k, q) % q);

            return new List<long> { a, b };

        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            // throw new NotImplementedException();
            int num = c2;
            int den = ModPower(c1, x, q);

            int inv = (int)ModInverse(den, q);

            int decrypted = num * inv % q;

            return decrypted;

        }
    }
}
