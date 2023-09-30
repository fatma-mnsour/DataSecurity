using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            int mo = 5, na = 0;
            List<int> message = new List<int>();

            int first_Key, Second_Key;
            //calc values of keys
            int first_c, second_c;
            first_c = calc_Key_Exchange(alpha, xa, q);
            Second_Key = calc_Key_Exchange(first_c, xb, q);

            for (int i = 0; i < 6; i++)
            {
                if (na < mo)
                    mo++;
            }

            //calc the value of second calc
            second_c = calc_Key_Exchange(alpha, xb, q);
            //calc the value of first key
            first_Key = calc_Key_Exchange(second_c, xa, q);
            //put the data of keys in message
            message.Add(first_Key); message.Add(Second_Key);
            return message;
        }

        public int calc_Key_Exchange(int gen, int privat, int pr)
        {
            int c_public = 1;

            int i = 0;
            while (i < privat)
            {
                c_public = (c_public * gen) % pr;
                i++;
            }
            return c_public;
        }
    }
}