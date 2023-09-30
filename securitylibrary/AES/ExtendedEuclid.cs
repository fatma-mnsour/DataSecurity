using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        ///  calculate the multiplicative inverse of a number number modulo baseN
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            //finding a linear combination of the two numbers such that their greatest common divisor equals 1.This linear combination can be used to calculate the multiplicative inverse.
            
            int inv = -1; //default is -1 if not found

            int a1 = 1, a2 = 0, a3 = baseN; //calculate the inverse

            int b1 = 0, b2 = 1, b3 = number; //calc inv

            int Quotient = a3 / b3; //initial quo value

            for (; b3 != 1;)  //loop until b3 = 1
            {
                //save the old values of a
                int[] OldA = new int[3];
                OldA[0] = a1;
                OldA[1] = a2;
                OldA[2] = a3;

                //calculate the new values of a and update with values of b
                a1 = b1;
                a2 = b2;
                a3 = b3;

                // calculate the new values of b1, b2, and b3 using the old values of a1, a2, a3, and the quotient
                b1 = OldA[0] - Quotient * b1;
                b2 = OldA[1] - Quotient * b2;
                b3 = OldA[2] - Quotient * b3;

                // if b3 equals 0, the inverse doesn't exist so set inv equal to -1 and break
                if (b3 == 0)
                {
                    inv = -1;
                    break;
                }

                else
                {
                    inv = -1;
                    
                }



                // calculate the new quotient
                Quotient = a3 / b3;
                // update the inverse with the new value of b2 and take the absolute(adjust) if it's negative
                inv = b2;
                if (inv < 0)
                {
                    inv += baseN;
                }
            }
            //final value of the inverse
            return inv;
        }

    }
}