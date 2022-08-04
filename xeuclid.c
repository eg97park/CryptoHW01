#include <stdio.h> 
#include <openssl/bn.h>

void printBN(const char* msg, BIGNUM* a){
    char* number_str = BN_bn2dec(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

BIGNUM *XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b)
{
        // ax + by = gcd
        BIGNUM *a_cur = BN_dup(a);
        BIGNUM *b_cur = BN_dup(b);

        // a * (1) + b * (0) = a -> a * (x_0) + b * (y_0) = a
        BIGNUM *x_0 = BN_new();  BN_dec2bn(&x_0, "1"); 
        BIGNUM *y_0 = BN_new();  BN_dec2bn(&y_0, "0");

        // a * (0) + b * (1) = b -> a * (x_1) + b * (y_1) = b
        BIGNUM *x_1 = BN_new();  BN_dec2bn(&x_1, "0");
        BIGNUM *y_1 = BN_new();  BN_dec2bn(&y_1, "1");

        BIGNUM *r = BN_new();
        BIGNUM *q = BN_new();

        // buf for mul, div operation.
        BN_CTX *ctx = BN_CTX_new();

        // tmp for mul.
        BIGNUM *tmp = BN_new();

        // x -> x_2, y -> y_2, k = 1
        while (!BN_is_zero(b_cur)){
                //      a_0 = b_0 * q_0 + r_0
                //   ┌  a_1(=b_0) = b_1(=r_0) * q_1 + r_1
                //   └> a_2(=b_1=r_0) = b_2(=r_1) * q_2 + r_2
                BN_div(q, r, a_cur, b_cur, ctx);
                BN_copy(a_cur, b_cur);
                BN_copy(b_cur, r);

                // x_0 - x_1 * q_2 = x_2
                BN_mul(tmp, x_1, q, ctx);
                BN_sub(x, x_0, tmp);

                // y_0 - y_1 * q_2 = y_2
                BN_mul(tmp, y_1, q, ctx);
                BN_sub(y, y_0, tmp);

                // k += 1
                BN_copy(x_0, x_1);
                BN_copy(x_1, x);
                BN_copy(y_0, y_1);
                BN_copy(y_1, y);
        }
        BN_copy(x, x_0);
        BN_copy(y, y_0);

        // make new object to return.
        BIGNUM *gcd = BN_dup(a_cur);

        // free everything!
        if(a_cur != NULL && b_cur != NULL)      BN_free(a_cur); BN_free(b_cur);
        if(x_0 != NULL && y_0 != NULL)          BN_free(x_0);   BN_free(y_0);
        if(x_1 != NULL && y_1 != NULL)          BN_free(x_1);   BN_free(y_1);
        if(r != NULL && q != NULL)              BN_free(r);     BN_free(q);
        if(tmp != NULL && ctx != NULL)          BN_free(tmp);   BN_CTX_free(ctx);

        return gcd;
}

int main (int argc, char *argv[])
{
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();
        BIGNUM *x = BN_new();
        BIGNUM *y = BN_new();
        BIGNUM *gcd;

        if(argc != 3){
                printf("usage: xeuclid num1 num2");
                return -1;
        }
        BN_dec2bn(&a, argv[1]);
        BN_dec2bn(&b, argv[2]);
        gcd = XEuclid(x,y,a,b);

        printBN("(a,b) = ", gcd);
        printBN("a = ", a);
        printBN("b = ", b);
        printBN("x = ", x);
        printBN("y = ", y);
        printf("%s*(%s) + %s*(%s) = %s\n",BN_bn2dec(a),BN_bn2dec(x),BN_bn2dec(b),BN_bn2dec(y),BN_bn2dec(gcd));

        if(a != NULL) BN_free(a);
        if(b != NULL) BN_free(b);
        if(x != NULL) BN_free(x);
        if(y != NULL) BN_free(y);
        if(gcd != NULL) BN_free(gcd);

        return 0;
}