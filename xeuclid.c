#include <stdio.h> 
#include <openssl/bn.h>

void printBN(const char* msg, BIGNUM* a){
    char* number_str = BN_bn2dec(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

BIGNUM *XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b)
{
        BIGNUM *gcd = BN_new();

        BIGNUM *a_ = BN_dup(a);
        BIGNUM *b_ = BN_dup(b);

        BIGNUM *x_0 = BN_new();  BN_dec2bn(&x_0, "1");
        BIGNUM *x_1 = BN_new();  BN_dec2bn(&x_1, "0");
        BIGNUM *y_0 = BN_new();  BN_dec2bn(&y_0, "0");
        BIGNUM *y_1 = BN_new();  BN_dec2bn(&y_1, "1");

        BIGNUM *rem = BN_new();
        BIGNUM *dv = BN_new();
        BN_CTX *ctx = BN_CTX_new();

        BIGNUM *mul_dv_p2 = BN_new();
        BIGNUM *mul_dv_q2 = BN_new();

        while (BN_is_zero(b_) != 1){
                BN_div(dv, rem, a_, b_, ctx);
                BN_copy(a_, b_);
                BN_copy(b_, rem);

                BN_mul(mul_dv_p2, dv, x_1, ctx);
                BN_sub(x, x_0, mul_dv_p2);
                BN_copy(x_0, x_1);
                BN_copy(x_1, x);

                BN_mul(mul_dv_q2, dv, y_1, ctx);
                BN_sub(y, y_0, mul_dv_q2);
                BN_copy(y_0, y_1);
                BN_copy(y_1, y);
        }
        BN_copy(x, x_0);
        BN_copy(y, y_0);
        BN_copy(gcd, a_);
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