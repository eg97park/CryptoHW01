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

        BIGNUM *p1 = BN_new();  BN_dec2bn(&p1, "1");
        BIGNUM *p2 = BN_new();  BN_dec2bn(&p2, "0");
        BIGNUM *q1 = BN_new();  BN_dec2bn(&q1, "0");
        BIGNUM *q2 = BN_new();  BN_dec2bn(&q2, "1");

        BIGNUM *rem = BN_new();
        BIGNUM *dv = BN_new();
        BN_CTX *ctx = BN_CTX_new();

        BIGNUM *mul_dv_p2 = BN_new();
        BIGNUM *mul_dv_q2 = BN_new();

        while (BN_is_zero(b_) != 1){
                BN_div(dv, rem, a_, b_, ctx);
                BN_copy(a_, b_);
                BN_copy(b_, rem);

                BN_mul(mul_dv_p2, dv, p2, ctx);
                BN_sub(x, p1, mul_dv_p2);
                BN_copy(p1, p2);
                BN_copy(p2, x);

                BN_mul(mul_dv_q2, dv, q2, ctx);
                BN_sub(y, q1, mul_dv_q2);
                BN_copy(q1, q2);
                BN_copy(q2, y);
        }
        BN_copy(x, p1);
        BN_copy(y, q1);
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