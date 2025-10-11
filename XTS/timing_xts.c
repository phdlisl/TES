#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include "aes.h"
#include <x86intrin.h> //linux
//#include <intrin.h>  //windows
#include "util.h"
#include "ae.h"
#include <sys/stat.h>
#include <sys/types.h>

// linux
// The aligned() specified variable or type should be aligned according to the n-byte boundary
// 用于指定变量、类型或结构体成员的内存对齐方式。
#define ALIGN(n) __attribute__((aligned(n)))
void createFolder(char *foldername)
{
    struct stat st = {0};
    if (stat(foldername, &st) == -1)
    {
        mkdir(foldername, 0777);
        printf("create done.");
    }
    return;
}

int main(int argc, char **argv)
{
    createFolder("result"); //linux，创建一个文件夹
    unsigned int ui;
    ALIGN(16) u8 key[32];
    ALIGN(16) u8 pt[4096] = {0};
    // create memory 按照所在系统创建内存
    ae_ctx *ctx = ae_allocate(NULL);
    ALIGN(16) u8 tag[16];
    u8 tweak[16];
    unsigned long long clock1, clock2;
    double cpb[101];
    // init
    for (int i = 0; i < 32; i++)
        key[i] = i;
    for (int i = 0; i < 4096; i++)
        pt[i] = i;
    for (int i = 0; i < 16; i++)
        tweak[i] = 0;
    // initial encrypt key 初始化密钥
    ae_init(ctx, key, 32, 0, 0);
    int pt_len = 32;
    FILE *fp = NULL;
#ifdef USE_AESNI_1
    fp = fopen("./result/XTS_1.txt", "w");
#endif
#ifdef USE_AESNI_2
    fp = fopen("./result/XTS_2.txt", "w");
#endif
#ifdef USE_AESNI_4
    fp = fopen("./result/XTS_4.txt", "w");
#endif
#ifdef USE_AESNI_6
    fp = fopen("./result/XTS_6.txt", "w");
#endif
#ifdef USE_AESNI_8
    fp = fopen("./result/XTS_8.txt", "w");
#endif
// Measure the performance of the encryption algorithm ae_encrypt under different data lengths
    while (pt_len <= 4096)
    {
        for (int z = 0; z < 101; z++)
        {// Test each length 101 times
            // __rdtscp 是一个编译器内置函数，用于读取处理器的时间戳计数器，并确保序列化执行，同时读取处理器的核心ID。
            clock1 = __rdtscp(&ui);
            for (int j = 0; j < 1e4; j++)
            {// Perform 10,000 encryptions
                ae_encrypt(ctx, tweak, pt, pt_len, NULL, 0, pt, tag, 1);
            }
            clock2 = __rdtscp(&ui);
            cpb[z] = (clock2 - clock1) / (1e4 * pt_len);
        }
        // Sort 101 measurement results
        // 比较规则compare在util.h中定义
        qsort(cpb, 101, sizeof(double), compare);
        // printf("length = %d bytes , cpb = %.3f cycles/byte\n", pt_len, cpb[50]);
        fprintf(fp, "%d %.3f\n", pt_len, cpb[50]);
        pt_len += 32;
    }
    fclose(fp);
    ae_free(ctx);
    return 0;
}