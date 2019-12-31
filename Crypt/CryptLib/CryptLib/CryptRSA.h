#ifndef _RSA_
#define _RSA_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WINNT
#include <ntifs.h>
#include <ntddk.h>
#define DPRINT(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
#define GetMem(size) ExAllocatePoolWithTag(NonPagedPool, size, 'lkey');
#define FreeMem(p) ExFreePoolWithTag(p, 'lkey');
#else
#include <stdio.h>
#include <windows.h>

typedef _Return_type_success_(return >= 0) LONG NTSTATUS;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#define STATUS_UNSUCCESSFUL              ((NTSTATUS)0xC0000001L)
//#define STATUS_INVALID_PARAMETER         ((NTSTATUS)0xC000000DL)    // winnt

#define DPRINT(format, ...) printf(format, __VA_ARGS__);
#define GetMem(size) malloc(size);
#define FreeMem(p) free(p);
#endif // !_USER_MODE

#include <bcrypt.h>

#ifndef DWORD 
#define DWORD ULONG
#endif

/*
能加密的内容长度取决于密钥的bit
最大内容为 密钥bit / 8
512bit:  64
1024bit: 128
2048bit: 256
4096bit: 512

对应的
512bit密钥:
公钥长度:91 私钥155
1024bit：
公钥:155 私钥283
2048bit：
公钥:283 私钥539
4096bit:
公钥:539 私钥1051
*/

/*
生成RSA密钥 支持生成 512 1024 2048 4096bit 密钥
缓冲区内部申请 外部释放
RSAGenerateKey:
dwKeyLen : 512 , 1024 , 2048, 4096 任意一个
lpPubKey : 返回公钥指针 使用完后由caller释放
lpcbPubKey : 返回公钥长度
lpPrivKey : 返回私钥指针 同2
lpcbPriv : 返回私钥长度
返回值: NTSTATUS 值
*/
NTSTATUS RSAGenerateKey(DWORD dwKeyLen, PVOID* lpPubKey, DWORD* lpcbPubKey, PVOID* lpPrivKey, DWORD* lpcbPriv);

/*
RSA公钥加密
RSAEncrypt:
PublicKey: 公钥存放地址
cbPublicKey : 公钥长度 (如果长度不符合会返回无效参数)
encryptData : 加密的数据
cbEncryptData : 加密数据的长度
lpEncryped : 返回加密后的数据指针 使用完后由caller释放
lpCbEncrypt : 返回加密后数据的长度
*/
NTSTATUS RSAEncrypt(PUCHAR PublicKey, DWORD cbPublicKey, PUCHAR encryptData, DWORD cbEncryptData, PVOID* lpEncryped, DWORD* lpCbEncrypt);

/*
RSA私钥解密
RSADecrypt:
PrivateKey: 私钥
cbPrivateKey ： 私钥长度 (如果长度不符合会返回无效参数)
decryptData : 要解密的数据
cbDecryptData : 要解密数据的长度
lpDecrypted : 返回解密之后数据指针 使用完后由caller释放
lpCbDecrypted : 返回解密之后数据的长度
*/
NTSTATUS RSADecrypt(PUCHAR PrivateKey, DWORD cbPrivateKey, PUCHAR decryptData, DWORD cbDecryptData, PVOID* lpDecrypted, DWORD* lpCbDecrypted);

#ifdef __cplusplus
}
#endif

#endif