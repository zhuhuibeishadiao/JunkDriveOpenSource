// KeyGenerate.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <bcrypt.h>
#include <Wincrypt.h>

#define NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)

#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

PVOID RSAExportKey(BCRYPT_KEY_HANDLE hKey, LPCWSTR pszBlobType, LPSTR lpFileName, DWORD* lpSize)
{
    HANDLE hFile = NULL;
    PBYTE pbKeyBlob = NULL;
    DWORD dwResult;
    NTSTATUS status;
    unsigned char byte[8] = {0x00};

    // Get export blob size
    if (!NT_SUCCESS(status = BCryptExportKey(
        hKey,        // _In_   BCRYPT_KEY_HANDLE hKey,
        NULL,        // _In_   BCRYPT_KEY_HANDLE hExportKey,
        pszBlobType, // _In_   LPCWSTR pszBlobType,
        NULL,        // _Out_  PUCHAR pbOutput,
        0,           // _In_   ULONG cbOutput,
        &dwResult,   // _Out_  ULONG *pcbResult,
        0            // _In_   ULONG dwFlags
    )))
    {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    // Allocate memory for the blob
    if (NULL == (pbKeyBlob = (PBYTE)HeapAlloc(
        GetProcessHeap(), // _In_  HANDLE hHeap,
        HEAP_ZERO_MEMORY, // _In_  DWORD dwFlags,
        dwResult // _In_  SIZE_T dwBytes
    )))
    {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    // Now we can export the key
    if (!NT_SUCCESS(status = BCryptExportKey(
        hKey,        // _In_   BCRYPT_KEY_HANDLE hKey,
        NULL,        // _In_   BCRYPT_KEY_HANDLE hExportKey,
        pszBlobType, // _In_   LPCWSTR pszBlobType,
        pbKeyBlob,   // _Out_  PUCHAR pbOutput,
        dwResult,    // _In_   ULONG cbOutput,
        &dwResult,   // _Out_  ULONG *pcbResult,
        0            // _In_   ULONG dwFlags
    )))
    {
        goto Cleanup;
    }

    //// Encode the blob to base64
    //if (!Base64Encode(pbKeyBlob, dwResult, &pszBase64Encoded, &dwBase64Encoded)) {
    //    status = CCRYPT_STATUS_BASE64_DECODE_FAIL;

    //    goto Cleanup;
    //}

    //if (INVALID_HANDLE_VALUE == (hFile = CreateFileA(
    //    lpFileName,     // _In_      LPCTSTR lpFileName,
    //    GENERIC_WRITE,  // _In_      DWORD dwDesiredAccess,
    //    0,              // _In_      DWORD dwShareMode,
    //    NULL,           // _In_opt_  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    //    OPEN_ALWAYS,    // _In_      DWORD dwCreationDisposition,
    //    FILE_ATTRIBUTE_NORMAL, // _In_      DWORD dwFlagsAndAttributes,
    //    NULL            // _In_opt_  HANDLE hTemplateFile
    //)))
    //{
    //    status = GetLastError();

    //    goto Cleanup;
    //}

    //for (size_t i = 0; i < dwResult; i++)
    //{
    //    //sprintf_s((char*)byte, "0x%02x,", (char*)pbKeyBlob[i]);
    //    sprintf((char*)byte, "0x%02x, ", pbKeyBlob[i]);
    //    if (WriteFile(hFile, byte, 6, NULL, NULL) == FALSE)
    //    {
    //        printf("write faild.\n");
    //        break;
    //    }
    //}
    freopen(lpFileName, "w", stdout);

    printf("unsigned char Key[%d] = {", dwResult);

    for (size_t i = 0; i < dwResult; i++)
    {
        if (i == dwResult - 1)
            printf("0x%02x", pbKeyBlob[i]);
        else
            printf("0x%02x, ", pbKeyBlob[i]);
    }

    printf("};");

    freopen("CON", "w", stdout);

    //if (FALSE == WriteFile(
    //    hFile,            // _In_         HANDLE hFile,
    //    pbKeyBlob, // _In_         LPCVOID lpBuffer,
    //    dwResult,  // _In_         DWORD nNumberOfBytesToWrite,
    //    NULL, // _Out_opt_    LPDWORD lpNumberOfBytesWritten,
    //    NULL  // _Inout_opt_  LPOVERLAPPED lpOverlapped
    //))
    //{
    //    status = GetLastError();

    //    goto Cleanup;
    //}

Cleanup:

    /*if (pbKeyBlob != NULL)
    {
        HeapFree(GetProcessHeap(), 0, pbKeyBlob);
    }*/
 
    /*if (hFile != NULL && hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
    }*/

    *lpSize = dwResult;

    return pbKeyBlob;
}

VOID printMem(PVOID Mem, int length)
{
    if (Mem == NULL)
    {
        printf("Mem is null\n");
        return;
    }

    printf("\nsize:%d\n", length);
    int i;
    for (i = 0; i < length; i++)
        printf("%02x ", ((unsigned char *)Mem)[i]);
}

int main(int argc, char **argv)
{
    BCRYPT_ALG_HANDLE hAlgo = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    DWORD dwPubSize = 0;
    DWORD dwPrivaSize = 0;
    PVOID pPub = NULL;
    PVOID pPriv = NULL;

    if (argc != 4) {
        printf("\nUSAGE:\n");
        printf("  %s <key_size> <public_key> <private_key>\n", argv[0]);
        printf("\nARGUMENTS:\n");
        printf("  <key_size>\tThe key size in bits, must be either 2048 or 4096\n");
        printf("  <public_key>\tName of the public key file\n");
        printf("  <private_key>\tName of the private key file\n");
        return -1;
    }

    // Simple sanity check
    if (atoi(argv[1]) != 2048 && atoi(argv[1]) != 4096 && atoi(argv[1]) != 1024 && atoi(argv[1]) != 512) {
        printf("The key size must be either 512 1024 2048 4096 !\n");
        return -1;
    }

    printf("Generating keys...\n");

    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
        &hAlgo,          // _Out_  BCRYPT_ALG_HANDLE *phAlgorithm,
        BCRYPT_RSA_ALGORITHM,   // _In_   LPCWSTR pszAlgId,
        NULL,                   // _In_   LPCWSTR pszImplementation,
        0                       // _In_   DWORD dwFlags
    )))
    {
        printf("BCryptOpenAlgorithmProvider() error: %x\n", status);
        goto Cleanup;
    }

    if (!NT_SUCCESS(status = BCryptGenerateKeyPair(
        hAlgo, // _Inout_  BCRYPT_ALG_HANDLE hAlgorithm,
        &hKey, // _Out_    BCRYPT_KEY_HANDLE *phKey,
        atoi(argv[1]), // _In_     ULONG dwLength,
        0 // _In_     ULONG dwFlags
    )))
    {
        printf("BCryptGenerateKeyPair() error: %x\n", status);
        goto Cleanup;
    }

    if (!NT_SUCCESS(status = BCryptFinalizeKeyPair(
        hKey, // _Inout_  BCRYPT_KEY_HANDLE hKey,
        0 // _In_     ULONG dwFlags
    )))
    {
        printf("BCryptFinalizeKeyPair() error: %x\n", status);
        goto Cleanup;
    }

    pPub = RSAExportKey(hKey, BCRYPT_RSAPUBLIC_BLOB, argv[2], &dwPubSize);
    pPriv = RSAExportKey(hKey, BCRYPT_RSAPRIVATE_BLOB, argv[3], &dwPrivaSize);

    printMem(pPub, dwPubSize);
    printMem(pPriv, dwPrivaSize);

    if (pPub)
        HeapFree(GetProcessHeap(), 0, pPub);

    if (pPriv)
        HeapFree(GetProcessHeap(), 0, pPriv);

    printf("Done!\n");

Cleanup:

    if (hKey != NULL) {
        BCryptDestroyKey(
            hKey // _Inout_  BCRYPT_KEY_HANDLE hKey
        );
    }

    if (hAlgo != NULL) {
        BCryptCloseAlgorithmProvider(
            hAlgo, // _Inout_  BCRYPT_ALG_HANDLE hAlgorithm,
            0 // _In_     ULONG dwFlags
        );
    }

    return 0;
}
