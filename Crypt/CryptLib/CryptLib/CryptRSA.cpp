
#include "CryptRSA.h"

NTSTATUS RSAGenerateKey(DWORD dwKeyLen, PVOID* lpPubKey, DWORD* lpcbPubKey, PVOID* lpPrivKey, DWORD* lpcbPriv)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BCRYPT_ALG_HANDLE hAlgo = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD dwResult = 0;
    PUCHAR pPub = NULL;
    PUCHAR pPriv = NULL;
    
    do
    {
        if (dwKeyLen != 512 && dwKeyLen != 1024 && dwKeyLen != 2048 && dwKeyLen != 4096)
            break;

        if (lpPubKey == NULL || lpcbPriv == NULL || lpPrivKey == NULL || lpcbPubKey == NULL)
            break;

        status = BCryptOpenAlgorithmProvider(&hAlgo, BCRYPT_RSA_ALGORITHM, NULL, 0);
        
        if (!NT_SUCCESS(status))
            break;

        status = BCryptGenerateKeyPair(hAlgo, &hKey, dwKeyLen, 0);

        if (!NT_SUCCESS(status))
            break;

        status = BCryptFinalizeKeyPair(hKey, 0);

        if (!NT_SUCCESS(status))
            break;

        // get size
        BCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &dwResult, 0);

        if (dwResult == 0)
        {
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        pPub = (PUCHAR)GetMem(dwResult);

        if (pPub == NULL)
        {
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        RtlZeroMemory(pPub, dwResult);

        status = BCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, pPub, dwResult, &dwResult, 0);

        if (!NT_SUCCESS(status))
            break;

        *lpcbPubKey = dwResult;
        *lpPubKey = pPub;

        dwResult = 0;

        BCryptExportKey(hKey, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, 0, &dwResult, 0);

        if (dwResult == 0)
        {
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        pPriv = (PUCHAR)GetMem(dwResult);

        if (pPriv == NULL)
        {
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        RtlZeroMemory(pPriv, dwResult);

        status = BCryptExportKey(hKey, NULL, BCRYPT_RSAPRIVATE_BLOB, pPriv, dwResult, &dwResult, 0);

        if (!NT_SUCCESS(status))
            break;

        *lpcbPriv = dwResult;
        *lpPrivKey = pPriv;

    } while (false);

    if (hKey != NULL)
        BCryptDestroyKey(hKey);

    if (hAlgo)
        BCryptCloseAlgorithmProvider(hAlgo, 0);

    if (!NT_SUCCESS(status))
    {
        if (pPub)
            FreeMem(pPub);

        if (pPriv)
            FreeMem(pPriv);

        if (lpcbPriv)
            *lpcbPriv = 0;

        if (lpcbPubKey)
            *lpcbPubKey = 0;

        if (lpPubKey)
            *lpPubKey = NULL;

        if (lpPrivKey)
            *lpPrivKey = NULL;
    }

    return status;
}

BOOLEAN RSACheck(DWORD cbKeySize, DWORD cbData, BOOLEAN bEncrypt)
{
    if (bEncrypt)
    {
        switch (cbKeySize)
        {
        case 91: // 512bit
            if (cbData > 64)
                return FALSE;
            break;
        case 155: // 1024bit
            if (cbData > 128)
                return FALSE;
            break;
        case 283: // 2048bit
            if (cbData > 256)
                return FALSE;
            break;
        case 539: // 4096bit
            if (cbData > 512)
                return FALSE;
            break;
        default:
            return FALSE;
            break;
        }
        /*if (cbKeySize - cbData > 27)
            return TRUE;
        else
            return FALSE;*/
        return TRUE;
    }
    else
    {
        switch (cbKeySize)
        {
        case 155: // 512bit
        case 283: // 1024bit
        case 539: // 2048bit
        case 1051: // 4096bit
            return TRUE;
            break;
        default:
            return FALSE;
            break;
        }
    }

}


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

DWORD RSAGetBuffSize(DWORD cbKey, BOOLEAN bPublicKey)
{
    if (bPublicKey)
    {
        switch (cbKey)
        {
        case 91:
            return 64;
        case 155:
            return 128;
        case 283:
            return 256;
        case 539:
            return 512;
        default:
            return 0;
            break;
        }
    }
    else
    {
        switch (cbKey)
        {
        case 155:
            return 64;
        case 283:
            return 128;
        case 539:
            return 256;
        case 1051:
            return 512;
        default:
            return 0;
            break;
        }
    }
}

PUCHAR RSAGetEncryptData(DWORD cbKey, PUCHAR encryptData, DWORD cbEncryptData, DWORD* dwRealData)
{
    PUCHAR pRet = NULL;

    DWORD dwNeed = RSAGetBuffSize(cbKey, TRUE);

    if (dwNeed == 0)
        return NULL;

    if (dwNeed < cbEncryptData)
        return 0;
    else
    {
        pRet = (PUCHAR)GetMem(dwNeed);
        
        if (pRet == NULL)
            return NULL;

        RtlZeroMemory(pRet, dwNeed);

        RtlCopyMemory(pRet, encryptData, dwNeed);

        *dwRealData = dwNeed;

        return pRet;
    }
}

NTSTATUS RSAEncrypt(PUCHAR PublicKey, DWORD cbPublicKey, PUCHAR encryptData, DWORD cbEncryptData, PVOID* lpEncryped, DWORD* lpCbEncrypt)
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    BCRYPT_ALG_HANDLE hAlgo = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD dwResult = 0;
    PUCHAR pEncryptedBuff = NULL;

    PUCHAR pPadEncryptBuff = NULL;
    DWORD  cbPadEncryBuff = 0;

    do
    {
        if (PublicKey == NULL || cbPublicKey == 0 || encryptData == NULL || cbEncryptData == 0 || lpEncryped == NULL || lpCbEncrypt == NULL)
            break;

        if (!RSACheck(cbPublicKey, cbEncryptData, TRUE))
            break;

        // 纯RSA的忧伤
        if (encryptData[0] > 0xb6)
            break;

        pPadEncryptBuff = RSAGetEncryptData(cbPublicKey, encryptData, cbEncryptData, &cbPadEncryBuff);

        if (pPadEncryptBuff == NULL)
            break;

        status = BCryptOpenAlgorithmProvider(&hAlgo, BCRYPT_RSA_ALGORITHM, NULL, 0);

        if (!NT_SUCCESS(status))
            break;

        status = BCryptImportKeyPair(hAlgo,
            NULL,
            BCRYPT_RSAPUBLIC_BLOB,
            &hKey,
            PublicKey,
            cbPublicKey,
            BCRYPT_NO_KEY_VALIDATION);

        if (!NT_SUCCESS(status))
        {
            DPRINT("Failded to import key status:0x%x\n", status);
            break;
        }

        status = BCryptEncrypt(hKey,
            pPadEncryptBuff,
            cbPadEncryBuff,
            NULL,
            NULL,
            0,
            NULL,
            0,
            &dwResult,
            0);

        if (dwResult == 0)
        {
            DPRINT("Failded to get Encrypt size.\n");
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        pEncryptedBuff = (PUCHAR)GetMem(dwResult);

        if (pEncryptedBuff == NULL)
        {
            status = STATUS_NO_MEMORY;
            break;
        }

        RtlZeroMemory(pEncryptedBuff, dwResult);

        status = BCryptEncrypt(hKey,
            pPadEncryptBuff,
            cbPadEncryBuff,
            NULL,
            NULL,
            0,
            pEncryptedBuff,
            dwResult,
            &dwResult,
            0);

        if (!NT_SUCCESS(status))
        {
            DPRINT("Failed encrypt data status:0x%x\n", status);
            break;
        }

        *lpCbEncrypt = dwResult;

        *lpEncryped = pEncryptedBuff;

    } while (false);

    if (!NT_SUCCESS(status))
    {
        if (pEncryptedBuff)
            FreeMem(pEncryptedBuff);

        if (lpCbEncrypt)
            *lpCbEncrypt = 0;

        if (lpEncryped)
            *lpEncryped = NULL;
    }

    if (pPadEncryptBuff)
        FreeMem(pPadEncryptBuff);

    if (hKey)
        BCryptDestroyKey(hKey);

    if (hAlgo)
        BCryptCloseAlgorithmProvider(hAlgo, 0);

    return status;
}

NTSTATUS RSADecrypt(PUCHAR PrivateKey, DWORD cbPrivateKey, PUCHAR decryptData, DWORD cbDecryptData, PVOID* lpDecrypted, DWORD* lpCbDecrypted)
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BCRYPT_ALG_HANDLE hAlgo = NULL;
    DWORD dwResult = 0;
    PUCHAR decryptedBuff = NULL;

    do
    {
        if (PrivateKey == NULL || cbPrivateKey == 0 ||
            decryptData == NULL || cbDecryptData == 0 ||
            lpDecrypted == NULL || lpCbDecrypted == NULL)
            break;

        if (!RSACheck(cbPrivateKey, cbDecryptData, FALSE))
            break;

        if (RSAGetBuffSize(cbPrivateKey, FALSE) != cbDecryptData)
            break;

        status = BCryptOpenAlgorithmProvider(&hAlgo,
            BCRYPT_RSA_ALGORITHM,
            NULL,
            0);

        if (!NT_SUCCESS(status))
            break;

        status = BCryptImportKeyPair(hAlgo,
            NULL,
            BCRYPT_RSAPRIVATE_BLOB,
            &hKey,
            PrivateKey,
            cbPrivateKey,
            BCRYPT_NO_KEY_VALIDATION);

        if (!NT_SUCCESS(status))
        {
            DPRINT("Faild to Import Key status :0x%x\n", status);
            break;
        }

        BCryptDecrypt(hKey,
            decryptData,
            cbDecryptData,
            NULL,
            NULL,
            0,
            NULL,
            0,
            &dwResult,
            0);

        if (dwResult == 0)
        {
            DPRINT("Failed to get req size.\n");
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        decryptedBuff = (PUCHAR)GetMem(dwResult);

        if (decryptedBuff == NULL)
        {
            status = STATUS_NO_MEMORY;
            break;
        }

        RtlZeroMemory(decryptedBuff, dwResult);

        status = BCryptDecrypt(hKey,
            decryptData,
            cbDecryptData,
            NULL,
            NULL,
            0,
            decryptedBuff,
            dwResult,
            &dwResult,
            0);

        if (!NT_SUCCESS(status))
        {
            DPRINT("Failed decrypt status:0x%x\n", status);
            break;
        }

        *lpCbDecrypted = dwResult;
        *lpDecrypted = decryptedBuff;

    } while (false);

    if (!NT_SUCCESS(status))
    {
        if (decryptedBuff)
            FreeMem(decryptedBuff);

        if (lpCbDecrypted)
            *lpCbDecrypted = 0;

        if (lpDecrypted)
            *lpDecrypted = NULL;
    }

    if (hKey)
        BCryptDestroyKey(hKey);

    if (hAlgo)
        BCryptCloseAlgorithmProvider(hAlgo, 0);

    return status;
}



