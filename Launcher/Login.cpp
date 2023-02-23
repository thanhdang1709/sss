#include "framework.h"
#include "Resource.h"

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#include <shlwapi.h>
#pragma comment (lib,"Shlwapi.lib")

extern "C" {
#include "..\Server\oicq\tea.h"
}

enum MsgType { Request = 0, Response = 1, Notify = 2, Ack = 3, Internal = 4 };

#pragma pack(push, 1)
struct CSHEAD
{
	unsigned int TotalLength;
	short Ver;
	short DialogID;
	int Seq;
	unsigned int Uin;
	char BodyFlag;
	unsigned char OptLength;
};

struct MSGHEAD
{
	unsigned short MsgID;
	short MsgType;
	int MsgSeq;
	char SrcFE;
	char DstFE;
	short SrcID;
	short DstID;
	unsigned short BodyLen;
};
#pragma pack(pop)


inline BYTE Get8(BYTE* ptr)
{
	return *(BYTE*)ptr;
}
inline WORD Get16(BYTE* ptr)
{
	return ntohs(*(WORD*)ptr);
}
inline DWORD Get32(BYTE* ptr)
{
	return ntohl(*(DWORD*)ptr);
}

inline void Set8(BYTE* ptr, BYTE val)
{
	*(BYTE*)ptr = val;
}
inline void Set16(BYTE* ptr, WORD val)
{
	*(WORD*)ptr = htons(val);
}
inline void Set32(BYTE* ptr, DWORD val)
{
	*(DWORD*)ptr = htonl(val);
}

inline BYTE Read8(BYTE*& ptr)
{
	return *(BYTE*)ptr++;
}
inline WORD Read16(BYTE*& ptr)
{
	return ntohs(*reinterpret_cast<WORD*&>(ptr)++);
}
inline DWORD Read32(BYTE*& ptr)
{
	return ntohl(*reinterpret_cast<DWORD*&>(ptr)++);
}

inline void Write8(BYTE*& ptr, BYTE val)
{
	*(BYTE*)ptr++ = val;
}
inline void Write16(BYTE*& ptr, WORD val)
{
	*reinterpret_cast<WORD*&>(ptr)++ = htons(val);
}
inline void Write32(BYTE*& ptr, DWORD val)
{
	*reinterpret_cast<DWORD*&>(ptr)++ = htonl(val);
}


extern HINSTANCE hInst;
extern TCHAR GamePath[MAX_PATH];
extern TCHAR GameAppFile[MAX_PATH];
extern UINT LoginUin;
extern char LoginPwd[128];
UINT IP = 0;
USHORT Port = 0;
BYTE Key[16];


constexpr int WM_MY_ASYNCSOCKET = (WM_APP + 1);
SOCKET hSocket = NULL;
LONG_PTR BufferPtr = NULL;
LONG_PTR BufferSize = 0;
LONG_PTR BufferOffset = 0;


void CloseConnect()
{
	if (hSocket)
	{
		closesocket(hSocket);
		hSocket = 0;
	}
}

void ConnectServer(HWND hWnd)
{
	CloseConnect();
	sockaddr_in ��ַ;
	hSocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	��ַ.sin_family = PF_INET;
	��ַ.sin_addr.S_un.S_addr = IP;
	��ַ.sin_port = htons(Port);

	connect(hSocket, (sockaddr*)&��ַ, sizeof(��ַ));

	WSAAsyncSelect(hSocket, hWnd, WM_MY_ASYNCSOCKET, FD_READ | FD_WRITE | FD_CLOSE);
}



void SendToServer(short MsgID, const BYTE* Data, DWORD Length, short SrcID, char DstFE, short DstID, short MsgType, char Encrypt)
{
	CSHEAD* ProtocolHead;
	MSGHEAD* MsgHead;
	void* MsgBody;
	int TotalLength;

	int MsgLen = sizeof(MSGHEAD) + USHORT(Length);
	MsgHead = (MSGHEAD*)malloc(MsgLen);
	if (!MsgHead)
	{
		return;
	}
	MsgHead->MsgID = htons(MsgID);
	MsgHead->MsgType = htons(MsgType);
	MsgHead->MsgSeq = ntohl(-1);
	MsgHead->SrcFE = 1;
	MsgHead->DstFE = DstFE;
	MsgHead->SrcID = htons(SrcID);
	MsgHead->DstID = htons(DstID);
	MsgHead->BodyLen = ntohs(sizeof(USHORT) + USHORT(Length));
	MsgBody = (void*)(MsgHead + 1);
	memcpy(MsgBody, Data, Length);
	if (Encrypt)
	{
		int EncryptLen = oi_symmetry_encrypt2_len(MsgLen);
		TotalLength = sizeof(CSHEAD) + EncryptLen;
		if (!(ProtocolHead = (CSHEAD*)malloc(TotalLength)))
		{
			return;
		}
		oi_symmetry_encrypt2((BYTE*)MsgHead, MsgLen, Key, (BYTE*)(ProtocolHead + 1), &EncryptLen);
		TotalLength = sizeof(CSHEAD) + EncryptLen;
	}
	else
	{
		TotalLength = sizeof(CSHEAD) + MsgLen;
		if (!(ProtocolHead = (CSHEAD*)malloc(TotalLength)))
		{
			return;
		}
		memcpy((MSGHEAD*)(ProtocolHead + 1), MsgHead, MsgLen);
	}
	free(MsgHead);

	ProtocolHead->TotalLength = htonl(TotalLength);
	ProtocolHead->Ver = ntohs(116);
	ProtocolHead->DialogID = htons(SrcID);
	ProtocolHead->Seq = ntohl(0);
	ProtocolHead->Uin = ntohl(0);
	ProtocolHead->BodyFlag = Encrypt;
	ProtocolHead->OptLength = 0;

	int LeftoverLength = TotalLength;
	int SendLength;
	char* p = (char*)ProtocolHead;
	while (LeftoverLength > 0)
	{
		SendLength = send(hSocket, p, LeftoverLength, 0);
		if (SendLength <= 0)
		{
			break;
		}
		p += SendLength;
		LeftoverLength -= SendLength;
	}
	free(ProtocolHead);
}


void OnFullReceive(void* Data, ULONG_PTR Length)
{
	CSHEAD* ProtocolHead = (CSHEAD*)Data;
	MSGHEAD* MsgHead;
	BYTE* Body;

	DWORD HeadLen = sizeof(CSHEAD) + ProtocolHead->OptLength;
	DWORD BodyLen = Length - HeadLen;
	if (BodyLen)
	{
		MsgHead = (MSGHEAD*)((DWORD)Data + HeadLen);
		if (ProtocolHead->BodyFlag)
		{
			Body = (BYTE*)malloc(BodyLen);
			if (!Body)
			{
				return;
			}
			if (oi_symmetry_decrypt2((BYTE*)MsgHead, BodyLen, Key, Body, (int*)&BodyLen) == false)
			{
				free(Body);
				return;
			}
		}
		else
		{
			Body = (BYTE*)malloc(BodyLen);
			if (!Body)
			{
				return;
			}
			memcpy(Body, MsgHead, BodyLen);
		}
		MsgHead = (MSGHEAD*)Body;
		Body = (BYTE*)Body + sizeof(MSGHEAD);
		BodyLen = BodyLen - sizeof(MSGHEAD);

		OnRecvFromServer(ntohs(MsgHead->MsgID), Body, ntohs(MsgHead->BodyLen));

		free(MsgHead);
	}
}

void OnAsyncSocket(HWND hDlg, SOCKET hSocket, WORD Event, WORD Error)
{
	switch (Event)
	{
	case FD_READ:
	{
		char buf[4096];
		char* pData = buf;
		int iLength = recv(hSocket, buf, sizeof(buf), 0);
		if (iLength <= 0)
		{
			break;
		}
		long left;
		long need;
		void* p;
		do
		{
			if (BufferPtr)
			{
				if (BufferOffset < sizeof(int))
				{
					left = min(iLength, int(sizeof(int) - BufferOffset));
					memcpy((void*)(BufferPtr + BufferOffset), pData, left);
					BufferOffset += left;
					if (BufferOffset < sizeof(int))
					{
						break;
					}
					pData += left;
					iLength -= left;
				}
				need = ntohl(*(u_long*)BufferPtr);
				left = need - BufferOffset;
				if (need > BufferSize)
				{
					BufferSize = need;
					p = realloc((void*)BufferPtr, BufferSize);
					if (!p)
					{
						//printf("�ڴ治��\n");
						break;
					}
					BufferPtr = (ULONG_PTR)p;
				}
				if (left >= 0)
				{
					left = min(iLength, left);
					memcpy((void*)(BufferPtr + BufferOffset), pData, left);
					BufferOffset += left;
					if (BufferOffset < need)
					{
						break;
					}
					OnFullReceive(hDlg, (BYTE*)BufferPtr, need);
					pData += left;
					iLength -= left;
				}
				free((void*)BufferPtr);
				BufferPtr = 0;
				BufferOffset = 0;
			}
			while (iLength > 0)
			{
				if (iLength < sizeof(int))
				{
					need = sizeof(int);
				}
				else
				{
					need = ntohl(*(u_long*)pData);
				}
				if (need > iLength)
				{
					BufferSize = need;
					p = malloc(BufferSize);
					if (!p)
					{
						//printf("�ڴ治��\n");
						break;
					}
					BufferPtr = (ULONG_PTR)p;
					memcpy((void*)BufferPtr, pData, iLength);
					BufferOffset = iLength;
					break;
				}
				else
				{
					OnFullReceive(hDlg, (BYTE*)pData, need);
					pData += need;
					iLength -= need;
				}
			}
		} while (false);
		break;
	}
	case FD_WRITE:
		//�����ӷ�����
		break;
	case FD_CLOSE:
		//���ӹر�
		break;
	}
}


void MyRequestGetUin(char* u)
{
	BYTE buf[8192];
	BYTE* p = buf;
	size_t len;

	len = strlen(u);
	Write8(p, (BYTE)len);
	memcpy(p, u, len);
	p += len;

	len = p - buf;
	SendToServer(1, buf, len, 0, 0, 0, 0, true);
}

void MyRequestRegister(char* u, char* pwd)
{
	BYTE buf[8192];
	BYTE* p = buf;
	size_t len;

	len = strlen(u);
	Write8(p, (BYTE)len);
	memcpy(p, u, len);
	p += len;

	len = strlen(pwd);
	Write8(p, (BYTE)len);
	memcpy(p, pwd, len);
	p += len;

	len = p - buf;
	SendToServer(2, buf, len, 0, 0, 0, 0, true);
}
