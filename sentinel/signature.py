"""Verificação de assinatura Authenticode usando a API WinVerifyTrust.

Executáveis do Windows podem ser assinados de duas formas:

1. **Assinatura embutida** — o certificado fica dentro do próprio .exe/.dll.
2. **Assinatura por catálogo** — o arquivo não tem assinatura própria; o hash
   dele está listado num arquivo .cat assinado pela Microsoft (comum em
   binários de System32).

Por isso tentamos primeiro a embutida e, se não houver, procuramos o hash
nos catálogos do sistema.
"""

from __future__ import annotations

import ctypes
import msvcrt
from ctypes import wintypes
from enum import Enum


class SignatureStatus(str, Enum):
    SIGNED = "assinado"
    UNSIGNED = "não assinado"
    INVALID = "inválido"
    UNKNOWN = "desconhecido"


# --------------------------------------------------------------------------- #
# Estruturas da API (espelham as structs em C de wintrust.h / mscat.h)
# --------------------------------------------------------------------------- #


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


# Política padrão de verificação Authenticode
WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
    0x00AAC56B, 0xCD44, 0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
)


class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.POINTER(GUID)),
    ]


class WINTRUST_CATALOG_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("dwCatalogVersion", wintypes.DWORD),
        ("pcwszCatalogFilePath", wintypes.LPCWSTR),
        ("pcwszMemberTag", wintypes.LPCWSTR),
        ("pcwszMemberFilePath", wintypes.LPCWSTR),
        ("hMemberFile", wintypes.HANDLE),
        ("pbCalculatedFileHash", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbCalculatedFileHash", wintypes.DWORD),
        ("pcCatalogContext", ctypes.c_void_p),
        ("hCatAdmin", wintypes.HANDLE),
    ]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pUnion", ctypes.c_void_p),  # ponteiro para FILE_INFO ou CATALOG_INFO
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


class CATALOG_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("wszCatalogFile", wintypes.WCHAR * 260),
    ]


# Constantes
WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_CHOICE_CATALOG = 2
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE = 2
WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000  # não acessa a rede durante a verificação

# Códigos de retorno que significam "não há assinatura" (vs. "assinatura ruim")
TRUST_E_NOSIGNATURE = 0x800B0100
TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003
TRUST_E_PROVIDER_UNKNOWN = 0x800B0001
NO_SIGNATURE_CODES = {
    TRUST_E_NOSIGNATURE,
    TRUST_E_SUBJECT_FORM_UNKNOWN,
    TRUST_E_PROVIDER_UNKNOWN,
}

# --------------------------------------------------------------------------- #
# Funções da DLL
# --------------------------------------------------------------------------- #

_wintrust = ctypes.WinDLL("wintrust", use_last_error=True)

_WinVerifyTrust = _wintrust.WinVerifyTrust
_WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.c_void_p]
_WinVerifyTrust.restype = wintypes.LONG

_AcquireContext2 = _wintrust.CryptCATAdminAcquireContext2
_AcquireContext2.argtypes = [
    ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(GUID),
    wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD,
]
_AcquireContext2.restype = wintypes.BOOL

_CalcHash2 = _wintrust.CryptCATAdminCalcHashFromFileHandle2
_CalcHash2.argtypes = [
    wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(ctypes.c_ubyte), wintypes.DWORD,
]
_CalcHash2.restype = wintypes.BOOL

_EnumCatalogFromHash = _wintrust.CryptCATAdminEnumCatalogFromHash
_EnumCatalogFromHash.argtypes = [
    wintypes.HANDLE, ctypes.POINTER(ctypes.c_ubyte), wintypes.DWORD,
    wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE),
]
_EnumCatalogFromHash.restype = wintypes.HANDLE

_CatalogInfoFromContext = _wintrust.CryptCATCatalogInfoFromContext
_CatalogInfoFromContext.argtypes = [
    wintypes.HANDLE, ctypes.POINTER(CATALOG_INFO), wintypes.DWORD,
]
_CatalogInfoFromContext.restype = wintypes.BOOL

_ReleaseCatalogContext = _wintrust.CryptCATAdminReleaseCatalogContext
_ReleaseCatalogContext.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD]
_ReleaseCatalogContext.restype = wintypes.BOOL

_ReleaseContext = _wintrust.CryptCATAdminReleaseContext
_ReleaseContext.argtypes = [wintypes.HANDLE, wintypes.DWORD]
_ReleaseContext.restype = wintypes.BOOL


# --------------------------------------------------------------------------- #
# Lógica
# --------------------------------------------------------------------------- #


def _win_verify_trust(union_choice: int, info: ctypes.Structure) -> int:
    """Chama WinVerifyTrust e devolve o código de retorno como unsigned."""
    data = WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    data.dwUIChoice = WTD_UI_NONE
    data.fdwRevocationChecks = WTD_REVOKE_NONE
    data.dwUnionChoice = union_choice
    data.pUnion = ctypes.cast(ctypes.pointer(info), ctypes.c_void_p)
    data.dwStateAction = WTD_STATEACTION_VERIFY
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL

    action = WINTRUST_ACTION_GENERIC_VERIFY_V2
    result = _WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))

    # Sempre liberar o estado alocado pela verificação
    data.dwStateAction = WTD_STATEACTION_CLOSE
    _WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))

    return result & 0xFFFFFFFF


def _verify_embedded(path: str) -> int:
    info = WINTRUST_FILE_INFO()
    info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
    info.pcwszFilePath = path
    return _win_verify_trust(WTD_CHOICE_FILE, info)


def _verify_catalog(path: str) -> int | None:
    """Procura o arquivo nos catálogos do sistema.

    Retorna o código do WinVerifyTrust, ou None se o hash não estiver em
    nenhum catálogo. Tenta SHA-256 (catálogos modernos) e depois SHA-1
    (catálogos antigos; None = algoritmo padrão).
    """
    for algorithm in ("SHA256", None):
        h_admin = wintypes.HANDLE()
        if not _AcquireContext2(ctypes.byref(h_admin), None, algorithm, None, 0):
            continue
        try:
            with open(path, "rb") as f:
                h_file = msvcrt.get_osfhandle(f.fileno())
                size = wintypes.DWORD(0)
                _CalcHash2(h_admin, h_file, ctypes.byref(size), None, 0)
                if size.value == 0:
                    continue
                file_hash = (ctypes.c_ubyte * size.value)()
                if not _CalcHash2(h_admin, h_file, ctypes.byref(size), file_hash, 0):
                    continue

            h_cat = _EnumCatalogFromHash(h_admin, file_hash, size.value, 0, None)
            if not h_cat:
                continue
            try:
                cat = CATALOG_INFO()
                cat.cbStruct = ctypes.sizeof(CATALOG_INFO)
                if not _CatalogInfoFromContext(h_cat, ctypes.byref(cat), 0):
                    continue

                info = WINTRUST_CATALOG_INFO()
                info.cbStruct = ctypes.sizeof(WINTRUST_CATALOG_INFO)
                info.pcwszCatalogFilePath = cat.wszCatalogFile
                info.pcwszMemberTag = bytes(file_hash).hex().upper()
                info.pcwszMemberFilePath = path
                info.pbCalculatedFileHash = file_hash
                info.cbCalculatedFileHash = size.value
                info.hCatAdmin = h_admin
                return _win_verify_trust(WTD_CHOICE_CATALOG, info)
            finally:
                _ReleaseCatalogContext(h_admin, h_cat, 0)
        finally:
            _ReleaseContext(h_admin, 0)
    return None


def check_signature(path: str) -> SignatureStatus:
    """Diz se o arquivo tem uma assinatura Authenticode válida."""
    try:
        code = _verify_embedded(path)
        if code == 0:
            return SignatureStatus.SIGNED
        if code not in NO_SIGNATURE_CODES:
            # Existe assinatura, mas ela é inválida (adulterada, cert não
            # confiável, revogado...). Isso é mais grave que "não assinado".
            return SignatureStatus.INVALID

        code = _verify_catalog(path)
        if code is None:
            return SignatureStatus.UNSIGNED
        return SignatureStatus.SIGNED if code == 0 else SignatureStatus.INVALID
    except OSError:
        return SignatureStatus.UNKNOWN
