// FileFindWDS.cpp	- Implementation of CFileFindWDS
//
// WinDirStat - Directory Statistics
// Copyright (C) 2004 Assarbad
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//
// Author: assarbad@users.sourceforge.net
//
// Last modified: $Date: 2004/11/29 07:07:47 $

#include "StdAfx.h"
#include "FileFindWDS.h"
#include "windirstat.h"
#include "objsel.h"
#include "comdef.h"

_COM_SMARTPTR_TYPEDEF(IDsObjectPicker, IID_IDsObjectPicker);

CList<PSID> CFileFindWDS::m_sids;

HRESULT InitializeObjectPicker(IDsObjectPicker *pObjectPicker)
{
	if (pObjectPicker == NULL)
		return E_INVALIDARG;

	DSOP_INIT_INFO dsInitInfo;
	DSOP_SCOPE_INIT_INFO dsScopes[1];
	PCWSTR apszAttributes[1];

	ZeroMemory(&dsScopes, sizeof(dsScopes));
	dsScopes[0].cbSize = sizeof(DSOP_SCOPE_INIT_INFO);
	dsScopes[0].flType = DSOP_SCOPE_TYPE_TARGET_COMPUTER | DSOP_SCOPE_TYPE_ENTERPRISE_DOMAIN;
	dsScopes[0].flScope = DSOP_SCOPE_FLAG_WANT_SID_PATH | DSOP_SCOPE_FLAG_DEFAULT_FILTER_USERS;
	dsScopes[0].FilterFlags.Uplevel.flBothModes =
		DSOP_FILTER_USERS |
		DSOP_FILTER_BUILTIN_GROUPS |
		DSOP_FILTER_UNIVERSAL_GROUPS_DL |
		DSOP_FILTER_UNIVERSAL_GROUPS_SE |
		DSOP_FILTER_GLOBAL_GROUPS_DL |
		DSOP_FILTER_GLOBAL_GROUPS_SE |
		DSOP_FILTER_DOMAIN_LOCAL_GROUPS_DL |
		DSOP_FILTER_DOMAIN_LOCAL_GROUPS_SE |
		DSOP_FILTER_COMPUTERS |
		DSOP_FILTER_WELL_KNOWN_PRINCIPALS;
	dsScopes[0].FilterFlags.flDownlevel =
		DSOP_DOWNLEVEL_FILTER_USERS |
		DSOP_DOWNLEVEL_FILTER_LOCAL_GROUPS |
		DSOP_DOWNLEVEL_FILTER_GLOBAL_GROUPS |
		DSOP_DOWNLEVEL_FILTER_COMPUTERS |
		DSOP_DOWNLEVEL_FILTER_ALL_WELLKNOWN_SIDS;
	apszAttributes[0] = L"objectSid";

	ZeroMemory(&dsInitInfo, sizeof(dsInitInfo));
	dsInitInfo.cbSize = sizeof(DSOP_INIT_INFO);
	dsInitInfo.cDsScopeInfos = countof(dsScopes);
	dsInitInfo.aDsScopeInfos = dsScopes;
	dsInitInfo.flOptions = DSOP_FLAG_MULTISELECT;
	dsInitInfo.cAttributesToFetch = countof(apszAttributes);
	dsInitInfo.apwzAttributeNames = apszAttributes;
	return pObjectPicker->Initialize(&dsInitInfo);
}

HRESULT GetSIDsFromObjectPicker(IDataObject *pDataObject, CList<PSID> &sids)
{
	if (pDataObject == NULL)
		return E_INVALIDARG;

	HRESULT     hr;
	STGMEDIUM   stm;
	FORMATETC   fe;

	fe.cfFormat = RegisterClipboardFormat(CFSTR_DSOP_DS_SELECTION_LIST);
	fe.ptd = NULL;
	fe.dwAspect = DVASPECT_CONTENT;
	fe.lindex = -1;
	fe.tymed = TYMED_HGLOBAL;

	hr = pDataObject->GetData(&fe, &stm);
	if(SUCCEEDED(hr))
	{
		PDS_SELECTION_LIST pDsSelList;

		pDsSelList = (PDS_SELECTION_LIST)GlobalLock(stm.hGlobal);
		if(NULL != pDsSelList)
		{
			if (pDsSelList->cFetchedAttributes == 1)
			{
				SAFEARRAY *sa;
				BYTE HUGEP *saArray;
				PSID sid;
				ULONG cb;

				for (ULONG i = 0; i < pDsSelList->cItems; i++) 
				{
					sa = pDsSelList->aDsSelection[i].pvarFetchedAttributes[0].parray;
					cb = sa->rgsabound[0].cElements;
					hr = SafeArrayAccessData(sa, (void HUGEP **)&saArray);
					if(SUCCEEDED(hr))
					{
						sid = HeapAlloc(GetProcessHeap(), 0, cb);
						if (sid != NULL)
						{
							CopyMemory(sid, saArray, cb);
							sids.AddTail(sid);
						}
						SafeArrayUnaccessData(sa);
					}
				}
			}
			else
				hr = E_FAIL;

			GlobalUnlock(stm.hGlobal);
		}
		else
			hr = E_POINTER;

		ReleaseStgMedium(&stm);
	}

	return hr;
}

VOID CFileFindWDS::InitializeFilter()
{
	IDsObjectPickerPtr ptrObjectPicker (CLSID_DsObjectPicker);
	IDataObjectPtr ptrDataObject;

	while (!m_sids.IsEmpty())
		HeapFree(GetProcessHeap(), 0, m_sids.RemoveTail());
	SUCCEEDED(InitializeObjectPicker(ptrObjectPicker)) &&
	SUCCEEDED(ptrObjectPicker->InvokeDialog(GetApp()->m_pMainWnd == NULL ? NULL : GetApp()->m_pMainWnd->GetSafeHwnd(), (IDataObject**)&ptrDataObject)) &&
	SUCCEEDED(GetSIDsFromObjectPicker(ptrDataObject, m_sids));
}

CFileFindWDS::CFileFindWDS(void)
{
}

CFileFindWDS::~CFileFindWDS(void)
{
}

// Function to access the file attributes from outside
DWORD CFileFindWDS::GetAttributes() const
{
	ASSERT(m_hContext != NULL);
	ASSERT_VALID(this);

	if (m_pFoundInfo != NULL)
		return ((LPWIN32_FIND_DATA)m_pFoundInfo)->dwFileAttributes;
	else
		return INVALID_FILE_ATTRIBUTES;
}

// Wrapper for file size retrieval
// This function tries to return compressed file size whenever possible.
// If the file is not compressed the uncompressed size is being returned.
ULONGLONG CFileFindWDS::GetCompressedLength() const
{
	// Try to use the NT-specific API
	if (GetApp()->GetComprSizeApi()->IsSupported())
	{
		ULARGE_INTEGER ret;
		ret.LowPart = GetApp()->GetComprSizeApi()->GetCompressedFileSize(GetFilePath(), &ret.HighPart);
		
		// Check for error
		if ((GetLastError() != NO_ERROR) && (ret.LowPart == INVALID_FILE_SIZE))
			// IN case of an error return size from CFileFind object
			return GetLength();
		else
			return ret.QuadPart;
	}
	else
		// Use the file size already found by the finder object
		return GetLength();
}

BOOL CFileFindWDS::IsFiltered()
{
	if (!GetApp()->GetSecurityApi()->IsSupported() || m_sids.IsEmpty())
		return FALSE;
	return !IsDirectory() && !GetApp()->GetSecurityApi()->IsOwnedBy(GetFilePath(), m_sids);
}

// $Log: FileFindWDS.cpp,v $
// Revision 1.3  2004/11/29 07:07:47  bseifert
// Introduced SRECT. Saves 8 Bytes in sizeof(CItem). Formatting changes.
//
// Revision 1.2  2004/11/28 14:40:06  assarbad
// - Extended CFileFindWDS to replace a global function
// - Now packing/unpacking the file attributes. This even spares a call to find encrypted/compressed files.
//
// Revision 1.1  2004/11/25 23:07:24  assarbad
// - Derived CFileFindWDS from CFileFind to correct a problem of the ANSI version
//
