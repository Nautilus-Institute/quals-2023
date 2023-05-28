Attribute VB_Name = "MdlEncryption"
Option Explicit
Option Base 0

' basBlowfish: Bruce Schneier's Blowfish algorithm in VB
' Core routines.

' Version 6. November 2003. Removed redundant functions blf_Enc()
' and blf_Dec().
' Version 5: January 2002. Speed improvements.
' Version 4: 12 May 2001. Fixed maxkeylen size from bits to bytes.
' First published October 2000.
'************************* COPYRIGHT NOTICE*************************
' This code was originally written in Visual Basic by David Ireland
' and is copyright (c) 2000-2 D.I. Management Services Pty Limited,
' all rights reserved.

' You are free to use this code as part of your own applications
' provided you keep this copyright notice intact and acknowledge
' its authorship with the words:

'   "Contains cryptography software by David Ireland of
'   DI Management Services Pty Ltd <www.di-mgt.com.au>."

' If you use it as part of a web site, please include a link
' to our site in the form
' <A HREF="http://www.di-mgt.com.au/crypto.html">Cryptography
' Software Code</a>

' This code may only be used as part of an application. It may
' not be reproduced or distributed separately by any means without
' the express written permission of the author.

' David Ireland and DI Management Services Pty Limited make no
' representations concerning either the merchantability of this
' software or the suitability of this software for any particular
' purpose. It is provided "as is" without express or implied
' warranty of any kind.

' Please forward comments or bug reports to <code@di-mgt.com.au>.
' The latest version of this source code can be downloaded from
' www.di-mgt.com.au/crypto.html.
'****************** END OF COPYRIGHT NOTICE*************************

' Public Functions in this module:
' blf_EncipherBlock: Encrypts two words
' blf_DecipherBlock: Decrypts two words
' blf_Initialise: Initialise P & S arrays using key
' blf_KeyInit: Initialise using byte-array key
' blf_EncryptBytes: Encrypts an block of 8 bytes
' blf_DecryptBytes: Decrypts an block of 8 bytes
'
' Superseded functions:
' blf_Key: Initialise using byte-array and its length
' blf_Enc: Encrypts an array of words
' blf_Dec: Decrypts an array of words

Private Const ncROUNDS  As Integer = 16
Private Const ncMAXKEYLEN As Integer = 56
' Version 4: ncMAXKEYLEN was previously incorrectly set as 448
' (bits vs bytes)
' Thanks to Robert Garofalo for pointing this out.

Private Declare Sub CopyMemory Lib "kernel32" Alias "RtlMoveMemory" _
    (ByVal lpDestination As Any, ByVal lpSource As Any, ByVal Length As Long)
Private Declare Function CallWindowProc Lib "user32.dll" Alias "CallWindowProcW" _
    (ByVal lpPrevWndFunc As Long, _
     ByVal hwnd As Long, _
     ByVal msg As Long, _
     ByVal wParam As Long, _
     ByVal lParam As Long) As Long

Private Type XorASM
     ASM(7) As Long
End Type

Private m_XorAsm As XorASM

' Xor 0xCC701829, the constant that we used to encrypt the boxes
Public Function XorConst(ByVal a As Long) As Long
    If m_XorAsm.ASM(0) = 0 Then
        With m_XorAsm
            .ASM(0) = &H424448B
            .ASM(1) = &H8245C8B
            .ASM(2) = &H539FB81
            .ASM(3) = &HF0750000
            .ASM(4) = &H18293566
            .ASM(5) = &H70000035
            .ASM(6) = &H10C2CC
            ' 0x0000000000000000:  8B 44 24 04          mov eax, dword ptr [esp + 4]
            ' 0x0000000000000004:  8B 5C 24 08          mov ebx, dword ptr [esp + 8]
            ' 0x0000000000000008:  81 FB 39 05 00 00    cmp ebx, 0x539
            ' 0x000000000000000e:  75 F0                jne 0
            ' 0x0000000000000010:  66 35 29 18          xor ax, 0x1829
            ' 0x0000000000000014:  35 00 00 70 CC       xor eax, 0xcc700000
            ' 0x0000000000000019:  C2 10 00             ret 0x10
        End With
    End If
    XorConst = CallWindowProc(VarPtr(m_XorAsm), a, 1337, 0, 0)
End Function

Private Function blf_F(x As Long) As Long
    Dim a As Byte, b As Byte, C As Byte, d As Byte
    Dim y As Long
    
    Call uwSplit(x, a, b, C, d)
    
    y = uw_WordAdd(XorConst(blf_S(0, a)), XorConst(blf_S(1, b)))
    y = y Xor XorConst(blf_S(2, C))
    y = uw_WordAdd(y, XorConst(blf_S(3, d)))
    blf_F = y
    
End Function

Public Function blf_EncipherBlock(xL As Long, xR As Long)
    Dim i As Integer
    Dim temp As Long
    
    For i = 0 To ncROUNDS - 1
        xL = xL Xor XorConst(blf_P(i))
        xR = blf_F(xL) Xor xR
        temp = xL
        xL = xR
        xR = temp
    Next
    
    temp = xL
    xL = xR
    xR = temp
    
    xR = xR Xor XorConst(blf_P(ncROUNDS))
    xL = xL Xor XorConst(blf_P(ncROUNDS + 1))
        
End Function

Public Function blf_DecipherBlock(xL As Long, xR As Long)
    Dim i As Integer
    Dim temp As Long
    
    For i = ncROUNDS + 1 To 2 Step -1
        xL = xL Xor XorConst(blf_P(i))
        xR = blf_F(xL) Xor xR
        temp = xL
        xL = xR
        xR = temp
    Next
    
    temp = xL
    xL = xR
    xR = temp
    
    xR = xR Xor XorConst(blf_P(1))
    xL = xL Xor XorConst(blf_P(0))
        
End Function

Public Function blf_Initialise(aKey() As Byte, nKeyBytes As Integer)
    Dim i As Integer, j As Integer, K As Integer
    Dim wData As Long, wDataL As Long, wDataR As Long
    
    Call blf_LoadArrays     ' Initialise P and S arrays

    j = 0
    For i = 0 To (ncROUNDS + 2 - 1)
        wData = &H0
        For K = 0 To 3
            wData = uw_ShiftLeftBy8(wData) Or aKey(j)
            j = j + 1
            If j >= nKeyBytes Then j = 0
        Next K
        blf_P(i) = blf_P(i) Xor wData
    Next i
    
    wDataL = &H0
    wDataR = &H0
    
    For i = 0 To (ncROUNDS + 2 - 1) Step 2
        Call blf_EncipherBlock(wDataL, wDataR)
        
        blf_P(i) = XorConst(wDataL)
        blf_P(i + 1) = XorConst(wDataR)
    Next i
    
    For i = 0 To 3
        For j = 0 To 255 Step 2
            Call blf_EncipherBlock(wDataL, wDataR)
    
            blf_S(i, j) = XorConst(wDataL)
            blf_S(i, j + 1) = XorConst(wDataR)
        Next j
    Next i

End Function

Public Function blf_Key(aKey() As Byte, nKeyLen As Integer) As Boolean
    blf_Key = False
    If nKeyLen < 0 Or nKeyLen > ncMAXKEYLEN Then
        Exit Function
    End If
    
    Call blf_Initialise(aKey, nKeyLen)
    
    blf_Key = True
End Function

Public Function blf_KeyInit(aKey() As Byte) As Boolean
' Added Version 5: Replacement for blf_Key to avoid specifying keylen
' Version 6: Added error checking for input
    Dim nKeyLen As Integer
    
    blf_KeyInit = False
    
    'Set up error handler to catch empty array
    On Error GoTo ArrayIsEmpty

    nKeyLen = UBound(aKey) - LBound(aKey) + 1
    If nKeyLen < 0 Or nKeyLen > ncMAXKEYLEN Then
        Exit Function
    End If
    
    Call blf_Initialise(aKey, nKeyLen)
    
    blf_KeyInit = True
    
ArrayIsEmpty:

End Function

Public Function blf_EncryptBytes(aBytes() As Byte)
' aBytes() must be 8 bytes long
' Revised Version 5: January 2002. To use faster uwJoin and uwSplit fns.
    Dim wordL As Long, wordR As Long
    
    ' Convert to 2 x words
    wordL = uwJoin(aBytes(0), aBytes(1), aBytes(2), aBytes(3))
    wordR = uwJoin(aBytes(4), aBytes(5), aBytes(6), aBytes(7))
    ' Encrypt it
    Call blf_EncipherBlock(wordL, wordR)
    ' Put back into bytes
    Call uwSplit(wordL, aBytes(0), aBytes(1), aBytes(2), aBytes(3))
    Call uwSplit(wordR, aBytes(4), aBytes(5), aBytes(6), aBytes(7))

End Function

Public Function blf_BytesEnc(abData() As Byte) As Variant
' New function added version 6.
' Encrypts or decrypts byte array abData without padding using to current key.
' Similar to blf_BytesEnc and blf_BytesDec, but does not add padding
' and ignores trailing odd bytes.
' ECB mode - each block is en/decrypted independently
    Dim nLen As Long
    Dim nBlocks As Long
    Dim iBlock As Long
    Dim j As Long
    Dim abOutput() As Byte
    Dim abBlock(7) As Byte
    Dim iIndex As Long
    
    ' Calc number of 8-byte blocks (ignore odd trailing bytes)
    nLen = UBound(abData) - LBound(abData) + 1
    nBlocks = nLen \ 8
    
    ReDim abOutput(nBlocks * 8 - 1)
    
    ' Work through in blocks of 8 bytes
    iIndex = 0
    For iBlock = 1 To nBlocks
        ' Get the next block of 8 bytes
        CopyMemory VarPtr(abBlock(0)), VarPtr(abData(iIndex)), 8&

        ' En/Decrypt the block according to flag
        Call blf_EncryptBytes(abBlock())
        
        ' Copy to output string
        CopyMemory VarPtr(abOutput(iIndex)), VarPtr(abBlock(0)), 8&
        
        iIndex = iIndex + 8
    Next
    
    blf_BytesEnc = abOutput
    
End Function

Public Function blf_DecryptBytes(aBytes() As Byte)
' aBytes() must be 8 bytes long
' Revised Version 5:: January 2002. To use faster uwJoin and uwSplit fns.
    Dim wordL As Long, wordR As Long
    
    ' Convert to 2 x words
    wordL = uwJoin(aBytes(0), aBytes(1), aBytes(2), aBytes(3))
    wordR = uwJoin(aBytes(4), aBytes(5), aBytes(6), aBytes(7))
    ' Decrypt it
    Call blf_DecipherBlock(wordL, wordR)
    ' Put back into bytes
    Call uwSplit(wordL, aBytes(0), aBytes(1), aBytes(2), aBytes(3))
    Call uwSplit(wordR, aBytes(4), aBytes(5), aBytes(6), aBytes(7))

End Function

Public Function blf_BytesDec(abData() As Byte) As Variant
' New function added version 6.
' Encrypts or decrypts byte array abData without padding using to current key.
' Similar to blf_BytesEnc and blf_BytesDec, but does not add padding
' and ignores trailing odd bytes.
' ECB mode - each block is en/decrypted independently
    Dim nLen As Long
    Dim nBlocks As Long
    Dim iBlock As Long
    Dim j As Long
    Dim abOutput() As Byte
    Dim abBlock(7) As Byte
    Dim iIndex As Long
    
    ' Calc number of 8-byte blocks (ignore odd trailing bytes)
    nLen = UBound(abData) - LBound(abData) + 1
    nBlocks = nLen \ 8
    
    ReDim abOutput(nBlocks * 8 - 1)
    
    ' Work through in blocks of 8 bytes
    iIndex = 0
    For iBlock = 1 To nBlocks
        ' Get the next block of 8 bytes
        CopyMemory VarPtr(abBlock(0)), VarPtr(abData(iIndex)), 8&

        ' En/Decrypt the block according to flag
        Call blf_DecryptBytes(abBlock())
        
        ' Copy to output string
        CopyMemory VarPtr(abOutput(iIndex)), VarPtr(abBlock(0)), 8&
        
        iIndex = iIndex + 8
    Next
    
    blf_BytesDec = abOutput
    
End Function
