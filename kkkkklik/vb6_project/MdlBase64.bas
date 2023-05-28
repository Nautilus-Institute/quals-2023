Attribute VB_Name = "MdlBase64"
Option Explicit
Option Base 0

' basRadix64: Radix 64 en/decoding functions
' Version 6. 20 November 2003. Added error handling for empty arrays.
' Version 5. 10 August 2003. Added EncodeBytes64() and DecodeBytes64()
'            functions that "do it properly" using a Byte array for
'            binary data and a String for textual data.
' Version 4. 17 August 2002 re-write even faster using Byte arrays
'            and StrConv function. Thanks to Chris Thompson for this
'            and for other much appreciated advice incorporated here.
' Version 3.1: 13 August 2002 mod to DecodeStr64 function
'              to cope with invalid characters.
'              Thanks to Seth Perelman for this.
' Version 3. Published January 2002 with even faster SHR/SHL functions
'            and using Mid$ function instead of appending to strings.
' Version 2. Published 12 May 2001
' Version 1. Published 28 December 2000
'************************* COPYRIGHT NOTICE*************************
' This code was originally written in Visual Basic by David Ireland
' and is copyright (c) 2000-3 D.I. Management Services Pty Limited,
' all rights reserved.

' You are free to use this code as part of your own applications
' provided you keep this copyright notice intact and acknowledge
' its authorship with the words:

'   "Contains cryptography software by David Ireland of
'   DI Management Services Pty Ltd <www.di-mgt.com.au>."

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

' Credit where credit is due:
' Some parts of this VB code are based on original C code
' by Carl M. Ellison. See "cod64.c" published 1995.
'****************** END OF COPYRIGHT NOTICE*************************

Private aDecTab(255) As Integer
Private aEncTab(63) As Byte

Public Function EncodeBytes64(abBytes() As Byte) As String
' Return base64 encoding of Byte array.
' Does not insert CRLFs. Just returns one long string,
' so it's up to the user to add line breaks or other formatting.
    Dim sOutput As String
    Dim abOutput() As Byte
    Dim sLast As String
    Dim b(3) As Byte
    Dim j As Integer
    Dim i As Long, nLen As Long, nQuants As Long
    Dim iIndex As Long
    
    'Set up error handler to catch empty array
    On Error GoTo ArrayIsEmpty
    nLen = UBound(abBytes) - LBound(abBytes) + 1
    nQuants = nLen \ 3
    iIndex = 0
    Call MakeEncTab
    If (nQuants > 0) Then
        ReDim abOutput(nQuants * 4 - 1)
        ' Now start reading in 3 bytes at a time
        For i = 0 To nQuants - 1
            For j = 0 To 2
               b(j) = abBytes((i * 3) + j)
            Next
            Call EncodeQuantumB(b)
            abOutput(iIndex) = b(0)
            abOutput(iIndex + 1) = b(1)
            abOutput(iIndex + 2) = b(2)
            abOutput(iIndex + 3) = b(3)
            iIndex = iIndex + 4
        Next
        sOutput = StrConv(abOutput, vbUnicode)
    End If
    
    ' Cope with odd bytes
    ' (no real performance hit by using strings here)
    Select Case nLen Mod 3
    Case 0
        sLast = ""
    Case 1
        b(0) = abBytes(nLen - 1)
        b(1) = 0
        b(2) = 0
        Call EncodeQuantumB(b)
        sLast = StrConv(b(), vbUnicode)
        ' Replace last 2 with =
        sLast = Left(sLast, 2) & "=="
    Case 2
        b(0) = abBytes(nLen - 2)
        b(1) = abBytes(nLen - 1)
        b(2) = 0
        Call EncodeQuantumB(b)
        sLast = StrConv(b(), vbUnicode)
        ' Replace last with =
        sLast = Left(sLast, 3) & "="
    End Select
    
    EncodeBytes64 = sOutput & sLast
    
ArrayIsEmpty:

End Function

Public Function DecodeBytes64(sEncoded As String) As Variant
' Return Byte array of decoded binary values given base64 string
' Ignores any chars not in the 64-char subset
    Dim abDecoded() As Byte
    Dim d(3) As Byte
    Dim C As Integer        ' NB Integer to catch -1 value
    Dim di As Integer
    Dim i As Long
    Dim nLen As Long
    Dim iIndex As Long
    
    nLen = Len(sEncoded)
    If nLen < 4 Then
        ' Return an empty array
        DecodeBytes64 = abDecoded
        Exit Function
    End If
    ReDim abDecoded(((nLen \ 4) * 3) - 1)
    
    iIndex = 0
    di = 0
    Call MakeDecTab
    ' Read in each char in turn
    For i = 1 To Len(sEncoded)
        C = CByte(Asc(Mid(sEncoded, i, 1)))
        C = aDecTab(C)
        If C >= 0 Then
            d(di) = CByte(C)
            di = di + 1
            If di = 4 Then
                abDecoded(iIndex) = SHL2(d(0)) Or (SHR4(d(1)) And &H3)
                iIndex = iIndex + 1
                abDecoded(iIndex) = SHL4(d(1) And &HF) Or (SHR2(d(2)) And &HF)
                iIndex = iIndex + 1
                abDecoded(iIndex) = SHL6(d(2) And &H3) Or d(3)
                iIndex = iIndex + 1
                If d(3) = 64 Then
                    iIndex = iIndex - 1
                    abDecoded(iIndex) = 0
                End If
                If d(2) = 64 Then
                    iIndex = iIndex - 1
                    abDecoded(iIndex) = 0
                End If
                di = 0
            End If
        End If
    Next i
    ' Trim to correct length
    ReDim Preserve abDecoded(iIndex - 1)
    DecodeBytes64 = abDecoded
End Function

Public Function EncodeStr64(sInput As String) As String
' Return radix64 encoding of string of binary values
' Does not insert CRLFs. Just returns one long string,
' so it's up to the user to add line breaks or other formatting.
' Version 4: Use Byte array and StrConv - much faster
    Dim abOutput() As Byte  ' Version 4: now a Byte array
    Dim sLast As String
    Dim b(3) As Byte    ' Version 4: Now 3 not 2
    Dim j As Integer
    Dim i As Long, nLen As Long, nQuants As Long
    Dim iIndex As Long
    
    EncodeStr64 = ""
    nLen = Len(sInput)
    nQuants = nLen \ 3
    iIndex = 0
    Call MakeEncTab
    If (nQuants > 0) Then
        ReDim abOutput(nQuants * 4 - 1)
        ' Now start reading in 3 bytes at a time
        For i = 0 To nQuants - 1
            For j = 0 To 2
               b(j) = Asc(Mid(sInput, (i * 3) + j + 1, 1))
            Next
            Call EncodeQuantumB(b)
            abOutput(iIndex) = b(0)
            abOutput(iIndex + 1) = b(1)
            abOutput(iIndex + 2) = b(2)
            abOutput(iIndex + 3) = b(3)
            iIndex = iIndex + 4
        Next
        EncodeStr64 = StrConv(abOutput, vbUnicode)
    End If
    
    ' Cope with odd bytes
    ' (no real performance hit by using strings here)
    Select Case nLen Mod 3
    Case 0
        sLast = ""
    Case 1
        b(0) = Asc(Mid(sInput, nLen, 1))
        b(1) = 0
        b(2) = 0
        Call EncodeQuantumB(b)
        sLast = StrConv(b(), vbUnicode)
        ' Replace last 2 with =
        sLast = Left(sLast, 2) & "=="
    Case 2
        b(0) = Asc(Mid(sInput, nLen - 1, 1))
        b(1) = Asc(Mid(sInput, nLen, 1))
        b(2) = 0
        Call EncodeQuantumB(b)
        sLast = StrConv(b(), vbUnicode)
        ' Replace last with =
        sLast = Left(sLast, 3) & "="
    End Select
    
    EncodeStr64 = EncodeStr64 & sLast
End Function

Public Function DecodeStr64(sEncoded As String) As String
' Return string of decoded binary values given radix64 string
' Ignores any chars not in the 64-char subset
' Version 4: Use Byte array and StrConv - much faster
    Dim abDecoded() As Byte 'Version 4: Now a Byte array
    Dim d(3) As Byte
    Dim C As Integer        ' NB Integer to catch -1 value
    Dim di As Integer
    Dim i As Long
    Dim nLen As Long
    Dim iIndex As Long
    
    nLen = Len(sEncoded)
    If nLen < 4 Then
        Exit Function
    End If
    ReDim abDecoded(((nLen \ 4) * 3) - 1) 'Version 4: Now base zero
    
    iIndex = 0  ' Version 4: Changed to base 0
    di = 0
    Call MakeDecTab
    ' Read in each char in turn
    For i = 1 To Len(sEncoded)
        C = CByte(Asc(Mid(sEncoded, i, 1)))
        C = aDecTab(C)
        If C >= 0 Then
            d(di) = CByte(C)    ' Version 3.1: add CByte()
            di = di + 1
            If di = 4 Then
                abDecoded(iIndex) = SHL2(d(0)) Or (SHR4(d(1)) And &H3)
                iIndex = iIndex + 1
                abDecoded(iIndex) = SHL4(d(1) And &HF) Or (SHR2(d(2)) And &HF)
                iIndex = iIndex + 1
                abDecoded(iIndex) = SHL6(d(2) And &H3) Or d(3)
                iIndex = iIndex + 1
                If d(3) = 64 Then
                    iIndex = iIndex - 1
                    abDecoded(iIndex) = 0
                End If
                If d(2) = 64 Then
                    iIndex = iIndex - 1
                    abDecoded(iIndex) = 0
                End If
                di = 0
            End If
        End If
    Next i
    ' Convert to a string
    DecodeStr64 = StrConv(abDecoded(), vbUnicode)
    ' Remove any unwanted trailing chars
    DecodeStr64 = Left(DecodeStr64, iIndex)
End Function

Private Sub EncodeQuantumB(b() As Byte)
' Expects at least 4 bytes in b, i.e. Dim b(3) As Byte
    
    Dim b0 As Byte, b1 As Byte, b2 As Byte, b3 As Byte
     
    b0 = SHR2(b(0)) And &H3F
    b1 = SHL4(b(0) And &H3) Or (SHR4(b(1)) And &HF)
    b2 = SHL2(b(1) And &HF) Or (SHR6(b(2)) And &H3)
    b3 = b(2) And &H3F
    
    b(0) = aEncTab(b0)
    b(1) = aEncTab(b1)
    b(2) = aEncTab(b2)
    b(3) = aEncTab(b3)
    
End Sub


Private Function MakeDecTab()
' Set up Radix 64 decoding table
    Dim t As Integer
    Dim C As Integer

    For C = 0 To 255
        aDecTab(C) = -1
    Next
  
    t = 0
    For C = Asc("A") To Asc("Z")
        aDecTab(C) = t
        t = t + 1
    Next
  
    For C = Asc("a") To Asc("z")
        aDecTab(C) = t
        t = t + 1
    Next
    
    For C = Asc("0") To Asc("9")
        aDecTab(C) = t
        t = t + 1
    Next
    
    C = Asc("+")
    aDecTab(C) = t
    t = t + 1
    
    C = Asc("/")
    aDecTab(C) = t
    t = t + 1
    
    C = Asc("=")    ' flag for the byte-deleting char
    aDecTab(C) = t  ' should be 64

End Function

Private Function MakeEncTab()
' Set up Radix 64 encoding table in bytes
    Dim i As Integer
    Dim C As Integer

    i = 0
    For C = Asc("A") To Asc("Z")
        aEncTab(i) = C
        i = i + 1
    Next
  
    For C = Asc("a") To Asc("z")
        aEncTab(i) = C
        i = i + 1
    Next
    
    For C = Asc("0") To Asc("9")
        aEncTab(i) = C
        i = i + 1
    Next
    
    C = Asc("+")
    aEncTab(i) = C
    i = i + 1
    
    C = Asc("/")
    aEncTab(i) = C
    i = i + 1
    
End Function

' Version 3: ShiftLeft and ShiftRight functions improved.
Private Function SHL2(ByVal bytValue As Byte) As Byte
' Shift 8-bit value to left by 2 bits
' i.e. VB equivalent of "bytValue << 2" in C
    SHL2 = (bytValue * &H4) And &HFF
End Function

Private Function SHL4(ByVal bytValue As Byte) As Byte
' Shift 8-bit value to left by 4 bits
' i.e. VB equivalent of "bytValue << 4" in C
    SHL4 = (bytValue * &H10) And &HFF
End Function

Private Function SHL6(ByVal bytValue As Byte) As Byte
' Shift 8-bit value to left by 6 bits
' i.e. VB equivalent of "bytValue << 6" in C
    SHL6 = (bytValue * &H40) And &HFF
End Function

Private Function SHR2(ByVal bytValue As Byte) As Byte
' Shift 8-bit value to right by 2 bits
' i.e. VB equivalent of "bytValue >> 2" in C
    SHR2 = bytValue \ &H4
End Function

Private Function SHR4(ByVal bytValue As Byte) As Byte
' Shift 8-bit value to right by 4 bits
' i.e. VB equivalent of "bytValue >> 4" in C
    SHR4 = bytValue \ &H10
End Function

Private Function SHR6(ByVal bytValue As Byte) As Byte
' Shift 8-bit value to right by 6 bits
' i.e. VB equivalent of "bytValue >> 6" in C
    SHR6 = bytValue \ &H40
End Function



