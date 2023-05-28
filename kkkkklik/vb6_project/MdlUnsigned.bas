Attribute VB_Name = "MdlUnsigned"
Private Const OFFSET_4 = 4294967296#
Private Const MAXINT_4 = 2147483647

Public Function uwJoin(a As Byte, b As Byte, C As Byte, d As Byte) As Long
' Added Version 5: replacement for uw_WordJoin
' Join 4 x 8-bit bytes into one 32-bit word a.b.c.d
    uwJoin = ((a And &H7F) * &H1000000) Or (b * &H10000) Or (CLng(C) * &H100) Or d
    If a And &H80 Then
        uwJoin = uwJoin Or &H80000000
    End If
End Function

Public Sub uwSplit(ByVal w As Long, a As Byte, b As Byte, C As Byte, d As Byte)
' Added Version 5: replacement for uw_WordSplit
' Split 32-bit word w into 4 x 8-bit bytes
    a = CByte(((w And &HFF000000) \ &H1000000) And &HFF)
    b = CByte(((w And &HFF0000) \ &H10000) And &HFF)
    C = CByte(((w And &HFF00) \ &H100) And &HFF)
    d = CByte((w And &HFF) And &HFF)
End Sub

' Function re-written 11 May 2001.
Public Function uw_ShiftLeftBy8(wordX As Long) As Long
    ' Shift 32-bit long value to left by 8 bits
    ' i.e. VB equivalent of "wordX << 8" in C
    ' Avoiding problem with sign bit
    uw_ShiftLeftBy8 = (wordX And &H7FFFFF) * &H100
    If (wordX And &H800000) <> 0 Then
        uw_ShiftLeftBy8 = uw_ShiftLeftBy8 Or &H80000000
    End If
End Function

Public Function uw_WordAdd(wordA As Long, wordB As Long) As Long
' Adds words A and B avoiding overflow
    Dim myUnsigned As Double
    
    myUnsigned = LongToUnsigned(wordA) + LongToUnsigned(wordB)
    ' Cope with overflow
    ' [2008-06-25] Changed "> OFFSET_4" to ">= OFFSET_4'
    ' -- thanks to Ernie Gibbs for this.
    If myUnsigned >= OFFSET_4 Then
        myUnsigned = myUnsigned - OFFSET_4
    End If
    uw_WordAdd = UnsignedToLong(myUnsigned)
    
End Function

Public Function uw_WordSub(wordA As Long, wordB As Long) As Long
' Subtract words A and B avoiding underflow
    Dim myUnsigned As Double
    
    myUnsigned = LongToUnsigned(wordA) - LongToUnsigned(wordB)
    ' Cope with underflow
    If myUnsigned < 0 Then
        myUnsigned = myUnsigned + OFFSET_4
    End If
    uw_WordSub = UnsignedToLong(myUnsigned)
End Function

'****************************************************
' These two functions from Microsoft Article Q189323
' "HOWTO: convert between Signed and Unsigned Numbers"

Function UnsignedToLong(value As Double) As Long
    If value < 0 Or value >= OFFSET_4 Then Error 6 ' Overflow
    If value <= MAXINT_4 Then
        UnsignedToLong = value
    Else
        UnsignedToLong = value - OFFSET_4
    End If
End Function

Public Function LongToUnsigned(value As Long) As Double
    If value < 0 Then
        LongToUnsigned = value + OFFSET_4
    Else
        LongToUnsigned = value
    End If
End Function

' End of Microsoft-article functions
'****************************************************
