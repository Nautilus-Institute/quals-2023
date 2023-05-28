VERSION 5.00
Begin VB.Form FrmMain 
   AutoRedraw      =   -1  'True
   BackColor       =   &H00FFFFFF&
   BorderStyle     =   3  'Fixed Dialog
   Caption         =   "kkkkklik"
   ClientHeight    =   5010
   ClientLeft      =   13770
   ClientTop       =   2025
   ClientWidth     =   5130
   LinkTopic       =   "Form1"
   MaxButton       =   0   'False
   MinButton       =   0   'False
   ScaleHeight     =   334
   ScaleMode       =   3  'Pixel
   ScaleWidth      =   342
   ShowInTaskbar   =   0   'False
   Begin VB.PictureBox pic 
      Appearance      =   0  'Flat
      AutoRedraw      =   -1  'True
      AutoSize        =   -1  'True
      BackColor       =   &H80000005&
      ForeColor       =   &H80000008&
      Height          =   35610
      Left            =   0
      Picture         =   "FrmMain.frx":0000
      ScaleHeight     =   2372
      ScaleMode       =   3  'Pixel
      ScaleWidth      =   512
      TabIndex        =   0
      Top             =   0
      Width           =   7710
   End
End
Attribute VB_Name = "FrmMain"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
Option Explicit

Private Type Bitmap
    Type As Long
    Width As Long
    Height As Long
    WidthBytes As Long
    Planes As Integer
    BitsPixel As Integer
    Bits As Long
End Type

Private Declare Function BitBlt Lib "gdi32" (ByVal hDestDC As Long, ByVal x As Long, ByVal y As Long, ByVal nWidth As Long, ByVal nHeight As Long, ByVal hSrcDC As Long, ByVal xSrc As Long, ByVal ySrc As Long, ByVal dwRop As Long) As Long
Private Declare Sub Sleep Lib "kernel32" (ByVal dwMilliseconds As Long)
Private Const SRCCOPY = &HCC0020 ' (DWORD) dest = source
Private Declare Function GetDC Lib "user32" (ByVal hwnd As Long) As Long
Private Declare Function CreateBitmap Lib "gdi32" (ByVal nWidth As Long, ByVal nHeight As Long, ByVal nPlanes As Long, ByVal nBitCount As Long, lpBits As Any) As Long
Private Declare Function GetForegroundWindow Lib "user32" () As Long
Private Declare Function ReleaseDC Lib "user32" (ByVal hwnd As Long, ByVal hDC As Long) As Long
Private Declare Function Rectangle Lib "gdi32" (ByVal hDC As Long, ByVal X1 As Long, ByVal Y1 As Long, ByVal X2 As Long, ByVal Y2 As Long) As Long
Private Declare Function CreateSolidBrush Lib "gdi32" (ByVal crColor As Long) As Long
Private Declare Function SelectObject Lib "gdi32" (ByVal hDC As Long, ByVal hObject As Long) As Long
Private Declare Function CreatePen Lib "gdi32" (ByVal nPenStyle As Long, ByVal nWidth As Long, ByVal crColor As Long) As Long
Private Declare Function SetLayeredWindowAttributes Lib "user32" (ByVal hwnd As Long, ByVal crKey As Long, ByVal bAlpha As Byte, ByVal dwFlags As Long) As Long
Private Declare Function GetWindowLong Lib "user32" Alias "GetWindowLongA" (ByVal hwnd As Long, ByVal nIndex As Long) As Long
Private Declare Function SetWindowLong Lib "user32" Alias "SetWindowLongA" (ByVal hwnd As Long, ByVal nIndex As Long, ByVal dwNewLong As Long) As Long
Private Declare Function GetTickCount Lib "kernel32" () As Long
Private Declare Function CreateCompatibleDC Lib "gdi32" (ByVal hDC As Long) As Long
Private Declare Function CreatePatternBrush Lib "gdi32" (ByVal hBitmap As Long) As Long
Private Declare Function PatBlt Lib "gdi32" (ByVal hDC As Long, ByVal x As Long, ByVal y As Long, ByVal nWidth As Long, ByVal nHeight As Long, ByVal dwRop As Long) As Long
Private Declare Function StretchBlt Lib "gdi32" (ByVal hDC As Long, ByVal x As Long, ByVal y As Long, ByVal nWidth As Long, ByVal nHeight As Long, ByVal hSrcDC As Long, ByVal xSrc As Long, ByVal ySrc As Long, ByVal nSrcWidth As Long, ByVal nSrcHeight As Long, ByVal dwRop As Long) As Long
Private Declare Function DeleteDC Lib "gdi32" (ByVal hDC As Long) As Long
Private Declare Function CreateCompatibleBitmap Lib "gdi32" (ByVal hDC As Long, ByVal nWidth As Long, ByVal nHeight As Long) As Long
Private Declare Function DeleteObject Lib "gdi32" (ByVal hObject As Long) As Long
Private Declare Function SetBkColor Lib "gdi32" (ByVal hDC As Long, ByVal crColor As Long) As Long
Private Declare Function SetWindowPos Lib "user32" (ByVal hwnd As Long, ByVal hWndInsertAfter As Long, ByVal x As Long, ByVal y As Long, ByVal cx As Long, ByVal cy As Long, ByVal wFlags As Long) As Long
Private Declare Function SetPixel Lib "gdi32" (ByVal hDC As Long, ByVal x As Long, ByVal y As Long, ByVal crColor As Long) As Long
Private Declare Function PrintWindow Lib "user32" (ByVal hDCSrc As Long, ByVal hDCDst As Long, ByVal uFlag As Long) As Long

Private Const PATCOPY = &HF00021 ' (DWORD) dest = pattern
Private Const PS_SOLID = 0
Private Const WS_EX_LAYERED = &H80000
Private Const GWL_EXSTYLE = (-20)
Private Const LWA_ALPHA = &H2
Private Const LWA_COLORKEY = &H1
Private Const WHITENESS = &HFF0062       ' (DWORD) dest = WHITE
Const SWP_NOMOVE = &H2
Const SWP_NOSIZE = &H1
Const HWND_TOPMOST = -1
Const HWND_NOTOPMOST = -2
Const lngLinesAtOnce As Long = 4
Const lngSpotsPerDC As Long = 200

Private nClickCounter As Long

Private Sub Form_Load()
    ShowInBrokenEffect Me
End Sub

Public Function ShowInBrokenEffect(ByVal objForm As Form)
    Dim nStartTime As Long
    Dim hDCDest As Long
    hDCDest = objForm.hDC
    Dim hDC As Long, hwnd As Long, sx As Long, sy As Long
    Dim frm As New FrmRender
    nStartTime = GetTickCount
    frm.Caption = objForm.Caption
    frm.Width = objForm.Width
    frm.Height = objForm.Height
    frm.Top = objForm.Top
    frm.Left = objForm.Left
    frm.AutoRedraw = True
    frm.Show
    SetWindowPos frm.hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOSIZE Or SWP_NOMOVE
    objForm.Show
    hDC = GetDC(0)
    BitBlt frm.hDC, 0, 0, frm.ScaleWidth, frm.ScaleHeight, hDC, objForm.Left / Screen.TwipsPerPixelX, objForm.Top / Screen.TwipsPerPixelY, vbSrcCopy
    ReleaseDC 0, hDC
    frm.AutoRedraw = False
    Dim i As Long, j As Long
    Dim arrBlocks() As Long, lngBlockCount As Long
    Dim x As Long, y As Long, xSrc As Long, ySrc As Long
    Dim hTempDC() As Long, hBitmap() As Long
    lngBlockCount = lngLinesAtOnce * frm.ScaleWidth
    ReDim hTempDC(lngBlockCount \ lngSpotsPerDC + 1)
    ReDim hBitmap(lngBlockCount \ lngSpotsPerDC + 1)
    For i = 1 To UBound(hTempDC())
        hBitmap(i) = CreateBitmap(frm.ScaleWidth, frm.ScaleHeight, 1, 1, ByVal 0&)
        hTempDC(i) = CreateCompatibleDC(frm.hDC)
        SetBkColor hTempDC(i), vbBlack
        SelectObject hTempDC(i), hBitmap(i)
    Next
    j = 1
    ReDim arrBlocks(1 To lngBlockCount)
    For i = 1 To lngBlockCount
        arrBlocks(i) = i
    Next
    Dim lngRand As Long, lngCurrBlock As Long
    For i = 1 To lngBlockCount
        Randomize
        lngRand = Int(Rnd * lngBlockCount) + 1
        lngCurrBlock = arrBlocks(lngRand)
        x = (lngCurrBlock - 1) Mod frm.ScaleWidth
        y = (lngCurrBlock - 1) \ (frm.ScaleWidth)
        SetPixel hTempDC(j), x, y, &HFFFFFF
        arrBlocks(lngRand) = arrBlocks(lngBlockCount)
        lngBlockCount = lngBlockCount - 1
        If i Mod lngSpotsPerDC = 0 Then
            j = j + 1
        End If
        DoEvents
    Next
    Randomize
    Dim nWidth As Long, nHeight As Long
    nWidth = frm.ScaleWidth
    nHeight = lngLinesAtOnce
    Dim hInvDC As Long, hMaskDC As Long, hDestDC As Long, hOriDC As Long, hObjFormDC As Long
    Dim hMaskBmp As Long, hInvBmp As Long, hDestBmp As Long, hSrcBmp As Long, hObjFormBmp As Long
    hOriDC = CreateCompatibleDC(frm.hDC)
    hInvDC = CreateCompatibleDC(frm.hDC)
    hMaskDC = CreateCompatibleDC(frm.hDC)
    hDestDC = CreateCompatibleDC(frm.hDC)
    hObjFormDC = CreateCompatibleDC(frm.hDC)
    hMaskBmp = CreateBitmap(frm.ScaleWidth, frm.ScaleHeight, 1, 1, ByVal 0&)
    hInvBmp = CreateBitmap(frm.ScaleWidth, frm.ScaleHeight, 1, 1, ByVal 0&)
    hDestBmp = CreateCompatibleBitmap(frm.hDC, frm.ScaleWidth, frm.ScaleHeight)
    hSrcBmp = CreateCompatibleBitmap(frm.hDC, frm.ScaleWidth, frm.ScaleHeight)
    hObjFormBmp = CreateCompatibleBitmap(frm.hDC, frm.ScaleWidth, frm.ScaleHeight)
    SelectObject hOriDC, hSrcBmp
    SelectObject hDestDC, hDestBmp
    SelectObject hInvDC, hInvBmp
    SelectObject hMaskDC, hMaskBmp
    SelectObject hObjFormDC, hObjFormBmp
    BitBlt hInvDC, 0, 0, frm.ScaleWidth, frm.ScaleHeight, 0, 0, 0, WHITENESS
    PrintWindow objForm.hwnd, hObjFormDC, 0
    ' Fetch the frm's image
    BitBlt hOriDC, 0, 0, frm.ScaleWidth, frm.ScaleHeight, frm.hDC, 0, 0, vbSrcCopy
    Dim nOffset As Long
    For j = 0 To frm.ScaleHeight / lngLinesAtOnce + UBound(hTempDC())
        For i = 0 To j
            If j - i + 1 <= UBound(hTempDC()) Then
                ' Make it transparent!
                ' Copy new dots onto the mask transparently
                nOffset = (j - i + 1 + j) Mod UBound(hTempDC()) + 1
                BitBlt hMaskDC, 0, i * lngLinesAtOnce, nWidth, nHeight, hTempDC(nOffset), 0, 0, vbSrcPaint
                ' Create inverted mask
                BitBlt hInvDC, 0, i * lngLinesAtOnce, nWidth, nHeight, hTempDC(nOffset), 0, 0, vbSrcInvert
                ' Copy the ObjForm onto hDestDC
                BitBlt hDestDC, 0, i * lngLinesAtOnce, frm.ScaleWidth, lngLinesAtOnce, hObjFormDC, 0, i * lngLinesAtOnce, vbSrcCopy
                ' AND
                BitBlt hDestDC, 0, i * lngLinesAtOnce, frm.ScaleWidth, lngLinesAtOnce, hMaskDC, 0, i * lngLinesAtOnce, vbSrcAnd
                ' AND
                BitBlt hOriDC, 0, i * lngLinesAtOnce, frm.ScaleWidth, frm.ScaleHeight, hInvDC, 0, i * lngLinesAtOnce, vbSrcAnd
                ' INVERT
                BitBlt hDestDC, 0, i * lngLinesAtOnce, frm.ScaleWidth, lngLinesAtOnce, hOriDC, 0, i * lngLinesAtOnce, vbSrcInvert
                ' Copy to the frm
                BitBlt frm.hDC, 0, i * lngLinesAtOnce, frm.ScaleWidth, lngLinesAtOnce, hDestDC, 0, i * lngLinesAtOnce, vbSrcCopy
                DoEvents
            End If
        Next
    Next
CleanStage:
    For i = 1 To UBound(hTempDC())
        DeleteDC hTempDC(i)
        DeleteObject hBitmap(i)
    Next
    DeleteDC hDestDC
    DeleteDC hOriDC
    DeleteDC hMaskDC
    DeleteDC hObjFormDC
    DeleteDC hInvDC
    DeleteObject hDestBmp
    DeleteObject hSrcBmp
    DeleteObject hMaskBmp
    DeleteObject hObjFormBmp
    DeleteObject hInvBmp
    frm.Hide
    Set frm = Nothing
    'nStartTime = GetTickCount - nStartTime
    'MsgBox "Time span: " & nStartTime & " ms", vbInformation
End Function

Public Function FadeInBrokenEffect(ByVal objForm As Form)
    Dim nStartTime As Long
    Dim hDCDest As Long
    hDCDest = objForm.hDC
    Dim hDC As Long, hwnd As Long, sx As Long, sy As Long
    Dim frm As New FrmRender
    nStartTime = GetTickCount
    frm.Caption = objForm.Caption
    frm.Width = objForm.Width
    frm.Height = objForm.Height
    frm.Top = objForm.Top
    frm.Left = objForm.Left
    frm.AutoRedraw = True
    ' Take a picture of the current form
    Dim hObjFormDC As Long, hObjFormBmp As Long, hBehindDC As Long, hBehindBmp As Long
    hObjFormDC = CreateCompatibleDC(frm.hDC)
    hBehindDC = CreateCompatibleDC(frm.hDC)
    hObjFormBmp = CreateCompatibleBitmap(frm.hDC, frm.ScaleWidth, frm.ScaleHeight)
    hBehindBmp = CreateCompatibleBitmap(frm.hDC, frm.ScaleWidth, frm.ScaleHeight)
    SelectObject hObjFormDC, hObjFormBmp
    SelectObject hBehindDC, hBehindBmp
    Dim lngFormLeft As Long, lngFormTop As Long, lngFormWidth As Long, lngFormHeight As Long
    lngFormLeft = objForm.Left / Screen.TwipsPerPixelX
    lngFormTop = objForm.Top / Screen.TwipsPerPixelY
    lngFormWidth = objForm.Width / Screen.TwipsPerPixelX
    lngFormHeight = objForm.Height / Screen.TwipsPerPixelY
    hDC = GetDC(0)
    BitBlt hObjFormDC, 0, 0, lngFormWidth, lngFormHeight, hDC, lngFormLeft, lngFormTop, vbSrcCopy
    ' hide the current form and take a picture here
    objForm.Left = -2000
    objForm.Width = 0
    objForm.Height = 0
    frm.Show
    SetWindowPos frm.hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOSIZE Or SWP_NOMOVE
    BitBlt hBehindDC, 0, 0, frm.ScaleWidth, frm.ScaleHeight, hDC, lngFormLeft, lngFormTop, vbSrcCopy
    ReleaseDC 0, hDC
    BitBlt frm.hDC, 0, 0, frm.ScaleWidth, frm.ScaleHeight, hObjFormDC, 0, 0, vbSrcCopy
    frm.AutoRedraw = False
    Dim i As Long, j As Long
    Dim arrBlocks() As Long, lngBlockCount As Long
    Dim x As Long, y As Long, xSrc As Long, ySrc As Long
    Dim hTempDC() As Long, hBitmap() As Long
    lngBlockCount = lngLinesAtOnce * frm.ScaleWidth
    ReDim hTempDC(lngBlockCount \ lngSpotsPerDC + 1)
    ReDim hBitmap(lngBlockCount \ lngSpotsPerDC + 1)
    For i = 1 To UBound(hTempDC())
        hBitmap(i) = CreateBitmap(frm.ScaleWidth, frm.ScaleHeight, 1, 1, ByVal 0&)
        hTempDC(i) = CreateCompatibleDC(frm.hDC)
        SetBkColor hTempDC(i), vbBlack
        SelectObject hTempDC(i), hBitmap(i)
    Next
    j = 1
    ReDim arrBlocks(1 To lngBlockCount)
    For i = 1 To lngBlockCount
        arrBlocks(i) = i
    Next
    Dim lngRand As Long, lngCurrBlock As Long
    For i = 1 To lngBlockCount
        Randomize
        lngRand = Int(Rnd * lngBlockCount) + 1
        lngCurrBlock = arrBlocks(lngRand)
        x = (lngCurrBlock - 1) Mod frm.ScaleWidth
        y = (lngCurrBlock - 1) \ (frm.ScaleWidth)
        SetPixel hTempDC(j), x, y, &HFFFFFF
        arrBlocks(lngRand) = arrBlocks(lngBlockCount)
        lngBlockCount = lngBlockCount - 1
        If i Mod lngSpotsPerDC = 0 Then
            j = j + 1
        End If
        DoEvents
    Next
    Randomize
    Dim nWidth As Long, nHeight As Long
    nWidth = frm.ScaleWidth
    nHeight = lngLinesAtOnce
    Dim hInvDC As Long, hMaskDC As Long, hDestDC As Long, hOriDC As Long
    Dim hMaskBmp As Long, hInvBmp As Long, hDestBmp As Long, hSrcBmp As Long
    hOriDC = CreateCompatibleDC(frm.hDC)
    hInvDC = CreateCompatibleDC(frm.hDC)
    hMaskDC = CreateCompatibleDC(frm.hDC)
    hDestDC = CreateCompatibleDC(frm.hDC)
    hMaskBmp = CreateBitmap(frm.ScaleWidth, frm.ScaleHeight, 1, 1, ByVal 0&)
    hInvBmp = CreateBitmap(frm.ScaleWidth, frm.ScaleHeight, 1, 1, ByVal 0&)
    hDestBmp = CreateCompatibleBitmap(frm.hDC, frm.ScaleWidth, frm.ScaleHeight)
    hSrcBmp = CreateCompatibleBitmap(frm.hDC, frm.ScaleWidth, frm.ScaleHeight)
    SelectObject hOriDC, hSrcBmp
    SelectObject hDestDC, hDestBmp
    SelectObject hInvDC, hInvBmp
    SelectObject hMaskDC, hMaskBmp
    
    BitBlt hInvDC, 0, 0, frm.ScaleWidth, frm.ScaleHeight, 0, 0, 0, WHITENESS
    ' Fetch the frm's image
    BitBlt hOriDC, 0, 0, frm.ScaleWidth, frm.ScaleHeight, hObjFormDC, 0, 0, vbSrcCopy
    Dim nOffset As Long
    For j = UBound(hTempDC()) + frm.ScaleHeight / lngLinesAtOnce To 0 Step -1
        For i = j To 0 Step -1
            If j - i + 1 <= UBound(hTempDC()) Then
                ' Make it transparent!
                ' Copy new dots onto the mask transparently
                nOffset = (j - i + 1 + j) Mod UBound(hTempDC()) + 1
                BitBlt hMaskDC, 0, i * lngLinesAtOnce, nWidth, nHeight, hTempDC(nOffset), 0, 0, vbSrcPaint
                ' Create inverted mask
                BitBlt hInvDC, 0, i * lngLinesAtOnce, nWidth, nHeight, hTempDC(nOffset), 0, 0, vbSrcInvert
                ' Copy the ObjForm onto hDestDC
                BitBlt hDestDC, 0, i * lngLinesAtOnce, frm.ScaleWidth, lngLinesAtOnce, hBehindDC, 0, i * lngLinesAtOnce, vbSrcCopy
                ' AND
                BitBlt hDestDC, 0, i * lngLinesAtOnce, frm.ScaleWidth, lngLinesAtOnce, hMaskDC, 0, i * lngLinesAtOnce, vbSrcAnd
                ' AND
                BitBlt hOriDC, 0, i * lngLinesAtOnce, frm.ScaleWidth, frm.ScaleHeight, hInvDC, 0, i * lngLinesAtOnce, vbSrcAnd
                ' INVERT
                BitBlt hDestDC, 0, i * lngLinesAtOnce, frm.ScaleWidth, lngLinesAtOnce, hOriDC, 0, i * lngLinesAtOnce, vbSrcInvert
                ' Copy to the frm
                BitBlt frm.hDC, 0, i * lngLinesAtOnce, frm.ScaleWidth, lngLinesAtOnce, hDestDC, 0, i * lngLinesAtOnce, vbSrcCopy
                DoEvents
            End If
        Next
    Next
CleanStage:
    For i = 1 To UBound(hTempDC())
        DeleteDC hTempDC(i)
        DeleteObject hBitmap(i)
    Next
    DeleteDC hDestDC
    DeleteDC hOriDC
    DeleteDC hMaskDC
    DeleteDC hObjFormDC
    DeleteDC hInvDC
    DeleteDC hBehindDC
    DeleteObject hDestBmp
    DeleteObject hSrcBmp
    DeleteObject hMaskBmp
    DeleteObject hObjFormBmp
    DeleteObject hInvBmp
    DeleteObject hBehindBmp
    frm.Hide
    Set frm = Nothing
    'nStartTime = GetTickCount - nStartTime
    'MsgBox "Time span: " & nStartTime & " ms", vbInformation
End Function

Private Sub Form_Unload(Cancel As Integer)
    FadeInBrokenEffect Me
    End
End Sub

Private Sub pic_Click()
    Dim strKey As String
    Dim aKey() As Byte
    Dim strEncryptedData As String
    Dim arrPrompt As Variant, i As Long, byteArray() As Byte
    
    nClickCounter = nClickCounter + 1
    
    If nClickCounter = 133337 Then
        ' Flag: flag{vb6_and_blowfish_fun_from_the_old_days}
        ' Draw the decryption key: AKAM1337
        Const nBaseY As Integer = 1000
        ' A
        pic.Line (40, nBaseY + 40)-(30, nBaseY + 70), vbBlue
        pic.Line (40, nBaseY + 40)-(50, nBaseY + 70), vbBlue
        pic.Line (35, nBaseY + 55)-(45, nBaseY + 55), vbBlue
        ' K
        pic.Line (60, nBaseY + 40)-(60, nBaseY + 70), vbBlue
        pic.Line (60, nBaseY + 55)-(80, nBaseY + 40), vbBlue
        pic.Line (60, nBaseY + 55)-(80, nBaseY + 70), vbBlue
        ' A
        pic.Line (95, nBaseY + 40)-(85, nBaseY + 70), vbBlue
        pic.Line (95, nBaseY + 40)-(105, nBaseY + 70), vbBlue
        pic.Line (90, nBaseY + 55)-(100, nBaseY + 55), vbBlue
        ' M
        pic.Line (115, nBaseY + 70)-(120, nBaseY + 40), vbBlue
        pic.Line (120, nBaseY + 40)-(125, nBaseY + 70), vbBlue
        pic.Line (125, nBaseY + 70)-(130, nBaseY + 40), vbBlue
        pic.Line (130, nBaseY + 40)-(135, nBaseY + 70), vbBlue
        ' 1
        pic.Line (155, nBaseY + 40)-(155, nBaseY + 70), vbBlue
        pic.Line (152, nBaseY + 43)-(155, nBaseY + 40), vbBlue
        pic.Line (150, nBaseY + 70)-(160, nBaseY + 70), vbBlue
        ' 3
        pic.Line (180, nBaseY + 40)-(200, nBaseY + 47), vbBlue
        pic.Line (200, nBaseY + 47)-(180, nBaseY + 54), vbBlue
        pic.Line (180, nBaseY + 54)-(200, nBaseY + 61), vbBlue
        pic.Line (200, nBaseY + 61)-(180, nBaseY + 70), vbBlue
        ' 3
        pic.Line (210, nBaseY + 40)-(230, nBaseY + 47), vbBlue
        pic.Line (230, nBaseY + 47)-(210, nBaseY + 54), vbBlue
        pic.Line (210, nBaseY + 54)-(230, nBaseY + 61), vbBlue
        pic.Line (230, nBaseY + 61)-(210, nBaseY + 70), vbBlue
        ' 7
        pic.Line (240, nBaseY + 40)-(260, nBaseY + 40), vbBlue
        pic.Line (260, nBaseY + 40)-(240, nBaseY + 70), vbBlue
    ElseIf nClickCounter = 1333337 Then
    ' ElseIf nClickCounter = 2 Then
        ' Print the encrypted flag

        ' MsgBox "Decrypt it to get your flag: jEJclmCsLkox48h7uChks6p/+Lo6XHquEPBbOJzC3+0Witqh+5EZ2D7Ed7KiAbJq"
        arrPrompt = Array(132, 164, 161, 177, 189, 181, 178, 231, 161, 189, 234, 191, 163, 237, 169, 170, 164, 241, 171, 188, 161, 167, 246, 177, 180, 184, 189, 225, 252, 183, 155, 149, 131, 141, 143, 160, 151, 169, 141, 136, 144, 221, 210, 131, 219, 152, 173, 135, 155, 130, 196, 131, 219, 222, 186, 152, 206, 161, 178, 138, 137, 184, 174, 189, 354, 334, 328, 377, 327, 310, 301, 311, 351, 352, 382, 378, 356, 294, 315, 330, 330, 291, 342, 292, 337, 369, 289, 348, 369, 344, 376, 337, 365)
        ReDim byteArray(0 To UBound(arrPrompt)) As Byte
        For i = 0 To UBound(arrPrompt)
            byteArray(i) = arrPrompt(i) Xor (&HC0 + i)
        Next i
        MsgBox StrConv(byteArray, vbUnicode)
    ElseIf nClickCounter = 1337 Then
    ' ElseIf nClickCounter = 1 Then
        ' Encrypt a string
        
        ' strKey = InputBox("Please provide an encryption key:")
        arrPrompt = Array(144, 173, 167, 162, 183, 160, 230, 183, 186, 166, 188, 162, 168, 168, 238, 174, 190, 241, 183, 189, 183, 167, 175, 167, 172, 176, 181, 181, 252, 182, 187, 166, 218)
        ReDim byteArray(0 To UBound(arrPrompt)) As Byte
        For i = 0 To UBound(arrPrompt)
            byteArray(i) = arrPrompt(i) Xor (&HC0 + i)
        Next i
        strKey = InputBox(StrConv(byteArray, vbUnicode))

        aKey = StrConv(strKey, vbFromUnicode)
        Call blf_KeyInit(aKey)

        ' strEncryptedData = EncodeBytes64(blf_BytesEnc(StrConv("flag{this_is_a_fake_flag_find_the_real_one!}", vbFromUnicode)))
        
        arrPrompt = Array(166, 173, 163, 164, 191, 177, 174, 174, 187, 150, 163, 184, 147, 172, 145, 169, 177, 186, 183, 140, 178, 185, 183, 176, 135, 191, 179, 181, 184, 130, 170, 183, 133, 190, 144, 134, 133, 137, 185, 136, 134, 140, 203, 150)
        ReDim byteArray(0 To UBound(arrPrompt)) As Byte
        For i = 0 To UBound(arrPrompt)
            byteArray(i) = arrPrompt(i) Xor (&HC0 + i)
        Next i
        strEncryptedData = EncodeBytes64(blf_BytesEnc(byteArray))

        ' MsgBox "Encrypted result: " + strEncryptedData
        arrPrompt = Array(133, 175, 161, 177, 189, 181, 178, 162, 172, 233, 184, 174, 191, 184, 162, 187, 234, 241)
        ReDim byteArray(0 To UBound(arrPrompt)) As Byte
        For i = 0 To UBound(arrPrompt)
            byteArray(i) = arrPrompt(i) Xor (&HC0 + i)
        Next i
        MsgBox StrConv(byteArray, vbUnicode) + strEncryptedData
        
        'Dim strDecryptedFlag
        'Dim strDecryptedFlag As String
        'Call blf_KeyInit(StrConv("AKAM1337", vbFromUnicode))
        'strDecryptedFlag = blf_BytesDec(DecodeBytes64("jEJclmCsLkox48h7uChks6p/+Lo6XHquEPBbOJzC3+0Witqh+5EZ2D7Ed7KiAbJq"))
        'MsgBox "Decrypted flag: " + StrConv(strDecryptedFlag, vbUnicode)
    End If
End Sub

Private Sub pic_DblClick()
    ' Clear the counter
    nClickCounter = 0
End Sub
