; ============================================================================
; CyberShield GUI: Password Security and Login Protection System  (DARK UI)
; EL-2003 COAL Lab | Fall 2026 | Group BDS-3A-12
; Wania Muddasir (25K-2516), Deenah Rehman (25K-2520), Sukaina Virani (25K-2526)
;
; Win32 API version (MASM, 32-bit). Does NOT use Irvine32.
; Libraries: kernel32 / user32 / gdi32 / dwmapi / uxtheme (all in the Windows SDK)
;
; Main menu (as in the proposal)
;   The program opens on a MAIN MENU: 1 Check Password Strength, 2 Login,
;   3 View Session Log, 4 Exit. Click an option or press 1-4. Each module
;   screen has a '< Menu' button (or Esc) to return to the menu.
;
; Visual features
;   * Dark palette, rounded "card" panels, header banner with accent line
;   * Segoe UI fonts (regular / bold / large title)
;   * Flat owner-drawn buttons (cyan primary, slate secondary), rounded corners
;   * Padded rounded input boxes
;   * Segmented 6-block strength meter
;   * Colour-coded session log (coloured stripe + text per event type)
;   * Dark title bar (Windows 10 2004+ / Windows 11)
;   * Lockout: banner subtitle turns red with a live countdown, inputs are
;     disabled, and login returns to normal when the timer reaches zero
;   * Enter key: login (username/password box), check (strength box)
;
; Login popup
;   A successful login shows a "Login successful" message box.
;
; Lockout timer
;   After 3 consecutive failed logins the session locks for LOCK_SECONDS.
;   A Win32 timer (SetTimer, 1 s tick) drives the countdown. At zero the
;   inputs are re-enabled, the failure counter resets and the log records it.
;
; Build (Visual Studio MASM project):
;   Linker > System > SubSystem = Windows (/SUBSYSTEM:WINDOWS)
;   OPTIONAL but recommended (themed scrollbars):
;   Linker > Manifest File > Additional Manifest Dependencies =
;   type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publicKeyToken='6595b64144ccf1df' language='*'
; ============================================================================

.386
.model flat, stdcall
option casemap:none

includelib kernel32.lib
includelib user32.lib
includelib gdi32.lib
includelib dwmapi.lib
includelib uxtheme.lib

; ------------------------------ prototypes ----------------------------------
GetModuleHandleA  PROTO :DWORD
ExitProcess       PROTO :DWORD
CreateFileA       PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ReadFile          PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WriteFile         PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CloseHandle       PROTO :DWORD

RegisterClassExA  PROTO :DWORD
CreateWindowExA   PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ShowWindow        PROTO :DWORD,:DWORD
UpdateWindow      PROTO :DWORD
GetMessageA       PROTO :DWORD,:DWORD,:DWORD,:DWORD
TranslateMessage  PROTO :DWORD
DispatchMessageA  PROTO :DWORD
DefWindowProcA    PROTO :DWORD,:DWORD,:DWORD,:DWORD
PostQuitMessage   PROTO :DWORD
LoadCursorA       PROTO :DWORD,:DWORD
LoadIconA         PROTO :DWORD,:DWORD
SendMessageA      PROTO :DWORD,:DWORD,:DWORD,:DWORD
GetWindowTextA    PROTO :DWORD,:DWORD,:DWORD
SetWindowTextA    PROTO :DWORD,:DWORD
MessageBoxA       PROTO :DWORD,:DWORD,:DWORD,:DWORD
InvalidateRect    PROTO :DWORD,:DWORD,:DWORD
SetFocus          PROTO :DWORD
EnableWindow      PROTO :DWORD,:DWORD
SetTimer          PROTO :DWORD,:DWORD,:DWORD,:DWORD
KillTimer         PROTO :DWORD,:DWORD
AdjustWindowRect  PROTO :DWORD,:DWORD,:DWORD
GetSystemMetrics  PROTO :DWORD
SetWindowRgn      PROTO :DWORD,:DWORD,:DWORD
FillRect          PROTO :DWORD,:DWORD,:DWORD
DrawTextA         PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
wsprintfA         PROTO C :DWORD,:DWORD,:VARARG

CreateSolidBrush  PROTO :DWORD
CreateRoundRectRgn PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CreateFontA       PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DeleteObject      PROTO :DWORD
SetBkMode         PROTO :DWORD,:DWORD
SetBkColor        PROTO :DWORD,:DWORD
SetTextColor      PROTO :DWORD,:DWORD

DwmSetWindowAttribute PROTO :DWORD,:DWORD,:DWORD,:DWORD
SetWindowTheme    PROTO :DWORD,:DWORD,:DWORD

; ------------------------------ structures ----------------------------------
WNDCLASSEX_ STRUCT
    cbSize        DWORD ?
    style         DWORD ?
    lpfnWndProc   DWORD ?
    cbClsExtra    DWORD ?
    cbWndExtra    DWORD ?
    hInstance     DWORD ?
    hIcon         DWORD ?
    hCursor       DWORD ?
    hbrBackground DWORD ?
    lpszMenuName  DWORD ?
    lpszClassName DWORD ?
    hIconSm       DWORD ?
WNDCLASSEX_ ENDS

MSG_ STRUCT
    hwnd     DWORD ?
    message  DWORD ?
    wParam   DWORD ?
    lParam   DWORD ?
    time     DWORD ?
    ptx      DWORD ?
    pty      DWORD ?
MSG_ ENDS

RECT_ STRUCT
    wLeft DWORD ?
    wTop DWORD ?
    wRight DWORD ?
    wBottom DWORD ?
RECT_ ENDS

; ------------------------------ constants -----------------------------------
NULL            = 0
TRUE            = 1
FALSE           = 0

; window messages / notifications
WM_CREATE          = 0001h
WM_DESTROY         = 0002h
WM_CLOSE           = 0010h
WM_DRAWITEM        = 002Bh
WM_SETFONT         = 0030h
WM_COMMAND         = 0111h
WM_TIMER           = 0113h
WM_CTLCOLOREDIT    = 0133h
WM_CTLCOLORLISTBOX = 0134h
WM_CTLCOLORSTATIC  = 0138h
WM_KEYDOWN         = 0100h
VK_RETURN          = 0Dh
VK_ESCAPE          = 1Bh
EN_CHANGE          = 0300h
EM_LIMITTEXT       = 00C5h
EM_SETPASSWORDCHAR = 00CCh
LB_ADDSTRING       = 0180h
LB_SETCURSEL       = 0186h
LB_SETITEMHEIGHT   = 01A0h

; lockout timer
IDT_LOCK           = 1
LOCK_SECONDS       = 30             ; change this to any lockout length

; styles
STYLE_MAIN      = 02CA0000h         ; CAPTION | SYSMENU | MINIMIZEBOX | CLIPCHILDREN
S_STATIC        = 50000000h         ; CHILD | VISIBLE
S_STATICR       = 50000002h         ; + SS_RIGHT
S_STATICC       = 50000001h         ; + SS_CENTER
S_PANEL         = 54000000h         ; + CLIPSIBLINGS (card / banner backgrounds)
S_EDIT          = 50010080h         ; + TABSTOP | ES_AUTOHSCROLL (no border)
S_EDITPW        = 500100A0h         ; + ES_PASSWORD
S_BUTTON        = 5001000Bh         ; TABSTOP + BS_OWNERDRAW
S_LIST          = 50A00151h         ; VSCROLL|BORDER|NOTIFY|OWNERDRAWFIXED|HASSTRINGS|NOINTEGRALH

; misc API constants
SW_HIDE         = 0
SW_SHOWNORMAL   = 1
SW_SHOW         = 5
IDC_ARROW       = 32512
IDI_APPLICATION = 32512
CS_HREDRAW      = 2
CS_VREDRAW      = 1
CW_USEDEFAULT   = 80000000h
TRANSPARENT     = 1
MB_OK           = 0
MB_ICONERROR    = 10h
MB_ICONWARNING  = 30h
MB_ICONINFO     = 40h
GENERIC_READ    = 80000000h
GENERIC_WRITE   = 40000000h
FILE_SHARE_READ = 1
CREATE_ALWAYS   = 2
OPEN_EXISTING   = 3
FILE_ATTR_NORMAL= 80h
INVALID_HANDLE  = -1

; layout
CLIENT_W        = 800
CLIENT_H        = 590
HDR_H           = 64

; control IDs
IDC_PWCHK       = 101
IDC_SHOW        = 102
IDC_BTNCHK      = 103
IDC_RULE1       = 110               ; 110..115
IDC_SCORE       = 116
IDC_RESULT      = 117
IDC_USER        = 120
IDC_PASS        = 121
IDC_BTNLOGIN    = 122
IDC_LSTATUS     = 123
IDC_LATT        = 124
IDC_LOG         = 130
IDC_BTNSAVE     = 131
IDC_BTNVIEW     = 132
IDC_FOOT        = 133
IDC_BACK        = 140
IDC_MENU1       = 141               ; 141..144
IDC_MENU4       = 144

; screens / control groups
GRP_ALWAYS      = 0                 ; banner: visible on every screen
SCR_MENU        = 1
SCR_STRENGTH    = 2
SCR_LOGIN       = 3
SCR_LOG         = 4
GRP_NOMENU      = 9                 ; visible on every screen except the menu
MAX_CTL         = 128

; program constants
MAX_ATTEMPTS    = 3
MAX_LOG         = 50
BUF_SIZE        = 64
MIN_LEN         = 8
LONG_LEN        = 12
FILE_BUF        = 8192

EV_PW_STRONG    = 1
EV_PW_WEAK      = 2
EV_LOGIN_OK     = 3
EV_LOGIN_FAIL   = 4
EV_LOCKOUT      = 5
EV_LOGIN_BLOCK  = 6
EV_UNLOCK       = 7

; colours (COLORREF = 00BBGGRR)
COL_BG          = 002A170Fh         ; #0F172A  window / input background
COL_BANNER      = 0020120Bh         ; #0B1220
COL_CARD        = 003B291Eh         ; #1E293B  cards
COL_TEXT        = 00F0E8E2h         ; #E2E8F0
COL_MUTED       = 00B8A394h         ; #94A3B8
COL_ACCENT      = 00EED322h         ; #22D3EE  cyan
COL_ACCENT_DN   = 00B29108h         ; #0891B2
COL_SLATE       = 00554133h         ; #334155
COL_SLATE_DN    = 00695547h         ; #475569
COL_RED         = 004444EFh         ; #EF4444
COL_ORANGE      = 000B9EF5h         ; #F59E0B
COL_GREEN       = 005EC522h         ; #22C55E
COL_DGREEN      = 0081B910h         ; #10B981
COL_GRAY        = 008B7464h         ; #64748B
COL_BARBG       = 00554133h         ; empty meter block

.data
; ---- demo credentials (defaults; may be replaced from file) ----
demoUser    BYTE "admin",0
            BYTE BUF_SIZE DUP(0)
demoPass    BYTE "Cyber@123",0
            BYTE BUF_SIZE DUP(0)

credFile    BYTE "demo_credentials.txt",0
logFile     BYTE "cybershield_log.txt",0

; ---- window / class ----
className   BYTE "CyberShieldWnd",0
windowTitle BYTE "CyberShield - Password Security & Login Protection",0
clsStatic   BYTE "STATIC",0
clsEdit     BYTE "EDIT",0
clsButton   BYTE "BUTTON",0
clsList     BYTE "LISTBOX",0
emptyStr    BYTE 0
fontName    BYTE "Segoe UI",0
darkTheme   WORD 'D','a','r','k','M','o','d','e','_','E','x','p','l','o','r','e','r',0

; ---- banner ----
txtTitle    BYTE "CyberShield",0
txtSub      BYTE "Password Security && Login Protection",0
txtTag      BYTE "EL-2003 COAL Lab  |  Group BDS-3A-12",0

; ---- labels ----
txtGrp1     BYTE "PASSWORD STRENGTH",0
txtGrp2     BYTE "DEMO LOGIN",0
txtGrp3     BYTE "SESSION LOG",0
txtEnter    BYTE "Enter a password to analyse (updates as you type):",0
txtShow     BYTE "Show",0
txtHide     BYTE "Hide",0
txtCheck    BYTE "Check && Log",0
txtUser     BYTE "Username",0
txtPass     BYTE "Password",0
txtLogin    BYTE "Login",0
txtSave     BYTE "Save Log to File",0
txtView     BYTE "View Saved Log",0
txtNote     BYTE "Demo only: no real accounts. Credentials come from demo_credentials.txt. Three wrong attempts lock login for 30 seconds.",0
txtReady    BYTE "Enter credentials and press Login.",0
txtMenuTitle BYTE "MAIN MENU",0
txtM1       BYTE "1    Check Password Strength",0
txtM2       BYTE "2    Login",0
txtM3       BYTE "3    View Session Log",0
txtM4       BYTE "4    Exit",0
txtBack     BYTE "< Menu",0
txtHint     BYTE "Click an option or press 1-4.   Esc returns to this menu.",0

; ---- strength rule texts ----
rOk0 BYTE "At least 8 characters",0
rOk1 BYTE "Uppercase letter (A-Z)",0
rOk2 BYTE "Lowercase letter (a-z)",0
rOk3 BYTE "Digit (0-9)",0
rOk4 BYTE "Symbol (! @ # $ % ^ & * ...)",0
rOk5 BYTE "Bonus: 12 or more characters",0
rNo0 BYTE "At least 8 characters",0
rNo1 BYTE "Uppercase letter (A-Z)",0
rNo2 BYTE "Lowercase letter (a-z)",0
rNo3 BYTE "Digit (0-9)",0
rNo4 BYTE "Symbol (! @ # $ % ^ & * ...)",0
rNo5 BYTE "Bonus: 12 or more characters",0
rOk DWORD OFFSET rOk0, OFFSET rOk1, OFFSET rOk2, OFFSET rOk3, OFFSET rOk4, OFFSET rOk5
rNo DWORD OFFSET rNo0, OFFSET rNo1, OFFSET rNo2, OFFSET rNo3, OFFSET rNo4, OFFSET rNo5

res0 BYTE "Strength: WEAK",0
res1 BYTE "Strength: MEDIUM",0
res2 BYTE "Strength: STRONG (all rules met)",0
res3 BYTE "Strength: VERY STRONG (all rules + 12 chars)",0
res4 BYTE "Strength: (type a password)",0
resTbl DWORD OFFSET res0, OFFSET res1, OFFSET res2, OFFSET res3, OFFSET res4
resCol DWORD COL_RED, COL_ORANGE, COL_GREEN, COL_DGREEN, COL_GRAY

fmtScore    BYTE "Score: %d / 5 required rules met",0
fmtAtt      BYTE "Attempts remaining: %d",0
msgEmpty    BYTE "Please type a password first.",0

; ---- login messages ----
msgOk       BYTE "LOGIN SUCCESSFUL. Welcome!",0
msgFail     BYTE "LOGIN FAILED: incorrect username or password.",0
msgLockNow  BYTE "Too many failed attempts. Login is now LOCKED.",0
msgBlocked  BYTE "ACCESS DENIED: login is temporarily locked.",0
msgUnlocked BYTE "Lockout over. You may try logging in again.",0
capLoginOk  BYTE "Login Successful",0
msgPopupOk  BYTE "Login successful!",0Dh,0Ah,0Dh,0Ah,"Welcome to CyberShield. Access granted.",0

; ---- lockout countdown text ----
fmtSubLock  BYTE "SESSION LOCKED: try again in %d s",0
fmtAttLock  BYTE "Attempts remaining: 0  (LOCKED - %d s)",0

; ---- session log ----
fmtLine     BYTE "%d. %s",0
fmtFileLine BYTE "%d. %s",0Dh,0Ah,0
fmtTitle    BYTE "CyberShield Session Log",0Dh,0Ah,0Dh,0Ah,0
fmtCred     BYTE "%s",0Dh,0Ah,"%s",0Dh,0Ah,0
ev1         BYTE "Password check: STRONG password",0
ev2         BYTE "Password check: WEAK/incomplete password",0
ev3         BYTE "Login SUCCESS",0
ev4         BYTE "Login FAILURE",0
ev5         BYTE "LOCKOUT after 3 failed attempts",0
ev6         BYTE "Login attempt BLOCKED (account locked)",0
ev7         BYTE "Lockout ended: login re-enabled",0
logMsgTable DWORD OFFSET ev1, OFFSET ev2, OFFSET ev3, OFFSET ev4, OFFSET ev5, OFFSET ev6, OFFSET ev7
evCol       DWORD COL_GREEN, COL_ORANGE, COL_GREEN, COL_RED, COL_RED, COL_RED, COL_GREEN
evIdx       DWORD 2, 1, 2, 0, 0, 0, 2       ; index into brushTbl for the stripe

; ---- file messages ----
credOkMsg   BYTE "Credentials loaded from demo_credentials.txt",0
credNewMsg  BYTE "demo_credentials.txt created with defaults.",0
credBadMsg  BYTE "demo_credentials.txt invalid, using defaults.",0
credNoMsg   BYTE "demo_credentials.txt missing, using defaults.",0
capApp      BYTE "CyberShield",0
capSaved    BYTE "Saved Log File (cybershield_log.txt)",0
saveOkMsg   BYTE "Session log saved to cybershield_log.txt",0
saveErrMsg  BYTE "ERROR: could not create cybershield_log.txt",0
saveNoneMsg BYTE "Nothing to save: no events recorded yet.",0
viewNoMsg   BYTE "No saved log file found. Click 'Save Log to File' first.",0

; ---- DWM attribute values ----
dwOne       DWORD 1
dwCapCol    DWORD COL_BANNER
dwTxtCol    DWORD COL_TEXT

.data?
hInst       DWORD ?
hMain       DWORD ?
hFont       DWORD ?
hFontBold   DWORD ?
hFontBig    DWORD ?
hPwChk      DWORD ?
hShow       DWORD ?
hUser       DWORD ?
hPass       DWORD ?
hLog        DWORD ?
hResult     DWORD ?
hScore      DWORD ?
hLStatus    DWORD ?
hLAtt       DWORD ?
hFoot       DWORD ?
hNote       DWORD ?
hBanner     DWORD ?
hAccLine    DWORD ?
hTitle      DWORD ?
hSub        DWORD ?
hTag        DWORD ?
hRules      DWORD 6 DUP(?)
hSegs       DWORD 6 DUP(?)
hDots       DWORD 6 DUP(?)          ; rule status dots
hHead       DWORD 4 DUP(?)          ; card headings
hBord       DWORD 4 DUP(?)          ; card outlines
hIn         DWORD 3 DUP(?)          ; input-box background panels
ruleColor   DWORD 6 DUP(?)
brushTbl    DWORD 5 DUP(?)          ; 0 red,1 orange,2 green,3 dgreen,4 empty-block
brushMain   DWORD ?
brushCard   DWORD ?
brushBanner DWORD ?
brushAccent DWORD ?
brushAccentDn DWORD ?
brushSlate  DWORD ?
brushSlateDn DWORD ?
credMsgPtr  DWORD ?
rcTmp       DWORD 4 DUP(?)
userBuf     BYTE BUF_SIZE+1 DUP(?)
passBuf     BYTE BUF_SIZE+1 DUP(?)
tmpBuf      BYTE 128 DUP(?)
lineBuf     BYTE 128 DUP(?)
fileBuf     BYTE FILE_BUF DUP(?)
logArr      BYTE MAX_LOG DUP(?)
bytesRead   DWORD ?
bytesWritten DWORD ?
hFileH      DWORD ?
lockRemain  DWORD ?                 ; seconds left in the lockout
ctlH        DWORD MAX_CTL DUP(?)    ; every control created by MakeCtl
ctlG        DWORD MAX_CTL DUP(?)    ; ...and the screen group it belongs to

.data
; ---- program state ----
failCount   DWORD 0
locked      DWORD 0
logCount    DWORD 0
curLevel    DWORD 4
curPoints   DWORD 0
showPw      DWORD 0
uiReady     DWORD 0
cardIdx     DWORD 0
lStatusColor DWORD COL_MUTED
subColor    DWORD COL_MUTED
ctlCount    DWORD 0
curGroup    DWORD 0             ; group assigned to controls being created
ofsX        DWORD 0             ; layout offset applied by MakeCtl
ofsY        DWORD 0
curScreen   DWORD 1             ; screen currently shown (SCR_*)

; strength flags: kept together so they can be used as an array
flags       LABEL DWORD
fLen        DWORD 0
fUpper      DWORD 0
fLower      DWORD 0
fDigit      DWORD 0
fSpecial    DWORD 0
fLong       DWORD 0

.code
; ============================================================================
; MakeCtl: create one child control and give it the standard GUI font.
; Returns the control handle in EAX.
; ============================================================================
MakeCtl PROC clsName:DWORD, txt:DWORD, style:DWORD, x:DWORD, y:DWORD, w:DWORD, h:DWORD, id:DWORD, exStyle:DWORD
    LOCAL hCtl:DWORD, px:DWORD, py:DWORD
    mov  eax, x
    add  eax, ofsX                  ; per-screen layout offset
    mov  px, eax
    mov  eax, y
    add  eax, ofsY
    mov  py, eax
    invoke CreateWindowExA, exStyle, clsName, txt, style, px, py, w, h, hMain, id, hInst, 0
    mov  hCtl, eax
    invoke SendMessageA, hCtl, WM_SETFONT, hFont, TRUE
    ; remember the control and its screen group (used by SwitchScreen)
    mov  ecx, ctlCount
    cmp  ecx, MAX_CTL
    jae  McDone
    mov  eax, hCtl
    mov  ctlH[ecx*4], eax
    mov  eax, curGroup
    mov  ctlG[ecx*4], eax
    inc  ctlCount
McDone:
    mov  eax, hCtl
    ret
MakeCtl ENDP

; RoundCtl: give a control rounded corners (radius r).
RoundCtl PROC hCtl:DWORD, w:DWORD, h:DWORD, r:DWORD
    mov  eax, w
    inc  eax
    mov  ecx, h
    inc  ecx
    invoke CreateRoundRectRgn, 0, 0, eax, ecx, r, r
    invoke SetWindowRgn, hCtl, eax, TRUE
    ret
RoundCtl ENDP

; MakeCard: rounded card with a 1px outline and an accent heading.
MakeCard PROC x:DWORD, y:DWORD, w:DWORD, h:DWORD, pTitle:DWORD
    LOCAL oX:DWORD, oY:DWORD, oW:DWORD, oH:DWORD
    mov  eax, x
    dec  eax
    mov  oX, eax
    mov  eax, y
    dec  eax
    mov  oY, eax
    mov  eax, w
    add  eax, 2
    mov  oW, eax
    mov  eax, h
    add  eax, 2
    mov  oH, eax
    invoke MakeCtl, ADDR clsStatic, ADDR emptyStr, S_PANEL, oX, oY, oW, oH, 0, 0
    mov  edx, cardIdx
    mov  hBord[edx*4], eax
    invoke RoundCtl, eax, oW, oH, 18
    invoke MakeCtl, ADDR clsStatic, ADDR emptyStr, S_PANEL, x, y, w, h, 0, 0
    invoke RoundCtl, eax, w, h, 16
    mov  eax, x
    add  eax, 16
    mov  ecx, y
    add  ecx, 12
    invoke MakeCtl, ADDR clsStatic, pTitle, S_STATIC, eax, ecx, 220, 20, 0, 0
    mov  edx, cardIdx
    mov  hHead[edx*4], eax
    invoke SendMessageA, eax, WM_SETFONT, hFontBold, TRUE
    inc  cardIdx
    ret
MakeCard ENDP

; MakeInput: rounded dark panel with a padded edit box inside. Returns edit in EAX.
MakeInput PROC x:DWORD, y:DWORD, w:DWORD, id:DWORD, style:DWORD, idx:DWORD
    LOCAL hE:DWORD
    invoke MakeCtl, ADDR clsStatic, ADDR emptyStr, S_PANEL, x, y, w, 32, 0, 0
    mov  edx, idx
    mov  hIn[edx*4], eax
    invoke RoundCtl, eax, w, 32, 10
    mov  eax, x
    add  eax, 10
    mov  ecx, y
    add  ecx, 6
    mov  edx, w
    sub  edx, 20
    invoke MakeCtl, ADDR clsEdit, ADDR emptyStr, style, eax, ecx, edx, 20, id, 0
    mov  hE, eax
    invoke SendMessageA, hE, EM_LIMITTEXT, BUF_SIZE, 0
    mov  eax, hE
    ret
MakeInput ENDP

; ============================================================================
; SwitchScreen: show one screen (menu / strength / login / log) and hide the
; others. Banner controls (group 0) are always shown; the "< Menu" button
; (group 9) is shown on every screen except the menu.
; ============================================================================
SwitchScreen PROC USES ebx esi scr:DWORD
    mov  eax, scr
    mov  curScreen, eax
    xor  ebx, ebx
SsLoop:
    cmp  ebx, ctlCount
    jae  SsDone
    mov  eax, ctlG[ebx*4]
    xor  esi, esi                   ; default: SW_HIDE
    cmp  eax, GRP_ALWAYS
    je   SsShow
    cmp  eax, GRP_NOMENU
    jne  SsCmp
    cmp  scr, SCR_MENU
    jne  SsShow
    jmp  SsDo
SsCmp:
    cmp  eax, scr
    jne  SsDo
SsShow:
    mov  esi, SW_SHOW
SsDo:
    mov  ecx, ctlH[ebx*4]
    invoke ShowWindow, ecx, esi
    inc  ebx
    jmp  SsLoop
SsDone:
    mov  eax, scr
    cmp  eax, SCR_STRENGTH
    jne  SsFocus2
    invoke SetFocus, hPwChk
    ret
SsFocus2:
    cmp  eax, SCR_LOGIN
    jne  SsEnd
    cmp  locked, 1
    je   SsEnd
    invoke SetFocus, hUser
SsEnd:
    ret
SwitchScreen ENDP

; ============================================================================
; MenuChoice: route a main-menu choice (1..4) to its module.
; ============================================================================
MenuChoice PROC choice:DWORD
    mov  eax, choice
    cmp  eax, 1
    jne  MnTwo
    invoke SwitchScreen, SCR_STRENGTH
    ret
MnTwo:
    cmp  eax, 2
    jne  MnThree
    invoke SwitchScreen, SCR_LOGIN
    ret
MnThree:
    cmp  eax, 3
    jne  MnExit
    invoke SwitchScreen, SCR_LOG
    ret
MnExit:
    invoke SendMessageA, hMain, WM_CLOSE, 0, 0      ; 4 = Exit
    ret
MenuChoice ENDP

; ============================================================================
; String helpers
; ============================================================================
; StrEqual: ESI, EDI = null-terminated strings. ZF=1 if equal. Regs preserved.
StrEqual PROC
    push esi
    push edi
    push eax
CmpLoop:
    mov  al, [esi]
    cmp  al, [edi]
    jne  SDone
    cmp  al, 0
    je   SDone
    inc  esi
    inc  edi
    jmp  CmpLoop
SDone:
    pop  eax
    pop  edi
    pop  esi
    ret
StrEqual ENDP

; StrCopy: copy string ESI -> EDI including terminator. Regs preserved.
StrCopy PROC
    push esi
    push edi
    push eax
CopyLoop:
    mov  al, [esi]
    mov  [edi], al
    inc  esi
    inc  edi
    cmp  al, 0
    jne  CopyLoop
    pop  eax
    pop  edi
    pop  esi
    ret
StrCopy ENDP

; ParseLine: copy one text line. In: ESI=src, ECX=bytes left, EDI=dest.
; Out: EAX=chars copied (dest null-terminated); ESI, ECX advanced past CR/LF.
ParseLine PROC
    push ebx
    xor  ebx, ebx
PLNext:
    cmp  ecx, 0
    je   PLEnd
    mov  al, [esi]
    cmp  al, 0Dh
    je   PLEol
    cmp  al, 0Ah
    je   PLEol
    cmp  ebx, BUF_SIZE
    jae  PLSkip
    mov  [edi + ebx], al
    inc  ebx
PLSkip:
    inc  esi
    dec  ecx
    jmp  PLNext
PLEol:
    inc  esi
    dec  ecx
    cmp  al, 0Dh
    jne  PLEnd
    cmp  ecx, 0
    je   PLEnd
    cmp  BYTE PTR [esi], 0Ah
    jne  PLEnd
    inc  esi
    dec  ecx
PLEnd:
    mov  BYTE PTR [edi + ebx], 0
    mov  eax, ebx
    pop  ebx
    ret
ParseLine ENDP

; ============================================================================
; AddLog: record an event (code 1..7) and show it in the list box.
; ============================================================================
AddLog PROC USES ebx esi edi code:DWORD
    mov  ebx, logCount
    cmp  ebx, MAX_LOG
    jae  AddLogEnd
    mov  eax, code
    mov  logArr[ebx], al
    dec  eax
    mov  edx, logMsgTable[eax*4]
    inc  ebx
    mov  logCount, ebx              ; EBX = event number (1-based)
    invoke wsprintfA, ADDR lineBuf, ADDR fmtLine, ebx, edx
    invoke SendMessageA, hLog, LB_ADDSTRING, 0, ADDR lineBuf
    dec  ebx
    invoke SendMessageA, hLog, LB_SETCURSEL, ebx, 0     ; highlight + scroll to newest
AddLogEnd:
    ret
AddLog ENDP

; ============================================================================
; Login status helpers
; ============================================================================
SetLStatus PROC pText:DWORD, pColor:DWORD
    mov  eax, pColor
    mov  lStatusColor, eax
    invoke SetWindowTextA, hLStatus, pText
    invoke InvalidateRect, hLStatus, 0, TRUE
    ret
SetLStatus ENDP

UpdateAttempts PROC
    cmp  locked, 1
    jne  AttNormal
    invoke wsprintfA, ADDR tmpBuf, ADDR fmtAttLock, lockRemain
    invoke SetWindowTextA, hLAtt, ADDR tmpBuf
    jmp  AttEnd
AttNormal:
    mov  eax, MAX_ATTEMPTS
    sub  eax, failCount
    invoke wsprintfA, ADDR tmpBuf, ADDR fmtAtt, eax
    invoke SetWindowTextA, hLAtt, ADDR tmpBuf
AttEnd:
    ret
UpdateAttempts ENDP

; UpdateLockUI: show the countdown in the banner and the attempts line
UpdateLockUI PROC
    invoke wsprintfA, ADDR tmpBuf, ADDR fmtSubLock, lockRemain
    invoke SetWindowTextA, hSub, ADDR tmpBuf
    invoke InvalidateRect, hSub, 0, TRUE
    call UpdateAttempts
    ret
UpdateLockUI ENDP

; ============================================================================
; Analyze: read the checker edit box, apply the fixed rules, update the GUI.
; Returns level in EAX: 0 weak, 1 medium, 2 strong, 3 very strong, 4 empty.
; ============================================================================
Analyze PROC USES ebx esi edi
    LOCAL len:DWORD, score:DWORD, level:DWORD

    ; clear the six flags
    mov  edi, OFFSET flags
    mov  ecx, 6
    xor  eax, eax
    cld
    rep  stosd

    invoke GetWindowTextA, hPwChk, ADDR passBuf, BUF_SIZE + 1
    mov  len, eax
    cmp  eax, 0
    je   AnScanDone

    cmp  eax, MIN_LEN
    jb   AnLen8
    mov  fLen, 1
AnLen8:
    cmp  len, LONG_LEN
    jb   AnLen12
    mov  fLong, 1
AnLen12:

    mov  esi, OFFSET passBuf
    mov  ecx, len
AnScan:
    mov  al, [esi]
    cmp  al, 'A'
    jb   AnBelowA
    cmp  al, 'Z'
    jbe  AnUpper
    cmp  al, 'a'
    jb   AnSpecial                  ; [ \ ] ^ _ `
    cmp  al, 'z'
    jbe  AnLower
    jmp  AnSpecial                  ; { | } ~
AnBelowA:
    cmp  al, '0'
    jb   AnSpecial
    cmp  al, '9'
    jbe  AnDigit
    jmp  AnSpecial                  ; : ; < = > ? @
AnUpper:
    mov  fUpper, 1
    jmp  AnNext
AnLower:
    mov  fLower, 1
    jmp  AnNext
AnDigit:
    mov  fDigit, 1
    jmp  AnNext
AnSpecial:
    cmp  al, 21h                    ; ignore space / control characters
    jb   AnNext
    cmp  al, 7Eh
    ja   AnNext
    mov  fSpecial, 1
AnNext:
    inc  esi
    dec  ecx
    jnz  AnScan
AnScanDone:

    ; score = rules met (0..5)
    mov  eax, fLen
    add  eax, fUpper
    add  eax, fLower
    add  eax, fDigit
    add  eax, fSpecial
    mov  score, eax

    ; level
    cmp  len, 0
    je   LvEmpty
    cmp  eax, 5
    jne  LvNot5
    mov  level, 2
    cmp  fLong, 1
    jne  LvDone
    mov  level, 3
    jmp  LvDone
LvNot5:
    mov  level, 1
    cmp  eax, 3
    jae  LvDone
    mov  level, 0
    jmp  LvDone
LvEmpty:
    mov  level, 4
LvDone:
    mov  eax, level
    mov  curLevel, eax

    ; ---- update the six rule labels ----
    xor  esi, esi
UpLoop:
    cmp  esi, 6
    jae  UpDone
    mov  eax, flags[esi*4]
    test eax, eax
    jz   UpMissing
    mov  ruleColor[esi*4], COL_TEXT
    mov  edx, rOk[esi*4]
    jmp  UpSet
UpMissing:
    mov  edx, rNo[esi*4]
    mov  ruleColor[esi*4], COL_MUTED
UpSet:
    mov  ecx, hRules[esi*4]
    invoke SetWindowTextA, ecx, edx
    mov  ecx, hRules[esi*4]
    invoke InvalidateRect, ecx, 0, TRUE
    mov  ecx, hDots[esi*4]
    invoke InvalidateRect, ecx, 0, TRUE
    inc  esi
    jmp  UpLoop
UpDone:

    ; ---- score label ----
    invoke wsprintfA, ADDR tmpBuf, ADDR fmtScore, score
    invoke SetWindowTextA, hScore, ADDR tmpBuf

    ; ---- result label ----
    mov  eax, level
    mov  edx, resTbl[eax*4]
    invoke SetWindowTextA, hResult, edx
    invoke InvalidateRect, hResult, 0, TRUE

    ; ---- segmented meter: lit blocks = rules met + bonus (0..6) ----
    mov  eax, score
    add  eax, fLong
    mov  curPoints, eax
    xor  esi, esi
SegInv:
    cmp  esi, 6
    jae  SegInvDone
    mov  ecx, hSegs[esi*4]
    invoke InvalidateRect, ecx, 0, TRUE
    inc  esi
    jmp  SegInv
SegInvDone:

    ; wipe the password from memory
    mov  edi, OFFSET passBuf
    mov  ecx, BUF_SIZE + 1
    xor  eax, eax
    cld
    rep  stosb

    mov  eax, level
    ret
Analyze ENDP

; ============================================================================
; DoCheckLog: "Check & Log" button - analyse and record the result.
; ============================================================================
DoCheckLog PROC
    call Analyze
    cmp  eax, 4
    jne  CkNotEmpty
    invoke MessageBoxA, hMain, ADDR msgEmpty, ADDR capApp, MB_OK or MB_ICONINFO
    ret
CkNotEmpty:
    cmp  eax, 2
    jae  CkStrong
    invoke AddLog, EV_PW_WEAK
    ret
CkStrong:
    invoke AddLog, EV_PW_STRONG
    ret
DoCheckLog ENDP

; ============================================================================
; DoLogin: authenticate, count consecutive failures, lock after 3.
; ============================================================================
DoLogin PROC
    cmp  locked, 1
    jne  LgNotLocked
    invoke SetLStatus, ADDR msgBlocked, COL_RED
    invoke AddLog, EV_LOGIN_BLOCK
    jmp  LgEnd

LgNotLocked:
    invoke GetWindowTextA, hUser, ADDR userBuf, BUF_SIZE + 1
    invoke GetWindowTextA, hPass, ADDR passBuf, BUF_SIZE + 1

    mov  esi, OFFSET userBuf
    mov  edi, OFFSET demoUser
    call StrEqual
    jne  LgFailed
    mov  esi, OFFSET passBuf
    mov  edi, OFFSET demoPass
    call StrEqual
    jne  LgFailed

    ; ---- success ----
    mov  failCount, 0
    invoke SetLStatus, ADDR msgOk, COL_GREEN
    invoke AddLog, EV_LOGIN_OK
    invoke SetWindowTextA, hPass, ADDR emptyStr     ; clear password before the popup
    invoke MessageBoxA, hMain, ADDR msgPopupOk, ADDR capLoginOk, MB_OK or MB_ICONINFO
    jmp  LgWipe

LgFailed:
    inc  failCount
    invoke AddLog, EV_LOGIN_FAIL
    cmp  failCount, MAX_ATTEMPTS
    jae  LgLock
    invoke SetLStatus, ADDR msgFail, COL_RED
    jmp  LgWipe
LgLock:
    mov  locked, 1
    invoke SetLStatus, ADDR msgLockNow, COL_RED
    invoke AddLog, EV_LOCKOUT
    ; visual lockout: red banner countdown, inputs disabled, 1-second timer
    mov  subColor, COL_RED
    mov  lockRemain, LOCK_SECONDS
    invoke SetTimer, hMain, IDT_LOCK, 1000, 0
    call UpdateLockUI
    invoke EnableWindow, hUser, FALSE
    invoke EnableWindow, hPass, FALSE

LgWipe:
    invoke SetWindowTextA, hPass, ADDR emptyStr     ; clear password box
    mov  edi, OFFSET passBuf
    mov  ecx, BUF_SIZE + 1
    xor  eax, eax
    cld
    rep  stosb
    call UpdateAttempts
LgEnd:
    ret
DoLogin ENDP

; ============================================================================
; File handling
; ============================================================================
; SaveLog: write the session log to cybershield_log.txt (overwrites).
SaveLog PROC USES ebx esi edi
    LOCAL len:DWORD
    cmp  logCount, 0
    jne  SvHasData
    invoke MessageBoxA, hMain, ADDR saveNoneMsg, ADDR capApp, MB_OK or MB_ICONINFO
    ret
SvHasData:
    mov  edi, OFFSET fileBuf
    invoke wsprintfA, edi, ADDR fmtTitle
    add  edi, eax
    xor  ebx, ebx
SvLoop:
    cmp  ebx, logCount
    jae  SvBuilt
    movzx eax, logArr[ebx]
    dec  eax
    mov  edx, logMsgTable[eax*4]
    lea  ecx, [ebx + 1]
    invoke wsprintfA, edi, ADDR fmtFileLine, ecx, edx
    add  edi, eax
    inc  ebx
    jmp  SvLoop
SvBuilt:
    sub  edi, OFFSET fileBuf
    mov  len, edi

    invoke CreateFileA, ADDR logFile, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTR_NORMAL, 0
    cmp  eax, INVALID_HANDLE
    je   SvError
    mov  hFileH, eax
    invoke WriteFile, hFileH, ADDR fileBuf, len, ADDR bytesWritten, 0
    invoke CloseHandle, hFileH
    invoke MessageBoxA, hMain, ADDR saveOkMsg, ADDR capApp, MB_OK or MB_ICONINFO
    ret
SvError:
    invoke MessageBoxA, hMain, ADDR saveErrMsg, ADDR capApp, MB_OK or MB_ICONERROR
    ret
SaveLog ENDP

; ViewLog: read cybershield_log.txt and show it in a message box.
ViewLog PROC USES ebx
    invoke CreateFileA, ADDR logFile, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTR_NORMAL, 0
    cmp  eax, INVALID_HANDLE
    je   VwNone
    mov  hFileH, eax
    mov  bytesRead, 0
    invoke ReadFile, hFileH, ADDR fileBuf, FILE_BUF - 1, ADDR bytesRead, 0
    invoke CloseHandle, hFileH
    mov  ebx, bytesRead
    mov  fileBuf[ebx], 0
    invoke MessageBoxA, hMain, ADDR fileBuf, ADDR capSaved, MB_OK or MB_ICONINFO
    ret
VwNone:
    invoke MessageBoxA, hMain, ADDR viewNoMsg, ADDR capApp, MB_OK or MB_ICONWARNING
    ret
ViewLog ENDP

; LoadCredentials: runs before the window exists. Reads demo_credentials.txt
; (line 1 = username, line 2 = password). Creates it with defaults if missing.
LoadCredentials PROC USES ebx esi edi
    invoke CreateFileA, ADDR credFile, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTR_NORMAL, 0
    cmp  eax, INVALID_HANDLE
    je   CrMissing
    mov  hFileH, eax
    mov  bytesRead, 0
    invoke ReadFile, hFileH, ADDR fileBuf, FILE_BUF - 1, ADDR bytesRead, 0
    invoke CloseHandle, hFileH
    mov  ebx, bytesRead
    mov  fileBuf[ebx], 0

    mov  esi, OFFSET fileBuf
    mov  ecx, ebx
    mov  edi, OFFSET userBuf
    call ParseLine                  ; EAX = length of line 1
    push eax
    mov  edi, OFFSET passBuf
    call ParseLine                  ; EAX = length of line 2
    pop  edx
    cmp  edx, 0
    je   CrBad
    cmp  eax, 0
    je   CrBad

    mov  esi, OFFSET userBuf
    mov  edi, OFFSET demoUser
    call StrCopy
    mov  esi, OFFSET passBuf
    mov  edi, OFFSET demoPass
    call StrCopy
    mov  edi, OFFSET passBuf        ; wipe temporary copy
    mov  ecx, BUF_SIZE + 1
    xor  eax, eax
    cld
    rep  stosb
    mov  credMsgPtr, OFFSET credOkMsg
    ret

CrBad:
    mov  credMsgPtr, OFFSET credBadMsg
    ret

CrMissing:
    invoke CreateFileA, ADDR credFile, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTR_NORMAL, 0
    cmp  eax, INVALID_HANDLE
    je   CrNoCreate
    mov  hFileH, eax
    invoke wsprintfA, ADDR fileBuf, ADDR fmtCred, ADDR demoUser, ADDR demoPass
    mov  ebx, eax
    invoke WriteFile, hFileH, ADDR fileBuf, ebx, ADDR bytesWritten, 0
    invoke CloseHandle, hFileH
    mov  credMsgPtr, OFFSET credNewMsg
    ret
CrNoCreate:
    mov  credMsgPtr, OFFSET credNoMsg
    ret
LoadCredentials ENDP

; ============================================================================
; WndProc: main window procedure
; ============================================================================
WndProc PROC USES ebx esi edi hWnd:DWORD, uMsg:DWORD, wParam:DWORD, lParam:DWORD
    mov  eax, uMsg
    cmp  eax, WM_CREATE
    je   OnCreate
    cmp  eax, WM_COMMAND
    je   OnCommand
    cmp  eax, WM_TIMER
    je   OnTimer
    cmp  eax, WM_CTLCOLORSTATIC
    je   OnCtlColor
    cmp  eax, WM_CTLCOLOREDIT
    je   OnCtlEdit
    cmp  eax, WM_CTLCOLORLISTBOX
    je   OnCtlEdit
    cmp  eax, WM_DRAWITEM
    je   OnDrawItem
    cmp  eax, WM_DESTROY
    je   OnDestroy
    jmp  WpDefault

; ---------------------------------------------------------------- WM_CREATE
OnCreate:
    mov  eax, hWnd
    mov  hMain, eax

    ; fonts: body, bold heading, big title
    invoke CreateFontA, -14,0,0,0,400,0,0,0,1,0,0,5,0, ADDR fontName
    mov  hFont, eax
    invoke CreateFontA, -14,0,0,0,700,0,0,0,1,0,0,5,0, ADDR fontName
    mov  hFontBold, eax
    invoke CreateFontA, -26,0,0,0,700,0,0,0,1,0,0,5,0, ADDR fontName
    mov  hFontBig, eax

    ; dark title bar (ignored on systems that do not support it)
    invoke DwmSetWindowAttribute, hWnd, 20, ADDR dwOne, 4          ; immersive dark mode
    invoke DwmSetWindowAttribute, hWnd, 35, ADDR dwCapCol, 4       ; caption colour (Win11)
    invoke DwmSetWindowAttribute, hWnd, 36, ADDR dwTxtCol, 4       ; caption text colour (Win11)

    ; ---------- header banner (always visible) ----------
    mov  curGroup, GRP_ALWAYS
    mov  ofsX, 0
    mov  ofsY, 0
    invoke MakeCtl, ADDR clsStatic, ADDR emptyStr, S_PANEL, 0, 0, CLIENT_W, HDR_H, 0, 0
    mov  hBanner, eax
    invoke MakeCtl, ADDR clsStatic, ADDR emptyStr, S_STATIC, 0, 62, CLIENT_W, 2, 0, 0
    mov  hAccLine, eax
    invoke MakeCtl, ADDR clsStatic, ADDR txtTitle, S_STATIC, 20, 4, 300, 36, 0, 0
    mov  hTitle, eax
    invoke SendMessageA, hTitle, WM_SETFONT, hFontBig, TRUE
    invoke MakeCtl, ADDR clsStatic, ADDR txtSub, S_STATIC, 22, 40, 420, 20, 0, 0
    mov  hSub, eax
    invoke MakeCtl, ADDR clsStatic, ADDR txtTag, S_STATICR, 330, 22, 320, 20, 0, 0
    mov  hTag, eax

    ; "< Menu" button: shown on every screen except the main menu
    mov  curGroup, GRP_NOMENU
    invoke MakeCtl, ADDR clsButton, ADDR txtBack, S_BUTTON, 664, 16, 120, 32, IDC_BACK, 0
    invoke RoundCtl, eax, 120, 32, 10

    ; ---------- MAIN MENU screen ----------
    mov  curGroup, SCR_MENU
    invoke MakeCard, 200, 84, 400, 330, ADDR txtMenuTitle
    invoke MakeCtl, ADDR clsButton, ADDR txtM1, S_BUTTON, 224, 124, 352, 52, IDC_MENU1, 0
    invoke RoundCtl, eax, 352, 52, 14
    invoke MakeCtl, ADDR clsButton, ADDR txtM2, S_BUTTON, 224, 188, 352, 52, 142, 0
    invoke RoundCtl, eax, 352, 52, 14
    invoke MakeCtl, ADDR clsButton, ADDR txtM3, S_BUTTON, 224, 252, 352, 52, 143, 0
    invoke RoundCtl, eax, 352, 52, 14
    invoke MakeCtl, ADDR clsButton, ADDR txtM4, S_BUTTON, 224, 316, 352, 52, IDC_MENU4, 0
    invoke RoundCtl, eax, 352, 52, 14
    invoke MakeCtl, ADDR clsStatic, ADDR txtHint, S_STATICC, 224, 380, 352, 20, 0, 0

    ; ---------- STRENGTH screen: card 1 (centred) ----------
    mov  curGroup, SCR_STRENGTH
    mov  ofsX, 196
    mov  ofsY, 0
    invoke MakeCard, 16, 76, 376, 290, ADDR txtGrp1
    invoke MakeCtl, ADDR clsButton, ADDR txtShow, S_BUTTON, 312, 84, 64, 22, IDC_SHOW, 0
    mov  hShow, eax
    invoke RoundCtl, hShow, 64, 22, 10
    invoke MakeCtl, ADDR clsStatic, ADDR txtEnter, S_STATIC, 32, 112, 344, 18, 0, 0
    invoke MakeInput, 32, 130, 240, IDC_PWCHK, S_EDITPW, 0
    mov  hPwChk, eax
    invoke MakeCtl, ADDR clsButton, ADDR txtCheck, S_BUTTON, 280, 130, 96, 32, IDC_BTNCHK, 0
    invoke RoundCtl, eax, 96, 32, 10

    xor  esi, esi
    mov  edi, 172
RulesMk:
    cmp  esi, 6
    jae  RulesDone
    lea  ecx, [edi + 5]
    invoke MakeCtl, ADDR clsStatic, ADDR emptyStr, S_STATIC, 34, ecx, 10, 10, 0, 0
    mov  hDots[esi*4], eax
    invoke RoundCtl, eax, 10, 10, 10
    mov  edx, esi
    add  edx, IDC_RULE1
    invoke MakeCtl, ADDR clsStatic, ADDR emptyStr, S_STATIC, 54, edi, 322, 19, edx, 0
    mov  hRules[esi*4], eax
    mov  ruleColor[esi*4], COL_MUTED
    add  edi, 19
    inc  esi
    jmp  RulesMk
RulesDone:
    invoke MakeCtl, ADDR clsStatic, ADDR emptyStr, S_STATIC, 32, 290, 344, 19, IDC_SCORE, 0
    mov  hScore, eax
    invoke MakeCtl, ADDR clsStatic, ADDR emptyStr, S_STATIC, 32, 310, 344, 20, IDC_RESULT, 0
    mov  hResult, eax
    invoke SendMessageA, hResult, WM_SETFONT, hFontBold, TRUE

    ; six meter blocks (54 px wide, 4 px gap)
    xor  esi, esi
    mov  edi, 32
SegMk:
    cmp  esi, 6
    jae  SegDone
    invoke MakeCtl, ADDR clsStatic, ADDR emptyStr, S_STATIC, edi, 340, 54, 12, 0, 0
    mov  hSegs[esi*4], eax
    invoke RoundCtl, eax, 54, 12, 12
    add  edi, 58
    inc  esi
    jmp  SegMk
SegDone:

    ; ---------- LOGIN screen: card 2 (moved up and centred) ----------
    mov  curGroup, SCR_LOGIN
    mov  ofsX, 196
    mov  ofsY, -270
    invoke MakeCard, 16, 378, 376, 200, ADDR txtGrp2
    invoke MakeCtl, ADDR clsStatic, ADDR txtUser, S_STATIC, 32, 414, 344, 18, 0, 0
    invoke MakeInput, 32, 432, 344, IDC_USER, S_EDIT, 1
    mov  hUser, eax
    invoke MakeCtl, ADDR clsStatic, ADDR txtPass, S_STATIC, 32, 470, 344, 18, 0, 0
    invoke MakeInput, 32, 488, 232, IDC_PASS, S_EDITPW, 2
    mov  hPass, eax
    invoke MakeCtl, ADDR clsButton, ADDR txtLogin, S_BUTTON, 276, 488, 100, 32, IDC_BTNLOGIN, 0
    invoke RoundCtl, eax, 100, 32, 10
    invoke MakeCtl, ADDR clsStatic, ADDR txtReady, S_STATIC, 32, 526, 344, 20, IDC_LSTATUS, 0
    mov  hLStatus, eax
    invoke MakeCtl, ADDR clsStatic, ADDR emptyStr, S_STATIC, 32, 546, 344, 20, IDC_LATT, 0
    mov  hLAtt, eax

    ; ---------- LOG screen: card 3 (centred) ----------
    mov  curGroup, SCR_LOG
    mov  ofsX, -196
    mov  ofsY, 0
    invoke MakeCard, 408, 76, 376, 502, ADDR txtGrp3
    invoke MakeCtl, ADDR clsList, ADDR emptyStr, S_LIST, 424, 114, 344, 330, IDC_LOG, 0
    mov  hLog, eax
    invoke SendMessageA, hLog, LB_SETITEMHEIGHT, 0, 26
    invoke SetWindowTheme, hLog, ADDR darkTheme, 0                 ; dark scrollbar
    invoke MakeCtl, ADDR clsButton, ADDR txtSave, S_BUTTON, 424, 452, 166, 32, IDC_BTNSAVE, 0
    invoke RoundCtl, eax, 166, 32, 10
    invoke MakeCtl, ADDR clsButton, ADDR txtView, S_BUTTON, 602, 452, 166, 32, IDC_BTNVIEW, 0
    invoke RoundCtl, eax, 166, 32, 10
    invoke MakeCtl, ADDR clsStatic, ADDR emptyStr, S_STATIC, 424, 490, 344, 20, IDC_FOOT, 0
    mov  hFoot, eax
    invoke SetWindowTextA, hFoot, credMsgPtr
    invoke MakeCtl, ADDR clsStatic, ADDR txtNote, S_STATIC, 424, 514, 344, 44, 0, 0
    mov  hNote, eax

    mov  uiReady, 1
    call UpdateAttempts
    call Analyze                    ; initialise the checker display
    invoke SwitchScreen, SCR_MENU   ; start on the main menu
    xor  eax, eax
    ret

; -------------------------------------------------------------- WM_COMMAND
OnCommand:
    mov  eax, wParam
    movzx ecx, ax                   ; control ID
    shr  eax, 16                    ; notification code

    cmp  ecx, IDC_PWCHK
    jne  CmdShow
    cmp  eax, EN_CHANGE
    jne  WpZero
    cmp  uiReady, 1
    jne  WpZero
    call Analyze                    ; live feedback while typing
    jmp  WpZero

CmdShow:
    cmp  ecx, IDC_SHOW
    jne  CmdCheck
    xor  showPw, 1
    mov  edx, '*'
    mov  eax, OFFSET txtShow
    cmp  showPw, 1
    jne  CmdShowSet
    xor  edx, edx                   ; showing -> no mask character
    mov  eax, OFFSET txtHide
CmdShowSet:
    push edx
    invoke SetWindowTextA, hShow, eax
    pop  edx
    invoke SendMessageA, hPwChk, EM_SETPASSWORDCHAR, edx, 0
    invoke InvalidateRect, hPwChk, 0, TRUE
    invoke InvalidateRect, hShow, 0, TRUE
    jmp  WpZero

CmdCheck:
    cmp  ecx, IDC_BTNCHK
    jne  CmdLogin
    call DoCheckLog
    jmp  WpZero

CmdLogin:
    cmp  ecx, IDC_BTNLOGIN
    jne  CmdSave
    call DoLogin
    jmp  WpZero

CmdSave:
    cmp  ecx, IDC_BTNSAVE
    jne  CmdView
    call SaveLog
    jmp  WpZero

CmdView:
    cmp  ecx, IDC_BTNVIEW
    jne  CmdBack
    call ViewLog
    jmp  WpZero

CmdBack:
    cmp  ecx, IDC_BACK
    jne  CmdMenu
    invoke SwitchScreen, SCR_MENU
    jmp  WpZero

CmdMenu:
    cmp  ecx, IDC_MENU1
    jb   WpZero
    cmp  ecx, IDC_MENU4
    ja   WpZero
    sub  ecx, IDC_MENU1
    inc  ecx                        ; 1..4
    invoke MenuChoice, ecx
    jmp  WpZero

; --------------------------------------------------------- WM_CTLCOLORSTATIC
OnCtlColor:
    mov  esi, lParam                ; control handle
    mov  edi, wParam                ; device context

    cmp  esi, hBanner
    je   CcBannerBg
    cmp  esi, hAccLine
    je   CcAccLine
    cmp  esi, hTitle
    je   CcTitle
    cmp  esi, hSub
    je   CcSub
    cmp  esi, hTag
    je   CcTag
    cmp  esi, hUser                 ; disabled edit boxes arrive here
    je   CcDisabledEdit
    cmp  esi, hPass
    je   CcDisabledEdit

    ; input-box background panels
    xor  ebx, ebx
CcInLoop:
    cmp  ebx, 3
    jae  CcHeads
    cmp  esi, hIn[ebx*4]
    je   CcInput
    inc  ebx
    jmp  CcInLoop

    ; card headings
CcHeads:
    xor  ebx, ebx
CcHeadLoop:
    cmp  ebx, 4
    jae  CcBords
    cmp  esi, hHead[ebx*4]
    je   CcHead
    inc  ebx
    jmp  CcHeadLoop

    ; card outlines
CcBords:
    xor  ebx, ebx
CcBordLoop:
    cmp  ebx, 4
    jae  CcDots
    cmp  esi, hBord[ebx*4]
    je   CcBord
    inc  ebx
    jmp  CcBordLoop

    ; rule status dots
CcDots:
    xor  ebx, ebx
CcDotLoop:
    cmp  ebx, 6
    jae  CcSegs
    cmp  esi, hDots[ebx*4]
    je   CcDot
    inc  ebx
    jmp  CcDotLoop

    ; meter blocks
CcSegs:
    xor  ebx, ebx
CcSegLoop:
    cmp  ebx, 6
    jae  CcRules
    cmp  esi, hSegs[ebx*4]
    je   CcSeg
    inc  ebx
    jmp  CcSegLoop

    ; rule labels
CcRules:
    xor  ebx, ebx
CcRuleLoop:
    cmp  ebx, 6
    jae  CcOthers
    cmp  esi, hRules[ebx*4]
    je   CcRule
    inc  ebx
    jmp  CcRuleLoop

CcRule:
    mov  ecx, ruleColor[ebx*4]
    jmp  CcText

CcOthers:
    mov  ecx, COL_MUTED             ; default label colour
    cmp  esi, hResult
    jne  CcNotRes
    mov  eax, curLevel
    mov  ecx, resCol[eax*4]
    jmp  CcText
CcNotRes:
    cmp  esi, hLStatus
    jne  CcNotLSt
    mov  ecx, lStatusColor
    jmp  CcText
CcNotLSt:
    cmp  esi, hFoot
    je   CcMuted
    cmp  esi, hNote
    je   CcMuted
    cmp  esi, hScore
    je   CcMuted
    cmp  esi, hLAtt
    jne  CcText
CcMuted:
    mov  ecx, COL_MUTED

CcText:
    invoke SetTextColor, edi, ecx
    invoke SetBkColor, edi, COL_CARD
    mov  eax, brushCard
    ret

CcSeg:
    mov  eax, curLevel              ; lit block colour = current level
    cmp  ebx, curPoints
    jb   CcSegOn
    mov  eax, 4                     ; unlit block
CcSegOn:
    mov  eax, brushTbl[eax*4]
    ret

CcInput:
    mov  eax, brushMain
    ret

CcHead:
    mov  ecx, COL_ACCENT
    jmp  CcText

CcBord:
    mov  eax, brushTbl[16]          ; slate outline
    ret

CcDot:
    mov  eax, flags[ebx*4]
    test eax, eax
    mov  eax, brushTbl[16]          ; unmet: slate
    jz   CcDotRet
    mov  eax, brushTbl[8]           ; met: green
CcDotRet:
    ret

CcDisabledEdit:
    invoke SetTextColor, edi, COL_MUTED
    invoke SetBkColor, edi, COL_BG
    mov  eax, brushMain
    ret

CcTitle:
    invoke SetTextColor, edi, COL_ACCENT
    jmp  CcBanner
CcSub:
    invoke SetTextColor, edi, subColor
    jmp  CcBanner
CcTag:
    invoke SetTextColor, edi, COL_MUTED
CcBanner:
    invoke SetBkColor, edi, COL_BANNER
CcBannerBg:
    mov  eax, brushBanner
    ret
CcAccLine:
    mov  eax, brushAccent
    ret

; ------------------------------------------- WM_CTLCOLOREDIT / LISTBOX
OnCtlEdit:
    invoke SetTextColor, wParam, COL_TEXT
    invoke SetBkColor, wParam, COL_BG
    mov  eax, brushMain
    ret

; ------------------------------------------------------------ WM_DRAWITEM
OnDrawItem:
    mov  esi, lParam                ; DRAWITEMSTRUCT*
    mov  edi, [esi+24]              ; hDC
    mov  ecx, [esi+4]               ; control ID
    cmp  ecx, IDC_LOG
    je   DiList

    ; ---- flat buttons ----
    mov  eax, [esi+16]              ; itemState (1 = pressed)
    mov  ebx, COL_TEXT
    mov  edx, brushSlate
    cmp  ecx, IDC_BTNCHK
    je   DiPrimary
    cmp  ecx, IDC_BTNLOGIN
    je   DiPrimary
    cmp  ecx, IDC_MENU1
    jb   DiNotMenu
    cmp  ecx, 143                   ; menu options 1-3 are cyan, Exit is slate
    jbe  DiPrimary
DiNotMenu:
    test eax, 1
    jz   DiFill
    mov  edx, brushSlateDn
    jmp  DiFill
DiPrimary:
    mov  ebx, COL_BG                ; dark text on cyan
    mov  edx, brushAccent
    test eax, 1
    jz   DiFill
    mov  edx, brushAccentDn
DiFill:
    lea  ecx, [esi+28]
    invoke FillRect, edi, ecx, edx
    invoke SetBkMode, edi, TRANSPARENT
    invoke SetTextColor, edi, ebx
    invoke GetWindowTextA, DWORD PTR [esi+20], ADDR tmpBuf, 64
    lea  ecx, [esi+28]
    invoke DrawTextA, edi, ADDR tmpBuf, -1, ecx, 25h        ; centre | vcentre | single line
    mov  eax, TRUE
    ret

    ; ---- log rows: coloured stripe + coloured text ----
DiList:
    mov  ebx, [esi+8]               ; item index
    cmp  ebx, -1
    je   DiDone
    cmp  ebx, logCount
    jae  DiDone

    mov  edx, brushMain             ; row background
    test DWORD PTR [esi+16], 1      ; selected (= newest) row is lighter
    jz   DiBg
    mov  edx, brushCard
DiBg:
    lea  ecx, [esi+28]
    invoke FillRect, edi, ecx, edx

    movzx eax, logArr[ebx]
    dec  eax
    push DWORD PTR evCol[eax*4]     ; text colour for this event
    mov  edx, evIdx[eax*4]
    mov  edx, brushTbl[edx*4]       ; stripe brush
    mov  eax, [esi+28]
    mov  rcTmp[0], eax              ; left
    add  eax, 4
    mov  rcTmp[8], eax              ; right = left + 4
    mov  eax, [esi+32]
    add  eax, 5
    mov  rcTmp[4], eax              ; top
    mov  eax, [esi+40]
    sub  eax, 5
    mov  rcTmp[12], eax             ; bottom
    invoke FillRect, edi, ADDR rcTmp, edx

    movzx eax, logArr[ebx]
    dec  eax
    mov  edx, logMsgTable[eax*4]
    lea  ecx, [ebx + 1]
    invoke wsprintfA, ADDR lineBuf, ADDR fmtLine, ecx, edx

    add  DWORD PTR [esi+28], 14     ; indent text past the stripe
    invoke SetBkMode, edi, TRANSPARENT
    pop  eax
    invoke SetTextColor, edi, eax
    lea  ecx, [esi+28]
    invoke DrawTextA, edi, ADDR lineBuf, -1, ecx, 824h      ; vcentre | single line | noprefix
DiDone:
    mov  eax, TRUE
    ret

; ----------------------------------------------------------------- WM_TIMER
; Fires once per second while locked. Counts down; at zero it restores
; normal login (inputs enabled, failure counter reset, event logged).
OnTimer:
    cmp  wParam, IDT_LOCK
    jne  WpZero
    cmp  locked, 1
    jne  WpZero
    dec  lockRemain
    jnz  TmTick

    ; ---- countdown finished: return to normal ----
    invoke KillTimer, hWnd, IDT_LOCK
    mov  locked, 0
    mov  failCount, 0
    mov  subColor, COL_MUTED
    invoke SetWindowTextA, hSub, ADDR txtSub
    invoke InvalidateRect, hSub, 0, TRUE
    invoke EnableWindow, hUser, TRUE
    invoke EnableWindow, hPass, TRUE
    invoke SetLStatus, ADDR msgUnlocked, COL_GREEN
    invoke AddLog, EV_UNLOCK
    call UpdateAttempts
    invoke SetFocus, hUser
    jmp  WpZero
TmTick:
    call UpdateLockUI
    jmp  WpZero

; --------------------------------------------------------------- WM_DESTROY
OnDestroy:
    invoke KillTimer, hWnd, IDT_LOCK
    xor  ebx, ebx
DelBr:
    cmp  ebx, 5
    jae  DelDone
    mov  eax, brushTbl[ebx*4]
    invoke DeleteObject, eax
    inc  ebx
    jmp  DelBr
DelDone:
    invoke DeleteObject, brushCard
    invoke DeleteObject, brushBanner
    invoke DeleteObject, brushAccent
    invoke DeleteObject, brushAccentDn
    invoke DeleteObject, brushSlate
    invoke DeleteObject, brushSlateDn
    invoke DeleteObject, brushMain
    invoke DeleteObject, hFont
    invoke DeleteObject, hFontBold
    invoke DeleteObject, hFontBig
    invoke PostQuitMessage, 0
WpZero:
    xor  eax, eax
    ret

WpDefault:
    invoke DefWindowProcA, hWnd, uMsg, wParam, lParam
    ret
WndProc ENDP

; ============================================================================
; WinMain: brushes, register class, centred window, message loop
; ============================================================================
WinMain PROC hInstance:DWORD
    LOCAL wc:WNDCLASSEX_
    LOCAL msg:MSG_
    LOCAL hwndMain:DWORD
    LOCAL wr:RECT_
    LOCAL winW:DWORD
    LOCAL winH:DWORD
    LOCAL posX:DWORD
    LOCAL posY:DWORD

    ; ---- brushes (needed before the class background is set) ----
    invoke CreateSolidBrush, COL_RED
    mov  brushTbl[0], eax
    invoke CreateSolidBrush, COL_ORANGE
    mov  brushTbl[4], eax
    invoke CreateSolidBrush, COL_GREEN
    mov  brushTbl[8], eax
    invoke CreateSolidBrush, COL_DGREEN
    mov  brushTbl[12], eax
    invoke CreateSolidBrush, COL_BARBG
    mov  brushTbl[16], eax
    invoke CreateSolidBrush, COL_BG
    mov  brushMain, eax
    invoke CreateSolidBrush, COL_CARD
    mov  brushCard, eax
    invoke CreateSolidBrush, COL_BANNER
    mov  brushBanner, eax
    invoke CreateSolidBrush, COL_ACCENT
    mov  brushAccent, eax
    invoke CreateSolidBrush, COL_ACCENT_DN
    mov  brushAccentDn, eax
    invoke CreateSolidBrush, COL_SLATE
    mov  brushSlate, eax
    invoke CreateSolidBrush, COL_SLATE_DN
    mov  brushSlateDn, eax

    ; ---- window class ----
    mov  wc.cbSize, SIZEOF WNDCLASSEX_
    mov  wc.style, CS_HREDRAW or CS_VREDRAW
    mov  wc.lpfnWndProc, OFFSET WndProc
    mov  wc.cbClsExtra, 0
    mov  wc.cbWndExtra, 0
    mov  eax, hInstance
    mov  wc.hInstance, eax
    invoke LoadIconA, 0, IDI_APPLICATION
    mov  wc.hIcon, eax
    mov  wc.hIconSm, eax
    invoke LoadCursorA, 0, IDC_ARROW
    mov  wc.hCursor, eax
    mov  eax, brushMain
    mov  wc.hbrBackground, eax
    mov  wc.lpszMenuName, 0
    mov  wc.lpszClassName, OFFSET className
    invoke RegisterClassExA, ADDR wc

    ; ---- outer size from desired client size, centred on screen ----
    mov  wr.wLeft, 0
    mov  wr.wTop, 0
    mov  wr.wRight, CLIENT_W
    mov  wr.wBottom, CLIENT_H
    invoke AdjustWindowRect, ADDR wr, STYLE_MAIN, FALSE
    mov  eax, wr.wRight
    sub  eax, wr.wLeft
    mov  winW, eax
    mov  eax, wr.wBottom
    sub  eax, wr.wTop
    mov  winH, eax
    invoke GetSystemMetrics, 0
    sub  eax, winW
    jns  PosXok
    xor  eax, eax
PosXok:
    shr  eax, 1
    mov  posX, eax
    invoke GetSystemMetrics, 1
    sub  eax, winH
    jns  PosYok
    xor  eax, eax
PosYok:
    shr  eax, 1
    mov  posY, eax

    invoke CreateWindowExA, 0, ADDR className, ADDR windowTitle, STYLE_MAIN, \
           posX, posY, winW, winH, 0, 0, hInstance, 0
    mov  hwndMain, eax
    invoke ShowWindow, hwndMain, SW_SHOWNORMAL
    invoke UpdateWindow, hwndMain

MsgLoop:
    invoke GetMessageA, ADDR msg, 0, 0, 0
    cmp  eax, 0
    je   MsgDone

    cmp  msg.message, WM_KEYDOWN
    jne  MsgNormal
    mov  eax, msg.wParam
    cmp  curScreen, SCR_MENU
    jne  KeyModule

    ; ---- main menu: keys 1-4 (also the numpad) choose an option ----
    cmp  eax, '1'
    jb   KeyNumpad
    cmp  eax, '4'
    ja   KeyNumpad
    sub  eax, '0'
    jmp  KeyMenuGo
KeyNumpad:
    cmp  eax, 61h
    jb   MsgNormal
    cmp  eax, 64h
    ja   MsgNormal
    sub  eax, 60h
KeyMenuGo:
    invoke MenuChoice, eax
    jmp  MsgLoop

KeyModule:
    cmp  eax, VK_ESCAPE             ; Esc = back to the main menu
    jne  KeyEnter
    invoke SwitchScreen, SCR_MENU
    jmp  MsgLoop

KeyEnter:                           ; Enter key shortcuts
    cmp  eax, VK_RETURN
    jne  MsgNormal
    mov  eax, msg.hwnd
    cmp  eax, hPwChk
    je   MsgEnterChk
    cmp  eax, hUser
    je   MsgEnterUser
    cmp  eax, hPass
    jne  MsgNormal
    call DoLogin                    ; Enter in the password box = Login
    jmp  MsgLoop
MsgEnterChk:
    call DoCheckLog                 ; Enter in the strength box = Check & Log
    jmp  MsgLoop
MsgEnterUser:
    invoke SetFocus, hPass          ; Enter in the username box = go to password
    jmp  MsgLoop

MsgNormal:
    invoke TranslateMessage, ADDR msg
    invoke DispatchMessageA, ADDR msg
    jmp  MsgLoop
MsgDone:
    mov  eax, msg.wParam
    ret
WinMain ENDP

; ============================================================================
; Entry point
; ============================================================================
start:
    invoke GetModuleHandleA, NULL
    mov  hInst, eax
    call LoadCredentials            ; file handling at startup
    invoke WinMain, hInst
    invoke ExitProcess, eax
END start
