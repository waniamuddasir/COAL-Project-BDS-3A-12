
INCLUDE Irvine32.inc

.data

; =====================================
; MENU
; =====================================

menuMsg BYTE 0Dh,0Ah,"===== CYBERSHIELD =====",0Dh,0Ah
        BYTE "1. Check Password Strength",0Dh,0Ah
        BYTE "2. Login",0Dh,0Ah
        BYTE "3. Exit",0Dh,0Ah
        BYTE "Enter choice: ",0

; =====================================
; MESSAGES
; =====================================

passwordMsg BYTE "Enter password: ",0
usernameMsg BYTE "Enter username: ",0

strongMsg BYTE "Password Strength: STRONG",0
veryStrongMsg BYTE "Password Strength: VERY STRONG",0
mediumMsg BYTE "Password Strength: MEDIUM",0
weakMsg BYTE "Password Strength: WEAK",0

loginSuccess BYTE "Login Successful!",0
loginFailed BYTE "Invalid username or password!",0
lockedMsg BYTE "Account locked! Maximum attempts reached.",0

remainingMsg BYTE "Attempts remaining: ",0
exitMsg BYTE "Thank you for using CyberShield!",0
invalidMsg BYTE "Invalid choice!",0

; =====================================
; DEMO LOGIN CREDENTIALS
; =====================================

correctUser BYTE "admin",0
correctPass BYTE "Cyber@123",0

; =====================================
; INPUT VARIABLES
; =====================================

userInput BYTE 32 DUP(0)
passInput BYTE 32 DUP(0)

choice DWORD ?
attempts DWORD 0
passLength DWORD ?

; =====================================
; PASSWORD CHECKING FLAGS
; =====================================

upperFlag BYTE 0
lowerFlag BYTE 0
digitFlag BYTE 0
specialFlag BYTE 0

.code

; =====================================
; MAIN PROCEDURE
; =====================================

main PROC

Menu:

    mov edx, OFFSET menuMsg
    call WriteString

    call ReadInt
    mov choice, eax

    cmp choice, 1
    je CheckPassword

    cmp choice, 2
    je Login

    cmp choice, 3
    je ExitProgram

    mov edx, OFFSET invalidMsg
    call WriteString
    call Crlf

    jmp Menu


; =====================================
; PASSWORD STRENGTH CHECKER
; =====================================

CheckPassword:

    mov edx, OFFSET passwordMsg
    call WriteString

    mov edx, OFFSET passInput
    mov ecx, SIZEOF passInput - 1
    call ReadString

    mov passLength, eax

    mov upperFlag, 0
    mov lowerFlag, 0
    mov digitFlag, 0
    mov specialFlag, 0

    mov esi, OFFSET passInput
    mov ecx, passLength

CheckLoop:

    cmp ecx, 0
    je CheckResult

    mov al, [esi]

    ; Check uppercase letters

    cmp al, 'A'
    jb CheckLower

    cmp al, 'Z'
    ja CheckLower

    mov upperFlag, 1
    jmp NextChar

CheckLower:

    ; Check lowercase letters

    cmp al, 'a'
    jb CheckDigit

    cmp al, 'z'
    ja CheckDigit

    mov lowerFlag, 1
    jmp NextChar

CheckDigit:

    ; Check digits

    cmp al, '0'
    jb CheckSpecial

    cmp al, '9'
    ja CheckSpecial

    mov digitFlag, 1
    jmp NextChar

CheckSpecial:

    ; Check printable special characters
    ; Space is not counted as a special character

    cmp al, 33
    jb NextChar

    cmp al, 126
    ja NextChar

    mov specialFlag, 1

NextChar:

    inc esi
    dec ecx

    jmp CheckLoop


; =====================================
; DISPLAY PASSWORD STRENGTH
; =====================================

CheckResult:

    ; Minimum length must be 8

    cmp passLength, 8
    jb WeakPassword

    ; Check uppercase

    cmp upperFlag, 1
    jne WeakPassword

    ; Check lowercase

    cmp lowerFlag, 1
    jne WeakPassword

    ; Check digit

    cmp digitFlag, 1
    jne WeakPassword

    ; Check special character

    cmp specialFlag, 1
    jne MediumPassword

    ; Check 12 character bonus

    cmp passLength, 12
    jae VeryStrongPassword

    mov edx, OFFSET strongMsg
    call WriteString
    call Crlf

    jmp Menu

VeryStrongPassword:

    mov edx, OFFSET veryStrongMsg
    call WriteString
    call Crlf

    jmp Menu

MediumPassword:

    mov edx, OFFSET mediumMsg
    call WriteString
    call Crlf

    jmp Menu

WeakPassword:

    mov edx, OFFSET weakMsg
    call WriteString
    call Crlf

    jmp Menu


; =====================================
; LOGIN AUTHENTICATION
; =====================================

Login:

    mov attempts, 0

LoginAgain:

    ; Input username

    mov edx, OFFSET usernameMsg
    call WriteString

    mov edx, OFFSET userInput
    mov ecx, SIZEOF userInput - 1
    call ReadString

    ; Input password

    mov edx, OFFSET passwordMsg
    call WriteString

    mov edx, OFFSET passInput
    mov ecx, SIZEOF passInput - 1
    call ReadString

    ; Compare username

    mov edx, OFFSET userInput
    mov ebx, OFFSET correctUser

    call CompareStrings

    cmp eax, 0
    jne WrongLogin

    ; Compare password

    mov edx, OFFSET passInput
    mov ebx, OFFSET correctPass

    call CompareStrings

    cmp eax, 0
    jne WrongLogin

    ; Successful login

    mov edx, OFFSET loginSuccess
    call WriteString
    call Crlf

    jmp Menu


; =====================================
; WRONG LOGIN ATTEMPT
; =====================================

WrongLogin:

    inc attempts

    mov edx, OFFSET loginFailed
    call WriteString
    call Crlf

    mov eax, 3
    sub eax, attempts

    cmp eax, 0
    je AccountLocked

    mov edx, OFFSET remainingMsg
    call WriteString

    call WriteDec
    call Crlf

    jmp LoginAgain


; =====================================
; ACCOUNT LOCKOUT
; =====================================

AccountLocked:

    mov edx, OFFSET lockedMsg
    call WriteString
    call Crlf

    jmp ExitProgram


; =====================================
; EXIT PROGRAM
; =====================================

ExitProgram:

    mov edx, OFFSET exitMsg
    call WriteString
    call Crlf

    exit

main ENDP


; =====================================
; STRING COMPARISON PROCEDURE
; This procedure is OUTSIDE main
;
; EDX = address of first string
; EBX = address of second string
; EAX = 0 if equal, 1 if not equal
; =====================================

CompareStrings PROC USES esi edi

    mov esi, edx
    mov edi, ebx

CompareLoop:

    mov al, [esi]
    cmp al, [edi]

    jne NotEqual

    cmp al, 0
    je Equal

    inc esi
    inc edi

    jmp CompareLoop

Equal:

    mov eax, 0
    ret

NotEqual:

    mov eax, 1
    ret

CompareStrings ENDP

END main
