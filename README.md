# WoW RDP Patcher

This small tool patches old WoW executables to make them runnable while on Remote Desktop (RDP). It disables the error message displayed when you launch it in an RDP session.

Just drop the executable on this `exe` to patch it. Always backup your original `exe` file! :wrench:

Working versions:

- 3.3.5a 12340
- 2.4.3 8606

**Might work with other versions** 😎

## Disclaimer

This software is intended for educational purposes only! :books:

## How does it work

1. The program searches your executable for the displayed error string.
2. Then it looks for the `PUSH` instruction that loads the string onto the stack.
3. Replaces everything with `NOP`s.
4. Profit... :moneybag:

3.3.5a 12340 address (rebased): **0x76BA39**

Assembly of the RDP check:
```c
...
CALL    GetRdpStatus
TEST    EAX, EAX
JZ      LAB_0076ba51
// This will be replaced by NOP instructions
PUSH    0xE34652 // the instruction we search for
MOV     EAX, 0xc
CALL    ShowErrorMessageAndExit
// -----------------------------------------
LAB_0076ba51:
...
```

C code of the RDP check:
```c
// just a wrapper for GetSystemMetrics(0x1000);
// 0x1000 checks for remote desktop
int status = GetRdpStatus();

if (status != 0) 
{
    // this thing will be NOPed out
    ShowErrorMessageAndExit("...");
}
```