/*** asmEncrypt.s   ***/

/* Declare the following to be in data memory */
.data  

/* create a string */
.global nameStr
.type nameStr,%gnu_unique_object
    
/*** STUDENTS: Change the next line to your name!  **/
nameStr: .asciz "Vivian Overbey"  
.align
 
/* initialize a global variable that C can access to print the nameStr */
.global nameStrPtr
.type nameStrPtr,%gnu_unique_object
nameStrPtr: .word nameStr   /* Assign the mem loc of nameStr to nameStrPtr */

/* Define the globals so that the C code can access them */
/* (in this lab we return the pointer, so strictly speaking, */
/* does not really need to be defined as global) */
/* .global cipherText */
.type cipherText,%gnu_unique_object

.align
 
/* NOTE: THIS .equ MUST MATCH THE #DEFINE IN main.c !!!!!
 * TODO: create a .h file that handles both C and assembly syntax for this definition */
.equ CIPHER_TEXT_LEN, 200
 
/* space allocated for cipherText: 200 bytes, prefilled with 0x2A */
cipherText: .space CIPHER_TEXT_LEN,0x2A  

.align
 
.global cipherTextPtr
.type cipherTextPtr,%gnu_unique_object
cipherTextPtr: .word cipherText

/* Tell the assembler that what follows is in instruction memory     */
.text
.align

/* Tell the assembler to allow both 16b and 32b extended Thumb instructions */
.syntax unified


 /*
 INPUTS: 
    r0 - byte of data that represents the ascii character
    r2 - key value
 OUTPUT:
    r0 - transposed character
 */
encryptAscii:
    push {r4-r11,LR}
    
    /* Step 1 - Check if in alphabet, and get offset */
    SUBS r11, r0, 0x41 /* will be 0 if character is 'A' */
    BMI asciiEncryptComplete /* non-letter, no change */
    SUBS r11, r11, 0x1A /* check if it is an uppercase letter */
    MOV r10, 0x41 /* character is in range to be uppercase, 0 becomes 'A' */
    SUBS r11, r0, 0x61 /* will be 0 if character is 'a' */
    BMI asciiEncryptComplete /* character is in the gap between upper and lowercase characters */
    SUBS r11, r11, 0x1A /* check if it is a lowercase letter */
    MOV r10, 0x61 /* character is in range to be lowercase, 0 becomes 'a' */
    B asciiEncryptComplete /* character is too high of a value to be a alphabetical character */
    
    /* Step 2 - Apply the offset */
    SUB r0, r0, r10 /* moves to 0-25 space */
    ADD r0, r0, r2 /* adds key */  
    
    /* Modulo behavior (wrap around) */
    CMP r0, 26 /* if our value is 0 or positive (PL) after having 26 subtracted, it is out of range */
    BMI shiftBack /* in range, can be shifted back */
    loopSubtract: /* out of range, subtract 26 until it is in range */
    SUBS r0, 26 /* subtract, update flags */
    ADDMI r0, 26 /* subtraction brought out or range, previous value was valid, bring back into range (maintain flags) */
    BMI shiftBack /* it is in range, shift back */
    B loopSubtract /* still out of range, subtract again */

    shiftBack:
    ADD r0, r10 /* shifts back to lowercase or uppercase range*/
    
    asciiEncryptComplete:
    pop {r4-r11,LR}
    MOV PC, LR
    
 /*
 INPUTS: 
    r0 - first byte of data for the multi-byte character
    r1 - address of the first data byte
    r2 - key value
 OUTPUT:
    r0 - hword of "#2", "#3", etc.
    r1 - address of next character
 */
encryptUTF8:
    push {r4-r11,LR}
    
    
    
    pop {r4-r11,LR}
    MOV PC, LR
 
 
/********************************************************************
function name: asmEncrypt
function description:
     pointerToCipherText = asmEncrypt ( ptrToInputText , key )
     
where:
     input:
     ptrToInputText: location of first character in null-terminated
                     input string. Per calling convention, passed in via r0.
     key:            shift value (K). Range 0-25. Passed in via r1.
     
     output:
     pointerToCipherText: mem location (address) of first character of
                          encrypted text. Returned in r0
     
     function description: asmEncrypt reads each character of an input
                           string, uses a shifted alphabet to encrypt it,
                           and stores the new character value in memory
                           location beginning at "cipherText". After copying
                           a character to cipherText, a pointer is incremented 
                           so that the next letter is stored in the bext byte.
                           Only encrypt characters in the range [a-zA-Z].
                           Any other characters should just be copied as-is
                           without modifications
                           Stop processing the input string when a NULL (0)
                           byte is reached. Make sure to add the NULL at the
                           end of the cipherText string.
     
     notes:
        The return value will always be the mem location defined by
        the label "cipherText".
     
     
********************************************************************/    
.global asmEncrypt
.type asmEncrypt,%function
asmEncrypt:   
    push {r4-r11,LR}
    
    /* Loop until the null terminator is hit */
    MOV r11, 0 /* pointer that is used as index */
    MOV r10, r0 /* perserve the initial state of the pointer */
    MOV r9, r1 /* perserve the key */
    LDR r8, =cipherTextPtr /* get start of output array address from data label */
    loop:
	LDRB r0, [r10, r11] /* get the current character of the string, then increment address by 1 byte */
	MOVS r0, r0 /* Get the flags of the character, can check if it is the null terminator or ascii from these */
	BEQ encryptComplete /* the null terminator was detected, so encryption is complete */
	BPL asciiHit
	BMI UTF8Hit /* the continuation bytes must also be acounted for in here */
    
    asciiHit: /* an ascii character was hit */
    MOV r2, r9 /* move the key to r2 */
    BL encryptAscii /* r0 set earlier in loop, get the encrypted ascii character */
    STRB r0, [r8, r11] /* output array offset by the movement across the input array, writes in sequence */
    
    /*ADD r11, r11, 1*/
    B loop
    
    UTF8Hit: /* a UTF* character was hit */
    
    B loop
	
    encryptComplete: 
    STRB r0, [r8, r11] /* stores null terminator in output array */
    
    LDR r0, =cipherTextPtr
    pop {r4-r11,LR}
    BX LR
   

/**********************************************************************/   
.end  /* The assembler will not process anything after this directive!!! */
           




