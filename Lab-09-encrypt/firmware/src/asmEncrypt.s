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
    push {r4-r11,LR} /* preserve registers (calling convention 1) */
    
    /* Step 1 - Check if in alphabet, and get offset */
    SUBS r11, r0, 0x41 /* will be 0 if character is 'A' */
    BMI asciiEncryptComplete /* non-letter, no change */
    SUBS r11, r11, 0x1A /* check if it is an uppercase letter */
    MOVMI r10, 0x41 /* character is in range to be uppercase, 0 becomes 'A' */
    BMI offset /* character in range to be uppercase, move to offset application code */
    SUBS r11, r0, 0x61 /* will be 0 if character is 'a' */
    BMI asciiEncryptComplete /* character is in the gap between upper and lowercase characters */
    SUBS r11, r11, 0x1A /* check if it is a lowercase letter */
    MOVMI r10, 0x61 /* character is in range to be lowercase, 0 becomes 'a' */
    BMI offset  /* character in range to be lowercase, move to offset application code */
    B asciiEncryptComplete /* character is too high of a value to be an alphabetical character */
    /* Step 2 - Apply the offset */
    offset:
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
    pop {r4-r11,LR} /* restore the caller's registers (calling convention 2) */
    MOV PC, LR /* return to caller (calling convention 3) */
    
 /*
 INPUTS: 
    r0 - first byte of data for the multi-byte character
 OUTPUT:
    r0 - hword of "#2", "#3", etc.
    r1 - byte count of the multibyte char
 */
encryptUTF8:
    push {r4-r11,LR} /* preserve registers (calling convention 1) */
    
    LSR r0, r0, 4 /* reduces loops needed to minimal ammount by shifting the relevant bits into the bottom of the register */
    MOV r1, -1 /* initializes the tally to -1. -1 allows for appropiate input reading pointer adjustment from return with less instructions */
    multibyteCountLoop:
	ADDS r0, 0 /* clears carry flag to prevent moving the carry flag into the top of the register */
	RRXS r0, r0 /* move LSB into carry flag */
	ADDCS r1, 1 /* add 1 to the byte count */
	MOVCC r1, -1 /* accounts for edgecase where UTF-8 char has 2 bytes, with first byte: 1101xxxx. resets count if 0 is hit */
	BNE multibyteCountLoop /* when the register is all clear, the tally is finished, in the case that the register is empty, fall through */
    ADD r0, r1, 0x31 /* gets the byte number by geting the code for 1, and adding the tally to it */
    LDR r3, =0x23 /* hashtag code */
    ADD r0, r3, r0, LSL 8 /* combines the ascii codes for the number and the hashtag sequentially */

    pop {r4-r11,LR} /* restore the caller's registers (calling convention 2) */
    MOV PC, LR /* return to caller (calling convention 3) */
 
 
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
    push {r4-r11,LR} /* preserve registers (calling convention 1) */
    
    /* Loop until the null terminator is hit */
    LDR r7, =cipherTextPtr /* get address of label that holds pointer (another address) to the start of the array */
    LDR r7, [r7] /* get the actual start of the array */
    MOV r11, r0 /* address for reading from input (acts like index) */
    MOV r10, r7 /* offset for writing to output (acts like index) */
    MOV r9, r0 /* perserve the initial state of the pointer */
    MOV r8, r1 /* perserve the key */
    loop:
	LDRB r0, [r11], 1 /* get the current character of the string, then increment address by 1 byte */
	/* Determine if floating continuation byte */
	LSR r6, r0, 6 /* check if top two bits == "10" (value 2), get top 2 */
	TEQ r6, 2 /* see if equal to value of top of continuation byte */
	MOVEQ r0, 0x2A /* if floating continuation byte, replace with specified character ('*') */
	BEQ asciiHit /* branch to code where r0 is written as an ascii character */
	/* Determine if character is ascii, or start of a UTF-8 character */
	MOVS r6, r0, LSL 24 /* Get the flags of the character, can check if it is the null terminator or ascii from these */
	BEQ encryptComplete /* the null terminator was detected, so encryption is complete (null terminator = 0x0) */	
	BPL asciiHit /* if the value shifted into the MSB is positive, it is ascii (byte < 128) */
	BMI UTF8Hit /* (byte >= 128, so is negative, UTF-8) the continuation bytes must also be acounted for in here */
	asciiHit: /* an ascii character was hit */
	    MOV r2, r8 /* move the key to r2 */
	    BL encryptAscii /* r0 set earlier in loop, get the encrypted ascii character */
	    STRB r0, [r10], 1 /* output array offset by the movement across the input array, writes in sequence */
	    B loop /* character has been parsed and shifted, process next */
	UTF8Hit: /* a UTF-8 character was hit */
	    BL encryptUTF8 /* get the encrypted UTF-8 character, r0 set earlier in loop */
	    STRH r0, [r10], 2 /* character is converted to "#2", "#3", or #4", these are all 2 characters, thus a half word is returned and stored */
	    ADD r11, r1 /* additional offset needed for reading the next character in the input char array */
	    B loop /* character has been parsed and shifted, process next */	
	encryptComplete: 
	    STRB r0, [r10] /* stores null terminator in output array */
    MOV r0, r7 /* pointer return for ciphered string */
    
    pop {r4-r11,LR} /* restore the caller's registers (calling convention 2) */
    BX LR /* return to caller (calling convention 3) */
   

/**********************************************************************/   
.end  /* The assembler will not process anything after this directive!!! */
           