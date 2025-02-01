Vulnerability 1: The PoC `src/id:000031,sig:11,src:000001,op:flip2,pos:13` triggers **Buffer Overflow** in the program given. In order to analysis the location of vulnerable code, I decided to use AddressSanitizer to work with. The following steps is to setup AddressSanitizer:
<Describe how do you setup AddressSanitizer>
According to the information provided by AddressSanitizer which shown in the following figure <attach the figure>, its appear to be the PoC trigger **stack buffer overflow** in the function <function name> at app.c:187. The variables <variable_name> defined at app.c:18 refer to the size of the buffer <variable_name> defined at app.c:19. However, its seem to the program didn't validate the size properly, which allows variables <variable_name> to be larger than the size of the buffer, and results buffer overflow in buffer <variable_name> in the for loop.

Vulnerability 2: The PoC `src/id:000071,sig:11,src:000058,op:flip2,pos:12` triggers **Format String Vulnerability** in the program given. 
<explain how you analysis>
<explain the result of analysis>

Vulnerability 1: The PoC `src/id:000029,src:000000,op:havoc,rep:2` triggers **Infinite Loops (Hangs)** in the program given. 
<explain how you analysis>
<explain the result of analysis>