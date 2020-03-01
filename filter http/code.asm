.CODE

GetRax PROC
	mov rcx,qword ptr [rcx+18h]         
	cmp dword ptr [rcx+4h],1            
	ja lable               
	mov eax,dword ptr [rcx]            
	add rax,rcx                           
	ret 
	lable:
	mov rdx,qword ptr [rcx+20h]         
	test rdx,rdx                          
	lea rax,qword ptr [rcx+rdx+20h]     
	cmove rax,rdx                         
	ret                                   
GetRax ENDP

END