.code

disable_tf proc
	pushfq
	and qword ptr[rsp], 0fffffeffh
	popfq
	ret
disable_tf endp

end