flags = -Wall -Wextra 


include = include/*


rule: include 
	cc $(flags) -o rule.o  

clean: 
	rm -rf *.o 
