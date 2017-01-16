all: fserver gen_html

fserver: fserver.c
	gcc -O3  fserver.c -o fserver
gen_html: gen_html.c
	gcc -O3  gen_html.c -o gen_html 

clean:
	rm -f fserver *.o gen_html 



