
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;
  char *clonedev = "/dev/net/tun";

  /* Arguments taken by the function:
   *
   * char *dev: the name of an interface (or '\0'). MUST have enough
   *   space to hold the interface name if '\0' is passed
   * int flags: interface flags (eg, IFF_TUN etc.)
   */

   /* open the clone device */
   if( (fd = open(clonedev, O_RDWR)) < 0 ) {
     return fd;
   }

   /* preparation of the struct ifr, of type "struct ifreq" */
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = flags;   /* IFF_TUN or IFF_TAP, plus maybe IFF_NO_PI */

   if (*dev) {
     /* if a device name was specified, put it in the structure; otherwise,
      * the kernel will try to allocate the "next" device of the
      * specified type */
     strncpy(ifr.ifr_name, dev, IFNAMSIZ);
   }

   /* try to create the device */
   if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
     close(fd);
     return err;
   }

  /* if the operation was successful, write back the name of the
   * interface to the variable "dev", so the caller can know
   * it. Note that the caller MUST reserve space in *dev (see calling
   * code below) */
  strcpy(dev, ifr.ifr_name);

  /* this is the special file descriptor that the caller will use to talk
   * with the virtual interface */
  return fd;
}


int tun_read(int tun_fd)
{

	int nread;
	char buffer[2048];
	if(tun_fd < 0){
		perror("Allocating interface");
		exit(1);
	}

	/* Now read data coming from the kernel */
	while(1) {
		/* Note that "buffer" should be at least the MTU size of the interface, eg 1500 bytes */
		nread = read(tun_fd,buffer,sizeof(buffer));
		if(nread < 0) {
			perror("Reading from interface");
			close(tun_fd);
			exit(1);
		}

		/* Do whatever with the data */
		printf("Read %d bytes from device \n", nread);
	}
}

int main(int argc, char ** argv)
{
	
	char dev[IFNAMSIZ] = {0};
//	int ret = tun_alloc(dev,IFF_TAP );

	int tun_fd = -1;

	if((argc == 2) && (strlen(argv[1]) <= IFNAMSIZ) ){
		strcpy(dev,argv[1]);
	}else{
		printf("argument error\n");
		return 1;
	}

	tun_fd = tun_alloc(dev,IFF_TUN | IFF_NO_PI);



	printf("%s fd = %d namesize = %d\n", dev, tun_fd,IFNAMSIZ);


	tun_read(tun_fd);
	sleep(100);
}
