#include "request.h"
void confirm(int new_fd,struct AUTH_CLIENT NEW_AUTH){
	NEW_AUTH.time_data++;
	if (send(new_fd, (int *)&NEW_AUTH.time_data,4 , 0) == -1)
		                        perror("send");


}
