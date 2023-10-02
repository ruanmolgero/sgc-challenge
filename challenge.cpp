#include <string>
#include <libcryptosec/MessageDigest.h>

int main(int argc, char **argv) {
	std::cout << "\033[1;31m teste \033[0m" << std::endl;
	
	MessageDigest::loadMessageDigestAlgorithms();
	
	return 0;
}
