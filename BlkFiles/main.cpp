#include <iostream>
#include <filesystem>
namespace fs = std::filesystem;

#include "translate.h"

void main(int argc, char** argv) {
	if (argc == 1) {
		cout << "将星穹铁道Unity3d文件转为正常Unity3d文件 By:菠萝小西瓜" << endl;
		cout << "本程序仅在内群传播，禁止外传！！！" << endl;
		cout << endl;
		cout << "参数: <method> <inpath> <outpath>" << endl;
		cout << "method : onlyfile (onlyfile仅允许输入单个文件解密)" << endl;
		cout << "inpath : 加密文件路径" << endl;
		cout << "outpath : 解密文件路径" << endl;
	}
	else {
		string args[4];
		for (int i = 0; i < argc; i++) {
			args[i] = argv[i];
		}
		if (args[1] == "onlyfile") {
			tranlate_to_normal_unity3d_file(args[2], args[3]);
		}
	}
}