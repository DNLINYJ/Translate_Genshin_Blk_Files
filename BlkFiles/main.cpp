#include <iostream>
#include <filesystem>
namespace fs = std::filesystem;

#include "translate.h"

void main(int argc, char** argv) {
	if (argc == 1) {
		cout << "���������Unity3d�ļ�תΪ����Unity3d�ļ� By:����С����" << endl;
		cout << "�����������Ⱥ��������ֹ�⴫������" << endl;
		cout << endl;
		cout << "����: <method> <inpath> <outpath>" << endl;
		cout << "method : onlyfile (onlyfile���������뵥���ļ�����)" << endl;
		cout << "inpath : �����ļ�·��" << endl;
		cout << "outpath : �����ļ�·��" << endl;
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