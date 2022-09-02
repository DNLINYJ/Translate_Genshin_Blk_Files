#include <iostream>
#include <Windows.h>
#include <fstream>
#include <algorithm>
#include <sstream>
#include <string>
using namespace std;

#include "magic_constants.h"
#include "lz4.h"
#include "blk.h"
#include <vector>
#include "util.h"

#define MAKE_UINT32(a, b1, b2, b3, b4) (uint8_t)a[b1] | ((uint8_t)a[b2] << 8) | ((uint8_t)a[b3] << 16) | ((uint8_t)a[b4] << 24)

void mhy0_extract(string outpath, int block_index, uint8_t* data);

// From : https://stackoverflow.com/questions/21819782/writing-hex-to-a-file
std::string translate_hex_to_write_to_file(std::string hex) {
    std::basic_string<uint8_t> bytes;

    // Iterate over every pair of hex values in the input string (e.g. "18", "0f", ...)
    for (size_t i = 0; i < hex.length(); i += 2)
    {
        uint16_t byte;

        // Get current pair and store in nextbyte
        std::string nextbyte = hex.substr(i, 2);

        // Put the pair into an istringstream and stream it through std::hex for
        // conversion into an integer value.
        // This will calculate the byte value of your string-represented hex value.
        std::istringstream(nextbyte) >> std::hex >> byte;

        // As the stream above does not work with uint8 directly,
        // we have to cast it now.
        // As every pair can have a maximum value of "ff",
        // which is "11111111" (8 bits), we will not lose any information during this cast.
        // This line adds the current byte value to our final byte "array".
        bytes.push_back(static_cast<uint8_t>(byte));
    }

    // we are now generating a string obj from our bytes-"array"
    // this string object contains the non-human-readable binary byte values
    // therefore, simply reading it would yield a String like ".0n..:j..}p...?*8...3..x"
    // however, this is very useful to output it directly into a binary file like shown below
    std::string result(begin(bytes), end(bytes));

    return result;
}

struct StorageBlock {
    unsigned __int32 compressedSize = 0;
    unsigned __int32 uncompressedSize = 0;
    unsigned __int16 flags = 0x43;
};

struct Node
{
    unsigned __int64 offset = 0;
    unsigned __int64 size = 0;
    unsigned __int16 flags = 0;
    string path;
};

unsigned int ReadMhy0Int1(uint8_t* header)
{
    uint8_t* buffer = new uint8_t[7];
    memcpy(buffer, header, 7);
    return buffer[1] | (buffer[6] << 8) | (buffer[3] << 0x10) | (buffer[2] << 0x18);
}

unsigned int ReadMhy0Int2(uint8_t* header)
{
    uint8_t* buffer = new uint8_t[6];
    memcpy(buffer, header, 6);
    return buffer[2] | (buffer[4] << 8) | (buffer[0] << 0x10) | (buffer[5] << 0x18);
}

bool ReadMhy0Bool(uint8_t* header) {
    uint8_t* buffer = new uint8_t[6];
    memcpy(buffer, header, 6);
    if (buffer[5] << 0x18) {
        return true;
    }
    else {
        return false;
    }
}

string ReadStringToNull(fstream& bytes) {
    //std::byte* m = bytes;
    unsigned int start_ptr = bytes.tellg();
    char* v3 = new char;
    int path_size = 0;
    for (int a = 0;; a++) {
        bytes.read(v3, 1);
        if ((int)*v3 == 0) {
            path_size++;
            break;
        }
        path_size++;
    }
    char* path_v1 = new char[path_size];
    bytes.clear();
    bytes.seekg(start_ptr);
    bytes.read(path_v1, path_size);
    string path = path_v1;
    return path;
}

int tranlate_to_normal_unity3d_file(string inpath, string outpath) {
    fstream mhy_blk_file;
    mhy_blk_file.open(inpath, ios::in | ios::binary);

    blk_header hdr;
    mhy_blk_file.read(reinterpret_cast<char*>(&hdr), sizeof(blk_header));

    key_scramble1(hdr.key1);
    key_scramble2(hdr.key1);

    uint8_t hard_key[] = { 0xE3, 0xFC, 0x2D, 0x26, 0x9C, 0xC5, 0xA2, 0xEC, 0xD3, 0xF8, 0xC6, 0xD3, 0x77, 0xC2, 0x49, 0xB9 };
    for (int i = 0; i < 16; i++)
        hdr.key1[i] ^= hard_key[i];

    mhy_blk_file.seekg(0, mhy_blk_file.end);
    // fseek(mhy_blk_file, 0, SEEK_END);

    size_t size = (size_t)mhy_blk_file.tellg() - sizeof(blk_header);

    mhy_blk_file.seekg(sizeof(blk_header), ios::beg);

    auto* data = new uint8_t[size];
    mhy_blk_file.read(reinterpret_cast<char*>(data), size);
    //fread(data, size, 1, blk_file);
    mhy_blk_file.close();
    //fclose(blk_file);

    uint8_t xorpad[4096] = {};
    create_decrypt_vector(hdr.key1, data, (std::min)((uint64_t)hdr.block_size, sizeof(xorpad)), xorpad, sizeof(xorpad));
    for (int i = 0; i < size; i++)
        data[i] ^= xorpad[i & 0xFFF];

    std::vector<size_t> mhy0_locs;
    size_t last_loc = 0;
    for (int i = 0; ; i++) {
        std::string num = to_string(i);
        auto res = memmem(data + last_loc, size - last_loc, (void*)"mhy0", 4);
        if (res) {
            auto loc = (uint8_t*)res - data;
            mhy0_locs.push_back(loc);
            //cout << "found mhy0 at 0x" << hex << loc << endl;
            mhy0_extract(outpath + "_" + num + ".bin", i, data + loc);
            last_loc = loc + 4;
        }
        else {
            break;
        }
    }

    delete[] data;

    return 0;
}

void mhy0_extract(string outpath, int block_index, uint8_t* input) {

    outpath = outpath + ".unity3d";

    cout << "[Debug] 输出解密文件目录:" << outpath << endl;

    // ReadHeader
    uint32_t size = *(uint32_t*)(input + 4);

    auto* data = new uint8_t[size];
    memcpy(data, input + 8, size);
    input += 8 + size;

    //data += m_Header.Size;
    //mhy_unity3d_file.read(reinterpret_cast<char*>(header), m_Header.Size);
    mhy0_header_scramble(data, 0x39, data + 4, 0x1C);

    uint32_t uncompressedHeaderSize = MAKE_UINT32(data, 0x20 + 1, 0x20 + 6, 0x20 + 3, 0x20 + 2);
    uint8_t* uncompressedBlocksInfo = new uint8_t[uncompressedHeaderSize];

    auto lz4_res = LZ4_decompress_safe((const char*)(data + 0x27), (char*)uncompressedBlocksInfo, size - 0x27, uncompressedHeaderSize);
    if (lz4_res < 0) {
        cout << "[Debug] decompression failed: " << lz4_res << endl;
        exit(1);
    }
    delete[] data;

    unsigned int nodesCount = ReadMhy0Int2(uncompressedBlocksInfo);
    uncompressedBlocksInfo += 6;
    Node* m_DirectoryInfo = new Node[nodesCount];

    for (int i = 0; i < nodesCount; i++)
    {
        // ReadMhy0String()
        uint8_t* bytes = new uint8_t[0x100];
        uint8_t* bytes_set = bytes;
        char* v3 = new char;
        unsigned int path_size = 0;
        memcpy(bytes, uncompressedBlocksInfo, 0x100);
        uncompressedBlocksInfo += 0x100;
        for (int a = 0;; a++) {
            memcpy(v3, bytes, 1i64);
            if ((int)*v3 == 0) {
                path_size++;
                bytes++;
                break;
            }
            path_size++;
            bytes++;
        }
        char* path_v1 = new char[path_size];
        strcpy_s(path_v1, path_size, (const char*)bytes_set);
        m_DirectoryInfo[i].path = path_v1;

        m_DirectoryInfo[i].flags = ReadMhy0Bool(uncompressedBlocksInfo);
        uncompressedBlocksInfo += 6i64;

        m_DirectoryInfo[i].offset = ReadMhy0Int2(uncompressedBlocksInfo);
        uncompressedBlocksInfo += 6i64;

        m_DirectoryInfo[i].size = ReadMhy0Int1(uncompressedBlocksInfo);
        uncompressedBlocksInfo += 7i64;
    }

    unsigned int blocksInfoCount = MAKE_UINT32(uncompressedBlocksInfo, 2, 4, 0, 5);
    uncompressedBlocksInfo += 6;
    StorageBlock* m_BlocksInfo = new StorageBlock[blocksInfoCount];

    for (int i = 0; i < blocksInfoCount; i++) {
        m_BlocksInfo[i].compressedSize = ReadMhy0Int2(uncompressedBlocksInfo);
        uncompressedBlocksInfo += 6i64;

        m_BlocksInfo[i].uncompressedSize = ReadMhy0Int1(uncompressedBlocksInfo);
        uncompressedBlocksInfo += 7i64;
    }

    // CreateBlocksStream

    // 为了重新打包改为compressedSizeSum
    /*
    unsigned __int32 uncompressedSizeSum = 0;
    for (int i = 0; i < blocksInfoCount; i++) {
        uncompressedSizeSum += m_BlocksInfo[i].uncompressedSize;
    }

    std::byte* blocksStream = new std::byte[uncompressedSizeSum];
    */

    unsigned __int32 compressedSizeSum = 0;
    for (int i = 0; i < blocksInfoCount; i++) {
        compressedSizeSum += m_BlocksInfo[i].compressedSize;
    }

    std::byte* blocksStream = new std::byte[compressedSizeSum];
    std::byte* blocksStream_start_address = blocksStream;

    // ReadBlocks(DecryptBlocks)

    unsigned int compressedSize;
    uint8_t* compressedBytes;

    for (int i = 0; i < blocksInfoCount; i++) {
        compressedSize = m_BlocksInfo[i].compressedSize;
        compressedBytes = new uint8_t[compressedSize];
        //mhy_unity3d_file.read(reinterpret_cast<char*>(compressedBytes), compressedSize);
        memcpy(compressedBytes, input, compressedSize);
        input += compressedSize;

        mhy0_header_scramble(compressedBytes, 0x21, compressedBytes + 4, 8);
        compressedBytes += 0xC;
        compressedSize -= 0xC;
        m_BlocksInfo[i].compressedSize = compressedSize;

        memcpy(blocksStream, reinterpret_cast<char*>(compressedBytes), compressedSize);
        blocksStream += compressedSize;

        //https://stackoverflow.com/questions/61443910/what-is-causing-invalid-address-specified-to-rtlvalidateheap-01480000-014a290
        //delete[] compressedBytes;
    }

    // 重新计算解密后的compressedSizeSum
    compressedSizeSum = 0;
    for (int i = 0; i < blocksInfoCount; i++) {
        compressedSizeSum += m_BlocksInfo[i].compressedSize;
    }

    // Output Unity Standard *.unity3d Files
    string unityFS = "556e697479465300"; // UnityFS\0 (8bit)
    string ArchiveVersion = "00000006"; // 6 (4bit)
    string UnityBundleVersion = "352e782e7800"; // 5.x.x\0 (6bit)
    string ABPackVersion = "323031372e342e333066310a3200"; // 2017.4.30f1.2\0 (28bit)

    // 获取路径信息总大小
    unsigned int nodesSize = 0;
    for (int i = 0; i < nodesCount; i++)
    {
        nodesSize = nodesSize + 20 + m_DirectoryInfo[i].path.length() + 1; // +1 是天杀的\00
    }

    // 46 为 上方header的大小
    // 20 为 ABPackSize + compressedBlocksInfoSize + uncompressedBlocksInfoSize + flags
    // 20 为区块信息（16bit hash / 4bit blockCount）
    // 10 * blocksInfoCount 为 各区块信息总大小
    // nodesSize 为 路径信息总大小
    // compressedSizeSum 为 blocks 总大小
    unsigned __int64 ABPackSize = 46 + 20 + 20 + (10 * blocksInfoCount) + nodesSize + compressedSizeSum;

    fstream testoutput;
    testoutput.open(outpath, std::ios::binary | std::ios::out);

    // 写入 Unity3d文件标准头
    testoutput << translate_hex_to_write_to_file(unityFS);
    testoutput << translate_hex_to_write_to_file(ArchiveVersion);
    testoutput << translate_hex_to_write_to_file(UnityBundleVersion);
    testoutput << translate_hex_to_write_to_file(ABPackVersion);

    // 打包新的BlocksInfoBytes
    unsigned int NewBlocksInfoBytes_Size = 20 + (10 * blocksInfoCount) + 4 + nodesSize;
    std::byte* NewBlocksInfoBytes = new std::byte[NewBlocksInfoBytes_Size];
    std::byte* NewBlocksInfoBytes_Start_Address = NewBlocksInfoBytes;

    // 不复原blockHash 用00填充
    unsigned __int64 blockHash = 0;
    memcpy(NewBlocksInfoBytes, &blockHash, 8i64);
    NewBlocksInfoBytes += 8i64;
    memcpy(NewBlocksInfoBytes, &blockHash, 8i64);
    NewBlocksInfoBytes += 8i64;

    // 写入blocksInfoCount
    blocksInfoCount = _byteswap_ulong(blocksInfoCount);
    memcpy(NewBlocksInfoBytes, &blocksInfoCount, 4i64);
    NewBlocksInfoBytes += 4i64;

    // 写入blocksInfo
    for (int i = 0; i < _byteswap_ulong(blocksInfoCount); i++) {
        // 大小端转换
        m_BlocksInfo[i].uncompressedSize = _byteswap_ulong(m_BlocksInfo[i].uncompressedSize);
        memcpy(NewBlocksInfoBytes, &m_BlocksInfo[i].uncompressedSize, 4i64);
        NewBlocksInfoBytes += 4i64;

        m_BlocksInfo[i].compressedSize = _byteswap_ulong(m_BlocksInfo[i].compressedSize);
        memcpy(NewBlocksInfoBytes, &m_BlocksInfo[i].compressedSize, 4i64);
        NewBlocksInfoBytes += 4i64;

        m_BlocksInfo[i].flags = _byteswap_ushort(m_BlocksInfo[i].flags);
        memcpy(NewBlocksInfoBytes, &m_BlocksInfo[i].flags, 2i64);
        NewBlocksInfoBytes += 2i64;
    }

    // 写入nodesCount
    nodesCount = _byteswap_ulong(nodesCount);
    memcpy(NewBlocksInfoBytes, &nodesCount, 4i64);
    NewBlocksInfoBytes += 4i64;

    // 写入nodes
    for (int i = 0; i < _byteswap_ulong(nodesCount); i++)
    {
        m_DirectoryInfo[i].offset = _byteswap_uint64(m_DirectoryInfo[i].offset);
        memcpy(NewBlocksInfoBytes, &m_DirectoryInfo[i].offset, 8i64);
        NewBlocksInfoBytes += 8i64;

        m_DirectoryInfo[i].size = _byteswap_uint64(m_DirectoryInfo[i].size);
        memcpy(NewBlocksInfoBytes, &m_DirectoryInfo[i].size, 8i64);
        NewBlocksInfoBytes += 8i64;
        //m_DirectoryInfo[i].size = _byteswap_uint64(m_DirectoryInfo[i].size);

        m_DirectoryInfo[i].flags = _byteswap_ulong(m_DirectoryInfo[i].flags);
        memcpy(NewBlocksInfoBytes, &m_DirectoryInfo[i].flags, 4i64);
        NewBlocksInfoBytes += 4i64;

        char* path_v1 = new char[m_DirectoryInfo[i].path.length()];
        path_v1 = (char*)m_DirectoryInfo[i].path.c_str();
        memcpy(NewBlocksInfoBytes, path_v1, m_DirectoryInfo[i].path.length() + 1);// +1 是天杀的\00
        NewBlocksInfoBytes += m_DirectoryInfo[i].path.length() + 1;
    }

    // 将新的BlocksInfoBytes用LZ4压缩
    unsigned int max_dst_size = LZ4_compressBound(NewBlocksInfoBytes_Size);
    std::byte* NewBlocksInfoBytes_LZ4 = new std::byte[max_dst_size];
    unsigned int NewBlocksInfoBytes_compSize = LZ4_compress_default((char*)NewBlocksInfoBytes_Start_Address, (char*)NewBlocksInfoBytes_LZ4, NewBlocksInfoBytes_Size, max_dst_size);

    // 释放内存 免得内存爆炸
    delete[] NewBlocksInfoBytes_Start_Address;
    //delete[] header;
    delete[] m_DirectoryInfo;
    delete[] m_BlocksInfo;

    // 小端转大端
    ABPackSize = _byteswap_uint64(ABPackSize);
    testoutput.write((const char*)&ABPackSize, sizeof(unsigned __int64));

    NewBlocksInfoBytes_compSize = _byteswap_ulong(NewBlocksInfoBytes_compSize);
    testoutput.write((const char*)&NewBlocksInfoBytes_compSize, sizeof(unsigned int));

    NewBlocksInfoBytes_Size = _byteswap_ulong(NewBlocksInfoBytes_Size);
    testoutput.write((const char*)&NewBlocksInfoBytes_Size, sizeof(unsigned int));

    string ArchiveFlags = "00000043";// LZ4压缩flags
    testoutput << translate_hex_to_write_to_file(ArchiveFlags);

    // 写入blocksInfoBytes
    testoutput.write((const char*)NewBlocksInfoBytes_LZ4, _byteswap_ulong(NewBlocksInfoBytes_compSize));
    // 释放内存 免得内存爆炸
    delete[] NewBlocksInfoBytes_LZ4;

    // 写入blocksStream
    testoutput.write((const char*)blocksStream_start_address, compressedSizeSum);
    // 释放内存 免得内存爆炸
    delete[] blocksStream_start_address;

}