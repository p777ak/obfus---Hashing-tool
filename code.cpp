#include <filesystem>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <algorithm>
#include <cstring>
#include <cstdint>

#ifdef _WIN32
#include <windows.h>
#endif

namespace fs = std::filesystem;

// ---------------- SHA256 ----------------
struct SHA256_CTX {
    uint32_t data[16];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
};

uint32_t k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

uint32_t ROTRIGHT(uint32_t a, uint32_t b){ return (a >> b) | (a << (32-b)); }
uint32_t CH(uint32_t x, uint32_t y, uint32_t z){ return (x & y) ^ (~x & z); }
uint32_t MAJ(uint32_t x, uint32_t y, uint32_t z){ return (x & y) ^ (x & z) ^ (y & z); }
uint32_t EP0(uint32_t x){ return ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22); }
uint32_t EP1(uint32_t x){ return ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25); }
uint32_t SIG0(uint32_t x){ return ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ (x >> 3); }
uint32_t SIG1(uint32_t x){ return ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ (x >> 10); }

void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]){
    uint32_t a,b,c,d,e,f,g,h,t1,t2,m[64];
    for(int i=0;i<16;i++)
        m[i] = (data[i*4] <<24) | (data[i*4+1]<<16) | (data[i*4+2]<<8) | (data[i*4+3]);
    for(int i=16;i<64;i++)
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];

    a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
    e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];

    for(int i=0;i<64;i++){
        t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }

    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

void sha256_init(SHA256_CTX *ctx){
    ctx->datalen = 0; ctx->bitlen =0;
    ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85; ctx->state[2]=0x3c6ef372;
    ctx->state[3]=0xa54ff53a; ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c;
    ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len){
    for(size_t i=0;i<len;i++){
        ((uint8_t*)ctx->data)[ctx->datalen] = data[i];
        ctx->datalen++;
        if(ctx->datalen==64){
            sha256_transform(ctx,(uint8_t*)ctx->data);
            ctx->bitlen +=512;
            ctx->datalen=0;
        }
    }
}

void sha256_final(SHA256_CTX *ctx, uint8_t hash[]){
    uint32_t i = ctx->datalen;
    ((uint8_t*)ctx->data)[i++] = 0x80;
    if(i>56){
        while(i<64) ((uint8_t*)ctx->data)[i++] =0x00;
        sha256_transform(ctx,(uint8_t*)ctx->data);
        i=0;
    }
    while(i<56) ((uint8_t*)ctx->data)[i++] =0x00;
    ctx->bitlen += ctx->datalen*8;
    for(int j=0;j<8;j++)
        ((uint8_t*)ctx->data)[63-j]=(ctx->bitlen>>(8*j))&0xff;
    sha256_transform(ctx,(uint8_t*)ctx->data);
    for(int i=0;i<8;i++){
        hash[i*4]   = (ctx->state[i]>>24)&0xff;
        hash[i*4+1] = (ctx->state[i]>>16)&0xff;
        hash[i*4+2] = (ctx->state[i]>>8)&0xff;
        hash[i*4+3] = (ctx->state[i])&0xff;
    }
}

// ---------------- Banner ----------------
void banner(){
    std::cout << 
    "         d8b         ,d8888b                 \n"
    "         ?88         88P'                    \n"
    "          88b     d888888P                   \n"
    " d8888b   888888b   ?88'    ?88   d8P .d888b,\n"
    "d8P' ?88  88P `?8b  88P     d88   88  ?8b,   \n"
    "88b  d88 d88,  d88 d88      ?8(  d88    `?8b \n"
    "`?8888P'd88'`?88P'd88'      `?88P'?8b`?888P' \n";
}

// ---------------- File/Folder Hash ----------------
std::string sha256_file(const fs::path& p){
    std::ifstream in(p,std::ios::binary);
    if(!in){ std::cerr<<"Cannot open file: "<<p<<"\n"; return ""; }

    SHA256_CTX ctx;
    sha256_init(&ctx);

    const size_t bufferSize = 64*1024*1024; // 64 MB
    std::vector<uint8_t> buffer(bufferSize);

    while(in){
        in.read((char*)buffer.data(), bufferSize);
        std::streamsize bytesRead = in.gcount();
        if(bytesRead>0) sha256_update(&ctx, buffer.data(), bytesRead);
    }

    uint8_t hash[32];
    sha256_final(&ctx,hash);

    std::stringstream ss;
    for(int i=0;i<32;i++) ss<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)hash[i];

    std::cout<<"Hashing file: "<<p<<"\n";
    return ss.str();
}

std::string sha256_folder(const fs::path& d){
    std::vector<fs::path> files;
    for(auto& p: fs::recursive_directory_iterator(d))
        if(p.is_regular_file()) files.push_back(p.path());
    std::sort(files.begin(),files.end());

    SHA256_CTX ctx;
    sha256_init(&ctx);

    const size_t bufferSize = 64*1024*1024; // 64 MB
    std::vector<uint8_t> buffer(bufferSize);

    std::cout<<"Hashing folder: "<<d<<"\n";
    for(auto& f: files){
        std::ifstream in(f,std::ios::binary);
        if(!in){ std::cerr<<"Cannot open: "<<f<<"\n"; continue; }

        while(in){
            in.read((char*)buffer.data(), bufferSize);
            std::streamsize bytesRead = in.gcount();
            if(bytesRead>0) sha256_update(&ctx, buffer.data(), bytesRead);
        }

        std::cout<<"Hashing file: "<<f<<"\n";
    }

    uint8_t hash[32];
    sha256_final(&ctx,hash);

    std::stringstream ss;
    for(int i=0;i<32;i++) ss<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)hash[i];
    return ss.str();
}

// ---------------- Single Mode (file by file) ----------------
void sha256_single_mode(const fs::path& root){
    std::vector<fs::path> files;
    std::vector<fs::path> dirs;

    for(auto& p : fs::recursive_directory_iterator(root)){
        if(p.is_regular_file())
            files.push_back(p.path());
        else if(p.is_directory())
            dirs.push_back(p.path());
    }

    for(auto& f : files){
        std::string hash = sha256_file(f);
        std::ofstream out(f.string(), std::ios::trunc);
        if(out.is_open()){
            out << hash;
            out.close();
            fs::path newPath = f;
            newPath += ".obfus"; 
            fs::rename(f, newPath);
            std::cout << "Hashed and renamed file: " << newPath << "\n";
        } else {
            std::cerr << "Cannot write to file: " << f << "\n";
        }
    }

    
    std::sort(dirs.begin(), dirs.end(),
        [](const fs::path& a, const fs::path& b){
            return std::distance(a.begin(), a.end()) > std::distance(b.begin(), b.end());
        });

    for(auto& d : dirs){
        fs::path newPath = d.parent_path() / "obfus";
        if(!fs::exists(newPath)){
            fs::rename(d, newPath);
            std::cout << "Renamed folder: " << d << " -> " << newPath << "\n";
        } else {
            fs::remove_all(d);
            std::cout << "Removed folder (conflict): " << d << "\n";
        }
    }

 
    fs::path rootNew = root.parent_path() / "obfus";
    if(!fs::exists(rootNew)){
        fs::rename(root, rootNew);
        std::cout << "Renamed root folder: " << root << " -> " << rootNew << "\n";
    } else {
        std::cerr << "Cannot rename root folder, 'obfus' already exists.\n";
    }
}



// ---------------- Main ----------------
int main(){
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

    while(true){
        banner();
        std::cout<<"\n=============================================\n";
        std::cout<<"https://github.com/p777ak\n\n";
        std::cout<<"1) Hash-in-one\n2) Hash\n3) Exit\n> ";
        int choice; std::cin>>choice; std::cin.ignore();
        if(choice==3) break;

        std::string pathStr;
        std::cout<<"Path: ";
        std::getline(std::cin,pathStr);

        fs::path path(pathStr);
        if(!fs::exists(path)){
            std::cout<<"Path does not exist\n\n";
            continue;
        }

        char confirm;
        std::cout<<"Are you sure? (Y/N) ["<<path<<"] : ";
        std::cin>>confirm; std::cin.ignore();
        if(confirm!='Y' && confirm!='y'){
            std::cout<<"Cancelled.\n\n";
            continue;
        }

        if(choice==1){
            if(fs::is_regular_file(path)){
                std::ofstream(path.string()+".obfus") << sha256_file(path);
                fs::remove(path);
                std::cout<<"File hashed.\n\n";
            } else if(fs::is_directory(path)){
                std::ofstream(path.string()+".obfus") << sha256_folder(path);
                fs::remove_all(path);
                std::cout<<"Folder hashed.\n\n";
            }
        }
        else if(choice==2){
            if(fs::is_directory(path)){
                sha256_single_mode(path);
                std::cout<<"Folder hashed (single mode).\n\n";
            } else {
                std::cout<<"Single mode works only on folders.\n\n";
            }
        }
    }
}
