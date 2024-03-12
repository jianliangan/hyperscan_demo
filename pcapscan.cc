/*
 * Copyright (c) 2015-2016, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  * Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Hyperscan example program 2: pcapscan
 *
 * This example is a very simple packet scanning benchmark. It scans a given
 * PCAP file full of network traffic against a group of regular expressions and
 * returns some coarse performance measurements.  This example provides a quick
 * way to examine the performance achievable on a particular combination of
 * platform, pattern set and input data.
 *
 * Build instructions:
 *
 *     g++ -std=c++11 -O2 -o pcapscan pcapscan.cc $(pkg-config --cflags --libs libhs) -lpcap
 *
 * Usage:
 *
 *     ./pcapscan [-n repeats] <pattern file> <pcap file>
 *
 * We recommend the use of a utility like 'taskset' on multiprocessor hosts to
 * pin execution to a single processor: this will remove processor migration
 * by the scheduler as a source of noise in the results.
 *
 */

#include <cstring>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include <sstream>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

// We use the BSD primitives throughout as they exist on both BSD and Linux.
#define __FAVOR_BSD
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include <pcap.h>

#include <hs.h>
#include "jsoncpp/json/json.h"
#include "pcapscan_core.h"
using std::cerr;
using std::cout;
using std::endl;
using std::ifstream;
using std::string;
using std::unordered_map;
using std::vector;
using namespace std;
int g_nlog_level = 0;
bool g_bOnlyLoadFile=false;

long LoadFileContent(const std::string& sFileName, char*& buffer);
bool cg_IsDirectory(const char *path)
{
	struct stat info;
	stat(path,&info);
	if(S_ISDIR(info.st_mode)){
		return true;
	}
	else{
		return false;
	}
}
int Listfile(string sPath,vector<string> &vecFileName,int nMaxNum)
{
	DIR *fdir=NULL;
	struct dirent *pdir=NULL;
	string  fname;
	sPath.erase(sPath.find_last_not_of("\\") + 1);
	if((fdir=opendir(sPath.c_str()))==NULL)
	{
		//fprintf(stderr,"Listfile open path=%s error!pid=%d\n",path,getpid());
		return -1;
	}

	int count=1;
	while((pdir=readdir(fdir))!=NULL)
	{
		if(0==strcmp(pdir->d_name,".")||0==strcmp(pdir->d_name,"..")||strstr(pdir->d_name,".swp")!=NULL)
			continue;

		//fname.clear();                            
		//fname.assign(path);
		//fname.append("/");
		fname=sPath;
		fname.append(pdir->d_name);

		if(!cg_IsDirectory(fname.c_str())){
			vecFileName.push_back(fname);
			count++;

			if(nMaxNum>0&&count>=nMaxNum){
				break;
			}
		}
	}
	closedir(fdir);
	return vecFileName.size();
}
long LoadFileContent(const std::string& sFileName, char*& buffer)
{
	FILE *fp = fopen( sFileName.c_str(), "rb" );
	if ( NULL == fp )
	{
		return -1;
	}
	fseek(fp,0,SEEK_END);
	size_t nSize = ftell(fp);
	fseek(fp,0,SEEK_SET);
	if(nSize<1)
	{
		fclose( fp );
		return -2;
	}
	//char *buffer = NULL;
	buffer = new char[nSize+1];
	if(buffer==NULL)
	{
		fclose( fp );
		return -3;
	}
	memset( buffer, 0, nSize+1);
	if (fread( buffer, 1, nSize, fp )!=nSize)
	{
		delete[] buffer;
		fclose( fp );           
		return -4;
	}
	fclose( fp );    
	return nSize;    
}
void stringSplit(string str,const char split,vector<string> &result){
	istringstream iss(str);
	string token;
	while(getline(iss,token,split)){
		result.push_back(token);
	}
}
// Class wrapping all state associated with the benchmark

// helper function - see end of file
int main(int argc, char **argv) {
	unsigned int repeatCount = 1;
	int opt;
	while ((opt = getopt(argc, argv, "n:v:f")) != -1) {
		switch (opt) {
			case 'n':
				repeatCount = atoi(optarg);
				break;
			case 'v':
				g_nlog_level = atoi(optarg);
				break; 
			case 'f':
				g_bOnlyLoadFile = true;
				break;            
			default:
				cerr << "Usage: " << argv[0] << " [-n repeats] [-v num] <pattern file> <scan path>" << endl;
				exit(-1);
		}
	}

	if (argc - optind != 3) {
		cerr << "Usage: " << argv[0] << " [-n repeats] [-v num] <pattern file> <scan path>" << endl;
		exit(-1);
	}

	const char *patternFile = argv[optind];
	const char *scanPath = argv[optind + 1];
	const char *newconfig=argv[optind +2 ];
	//const char *pcapFile = argv[optind + 1];
	if(g_bOnlyLoadFile){
		cout << "*******only load file,not scan prce" <<  endl;        
	}
	// Read our pattern set in and build Hyperscan databases from it.
	HyperScanName::Clock clock;

	char *patternsEx=NULL;
	char *patterns=NULL;
	int patExSize=LoadFileContent(newconfig, patternsEx);
	int patSize=LoadFileContent(patternFile,patterns);
	vector<string> patVector;
	stringSplit(string(patterns),'\n',patVector);
	Json::Value rootPatterns;
	Json::Reader JsonReader;	
	if(!JsonReader.parse(patternsEx,patternsEx+strlen(patternsEx),rootPatterns)){
		printf("json reader error!\n");
		return 0;
	}
	int j=0;
	int m=0;
	// typedef unordered_map<int,patterns_s>PatternsMap;
	HyperScanName::PatternsMap patVector_Ex;
	Json::Value::Members patternsKeys=rootPatterns.getMemberNames();
	for(j=0;j<patternsKeys.size();j++){
		int key=stoi(patternsKeys[j]);
		Json::Value &jvArr=rootPatterns[to_string(key)]["rules"];
		for(m=0;m<jvArr.size();m++){
			Json::Value &jv=jvArr[m];
			HyperScanName::rule_s rs;
			rs.cmd=jv["cmd"].asString();
			rs.value=jv["value"].asString();
			rs.direct=jv["direct"].asInt();
			rs.istrue=jv["true"].asInt();
			patVector_Ex[key].rules.push_back(rs);
		}
		/*if(rootPatterns[*iter].type()==Json::arrayValue){
		  }else()
		 */
	}
	//demo 代码
	HyperScanName::NewHyperScan newHyperScan;
	newHyperScan.hyperSetLogLevel(g_nlog_level);
	newHyperScan.hyperCompile(patVector, patVector_Ex);
	if(g_nlog_level>=1)
		cout<<newHyperScan.hyperGetMessage();
	//demo 结束
	cout<<endl;
	cout<<"Match summary:"<<endl;
	char *pFileContent=NULL;       
	int tmpMatchTotal=0;
	double secondsTotal=0.0;
	std::vector<string> vecFiles;
	Listfile(scanPath,vecFiles,1000);
	for (size_t i = 0; i != vecFiles.size(); ++i) {
		const std::string &curFile = vecFiles[i];
		size_t nFileSize=LoadFileContent(curFile, pFileContent);
		if(nFileSize>0){
			if(g_bOnlyLoadFile){

			}else{
				clock.start();
				//hs_error_t err = hs_scan(db_block, pFileContent, nFileSize, 0,
				//		scratch, onMatch, this);
				//demo 代码 扫描
				int err=newHyperScan.hyperScan(pFileContent,nFileSize);
				if (err != 0) {
					cerr << "ERROR: Unable to scan file fail." << curFile << endl;
					//exit(-1);
				}
				clock.stop();
				cout<<curFile<<" ::match ["<<newHyperScan.tmpMatch<<"],scan-time ["<<clock.seconds()*1000<<"]ms";
				if(g_nlog_level>=1)
					cout<<" ids:"<<newHyperScan.tmpIds;
				cout<<endl;
				//读取结果newHyperScan.resultVet
				if(g_nlog_level>=2){
					HyperScanName::ResultVet::iterator resit; 
					for(resit= newHyperScan.resultVet.begin();resit!=newHyperScan.resultVet.end();resit++){
						vector<HyperScanName::position_s>& mattmp=resit->second.matches;
						cout<<"ids:"<<resit->first<<endl;
						for(int i=0;i<mattmp.size();i++){
							cout<<"   from:"<<mattmp[i].from<<" to:"<<mattmp[i].to<<endl;
						}
					}
				}
				//demo代码结束
				secondsTotal+=clock.seconds();
				tmpMatchTotal+=newHyperScan.tmpMatch;
			}
		}
		if(pFileContent){
			free(pFileContent);
			pFileContent=NULL;
		}
	}


	cout<<endl;
	cout<<" All file : match       ["<<tmpMatchTotal<<"]"<<endl;
	cout<<"            scan-time   ["<<secondsTotal*1000<<"]ms";
	cout<<endl;

	return 0;
}




