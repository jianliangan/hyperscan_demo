
// We use the BSD primitives throughout as they exist on both BSD and Linux. ajl
#define __FAVOR_BSD
#include <hs.h>
#include "pcapscan_core.h"
namespace HyperScanName{


	enum Direct{
		DirectPre,
		DirectTail,
	};
	int check_a(char v);
	int check_A(char v);
	int check_w(char v);
	int check_d(char v);
	int check(const char *bufStart,size_t bufLen,size_t from,size_t to,const char *cmd,const char *value,int direct,const char *&ret);
	int check_a(char v){
		if((v&(1<<7))==128){
			return -1;
		}
		if(v>='a'&&v<='z'){
			return 0;}
		return -1;
	}
	int check_A(char v){
		if((v&(1<<7))==128){
			return -1;
		}
		if(v>='A'&&v<='Z')
			return 0;
		return -1;
	}

	int check_w(char v){
		if((v&(1<<7))==128){
			return -1;
		}
		if(check_d(v)==0){
			return 0;
		}
		if(check_a(v)==0)
			return 0;
		if(check_A(v)==0){
			return 0;}
		if(v=='_')
			return 0;
		return -1;
	}
	int check_d(char v){
		if((v&(1<<7))==128){
			return -1;
		}
		if(v>='0'&&v<='9'){
			return 0;
		}
		return -1;
	}
	void splitCb(const char*ss1,const char*split,const char*&dist,int &distLen){
		if(ss1==NULL)
			return;
		const char* strEnd=NULL;
		const char* strStart=ss1;
		int allLen=strlen(strStart);
		int strLen=0;
		const char*tmpStart=strStart;
		while(true){

			strEnd=strstr(tmpStart,split);
			if(strEnd!=NULL&&strEnd-strStart>=1){

				if(*(strEnd-1)=='\\'){
					tmpStart=strEnd+1;
					continue;
				}else{
					break;
				}   
			}else{
				break;
			}   
		}   
		if(strEnd==NULL){
			strLen=allLen;
		}else{
			strLen=strEnd-strStart;
		}   
		dist=strStart;
		distLen=strLen;

	}
	/**
	 *正则结果过滤扩展
	 *bufStart:当前准备往前/往后时的指针,bufLen:前面/后面总共有多长可用,cmd:分为str_match"前面固定字符",number_assert“\w|\d\.”,number_assert_2"\w|\d|\.",char_assert "\w",
	 *value:目前只是str_match有用
	 *direct:检查方向:前后
	 *return:0 匹配上了
	 **/
	int check(const char *bufPos,size_t bufLength,size_t from,size_t to,const char *cmd,const char *value,int direct,const char *&ret){

		if(strcmp(cmd,"str_match")==0&&direct==1){//向后查短语
			int bufLen=bufLength-to;
			const char *bufStart=bufPos+to;
			const char* dist=NULL;
			int valueLen=0;
			const char* valueTmp=value;
			while(1){
				splitCb(valueTmp,"|",dist,valueLen);
				if(dist==NULL){
					break;
				}	
				//int valueLen=strlen(value);
				if(valueLen>bufLen){
					//ret=NULL;
					//return -1;
					continue;   
				}else{
					if(strncmp(bufStart,dist,valueLen)==0){
						ret=bufStart+valueLen;
						return 0; 
					}
				}
				valueTmp=valueTmp+valueLen+1;
				if(dist[valueLen]==0){
					break;
				}
			}
			ret=NULL;
			return -1;
		}
		else if(strcmp(cmd,"str_match")==0&&direct==0){//向前查短语
			int bufLen=from;
			const char *bufStart=bufPos+from;
			//int valueLen=strlen(value);
			const char* dist=NULL;
			int valueLen=0;
			const char* valueTmp=value;
			while(1){
				splitCb(valueTmp,"|",dist,valueLen);
				if(dist==NULL){         
					break;
				}
				if(valueLen>bufLen){
					continue;				
					//ret=NULL;		
					//return -1;   
				}else{
					if(strncmp(bufStart-valueLen,dist,valueLen)==0){
						ret=bufStart-valueLen;	
						return 0; 
					}
				}
				valueTmp=valueTmp+valueLen+1;
				if(dist[valueLen]==0){
					break;
				}
			}
			ret=NULL;
			return -1;
		}else if(strcmp(cmd,"number_assert")==0&&direct==0){//向前查小数
			int bufLen=from;
			const char *bufStart=bufPos+from;
			if(bufLen>=2){
				if(check_w(*(bufStart-1))==0){
					ret=bufStart-1;	
					return 0;
				}
				if(check_d(*(bufStart-2))==0&&*(bufStart-1)=='.'){
					ret=bufStart-2;	
					return 0;
				}
				ret=NULL;	
				return -1;
			}else if(bufLen==1){
				if(check_w(*(bufStart-1))==0){
					ret=bufStart-1;	
					return 0;
				}
				ret=NULL;	
				return -1;
			}else{
				ret=NULL;	
				return -1;
			}
		}else if(strcmp(cmd,"number_assert")==0&&direct==1)//向后查小数
		{

			int bufLen=bufLength-to;
			const char *bufStart=bufPos+to;
			if(bufLen>=2){
				if(check_w(*(bufStart))==0){
					ret=bufStart+1;	
					return 0;
				}
				if(check_d(*(bufStart+1))==0&&*(bufStart)=='.'){
					ret=bufStart+2;		
					return 0;
				}
				ret=NULL;		
				return -1;
			}else if(bufLen==1){
				if(check_w(*(bufStart))==0){
					ret=bufStart+1;	
					return 0;
				}
				ret=NULL;	
				return -1;
			}else{
				ret=NULL;	
				return -1;
			}

		}else if(strcmp(cmd,"number_assert_2")==0&&direct==0){//向前查小数
			int bufLen=from;
			const char *bufStart=bufPos+from;
			if(bufLen>=1){
				if(check_w(*(bufStart-1))==0||*(bufStart-1)=='.'){
					ret=bufStart-1;	
					return 0;
				}
				ret=NULL;	
				return -1;
			}else{
				ret=NULL;	
				return -1;
			}
		}else if(strcmp(cmd,"number_assert_2")==0&&direct==1){

			int bufLen=bufLength-to;
			const char *bufStart=bufPos+to;
			if(bufLen>=1){
				if(check_w(*(bufStart))==0||*(bufStart)=='.'){
					ret=bufStart+1;	
					return 0;
				}
				ret=NULL;	
				return -1;
			}else{
				ret=NULL;	
				return -1;
			}

		}
		else if(strcmp(cmd,"char_assert")==0&&direct==0){//向前查字符
			int bufLen=from;
			const char *bufStart=bufPos+from;
			if(bufLen>=1){
				if(check_w(*(bufStart-1))==0){
					ret=bufStart-1;	
					return 0;
				}
				ret=NULL;	
				return -1;
			}else{
				ret=NULL;	
				return -1;
			}
		}else if(strcmp(cmd,"char_assert")==0&&direct==1){

			int bufLen=bufLength-to;
			const char *bufStart=bufPos+to;
			if(bufLen>=1){
				if(check_w(*(bufStart))==0){
					ret=bufStart+1;	
					return 0;
				}
				ret=NULL;		
				return -1;
			}else{
				ret=NULL;	
				return -1;
			}

		}
		else {
			ret=NULL;	
			return -1;
		}

	}

	static unsigned parseFlags(const string &flagsStr,int &err) {
		unsigned flags = 0;
		err=0;
		for (const auto &c : flagsStr) {
			switch (c) {
				case 'S':
					flags |= HS_FLAG_SOM_LEFTMOST;break;
				case 'p':
					flags |= HS_FLAG_PREFILTER;break;
				case 'c':
					flags |= HS_FLAG_COMBINATION;break;
				case 'i':
					flags |= HS_FLAG_CASELESS; break;
				case 'm':
					flags |= HS_FLAG_MULTILINE; break;
				case 's':
					flags |= HS_FLAG_DOTALL; break;
				case 'H':
					flags |= HS_FLAG_SINGLEMATCH; break;
				case 'V':
					flags |= HS_FLAG_ALLOWEMPTY; break;
				case '8':
					flags |= HS_FLAG_UTF8; break;
				case 'W':
					flags |= HS_FLAG_UCP; break;
				case '\r': // stray carriage-return
					break;
				default:
					err=-1;
			}
		}
		return flags;
	}


	// Match event handler: called every time Hyperscan finds a match.
	static
		int onMatch(unsigned int id, unsigned long long from, unsigned long long to,
				unsigned int flags, void *ctx) {
			// Our context points to a size_t storing the match count
			HyperScanName::NewHyperScan *benchmark=(HyperScanName::NewHyperScan *)ctx;
			// check(char *bufStart,int bufLen,string &cmd,string &value,char *&ret);
			bool findOk=true;
			int j=0;
			vector<rule_s> &jv=benchmark->patVector_Ex[id].rules;
			int prefrom=0;
			int preto=0;
			if(from==0)
				goto goto_ret;
			for(j=0;j<jv.size();j++)
			{
				const char *pos=NULL;
				int direct=jv[j].direct;
				int logic=0;
				int truevalue=jv[j].istrue;
				int tmpfrom=from;
				int tmpto=to;
				/*		if(prepos==1){
						tmpfrom=preform;
						tmpto=preto;
						}
				 */

				int ret=check(benchmark->pFileContent,benchmark->pFileLen,tmpfrom,tmpto,jv[j].cmd.c_str(),jv[j].value.c_str(),direct,pos);
				/*
				   if(direct==0){
				   if(ret==0){
				   prefrom=pos-benchmark->pFileContent;
				   }else{
				   prefrom=from;
				   }
				   }else{
				   if(ret==0){
				   preto=pos-benchmark->pFileContent;
				   }else{
				   preto=to;
				   }

				   }
				 */

				int tmp=1;         
				/*if(g_nlog_level>=2){		
				  printf("ret:%d cmd:%s,value:%s,direct %d\n",ret,jv[j]["cmd"].asString().c_str(),jv[j]["value"].asString().c_str(),direct);	
				  }*/
				if(ret==0){
					tmp=1;
				}        else{
					tmp=0;
				}
				if(j==0){
					if(tmp!=truevalue){
						findOk=false;
						//break;
					}
				}else{
					if(logic==0){//逻辑与
						if(findOk==true){
							if(tmp!=truevalue){
								findOk=false;
								//break;
							} 
						}
					}else{//逻辑或
						if(findOk==true)
						{
							break;
						}else{
							if(tmp!=truevalue){
								findOk=false;
								//break;
							}else{
								findOk=true;
							}

						}

					}
				}
				/*		if(tmp!=truevalue){
						findOk=false;
				//break;
				}		*/
				/*if(g_nlog_level>=2){
				  if(pos!=NULL){
				  cout << jv[j]["cmd"].asString().c_str()<<" "<<jv[j]["value"].asString().c_str()<<" ret:"<<ret<<" pos:"<<(pos-benchmark->pFileContent)<<"--"<<string(pos,8)<<endl;
				  }else
				  {
				  cout << jv[j]["cmd"].asString().c_str()<<" "<<jv[j]["value"].asString().c_str()<<" ret:"<<ret<<" pos:"<<-1<<"--"<<"--"<<endl; 
				  }
				  }*/
			}
goto_ret:
			if(findOk){
				ResultVet::iterator itResultVet=benchmark->resultVet.find(id);
				if(itResultVet==benchmark->resultVet.end()){

					matches_s matches;
					position_s position;
					position.from=from;
					position.to=to;
					matches.matches.push_back(position);
					benchmark->resultVet[id]=matches;
				}else{
					position_s position;
					position.from=from;
					position.to=to;
					benchmark->resultVet[id].matches.push_back(position);
				}
				if(benchmark->benchMap[id]!=1){
					benchmark->benchMap[id]=1;      
					benchmark->tmpIds=benchmark->tmpIds+std::to_string(id)+",";
					benchmark->tmpMatch++;
				}  
			}
			return 0; // continue matching
		}
	;
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
}


// Class wrapping all state associated with the benchmark
namespace HyperScanName {
	string &NewHyperScan::hyperGetMessage(){
		return logMessage;
	}
	void NewHyperScan::hyperSetLogLevel(int level){
		g_nlog_level = level;
	}
	int NewHyperScan::parseBuffer(vector<string> &patVector, vector<string> &patterns,
			vector<unsigned> &flags, vector<unsigned> &ids) {
		if (patVector.size()==0) {
			return 0;
		}

		for (unsigned i = 0; i<patVector.size(); ++i) {
			string line=patVector[i];


			// if line is empty, or a comment, we can skip it
			if (line.empty() || line[0] == '#') {
				continue;
			}

			// otherwise, it should be ID:PCRE, e.g.
			//  10001:/foobar/is

			size_t colonIdx = line.find_first_of(':');
			if (colonIdx == string::npos) {
				logMessage+= "ERROR: Could not parse line "+ to_string(i)+"\n";
				return -1;
			}

			// we should have an unsigned int as an ID, before the colon
			unsigned id = std::stoi(line.substr(0, colonIdx).c_str());

			// rest of the expression is the PCRE
			const string expr(line.substr(colonIdx + 1));

			size_t flagsStart = expr.find_last_of('/');
			if (flagsStart == string::npos) {
				logMessage+= "ERROR: no trailing '/' char\n";
				return -1;			
			}

			string pcre(expr.substr(1, flagsStart - 1));
			string flagsStr(expr.substr(flagsStart + 1, expr.size() - flagsStart));
			if(g_nlog_level>=2){
				logMessage+="pattern " + to_string(id) + ": "+expr+"\n";
			}
			int err;
			unsigned flag = parseFlags(flagsStr,err);
			if(err!=0){

				logMessage+= "Unsupported flag \'" +flagsStr+ "\'\n" ;
				return -1;
			}
			patterns.push_back(pcre);
			flags.push_back(flag);
			ids.push_back(id);
		}
		return 0;
	}
	int NewHyperScan::databasesFromBuffer(vector<string> &patVector) {
		// hs_compile_multi requires three parallel arrays containing the patterns,
		// flags and ids that we want to work with. To achieve this we use
		// vectors and new entries onto each for each valid line of input from
		// the pattern file.
		vector<string> patterns;
		vector<unsigned> flags;
		vector<unsigned> ids;

		// do the actual file reading and string handling
		int err=parseBuffer(patVector, patterns,
				flags, ids);
		if(err!=0){
			return -1;
		}
		vector<const char*> cstrPatterns;
		for (const auto &pattern : patterns) {
			cstrPatterns.push_back(pattern.c_str());
		}

		logMessage+= "total pattern number: [" +to_string(patterns.size())+"]\n";

		//*db_streaming = buildDatabase(cstrPatterns, flags, ids, HS_MODE_STREAM);
		db_block = buildDatabase(cstrPatterns, flags, ids, HS_MODE_BLOCK);
		if(db_block==NULL){
			return -1;
		}
		return 0;	
	}
	hs_database_t *NewHyperScan::buildDatabase(const vector<const char *> &expressions,
			const vector<unsigned> flags,
			const vector<unsigned> ids,
			unsigned int mode) {
		hs_database_t *db;
		hs_compile_error_t *compileErr;
		hs_error_t err;

		clock.start();

		err = hs_compile_multi(expressions.data(), flags.data(), ids.data(),
				expressions.size(), mode, nullptr, &db, &compileErr);

		clock.stop();

		if (err != HS_SUCCESS) {
			if (compileErr->expression < 0) {
				// The error does not refer to a particular expression.
				logMessage+= "ERROR: " + string(compileErr->message) +"\n";
			} else {
				logMessage+= "ERROR: Pattern '" + string(expressions[compileErr->expression]) 
					+ "' failed compilation with error: " + string(compileErr->message)+"\n";

			}
			// As the compileErr pointer points to dynamically allocated memory, if
			// we get an error, we must be sure to release it. This is not
			// necessary when no error is detected.
			hs_free_compile_error(compileErr);
			return NULL;
		}
		logMessage+= "compile-time["+to_string(clock.seconds())+"]ms\n";
		/*  cout << "Hyperscan " << (mode == HS_MODE_STREAM ? "streaming" : "block")
		    << " mode database compiled in " << clock.seconds() << " seconds."
		    << endl;*/

		return db;
	}
	int NewHyperScan::hyperCompile(vector<string> &patVector,PatternsMap &patternsEx)
	{
		logMessage="";
		scratch=nullptr;
		PatternsMap().swap(patVector_Ex);		
		int err1=databasesFromBuffer(patVector);
		if(err1!=0){
			return -3;
		}
		// Allocate enough scratch space to handle block
		// mode, so we only need the one scratch region.
		hs_error_t err = hs_alloc_scratch(db_block, &scratch);
		if (err != HS_SUCCESS) {
			logMessage+= "ERROR: could not allocate scratch space. Exiting.\n";
			return -1;	
		}
                patVector_Ex.swap(patternsEx);
	//	printf("%d,,\n",patVector_Ex.size());
		return 0;
	}

	NewHyperScan::NewHyperScan(){}
	NewHyperScan::~NewHyperScan() {
		// Free scratch region
		hs_free_database(db_block);
		hs_free_scratch(scratch);
	}

	// Clear the number of matches found.

	int NewHyperScan::hyperScan(const char *data,size_t size) {
		static int s_CurIndex=0;
		// cout << ++s_CurIndex << " call " << __func__ << " vecFiles.size()="<< vecFiles.size() << endl;
		logMessage.clear();	
		tmpIds.clear();
		benchMap.clear();
		resultVet.clear();
		//        BenchMap().swap(benchMap);
		ResultVet().swap(resultVet);
		if(size>0){

			tmpMatch=0;
			pFileContent=data;
			pFileLen=size;
			hs_error_t err = hs_scan(db_block, data, size, 0,
					scratch, onMatch, this);
			if (err != HS_SUCCESS) {
				return -1;
			}
		}
	}


};
