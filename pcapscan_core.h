#ifndef HYPERSCANNAMENEW
#define HYPERSCANNAMENEW

#include <string>
#include <unordered_map>
#include <vector>
#include <chrono>
#include <cstring>
// We use the BSD primitives throughout as they exist on both BSD and Linux.
#define __FAVOR_BSD
namespace HyperScanName {

using namespace std;
	typedef struct {
		string cmd;//对应rolDefList里的assertSet的command,比如：str_match number_assert ....
		string value;//对应rolDefList的assertSet的value比如当key为str_match时，这里放具体字符串
		int direct;//对应rolDefList里的beginAssert，如果是前置的断言,direct就为0，如果是后置的断言,direct为1
		int istrue;//对应rolDefList的assertSet的negativeMatch,如果negativeMatch==true,istrue就用false，negativeMatch==false,istrue就用true，他们是相反的。
	}rule_s;

	typedef struct {
		vector<rule_s> rules;//对应外部正则的扩展部分 beginAssert ,endAssert
	}patterns_s;

	typedef struct{
		unsigned int from;
		unsigned int to;
	}position_s;

	typedef struct{
		vector<position_s> matches;
	}matches_s;

	typedef unordered_map<int ,int> BenchMap;
	typedef unordered_map<int,patterns_s>PatternsMap;//key 是每条正则的id
	typedef unordered_map<int,matches_s> ResultVet;//key是每条正则id
	static void databasesFromBuffer(vector<string> &patVector,
			hs_database_t **db_streaming,
			hs_database_t **db_block); 

	// Simple timing class
	class Clock {
		public:
			void start() {
				time_start = std::chrono::system_clock::now();
			}

			void stop() {
				time_end = std::chrono::system_clock::now();
			}

			double seconds() const {
				std::chrono::duration<double> delta = time_end - time_start;
				return delta.count();
			}
		private:
			std::chrono::time_point<std::chrono::system_clock> time_start, time_end;
	};
	// Class wrapping all state associated with the benchmark
	class NewHyperScan {
		private:
			Clock clock;			
			bool g_bOnlyLoadFile=false;
			vector<string> packets;
			hs_scratch_t *scratch;
			hs_database_t *db_streaming, *db_block;
			void scanBlock_Files(unsigned int repeatCount); 
			int parseBuffer(vector<string> &patVector, vector<string> &patterns,
					vector<unsigned> &flags, vector<unsigned> &ids);			
			hs_database_t *buildDatabase(const vector<const char *> &expressions,
					const vector<unsigned> flags,
					const vector<unsigned> ids,
					unsigned int mode);
		public:
			ResultVet resultVet; 
			int g_nlog_level = 0;
			BenchMap benchMap;
			const char *pFileContent=NULL;
			size_t pFileLen=0;
			PatternsMap patVector_Ex;
			int tmpMatch;			
			string tmpIds;
			size_t matchCount=0;
			string logMessage;
		public:
			int databasesFromBuffer(vector<string> &patVector);
			NewHyperScan(); 


			~NewHyperScan(); 

			void hyperSetLogLevel(int level);
			string &hyperGetMessage();
			int hyperCompile(vector<string> &patVector,PatternsMap &patternsEx); 
			int hyperScan(const char* patVector,size_t size) ;


	};
	// helper function - see end of file

}

// Match event handler: called every time Hyperscan finds a match.
#endif


