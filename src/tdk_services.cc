#include "tdk_services/tdk_services.h"
#include <signal.h>
#include <map>
#include <sstream>
#include <iomanip>
#include "smartbot/account/register_new.h"
#include "smartbot/account/third_appleid.h"
#include "smartbot/account/third_mailid.h"
#include "smartbot/passport/itunes_client_interface.h"
#pragma comment(lib,"ios_cracker.lib")
#pragma comment(lib,"ios_broker.lib")
#include "event2/bufferevent.h"
#include "event2/buffer.h"
#include "event2/buffer_compat.h"
#include "event2/listener.h"
#include "event2/event.h"
#include "event2/event_compat.h"
#include "event2/http.h"
#include "event2/http_struct.h"
#include "event2/http_compat.h"
#include "event2/keyvalq_struct.h"
#pragma comment(lib,"libevent.lib")
#pragma comment(lib,"libevent_core.lib")
#pragma comment(lib,"libevent_extras.lib")
#include "ABI/thirdparty/glog/scoped_ptr.h"
#include "ABI/thirdparty/openssl/evp.h"
#include "ABI/exception/exception_dump.h"
#pragma comment(lib,"ssleay32.lib")
#pragma comment(lib,"libeay32.lib")

namespace tdk{
	namespace internal{
		class SRVTime
		{
		public:
			SRVTime():over_time_(0),now_time_(0){

			}
			~SRVTime(){
				set_overtime(0);
				set_nowtime(0);
			}
			void set_overtime(unsigned long t = 0){
				over_time_ = t==0?static_cast<unsigned long>(clock()):t;
			}
			void set_nowtime(unsigned long t = 0){
				now_time_ = t==0?static_cast<unsigned long>(clock()):t;
			}
			unsigned long overtime() const{
				return over_time_;
			}
			unsigned long now_time()const{
				return now_time_;
			}
			static SRVTime* GetInstance(){
				static SRVTime* info;
				if(!info){
					SRVTime* new_info = new SRVTime;
					if(InterlockedCompareExchangePointer(reinterpret_cast<PVOID*>(&info),new_info,NULL)){
						delete new_info;
					}
				}
				return info;
			}
		private:
			unsigned long over_time_;
			unsigned long now_time_;
		};
		namespace global{
			struct evhttp* http_services = NULL;
			passport::tdk_callback itunes_tdk;
			std::map<std::string,std::string> fork_process;
			bool is_process_mgr = false;
			const unsigned long libevent_timeout = 120;
			const unsigned long kMaxLength = 1024*1024*8;
		}
		void SendResponse(struct evhttp_request* request,const std::string& msg,int code=HTTP_OK){
			if(request!=NULL){
				evhttp_add_header(request->output_headers,"Server","tdk_services");
				evhttp_add_header(request->output_headers,"Content-Type","text/plain;charset=UTF-8");
				evhttp_add_header(request->output_headers,"Connection","close");
				struct evbuffer *buf  = evbuffer_new();
				evbuffer_add_printf(buf,"%s",msg.c_str());
				if (code!=HTTP_OK)
					evhttp_send_reply(request, code, "ERROR", buf);
				else
					evhttp_send_reply(request,code,"OK",buf);
				evbuffer_free(buf);
			}
		}
		int ParseURI(const char *dst,const char *src){
			int ch1, ch2;
			for(int len = strlen(src);;len--){
				if(((ch1=(unsigned char)(*(dst++)))>='A')&&(ch1<='Z')){
					ch1 += 0x20;
				}
				if(((ch2=(unsigned char)(*(src++)))>='A')&&(ch2<='Z')){
					ch2 += 0x20;
				}
				if(!ch2 || (ch1 != ch2) || len==0){
					ch1 = (ch1=='?'||ch1==0)?0:1;
					break;
				}
			}
			return(ch1 - ch2);
		}
		const char* ParseArg(const char* url,const char* name){
			if(url!=NULL&&name!=NULL){
				struct evkeyvalq param = {0};
				int err = evhttp_parse_query(url,(struct evkeyvalq*)&param);
				return evhttp_find_header((struct evkeyvalq*)&param,name);
			}
			return "";
		}
		const char* ParsePyload(struct evhttp_request *req){
			if(req!=NULL){
				char* pyload = (char*)EVBUFFER_DATA(req->input_buffer);
				pyload[EVBUFFER_LENGTH(req->input_buffer)] = 0;
				return pyload;
			}
			return "";
		}
		std::string NewRandomString(const unsigned long length){
			char password[1024] = {0};
			static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
			srand(static_cast<unsigned int>(time(NULL)));
			while(strlen(password)!=length){
				for(unsigned int i=0;i<length;i++){
					int rand_position = (static_cast<int>(rand()%sizeof(alphanum)-1));
					password[i] = alphanum[static_cast<int>(floor(static_cast<long double>(rand_position)))];
				}
			}
			return password;
		}
		std::string NewRandomNumber(){
			char buffer[MAX_PATH] = {0};
			srand((unsigned int)time(NULL));
			_snprintf(buffer,MAX_PATH,"%d",rand()%9999);
			return buffer;
		}
		std::string Base64Encode(const unsigned char* cert,const size_t length){
			scoped_array<unsigned char> cert_buffer(new unsigned char[global::kMaxLength]);
			if(length){
				memset(cert_buffer.get(),0,global::kMaxLength);
				unsigned long sign_sap_setup_length = EVP_EncodeBlock(cert_buffer.get(),cert,length);
			}
			return std::string((char*)cert_buffer.get());
		}
		std::wstring ForkProcessInfo(const char* fork,const char* port){
			char buffer[MAX_PATH] = {0};
			char tmp[MAX_PATH] = {0};
			wchar_t tmp_1[MAX_PATH] = {0};
			GetModuleFileNameA(NULL,buffer,MAX_PATH);
			wnsprintfA(tmp,MAX_PATH,"%s %s %d",buffer,fork,atoi(port));
			mbstowcs(tmp_1,tmp,MAX_PATH);
			return std::wstring(tmp_1);
		}
		bool ForkWorkProcess(const char* process,const char* port){
			STARTUPINFOW si = {sizeof(STARTUPINFOW),0};
			PROCESS_INFORMATION pi = {0};
			std::wstring command_line = ForkProcessInfo(process,port);
			std::string process_tmp = process;
			std::string port_tmp = port;
			for(int i=0;i<10;i++){
				srand((unsigned int)time(NULL));
				OutputDebugStringW(command_line.c_str());
				if(!CreateProcessW(NULL,(LPWSTR)command_line.c_str(),NULL,NULL,FALSE,0,NULL,NULL,&si,&pi)){
					process_tmp = NewRandomString(6);
					port_tmp = NewRandomNumber();
					command_line = ForkProcessInfo(process_tmp.c_str(),port_tmp.c_str());
					continue;
				}
				CloseHandle(pi.hProcess);
				CloseHandle(pi.hThread);
				command_line.resize(0);
				break;
			}
			if(command_line.length()){
				MessageBoxW(GetActiveWindow(),L"工作进程创建失败",L"提示",MB_OK);
				return false;
			}
			return true;
		}
		void ChunkCallback(struct evhttp_request* req,void * arg){
			struct evhttp_request *response = (struct evhttp_request *)arg;
			if(req){
				if(req->type==EVHTTP_REQ_POST){
					evbuffer_add_buffer(response->output_buffer,req->input_buffer);
				}
				evhttp_send_reply(response,req->response_code,req->response_code_line,req->input_buffer);
			}
		}  
		void NewRequestObjectCallback(struct evhttp_request* req, void * arg){
			struct evhttp_request *response = (struct evhttp_request*)arg;
			if(req&&response){
				struct evkeyvalq *header = req->input_headers;
				if(header){
					for(struct evkeyval* kv = header->tqh_first;kv!=NULL;kv = kv->next.tqe_next){
						evhttp_add_header(response->output_headers,(const char *)kv->key,(const char *)kv->value);
					}
					evhttp_send_reply(response, req->response_code,req->response_code_line,req->input_buffer);
					evhttp_send_reply_end(response);
				}
			}
		}  
		void SendProxyMessage(const char *domain,unsigned short port,int secs,struct evhttp_request *response,const char* uri){
			if(domain==NULL||response==NULL||uri==NULL){
				return;
			}
			struct event_base* base = event_base_new();
			struct evhttp_request* request = evhttp_request_new(NewRequestObjectCallback, (void*)response);
			for (bool is_stop = true; is_stop && request != nullptr&&base != nullptr; is_stop = false){
				struct evhttp_connection* evcon = evhttp_connection_base_new(base, NULL, domain, port);
				if (evcon == NULL){
					continue;
				}
				request->chunk_cb = ChunkCallback;
				struct evkeyvalq *header = response->input_headers;
				for (struct evkeyval* kv = header->tqh_first; kv != NULL; kv = kv->next.tqe_next){
					evhttp_add_header(request->output_headers, (const char *)kv->key, (const char *)kv->value);
				}
				if (response->type == EVHTTP_REQ_POST){
					evbuffer_add_buffer(request->output_buffer, response->input_buffer);
				}
				evhttp_make_request(evcon, request, response->type, uri);
				evhttp_connection_set_timeout(request->evcon, secs);
				event_base_dispatch(base);
			}
			if (base)
				event_base_free(base);
			return;
		}
		void RequestDone(struct evhttp_request *req, void *ctx){
			char buf[1024] = {0};
			int s = evbuffer_remove(req->input_buffer, &buf, sizeof(buf) - 1);
			event_base_loopbreak((struct event_base *)ctx);
			return;
		}
		void SRVTimeoutThread(void* arg){
			for(;!tdk::internal::global::is_process_mgr;){
				unsigned long now = tdk::internal::SRVTime::GetInstance()->now_time();
				unsigned long over = tdk::internal::SRVTime::GetInstance()->overtime();
				if(((now/CLOCKS_PER_SEC)+1800)<=(over/CLOCKS_PER_SEC)){
					std::map<std::string,std::string>::iterator fork_info = tdk::internal::global::fork_process.begin();
					for(;fork_info!=tdk::internal::global::fork_process.end();fork_info++){
						const std::string process = fork_info->first;
						const std::string uri = std::string("/Exit")+std::string("?key=")+process;
						struct event_base* base = event_base_new();
						struct evhttp_connection* conn = evhttp_connection_base_new(base,NULL,"127.0.0.1",80);
						struct evhttp_request* req = evhttp_request_new(RequestDone,(void*)base);
						evhttp_add_header(req->output_headers,"Host","127.0.0.1");
						evhttp_add_header(req->output_headers,"Connection","close");
						evhttp_make_request(conn,req,EVHTTP_REQ_GET,uri.c_str());
						evhttp_connection_set_timeout(conn,internal::global::libevent_timeout);
						event_base_dispatch(base);
						event_base_free(base);
					}
					break;
				}
				tdk::internal::SRVTime::GetInstance()->set_overtime();
				Sleep(1000);
			}
		}
		void Messenger(struct evhttp_request *req,void *arg){
			std::string response;
			const char *relative_uri = evhttp_request_uri(req);
			const char *fork_process_key = ParseArg(relative_uri,"key");
			if(EVHTTP_REQ_GET!=req->type&&EVHTTP_REQ_POST!=req->type){
				std::ostringstream response_message;
				response_message<<"ERROR:"<<"File#"<<__FILE__<<"Function#"<<__FUNCTION__<<"Line#"<<__LINE__<<std::endl;
				SendResponse(req,response_message.str(),HTTP_OK);
				return;
			}
			tdk::internal::SRVTime::GetInstance()->set_nowtime();
			if(!ParseURI(relative_uri,"/Initialize")){
				if(tdk::internal::global::is_process_mgr){
					STARTUPINFOW si = {sizeof(STARTUPINFOW),0};
					PROCESS_INFORMATION pi = {0};
					const std::string process = NewRandomString(10);
					const std::string port = NewRandomNumber();
					if(!ForkWorkProcess(process.c_str(),port.c_str())){
						std::ostringstream response_message;
						response_message<<"ERROR:"<<"File#"<<__FILE__<<"Function#"<<__FUNCTION__<<"Line#"<<__LINE__<<std::endl;
						SendResponse(req,response_message.str(),HTTP_SERVUNAVAIL);
						return;
					}
					tdk::internal::global::fork_process.insert(std::pair<std::string,std::string>(process,port));
					const std::string uri = std::string("/Initialize")+std::string("?key=")+process;
					SendProxyMessage("127.0.0.1",atoi(port.c_str()),tdk::internal::global::libevent_timeout,req,uri.c_str());
				}
				else{
					if(fork_process_key!=NULL&&!tdk::internal::global::is_process_mgr&&
						tdk::internal::global::fork_process.find(fork_process_key)!=tdk::internal::global::fork_process.end()){
						std::map<std::string,std::string>::iterator fork_info = tdk::internal::global::fork_process.find(fork_process_key);
						tdk::internal::global::itunes_tdk.Initialize();
						response.append("key=");
						response.append(fork_info->first);
						tdk::internal::SendResponse(req,response);//fork process response
					}
				}
			}
			else if(!ParseURI(relative_uri,"/SapSetupInitialize")){
				if(fork_process_key!=NULL&&
					tdk::internal::global::fork_process.find(fork_process_key)!=tdk::internal::global::fork_process.end()){
					std::map<std::string,std::string>::iterator fork_info = tdk::internal::global::fork_process.find(fork_process_key);
					if(tdk::internal::global::is_process_mgr){
						const std::string process = fork_info->first;
						const std::string port = fork_info->second;
						std::string uri = std::string("/SapSetupInitialize")+std::string("?key=")+process;
						SendProxyMessage("127.0.0.1",atoi(port.c_str()),tdk::internal::global::libevent_timeout,req,uri.c_str());
					}
					else{
						const char *contenttype = evhttp_find_header(req->input_headers,"Content-Type");
						if(req->type==EVHTTP_REQ_POST/*&&stricmp(contenttype,"application/x-www-form-urlencoded")==0*/){
							struct evkeyvalq params = {0};
							const char* pyload = ParsePyload(req);
							evhttp_parse_query_str(pyload,&params);
							const char* x_aa_sig = evhttp_find_header((struct evkeyvalq*)&params,"X-Apple-ActionSignature");
							const char* sign_cert = evhttp_find_header((struct evkeyvalq*)&params,"sign-sap-setup-cert");
							const char* sign_buffer = evhttp_find_header((struct evkeyvalq*)&params,"sign-sap-setup-buffer");
							if(sign_cert&&sign_cert[0]){
								char* sap_buffer = new char[global::kMaxLength];
								memset(sap_buffer,0,global::kMaxLength);
								tdk::internal::global::itunes_tdk.SapSetupInitialize(atoi(x_aa_sig),sign_cert,sap_buffer,global::kMaxLength);
								if(sap_buffer[0]){
									response.append(sap_buffer);
								}
								delete[] sap_buffer;
								tdk::internal::SendResponse(req,response);//fork process response
							}
							else if(sign_buffer&&sign_buffer[0]){
								char* sap_buffer = new char[global::kMaxLength];
								memset(sap_buffer,0,global::kMaxLength);
								tdk::internal::global::itunes_tdk.SapSetupInitialize(atoi(x_aa_sig),sign_buffer,sap_buffer,global::kMaxLength);
								if(sap_buffer[0]){
									response.append(sap_buffer);
								}
								delete[] sap_buffer;
								tdk::internal::SendResponse(req,response);//fork process response
							}
							else{
								std::ostringstream response_message;
								response_message<<"ERROR:"<<"File#"<<__FILE__<<"Function#"<<__FUNCTION__<<"Line#"<<__LINE__<<std::endl;
								SendResponse(req,response_message.str(),HTTP_SERVUNAVAIL);
							}
						}
						else{
							std::ostringstream response_message;
							response_message<<"ERROR:"<<"File#"<<__FILE__<<"Function#"<<__FUNCTION__<<"Line#"<<__LINE__<<std::endl;
							SendResponse(req,response_message.str(),HTTP_SERVUNAVAIL);
						}
					}
				}
				else{
					std::ostringstream response_message;
					response_message<<"ERROR:"<<"File#"<<__FILE__<<"Function#"<<__FUNCTION__<<"Line#"<<__LINE__<<std::endl;
					SendResponse(req,response_message.str(),HTTP_SERVUNAVAIL);
				}
			}
			else if(!ParseURI(relative_uri,"/XAppleActionSignature")){
				if(fork_process_key!=NULL&&
					tdk::internal::global::fork_process.find(fork_process_key)!=tdk::internal::global::fork_process.end()){
						std::map<std::string,std::string>::iterator fork_info = tdk::internal::global::fork_process.find(fork_process_key);
						if(tdk::internal::global::is_process_mgr){
							const std::string process = fork_info->first;
							const std::string port = fork_info->second;
							std::string uri = std::string("/XAppleActionSignature")+std::string("?key=")+process;
							SendProxyMessage("127.0.0.1",atoi(port.c_str()),tdk::internal::global::libevent_timeout,req,uri.c_str());
						}
						else{
							const char *contenttype = evhttp_find_header(req->input_headers,"Content-Type");
							if(req->type==EVHTTP_REQ_POST/*&&stricmp(contenttype,"application/x-www-form-urlencoded")==0*/){
								struct evkeyvalq params = {0};
								char* calc_buffer = new char[global::kMaxLength];
								const char* pyload = ParsePyload(req);
								evhttp_parse_query_str(pyload,&params);
								const char* data = evhttp_find_header((struct evkeyvalq*)&params,"data");
								const char* type = evhttp_find_header((struct evkeyvalq*)&params,"type");
								if(!data||!type){
									std::ostringstream response_message;
									response_message<<"ERROR:"<<"File#"<<__FILE__<<"Function#"<<__FUNCTION__<<"Line#"<<__LINE__<<std::endl;
									SendResponse(req,response_message.str(),HTTP_SERVUNAVAIL);
								}
								else{
									switch(atoi(type)){
									case 1:
										memset(calc_buffer,0,global::kMaxLength);
										tdk::internal::global::itunes_tdk.CalcXAppleActionSignature(calc_buffer,global::kMaxLength);
										if(calc_buffer[0]){
											response.append(calc_buffer);
											OutputDebugStringA("CalcXAppleActionSignature_1");
											OutputDebugStringA(calc_buffer);
										}
										else{
											std::ostringstream response_message;
											response_message<<"ERROR:"<<"File#"<<__FILE__<<"Function#"<<__FUNCTION__<<"Line#"<<__LINE__<<std::endl;
											SendResponse(req,response_message.str(),HTTP_SERVUNAVAIL);
										}
										break;
									case 2:
										tdk::internal::global::itunes_tdk.CalcXAppleActionSignature(data,strlen(data));
										response.append("success");
										break;
									case 3:
										memset(calc_buffer,0,global::kMaxLength);
										tdk::internal::global::itunes_tdk.CalcXAppleActionSignature(data,strlen(data),calc_buffer,global::kMaxLength);
										if(calc_buffer[0]){
											OutputDebugStringA("CalcXAppleActionSignature_2");
											OutputDebugStringA(calc_buffer);
											response.append(calc_buffer);
										}
										else{
											std::ostringstream response_message;
											response_message<<"ERROR:"<<"File#"<<__FILE__<<"Function#"<<__FUNCTION__<<"Line#"<<__LINE__<<std::endl;
											SendResponse(req, response_message.str(), HTTP_SERVUNAVAIL);
										}
										break;
									default:
										std::ostringstream response_message;
										response_message<<"ERROR:"<<"File#"<<__FILE__<<"Function#"<<__FUNCTION__<<"Line#"<<__LINE__<<std::endl;
										SendResponse(req,response_message.str(),HTTP_SERVUNAVAIL);
										break;
									}
									tdk::internal::SendResponse(req,response);//fork process response
								}
								delete[] calc_buffer;
							}
							else{
								std::ostringstream response_message;
								response_message<<"ERROR:"<<"File#"<<__FILE__<<"Function#"<<__FUNCTION__<<"Line#"<<__LINE__<<std::endl;
								SendResponse(req,response_message.str(),HTTP_SERVUNAVAIL);
							}
						}
				}
				else{
					std::ostringstream response_message;
					response_message<<"ERROR:"<<"File#"<<__FILE__<<"Function#"<<__FUNCTION__<<"Line#"<<__LINE__<<std::endl;
					SendResponse(req,response_message.str(),HTTP_SERVUNAVAIL);
				}
			}
			else if(!ParseURI(relative_uri,"/Process")){
				if(tdk::internal::global::is_process_mgr){
					std::map<std::string,std::string>::iterator it;
					for(it=tdk::internal::global::fork_process.begin();it!=tdk::internal::global::fork_process.end();it++){
						response.append("key=");
						response.append(it->first);
						response.append("\n");
					}
					tdk::internal::SendResponse(req,response);//parent process response
				}
				else{
					std::ostringstream response_message;
					response_message<<"ERROR:"<<"File#"<<__FILE__<<"Function#"<<__FUNCTION__<<"Line#"<<__LINE__<<std::endl;
					SendResponse(req,response_message.str(),HTTP_SERVUNAVAIL);
				}
			}
			else if(!ParseURI(relative_uri,"/Exit")){
				if(fork_process_key!=NULL&&
					tdk::internal::global::fork_process.find(fork_process_key)!=tdk::internal::global::fork_process.end()){
					std::map<std::string,std::string>::iterator fork_info = tdk::internal::global::fork_process.find(fork_process_key);
					if(tdk::internal::global::is_process_mgr){
						const std::string process = fork_info->first;
						const std::string port = fork_info->second;
						const std::string uri = std::string("/Exit")+std::string("?key=")+process;
						tdk::internal::global::fork_process.erase(fork_info);
						SendProxyMessage("127.0.0.1",atoi(port.c_str()),tdk::internal::global::libevent_timeout,req,uri.c_str());
						std::ostringstream response_message;
						response_message<<"ERROR:"<<"File#"<<__FILE__<<"Function#"<<__FUNCTION__<<"Line#"<<__LINE__<<std::endl;
						SendResponse(req,response_message.str(),HTTP_SERVUNAVAIL);
					}
					else{
						exit(0);//fork process response
					}
				}
				else{
					std::ostringstream response_message;
					response_message<<"ERROR:"<<"File#"<<__FILE__<<"Function#"<<__FUNCTION__<<"Line#"<<__LINE__<<std::endl;
					SendResponse(req,response_message.str(),HTTP_SERVUNAVAIL);
				}
			}
			else{
				std::ostringstream response_message;
				response_message<<"ERROR:"<<"File#"<<__FILE__<<"Function#"<<__FUNCTION__<<"Line#"<<__LINE__<<std::endl;
				SendResponse(req,response_message.str(),HTTP_SERVUNAVAIL);
				return;
			}
		}
	}
	bool tdk_services::Initialize(const int port){
		WSADATA WSAData;
		WSAStartup(0x101, &WSAData);
		event_init();
		ABI::carsh_exception::EnableExceptionHandler();
		tdk::internal::global::http_services = evhttp_start("0.0.0.0",port);
		if (tdk::internal::global::http_services){
			_beginthread(tdk::internal::SRVTimeoutThread, 0, NULL);
		}
		return (tdk::internal::global::http_services!=NULL);
	}
	void tdk_services::Uninitialize(){
		ABI::carsh_exception::DisableExceptionHandler();
		if (tdk::internal::global::http_services){
			evhttp_free(tdk::internal::global::http_services);
			tdk::internal::global::http_services = NULL;
		}
	}
	void tdk_services::Run(const int time_out){
		if (tdk::internal::global::http_services){
			evhttp_set_timeout(tdk::internal::global::http_services, time_out);
			evhttp_set_gencb(tdk::internal::global::http_services, tdk::internal::Messenger, NULL);
			event_dispatch();
		}
	}
}
int main(int argc,char *argv[]){
	bool is_fork_process = (argc==3);
	if(tdk::tdk_services::Initialize(is_fork_process?atoi(argv[2]):88)){
		if(is_fork_process){
			tdk::internal::global::fork_process.insert(std::pair<std::string,std::string>(argv[1],argv[2]));
			tdk::tdk_services::Run(240);
		}
		else{
			tdk::internal::global::is_process_mgr = true;
			tdk::tdk_services::Run(tdk::internal::global::libevent_timeout);
		}
		tdk::tdk_services::Uninitialize();
		return 0;
	}
	return 1;
}