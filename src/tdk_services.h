#ifndef TDK_SERVICES_TDK_SERVICES_H_
#define TDK_SERVICES_TDK_SERVICES_H_

namespace tdk{
	class tdk_services{
	public:
		static bool Initialize(const int port);
		static void Uninitialize();
		static void Run(const int time_out);
	};
}

#endif