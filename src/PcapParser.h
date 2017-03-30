#ifndef PCAPPARSER_H
#define PCAPPARSER_H

//---------------------------------------------------------------
#include <iostream>
//---------------------------------------------------------------
#include <IpAddress.h>
//---------------------------------------------------------------

#define OUT(x) std::cout << x << '\n';

#ifdef DEBUG
#define DEB(x) std::cout << "[" << __PRETTY_FUNCTION__ << " debug]: " << x << '\n';
#define ERR(x) std::cerr << "[" << __PRETTY_FUNCTION__ << " error]: " << x << '\n';
#else
#define DEB(x) ;
#define ERR(x) ;
#endif

using Port = uint16_t;

///
/// \brief The PcapParser class парсер файлов типа .pcap
///
class PcapParser
{
public:
	PcapParser() = default;

	///
	/// \brief parse открывает и парсит файл по переданному имени
	/// Печатает в std::cout все обработанные пакеты в формате:
	/// <Таймстемп захвата пакета> <Адрес назначения> <Порт назначения> <размер полезных данных в UDP пакете>
	/// \param fileName
	///
	void parse(const std::string& fileName);

	///
	/// \brief setFilter добавляет фильтр выходного потока пакетов по адресу назначения
	/// \param ipv4address адрес назначения
	///
	void setFilter(const pcpp::IPv4Address& ipv4Address);

	///
	/// \brief setFilter добавляет фильтр выходного потока пакетов по порту назначения
	/// \param port порт назначения
	///
	void setFilter(const Port port);

private:
	struct Constant {
		static const Port invalidPort = 0;
		struct Formatting {
			static const auto minimumWidthOfHostField = 15;
			static const auto minimumWidthOfMicrosecondField = 6;
			static const auto minimumWidthOfPortField = 5;
		};
	};

	static std::string timevalToString(const timeval& tv);

	pcpp::IPv4Address _addressToPrint = std::string("");
	Port _portToPrint = Constant::invalidPort;

};

#endif // PCAPPARSER_H
