//---------------------------------------------------------------
#include <ctime>
#include <iomanip>
#include <sstream>
//---------------------------------------------------------------
#include <IPv4Layer.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <UdpLayer.h>
//---------------------------------------------------------------
#include "PcapParser.h"
//---------------------------------------------------------------

/***************************************************************/
void PcapParser::parse(const std::string &fileName)
{
	DEB("Начало парсинга файла=" << fileName);
	pcpp::PcapFileReaderDevice rdevice(fileName.c_str());
	//berkley packet filter
	std::string bpfString = "udp and ip";
	pcpp::RawPacket rawPacket;

	if(_addressToPrint.isValid())
	{
		DEB("_addressToPrint валиден-добавляю к фильтрующей строке:" << _addressToPrint.toString());
		bpfString += " and ip dst host " + _addressToPrint.toString();
	}

	if(_portToPrint != Constant::invalidPort)
	{
		DEB("_portToPrint валиден-добавляю к фильтрующей строке:" << _portToPrint);
		bpfString += " and dst port " + std::to_string(_portToPrint);
	}

	DEB("Попытка открыть файл=" << fileName << "...");
	if(!rdevice.open())
		throw std::runtime_error(fileName + " открыть не удалось");

	DEB("...удачна");
	DEB("установка bpf строки=" << bpfString);
	if(!rdevice.setFilter(bpfString))
		throw std::runtime_error("bpf сформирован некорректно");

	DEB("Предустановки выполнены; переход к парсингу пакетов");
	while(rdevice.getNextPacket(rawPacket))
	{
		pcpp::Packet packet(&rawPacket);
		const auto& ipv4Layer = packet.getLayerOfType<pcpp::IPv4Layer>();
		const auto& udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
		const auto timestamp = timevalToString(rawPacket.getPacketTimeStamp());
		pcpp::IPv4Address dstIpAddress = std::string("");
		const pcpp::udphdr* udpHeader = nullptr;

		// null используется из-за док-ции библиотеки. нуллптр не всегда равен нуллу и применять его здесь было бы опасно
		if(ipv4Layer == NULL || udpLayer == NULL)
			throw std::runtime_error("В пакете неправильный стек протоколов. Значит ошибка в фильтрации");

		dstIpAddress = ipv4Layer->getDstIpAddress();

		if(!dstIpAddress.isValid())
		{
			ERR("Адрес назначения некорректен. ошибка?");
			continue;
		}

		udpHeader = udpLayer->getUdpHeader();

		if(!udpHeader)
		{
			ERR("Не удалось получить заголовок удп");
			continue;
		}

		{
			const auto readableDstPort = ntohs(udpHeader->portDst);
			const auto readablePayLoad = ntohs(udpHeader->length) - udpLayer->getHeaderLen();

			OUT('<' << timestamp << "> " <<
				std::setw(Constant::Formatting::minimumWidthOfHostField) << std::left << dstIpAddress.toString() << " " <<
				std::setw(Constant::Formatting::minimumWidthOfPortField) << std::left << readableDstPort << " " <<
				readablePayLoad);
		}
	}

	DEB("Завершение парсинга");
}

/***************************************************************/
void PcapParser::setFilter(const pcpp::IPv4Address &ipv4Address)
{
	DEB("Добавление фильтра по адресу=" << ipv4Address.toString());
	_addressToPrint = ipv4Address;
}

/***************************************************************/
void PcapParser::setFilter(const Port port)
{
	DEB("Добавление фильтра по порту=" << port);
	_portToPrint = port;
}

/***************************************************************/
std::string PcapParser::timevalToString(const timeval &tv)
{
	std::stringstream ss;

	ss << std::put_time(std::localtime(&tv.tv_sec), "%F %T") << "." << std::setw(Constant::Formatting::minimumWidthOfMicrosecondField) << std::left << std::to_string(tv.tv_usec);

	return ss.str();
}
