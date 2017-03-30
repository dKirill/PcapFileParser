//
//  main.cpp
//  PcapFileParser
//
//  Created by Кирилл Делимбетов on 28.03.17.
//  Copyright © 2017 Кирилл Делимбетов. All rights reserved.
//

//---------------------------------------------------------------
#include <limits>
//---------------------------------------------------------------
#include "cxxopts.hpp"
#include "PcapParser.h"
//---------------------------------------------------------------

namespace Constant {
	namespace Option {
		const std::string help = "help";
		const std::string address = "address";
		const std::string port = "port";

		namespace Positional {
			const std::string fileName = "fileName";
		}
	}

	const std::string correctFilePostfix = ".pcap";
}

/***************************************************************/
bool doesStringEndsWithAnother(std::string const &fullString, std::string const &ending) {
	if (fullString.length() >= ending.length()) {
		return (0 == fullString.compare (fullString.length() - ending.length(), ending.length(), ending));
	} else {
		return false;
	}
}

/***************************************************************/
int main(int argc, char* argv[])
{
	DEB("Начало работы...");
	int ret = -1;

	try
	{
		PcapParser parser;
		cxxopts::Options options(argv[0], "Программа для парсинга .pcap файлов");
		std::string address;
		int32_t port;
		std::string fileName;

		DEB("Добавление возможных опций командной строки");
		options.add_options()
				("h," + Constant::Option::help, "Напечатать помощь")
				("a," + Constant::Option::address, "IPv4 адрес; если опция указана, выводятся только пакеты, отправленые на этот адрес. Опциональный аргумент", cxxopts::value<decltype(address)>(address))
				("p," + Constant::Option::port, "Порт; если опция указана, выводятся только пакеты, отправленые на этот порт. Опциональный аргумент", cxxopts::value<decltype(port)>(port))
				(Constant::Option::Positional::fileName, "Имя файла с расшерением .pcap, которое парсится программой. Обязательный аргумент", cxxopts::value<std::vector<std::string>>())
				;

		DEB("Парсинг аргументов командной строки");
		options.parse_positional( { Constant::Option::Positional::fileName } );
		options.parse(argc, argv);

		// если запрошен хелп, вывод его и выход
		if(options.count(Constant::Option::help))
		{
			OUT(options.help({""}));
		}
		else
		{
			const auto positionalCount = options.count(Constant::Option::Positional::fileName);

			DEB("Извлечение опционального адреса, по которому может идти фильтрация");
			if(options.count(Constant::Option::address))
			{
				DEB("address=" << address);
				pcpp::IPv4Address ipv4(address);

				if(!ipv4.isValid())
					throw std::runtime_error("передан ipv4 адрес некорректного вида");

				parser.setFilter(ipv4);
			}

			DEB("Извлечение опционального порта, по которому может идти фильтрация");
			if(options.count(Constant::Option::port))
			{
				DEB("port=" << port);
				if(std::numeric_limits<Port>::max() < port || std::numeric_limits<Port>::min() > port)
					throw std::runtime_error("передан порт не попадающий в диапазон значений");

				parser.setFilter(port);
			}

			DEB("Извлечение обязательного имени файла, который будет парсится");
			if(positionalCount != 1)
				throw std::runtime_error("Некорректное количество позициональных (без опций) аргументов");
			else
			{
				fileName = options[Constant::Option::Positional::fileName].as<std::vector<std::string>>().at(0);

				if(!doesStringEndsWithAnother(fileName, Constant::correctFilePostfix))
					throw std::runtime_error("Недопустимое расширение файла");

				DEB("имя файла для парсинга=" << fileName);
			}

			DEB("Первоначальные проверки корректности пройдены; запуск парсинга файла");
			parser.parse(fileName);
		}

		DEB("Штатное завершение программы");
		ret = 0;
	}
	catch(const cxxopts::OptionException& e)
	{
		OUT("Ошибка парсинга опций: " << e.what() << "; аварийное завершение");
		ret = 1;
	}
	catch(const std::exception& e)
	{
		OUT("Ошибка выполнения: " << e.what() << "; аварийное завершение");
		ret = 2;
	}
	catch(...)
	{
		OUT("Неизвестная ошибка выполнения; аварийное завершение");
		ret = 3;
	}

	return ret;
}
