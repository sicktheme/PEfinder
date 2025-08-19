#pragma once

#define IMAGE_FILE_RELOCS_STRIPPED 0x0001			// Windows CE/Windows NT. Означает что файл не содержит таблицы релокаций
#define IMAGE_FILE_EXECUTABLE_IMAGE 0x0002			// Файл является исполняемым. Помогает чтоб отличить EXE/DLL от других форматов
#define IMAGE_FILE_LINE_NUMS_STRIPPED 0x0004		// NULL
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED 0x0008		// NULL
#define IMAGE_FILE_AGGRESSIVE_WS_TRIM 0x0010		// NULL
#define IMAGE_FILE_LARGE_ADDRESS_AWARE 0x0020		// > 2G addr. Если флаг есть то 32-битный процесс может использовать до 4 ГБ памяти
//reserve 0x0040
#define IMAGE_FILE_BYTES_REVERSED_LO 0x0080			// NULL
#define IMAGE_FILE_32BIT_MACHINE 0x0100				// 32-architecture word
#define IMAGE_FILE_DEBUG_STRIPPED 0x0200			// Сведения об отладке удаляются из файла образа
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP 0x0400	// Если образ находится на носителях, то скопировать его и загрузить в файл подкачки
#define IMAGE_FILE_NET_RUN_FROM_SWAP 0x0800			// Если образ находится на сетевом носителе, загрузить его и скопировать в файл буфера
#define IMAGE_FILE_SYSTEM 0x1000					// Файл является системным (например .sys(драйвер)). ОС не будет пытаться загрузить его как обычный EXE
#define IMAGE_FILE_DLL 0x2000						// Файл является DLL. Загрузчик проверяет флаг, чтоб понять нужно ли вызывать DllMain
#define IMAGE_FILE_UP_SYSTEM_ONLY 0x4000			// Выполняется только на ПК с юнипроцессором
#define IMAGE_FILE_BYTES_REVERSED_HI 0x8000			// NULL