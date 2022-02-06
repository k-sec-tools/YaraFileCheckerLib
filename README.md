# file_cheker

конфиг:

* FileSizeLimitKb: !!int // ограничение: ограничение суммарного размера исследуемых файлов (в т.ч. в архиве)
* ArchiveDepthLimit: !!int // ограничение: сколько вложенных архивов можно проверять
* ProcessingTimeLimitMs: !!int // ограничение: сколько милисекунд ждать от библиотеки результатов, прежде чем прервать ее работу
* FilesCountLimit: !!int // ограничение: сколько файлов в архиве можно проверять
* DangerousThreshold: !!int // настройка: порог, после достижения которого (исходя из суммы весов правил yara, которые сматчились при обработке файла) принимается решение о том, что файл вредоносный и обработка прекращается
* YaraRuleScoreDefault: !!int // настройка: удельный вес правила yara, если не указано иное в теге score_
* ScanArchives: !!bool // настройка: сканировать ли архивы. необходима библиотека 7z.dll в папке Resources рядом с FileCheckerLib.dll
* FastScan: !!bool // настройка: быстрое сканирование. если True, при обнаружении первых совпадений Yara дальнейший поиск матчей правила прекращается. рекомендуется для ускорения сканирования
* ArchiveFileTypes: массив // настройка - список расширений файлов архивов
* ExecutableExtensions: массив// настройка - список расширений исполняемых файлов

Использование:
```
var log = new SynchronousConsoleLog(); // любой ILog
var fileChecker = new FileChecker();
var fileBytes = ReadFileBytes(sampleFilePath); // любыми средствами разбираем файл для проверки на массив байт
var fileObject = new FileObject(fileBytes, sampleFilePath); // объект, состоящий из массива байт проверяемого файла и его имени (опционально)
var scanMode = FileChecker.ScanMode.Mid; // режим проверки
/*
Lite - правила из папки Resources/YaraRules/Lite
Mid - Lite + Resources/YaraRules/Mid
Hard - Mid + Resources/YaraRules/Hard
Custom - Resources/YaraRules/custom. 
вкратце суть:
Lite - определить исполняемый ли файл или содержит ли откровенно подозрительные строки (быстро, лучше использовать если надо только определить, исполняемый ли файл)
Mid - кастомный набор правил, для определения уязвимых доков, eicar, наиболее популярной малвари (норм по соотношению быстродействие/качество)
Hard - конвертированная база антивируса ClamAV (медленно и неэффективно)
Custom - если потребуется использовать какой-то очень специфичный набор правил
*/

var result = fileChecker.CheckFile(fileObject, scanMode, log); // FileScanResult со следующими свойствами%
/*
    ScanSuccessful - успешно ли завершено исследование (если нет - вероятно либо достигнут один из лимитов или в процессе скана возникали какие-то ошибки, подробности в AdditionalInfo)
    YaraResults - лист ScanResult https://github.com/microsoft/libyara.NET/blob/master/libyara.NET/ScanResult.h
    AdditionalInfo - сведения об ошибках, возникших в процессе обработки
    FileName - имя файла/файлов через |, если это архив
    MatchedRules - список уникальных названий сматченных правил
    Executable - является ли файл исполняеемым
    TotalScore - сумма весов правил yara, которые сматчились при обработке файла
    Dangerous - принято ли решение, что файл с высокой вероятностью является вредоносным
*/
```

