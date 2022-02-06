# yara_file_cheker

the library is designed to make it easier to check potentially malicious files and archives using YARA and make a decision about their harmfulness based on the weights of the detected rules


Config:

* FileSizeLimitKb: !!int // limit: limit of summary checked files size (archived files included)
* ArchiveDepthLimit: !!int // limit: how many nested archives we can check
* ProcessingTimeLimitMs: !!int // limit: how much time to wait until stoping check
* FilesCountLimit: !!int // limit: how many files in archive we can check
* DangerousThreshold: !!int // setting: threshold, after reaching which (based on the sum of the weights of the yara rules that matched during file processing) a decision is made that the file is malicious and processing stops
* YaraRuleScoreDefault: !!int // setting: the weight of the yara rule, unless otherwise specified in the score_ tag
* ScanArchives: !!bool // setting: whether to scan archives. the 7z.dll library is required in the Resources folder
* FastScan: !!bool // setting: yara fast scan
* ArchiveFileTypes: array // setting - list of archive file extensions
* ExecutableExtensions: array// setting - list of executable file extensions

Using:
```
var log = new SynchronousConsoleLog(); 
var fileChecker = new FileChecker();
var fileBytes = ReadFileBytes(sampleFilePath);
var fileObject = new FileObject(fileBytes, sampleFilePath); 
var scanMode = FileChecker.ScanMode.Mid; 
/*
rules from:
- Lite -  Resources/YaraRules/Lite
- Mid - Lite + Resources/YaraRules/Mid
- Hard - Mid + Resources/YaraRules/Hard
- Custom - Resources/YaraRules/custom. 
*/

var result = fileChecker.CheckFile(fileObject, scanMode, log); // FileScanResult со следующими свойствами%
/*
    ScanSuccessful - is scan successful (if not - check AdditionalInfo)
    YaraResults - list of ScanResult https://github.com/microsoft/libyara.NET/blob/master/libyara.NET/ScanResult.h
    AdditionalInfo
    FileName - file name/ filenames delimited with | in case of checking archives
    MatchedRules - list of matched rules names
    Executable - is executable/ archive contains one or more executables
    TotalScore - summ of yara rule scores (from tag score_XXX or from YaraRuleScoreDefault in config)
    Dangerous - is DangerousThreshold reached
*/
```

