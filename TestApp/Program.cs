using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using YaraFileCheckerLib;
using Vostok.Logging.Abstractions;
using Vostok.Logging.File;
using Vostok.Logging.File.Configuration;

namespace TestApp;

internal class Program
{
    public static string FilesFolder = $@"{Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)}\Samples\VirusShare";

    public static byte[] ReadFileBytes(string filePath)
    {
        byte[] fileData = null;

        using (var fs = File.OpenRead(filePath))
        {
            using (var binaryReader = new BinaryReader(fs))
            {
                fileData = binaryReader.ReadBytes((int)fs.Length);
            }
        }

        return fileData;
    }

    public static List<string> GetFilesInFolder(string path)
        => Directory.GetFiles(path, "*", SearchOption.AllDirectories).ToList();

    public static string GetSizeInMemory(long bytesize)
    {
        string[] sizes = { "B", "KB", "MB", "GB", "TB" };
        var len = Convert.ToDouble(bytesize);
        var order = 0;
        while (len >= 1024D && order < sizes.Length - 1)
        {
            order++;
            len /= 1024;
        }

        return string.Format(CultureInfo.CurrentCulture, "{0:0.##} {1}", len, sizes[order]);
    }

    private static void Main(string[] args)
    {
        FilesFolder = $"{Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)}\\currscan";

        var fls = new FileLogSettings();
        fls.FilePath = "scanlog/checker.log";
        var log = new FileLog(fls);
        //var log = new SynchronousConsoleLog();

        var sw = new Stopwatch();
        string folder = null;
        if (args.Length > 0)
        {
            folder = args[0];
        }

        if (folder == null)
        {
            folder = FilesFolder;
        }

        var stat05 = new Statistics();
        var stat1 = new Statistics();
        var stat10 = new Statistics();
        var stat50 = new Statistics();
        var stat100 = new Statistics();

        foreach (var sampleFilePath in GetFilesInFolder(folder))
        {
            try
            {
                sw.Start();
                var ss = new FileChecker();
                var fileBytes = ReadFileBytes(sampleFilePath);
                var fo = new FileObject(fileBytes, sampleFilePath);
                var result = ss.CheckFile(fo, FileChecker.ScanMode.Mid, log);
                sw.Stop();

                if (result.MatchedRules.Count > 0)
                {
                    log.Info($"{result.FileName}:"
                             + $"D=>{result.Dangerous},"
                             + $"E:{result.Executable},"
                             + $"S:{result.ScanSuccessful},"
                             + $"A=>{result.AdditionalInfo},"
                             +
                             //$"\r\nY =>{string.Join("|", result.YaraResults.SelectMany(x => x.Matches.Select(y => y.Key)))}" +
                             $"M=>{string.Join("|", result.MatchedRules.Where(s => !string.IsNullOrEmpty(s)).Distinct())}/"
                             + $"{result.MatchedRules.Count}/{result.TotalScore},"
                             + $"T => {sw.Elapsed},"
                             + $"S=> {GetSizeInMemory(fileBytes.Length)}"
                    );
                }

                sw.Reset();
            }
            catch (Exception ex)
            {
                log.Error(ex.Message);
            }
        }

        log.Info($"average: 0.5=>{Statistics.StaticsticsToString(stat05)}, 1=> {Statistics.StaticsticsToString(stat1)}"
                 + $", 10=>{Statistics.StaticsticsToString(stat10)}, "
                 + $"50=>{Statistics.StaticsticsToString(stat50)}, 100=>{Statistics.StaticsticsToString(stat100)}");
        if (sw.IsRunning)
        {
            sw.Stop();
        }
    }

    private void ScanByteArray(byte[] byteArray, string fileName = null, string profileName = null)
    {
        var fileCheckerInstance = new FileChecker();
        var fileObject = new FileObject(byteArray, fileName);
        var scanResult = fileCheckerInstance.CheckFile(fileObject, profileName);
        Console.WriteLine($"{scanResult.FileName} processed:"
                          + $"successful=>{scanResult.ScanSuccessful},"
                          + $"matches found=>{scanResult.MatchedRules.Count > 0},"
                          + $"additional info=>{scanResult.AdditionalInfo ?? "No Info"},"
                          + $"yara matches=>{string.Join("|", scanResult.MatchedRules.Where(s => !string.IsNullOrEmpty(s)))}"
        );
    }

    private void ScanByteArrayWithCustomProfile(byte[] byteArray, string fileName = null)
    {
        var fileCheckerInstance = new FileChecker();
        var fileObject = new FileObject(byteArray, fileName);

        using var scanConfiguration = new ScanConfig();

        scanConfiguration.FileSizeLimitKb = 2048; // ограничение: ограничение суммарного размера исследуемых файлов (в т.ч. в архиве)
        scanConfiguration.ArchiveDepthLimit = 1; // ограничение: сколько вложенных архивов можно проверять
        scanConfiguration.ProcessingTimeLimitMs = 10000; // ограничение: 
        scanConfiguration.FilesCountLimit = 10; // ограничение: сколько файлов в архиве можно проверять
        scanConfiguration.ScanArchives = true; // настройка: сканировать ли архивы. необходима библиотека 7z.dll в папке Resources рядом с FileCheckerLib.dll или в Program Files
        scanConfiguration.FastScan = false; // настройка: быстрое сканирование. если True, при обнаружении первых совпадений Yara дальнейшая обработка прекращается. рекомендуется для ускорения сканирования
        scanConfiguration.ArchiveFileTypes = new List<string> { "*.7z" /* etc */ }; // расширения файлов архивов. не обязательны
        scanConfiguration.YaraRules = new List<string> { "C:/path/to/files/with/yara/rules" /* etc */ }; // пути до файлов с Yara сигнатурами на диске
        scanConfiguration.ProcessingLimits = new Limits(); // тут содержатся ограничители, необходимые для работы библиотеки

        var scanResult = fileCheckerInstance.CheckFile(fileObject, scanConfiguration);
        Console.WriteLine($"{scanResult.FileName} processed:"
                          + $"successful=>{scanResult.ScanSuccessful},"
                          + $"matches found=>{scanResult.MatchedRules.Count > 0},"
                          + $"additional info=>{scanResult.AdditionalInfo ?? "No Info"},"
                          + $"yara matches=>{string.Join("|", scanResult.MatchedRules.Where(s => !string.IsNullOrEmpty(s)))}");
    }

    public class Statistics
    {
        public Dictionary<string, int> MatchedRules;
        public double AverageTime;
        public double MatchedFilesCount;
        public double FilesCount;
        public double TimeSumm;

        public Statistics()
        {
            MatchedRules = new Dictionary<string, int>();
            AverageTime = 0;
            TimeSumm = 0;
            MatchedFilesCount = 0;
            FilesCount = 0;
        }

        public static string StaticsticsToString(Statistics stat)
        {
            string res = null;
            res += $"FilesCount={stat.FilesCount},AvgTime={stat.AverageTime}"
                   + $",MatchedFilesCount={stat.MatchedFilesCount},"
                   + $"MatchedRules={string.Join(",", stat.MatchedRules.Select(s => s.Key + "-" + s.Value).ToArray())} ";

            return res;
        }
    }
}