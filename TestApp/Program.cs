using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using YaraFileCheckerLib;
using Vostok.Logging.Abstractions;
using Vostok.Logging.Console;

namespace TestApp;

internal class Program
{
    public static string FilesFolder = $@"{Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)}\Desktop\Samples\VirusShare";

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
        FilesFolder = $"{Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)}\\Desktop\\currscan";


        var log = new SynchronousConsoleLog();

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
                             + $"M=>{string.Join("|", result.MatchedRules.Where(s => !string.IsNullOrEmpty(s)).Distinct())}/"
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

        scanConfiguration.FileSizeLimitKb = 2048; 
        scanConfiguration.ArchiveDepthLimit = 1; 
        scanConfiguration.ProcessingTimeLimitMs = 10000;
        scanConfiguration.FilesCountLimit = 10; 
        scanConfiguration.ScanArchives = true; 
        scanConfiguration.FastScan = false; 
        scanConfiguration.ArchiveFileTypes = new List<string> { "*.7z" };
        scanConfiguration.YaraRules = new List<string> { "C:/path/to/files/with/yara/rules"  }; 
        scanConfiguration.ProcessingLimits = new Limits();

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