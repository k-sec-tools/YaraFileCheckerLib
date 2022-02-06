using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using libyaraNET;
using SevenZip;
using Vostok.Logging.Abstractions;

namespace YaraFileCheckerLib;

public partial class FileChecker : IFileChecker
{
    public static bool IsExecutable(List<ScanResult> scanResults)
        => scanResults.Any(r => r.MatchingRule.Tags.Any(t => t == "executable"));

    public static bool IsExecutable(string fileName, ScanConfig scanConfig)
        => NameCheckByWildcardList(fileName, scanConfig.ExecutableExtensions);

    public FileScanResult CheckFile(FileObject fileObject, ScanConfig scanConfig)
        => ProcessFileBytes(fileObject, scanConfig);

    public FileScanResult CheckFile(FileObject fileObject, ScanMode mode, ILog log)
    {
        using var scanConfig = new ScanConfig(true, mode);
        scanConfig.Log = log;
        scanConfig.Log.Info($"Start checking {fileObject.Name}");
        var sw = Stopwatch.StartNew();
        var res = CheckFile(fileObject, scanConfig);
        scanConfig.Log.Info($"Finished checking {fileObject.Name}, " +
                            $"files size:{GetSizeInMemory(fileObject.Bytes.Length)}," +
                            $" time spent: {sw.ElapsedMilliseconds}ms, result: {res}");
        sw.Stop();
        return res;
    }

    

    public FileScanResult ProcessArchiveBytes(FileObject fileObject, ScanConfig scanConfig)
    {
        var result = new FileScanResult();
        scanConfig.ProcessingLimits.ArchiveDepth += 1;

        if (scanConfig.ProcessingLimits.ArchiveDepth <= scanConfig.ArchiveDepthLimit)
        {
            try
            {
                using var abms = new MemoryStream(fileObject.Bytes);
                using var extractor = new SevenZipExtractor(abms);
                if (ExtractorCheck(extractor, scanConfig))
                {
                    result = ArchiveBytesProcessing(fileObject, scanConfig);
                }
            }
            catch (Exception ex)
            {
                scanConfig.Log.Error(ex,$"{fileObject.Name}: Cant process as archive");
                // ignored
            }
        }
        else
        {
            result = new FileScanResult(false, $"{fileObject.Name} processing stopped," + $" archive depth limit {scanConfig.ArchiveDepthLimit} reached",
                                        fileObject.Name);
        }

        return result;
    }

    public FileScanResult CheckFile(FileObject fileObject, string scanProfileName)
    {
        using var scanConfig = new ScanConfig(true, scanProfileName);
        return CheckFile(fileObject, scanConfig);
    }

    private static bool ScanObject(FileObject fileObject,
                                   ScanConfig scanConfig,
                                   string ruleFile,
                                   ref FileScanResult fileScanResult)
    {
        try
        {
            using var ctx = new YaraContext();
            using var compiler = new Compiler();
            compiler.AddRuleFile(ruleFile);
            using var rules = compiler.GetRules();
            var scanner = new Scanner();

            var scanRes = scanner.ScanMemory(fileObject.Bytes, rules,
                scanConfig.FastScan ? ScanFlags.Fast : ScanFlags.None);
            var tempResult = new FileScanResult(scanRes, scanConfig, fileObject.Name);

            fileScanResult = FileScanResult.ConcatFileScanResults(fileScanResult, tempResult, scanConfig);
        }
        catch (Exception ex)
        {
            scanConfig.Log.Error(ex, $"Object {fileObject.Name} scan failed");
            fileScanResult.ScanSuccessful = false;
        }

        return fileScanResult.Dangerous;
    }

    private static string GenerateLimitText(string fileName, ScanConfig scanConfig)
    {
        var result = $"{fileName} processing stopped, limits reached: "
            + $"total size: {scanConfig.ProcessingLimits.TotalBytes / 1024}kb, limit: {scanConfig.FileSizeLimitKb}kb;"
            + $"archive depth: {scanConfig.ProcessingLimits.ArchiveDepth}, limit: {scanConfig.ArchiveDepthLimit};"
            + $"files count: {scanConfig.ProcessingLimits.FilesCount}, limit: {scanConfig.FilesCountLimit};"
            + $"danger score: {scanConfig.ProcessingLimits.TotalScore}, limit: {scanConfig.DangerousThreshold}.";
        scanConfig.Log.Info(result);
        return result;
    } 

    private static bool IsAnyLimitReached(ScanConfig scanConfig)
        => scanConfig.FastScan && scanConfig.DangerousThreshold <= scanConfig.ProcessingLimits.TotalScore
           || !(scanConfig.ProcessingTimeLimitMs > scanConfig.ProcessingLimits.StopWatch.ElapsedMilliseconds
                && scanConfig.ProcessingLimits.TotalBytes <= scanConfig.FileSizeLimitKb * 1024
                && scanConfig.ProcessingLimits.FilesCount <= scanConfig.FilesCountLimit);

    private FileScanResult GetYaraScanResults(FileObject fileObject, ScanConfig scanConfig)
    {
        var fileScanResult = new FileScanResult(fileObject.Name, scanConfig);
        foreach (var ruleFile in scanConfig.YaraRules)
        {
            try
            {
                if (!IsAnyLimitReached(scanConfig))
                {
                    if (ScanObject(fileObject, scanConfig, ruleFile, ref fileScanResult))
                    {
                        break;
                    }
                }
                else
                {
                    var additionalInfo = $"Processing {fileObject.Name} stoppped" + $" - Time limit {scanConfig.ProcessingTimeLimitMs}ms reached";
                    scanConfig.Log.Info(additionalInfo);
                    var newFileScanResult = new FileScanResult(false, additionalInfo, fileObject.Name);
                    fileScanResult = FileScanResult.ConcatFileScanResults(fileScanResult, newFileScanResult, scanConfig);
                    break;
                }
            }
            catch (Exception ex)
            {
                var additionalInfo = $"Yara scan failed, {fileObject.Name}:{ex.Message}";
                var newFileScanResult = new FileScanResult(false, additionalInfo, fileObject.Name);
                fileScanResult = FileScanResult.ConcatFileScanResults(fileScanResult, newFileScanResult, scanConfig);
                scanConfig.Log.Error(ex, additionalInfo);
            }
        }

        return fileScanResult;
    }

    private FileScanResult ProcessFileBytes(FileObject fileObject, ScanConfig scanConfig)
    {
        scanConfig.ProcessingLimits.FilesCount += 1;
        var result = new FileScanResult(fileObject.Name, scanConfig);

        scanConfig.ProcessingLimits.TotalBytes += fileObject.Bytes.Length;
        if (!IsAnyLimitReached(scanConfig))
        {
            try
            {
                //YaraChecking
                var yaraResults = GetYaraScanResults(fileObject, scanConfig);
                result = FileScanResult.ConcatFileScanResults(yaraResults, result,
                                                              scanConfig);
                if (result.YaraResults.Any(x => x.Matches.Count > 0))
                    //ArchiveChecking
                {
                    if (!IsAnyLimitReached(scanConfig))
                    {
                        if (IsArchive(fileObject, scanConfig))
                        {
                            var processingResult = ProcessArchiveBytes(fileObject, scanConfig);
                            result = FileScanResult.ConcatFileScanResults(result, processingResult, scanConfig);
                        }
                    }
                    else
                    {
                        var limText = GenerateLimitText(fileObject.Name, scanConfig);
                        var tempResult = new FileScanResult(false, limText, fileObject.Name);
                        result = FileScanResult.ConcatFileScanResults(result, tempResult, scanConfig);
                    }
                }
            }
            catch (Exception ex)
            {
                scanConfig.Log.Error(ex, $"Cant process {fileObject.Name}");
                result = FileScanResult.ConcatFileScanResults(result,
                                                              new FileScanResult(false, $"Error while processing {fileObject.Name}: {ex.Message}",
                                                                                 fileObject.Name), scanConfig);
            }
        }
        else
        {
            result = FileScanResult.ConcatFileScanResults(result,
                                                          new FileScanResult(false, GenerateLimitText(fileObject.Name, scanConfig), fileObject.Name),
                                                          scanConfig);
        }

        result.YaraResults = result.YaraResults.Distinct().Where(x => x.Matches.Count > 0).ToList();
        return result;
    }

    private FileScanResult ArchiveBytesProcessing(FileObject fileObject, ScanConfig scanConfig)
    {
        var result = new FileScanResult();
        using var archiveStream = new MemoryStream(fileObject.Bytes);
        using var extractor = new SevenZipExtractor(archiveStream);
        result = ExtractorProcessing(fileObject.Name, extractor, scanConfig);

        return result;
    }

    private FileScanResult ExtractorProcessing(string fileName,
                                               SevenZipExtractor extractor,
                                               ScanConfig scanConfig)
    {
        var result = new FileScanResult();
        for (var cnt = 0; cnt <= extractor.FilesCount - 1; cnt++)
        {
            if (!IsAnyLimitReached(scanConfig))
            {
                var entrySize = Convert.ToInt32(extractor.ArchiveFileData[cnt].Size);
                var entryName = extractor.ArchiveFileData[cnt].FileName;
                scanConfig.ProcessingLimits.TotalBytes += entrySize;
                if (entrySize / 1024 <= scanConfig.FileSizeLimitKb && scanConfig.ProcessingLimits.TotalBytes / 1024 <= scanConfig.FileSizeLimitKb)
                {
                    using (var stream = new MemoryStream())
                    {
                        extractor.ExtractFile(cnt, stream);
                        result = FileScanResult.ConcatFileScanResults(result, ProcessArchiveEntry(
                                                                          new FileObject(StreamToByteArray(stream), entryName), scanConfig), scanConfig);
                    }

                    if (scanConfig.FastScan && result.Dangerous)
                    {
                        break;
                    }
                }
                else
                {
                    result = FileScanResult.ConcatFileScanResults(result,
                                                                  new FileScanResult(false,
                                                                                     $"{fileName} processing stopped, file size limit {scanConfig.FileSizeLimitKb} reached",
                                                                                     fileName), scanConfig);
                    break;
                }
            }
            else
            {
                result = FileScanResult.ConcatFileScanResults(result,
                                                              new FileScanResult(false, GenerateLimitText(fileName, scanConfig), fileName),
                                                              scanConfig);
                break;
            }
        }

        return result;
    }

    private FileScanResult ProcessArchiveEntry(FileObject fileObject, ScanConfig scanConfig)
        => scanConfig.FileSizeLimitKb > fileObject.Bytes.Length / 1024
           && scanConfig.ProcessingLimits.ArchiveDepth <= scanConfig.ArchiveDepthLimit
           && scanConfig.ProcessingLimits.FilesCount <= scanConfig.FilesCountLimit
            ? ProcessFileBytes(fileObject, scanConfig)
            : new FileScanResult(false, GenerateLimitText(fileObject.Name, scanConfig), fileObject.Name);
}