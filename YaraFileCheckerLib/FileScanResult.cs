using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using libyaraNET;

namespace YaraFileCheckerLib;

public class FileScanResult: IFileScanResult
{
    public FileScanResult()
    {
        ScanSuccessful = true;
        YaraResults = new List<ScanResult>();
        AdditionalInfo = null;
        FileName = null;
        MatchedRules = new List<string>();
        Executable = false;
        TotalScore = 0;
        Dangerous = false;
    }

    public FileScanResult(string fileName, ScanConfig scanConfig)
    {
        ScanSuccessful = true;
        YaraResults = new List<ScanResult>();
        AdditionalInfo = null;
        FileName = fileName;
        MatchedRules = new List<string>();
        Executable = FileChecker.IsExecutable(fileName, scanConfig);
        TotalScore = 0;
        Dangerous = false;
    }

    public override string ToString()
    {
        return $"{FileName}:"
               + $"Dangerous=>{Dangerous},"
               + $"Executable:{Executable},"
               + $"ScanSuccessful:{ScanSuccessful},"
               + $"AdditionalInfo=>{AdditionalInfo},"
               + $"MatchedRules=>{string.Join("|", MatchedRules.Where(s => !string.IsNullOrEmpty(s)).Distinct())}/"
               + $"{MatchedRules.Count}/{TotalScore}";
    }

    public FileScanResult(List<ScanResult> scanResults, ScanConfig scanConfig, string fileName = null)
    {
        ScanSuccessful = true;
        YaraResults = scanResults;
        AdditionalInfo = null;
        FileName = fileName;
        MatchedRules = new List<string>(YaraResults.Select(x => x.MatchingRule.Identifier).Distinct().ToList());
        TotalScore = 0;
        Dangerous = false;

        foreach (var yaraRes in scanResults)
        {
            if (yaraRes.MatchingRule.Tags.Exists(x => Regex.IsMatch(x, "^score_(\\d)+$")))
            {
                TotalScore += int.Parse(yaraRes.MatchingRule.Tags.Find(x => Regex.IsMatch(x, "score_(\\d)+")).Replace("score_", ""));
            }
            else
            {
                TotalScore += scanConfig.YaraRuleScoreDefault;
            }
        }

        Dangerous = TotalScore >= scanConfig.DangerousThreshold;
        Executable = FileChecker.IsExecutable(scanResults) || FileChecker.IsExecutable(fileName, scanConfig);
    }

    public FileScanResult(bool scanSuccessful, string additionalInfo, string fileName = null)
    {
        ScanSuccessful = scanSuccessful;
        YaraResults = new List<ScanResult>();
        AdditionalInfo = additionalInfo;
        FileName = fileName;
        MatchedRules = new List<string>();
        Executable = false;
        TotalScore = 0;
        Dangerous = false;
    }

    public bool ScanSuccessful { get; set; }
    public List<ScanResult> YaraResults { get; set; }
    public string AdditionalInfo { get; set; }
    public string FileName { get; set; }
    public List<string> MatchedRules { get; set; }
    public bool Executable { get; set; }
    public bool Dangerous { get; set; }
    public int TotalScore { get; set; }

/*
    public static FileScanResult ConcatFileScanResults(List<FileScanResult> fsrList, ScanConfig scanConfig)
    {
        // я надеюсь его использовать позже, хай остается
        var result = new FileScanResult
        {
            AdditionalInfo = string.Join("|", fsrList.Select
                                                         (x => x.AdditionalInfo)
                                                     .Where(s => !string.IsNullOrEmpty(s))),
            ScanSuccessful = fsrList.Any(x => x.ScanSuccessful)
        };
        result.YaraResults.AddRange(fsrList.SelectMany(x => x.YaraResults));
        result.MatchedRules = new List<string>();
        result.MatchedRules.AddRange(fsrList.SelectMany(x => x.MatchedRules));
        result.Executable = fsrList.Any(x => x.Executable);
        result.TotalScore = fsrList.Sum(x => x.TotalScore);
        result.Dangerous = fsrList.Any(x => x.Dangerous);
        result.Dangerous = result.Dangerous || result.TotalScore >= scanConfig.DangerousThreshold;
        return result;
    }
*/

    public static FileScanResult ConcatFileScanResults(FileScanResult fsr1, FileScanResult fsr2, ScanConfig scanConfig)
    {
        var result = new FileScanResult
        {
            AdditionalInfo = string.Join("|", new[] { fsr1.AdditionalInfo, fsr2.AdditionalInfo }
                                              .Where(s => !string.IsNullOrEmpty(s))
                                              .Distinct()),
            ScanSuccessful = fsr1.ScanSuccessful && fsr2.ScanSuccessful
        };
        result.YaraResults.AddRange(fsr1.YaraResults);
        result.YaraResults.AddRange(fsr2.YaraResults);
        result.YaraResults = result.YaraResults.Distinct().ToList();
        result.MatchedRules = new List<string>();
        result.MatchedRules.AddRange(fsr1.MatchedRules);
        result.MatchedRules.AddRange(fsr2.MatchedRules);
        if (fsr1.FileName == fsr2.FileName)
        {
            result.FileName = fsr1.FileName;
        }
        else
        {
            result.FileName = string.Join("|", new[] { fsr1.FileName, fsr2.FileName }
                                              .Where(s => !string.IsNullOrEmpty(s)));
        }

        result.Executable = fsr1.Executable || fsr2.Executable;
        result.TotalScore = fsr1.TotalScore + fsr2.TotalScore;
        result.Dangerous = fsr1.Dangerous || fsr2.Dangerous;
        result.Dangerous = result.Dangerous || result.TotalScore >= scanConfig.DangerousThreshold;
        return result;
    }
}