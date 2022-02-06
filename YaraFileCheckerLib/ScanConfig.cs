using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using SevenZip;
using Vostok.Logging.Abstractions;
using YamlDotNet.Serialization;

namespace YaraFileCheckerLib;

public class ScanConfig : IDisposable
{
    public Limits ProcessingLimits = new();

    public ScanConfig()
    {
    }

   public ScanConfig(bool useDefaultConfig, string profileName)
    {
        Initialize(profileName, 0);
    }

    public ScanConfig(bool useDefaultConfig, FileChecker.ScanMode mode)
    {
        Initialize(null, mode);
    }

    //используется при чтении yaml, неочевидно но факт
    public ScanConfig(string configFilePath = null)
    {
        Initialize();
    }

    public ILog Log { get; set; }
    public int FileSizeLimitKb { get; set; }
    public int ArchiveDepthLimit { get; set; }

    public long ProcessingTimeLimitMs { get; set; }

    public List<string> YaraRules { get; set; }
    public int YaraRuleScoreDefault { get; set; }
    public bool ScanArchives { get; set; }
    public int FilesCountLimit { get; set; }
    public bool FastScan { get; set; }
    public int DangerousThreshold { get; set; }
    public IEnumerable<string> ArchiveFileTypes { get; set; }
    public IEnumerable<string> ExecutableExtensions { get; set; }

/*
    public static bool IsDirectory(string path)
        => Directory.Exists(path);
*/

    public static bool IsFile(string path)
        => File.Exists(path);

    public static List<string> GetFilesList(string path, SearchOption searchOption = SearchOption.AllDirectories, string template = "*") 
        => Directory.GetFileSystemEntries(path, template, searchOption).ToList();

        
    

    public void Dispose() => ProcessingLimits?.Dispose();

    private static string CombinePathWithResources(string fileName)
        => Path.Combine(DefaultConfig.currentDirectoryPath, "Resources", fileName);

    private static IEnumerable<string> GetRules(string profileName, string scanModeModificator, string yaraFolderPath)
    {
        var path = scanModeModificator == null ? yaraFolderPath : Path.Combine(yaraFolderPath, scanModeModificator);

        return profileName == null
            ? GetFilesList(path, SearchOption.TopDirectoryOnly, "*_index.yar").ToArray()
            : Directory.GetFileSystemEntries(path, $"*{profileName}_index.yar");
    }

    private void Initialize(string profileName = null, FileChecker.ScanMode scanMode = FileChecker.ScanMode.Mid)
    {
        try
        {
            FileSizeLimitKb = DefaultConfig.FileSizeLimitDefault;
            ArchiveDepthLimit = DefaultConfig.ArchiveDepthLimitDefault;
            ProcessingTimeLimitMs = DefaultConfig.ProcessingTimeLimitDefault;
            ScanArchives = DefaultConfig.ScanArchivesDefault;
            FastScan = DefaultConfig.FastScanDefault;
            ArchiveFileTypes = DefaultConfig.ArchiveFileTypesDefault;
            YaraRules = new List<string>();
            YaraRuleScoreDefault = DefaultConfig.YaraRuleScoreDefault;
            DangerousThreshold = DefaultConfig.DangerousThresholdDefault;
            FilesCountLimit = DefaultConfig.FilesCountLimitDefault;
            ExecutableExtensions = DefaultConfig.ExecutableExtensionsDefault;

            string configPath;
            if (profileName == null)
            {
                configPath = CombinePathWithResources("config.yaml");
            }
            else
            {
                var profileConfigPath = CombinePathWithResources($"{profileName}_config.yaml");
                configPath = !IsFile(profileConfigPath)
                    ? CombinePathWithResources("config.yaml")
                    : profileConfigPath;
            }

            var sevenZipPath = CombinePathWithResources("7z.dll");
            var yaraFolderPath = CombinePathWithResources("YaraRules");

            if (IsFile(sevenZipPath))
            {
                SevenZipBase.SetLibraryPath(sevenZipPath);
            }

            if (IsFile(configPath))
            {
                using var reader = new StreamReader(configPath, Encoding.UTF8, true);
                var cc = new DeserializerBuilder().Build();
                var c = cc.Deserialize<ScanConfig>(reader);
                ArchiveDepthLimit = c.ArchiveDepthLimit;
                ArchiveFileTypes = c.ArchiveFileTypes;
                FastScan = c.FastScan;
                FileSizeLimitKb = c.FileSizeLimitKb;
                ProcessingTimeLimitMs = c.ProcessingTimeLimitMs;
                ScanArchives = c.ScanArchives;
                FilesCountLimit = c.FilesCountLimit;
                ExecutableExtensions = c.ExecutableExtensions;
                YaraRuleScoreDefault = c.YaraRuleScoreDefault;
                DangerousThreshold = c.DangerousThreshold;
            }

            switch (scanMode)
            {
                case FileChecker.ScanMode.Custom:
                    YaraRules.AddRange(GetRules(profileName, "Custom", yaraFolderPath));
                    break;
                case FileChecker.ScanMode.Lite:
                    YaraRules.AddRange(GetRules(profileName, "Lite", yaraFolderPath));
                    break;
                case FileChecker.ScanMode.Mid:
                    YaraRules.AddRange(GetRules(profileName, "Lite", yaraFolderPath));
                    YaraRules.AddRange(GetRules(profileName, "Mid", yaraFolderPath));
                    break;
                case FileChecker.ScanMode.Hard:
                    YaraRules.AddRange(GetRules(profileName, "Lite", yaraFolderPath));
                    YaraRules.AddRange(GetRules(profileName, "Mid", yaraFolderPath));
                    YaraRules.AddRange(GetRules(profileName, "Hard", yaraFolderPath));
                    break;
            }

            if (YaraRules.Count == 0)
            {
                throw new Exception($"No Yara rules found with pattern .*({profileName})(_index.yar)$");
            }
        }
        catch (Exception ex)
        {
            throw new Exception($"Failed getting configuration: {ex.Message}");
        }
    }
}