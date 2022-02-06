using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;

namespace YaraFileCheckerLib;

public class DefaultConfig
{
    public const int FileSizeLimitDefault = 2048;
    public const int ArchiveDepthLimitDefault = 10;
    public const int FilesCountLimitDefault = 10;
    public const int DangerousThresholdDefault = 100;
    public const int ProcessingTimeLimitDefault = 10000;
    public const bool ScanArchivesDefault = true;
    public const bool FastScanDefault = false;
    public const int YaraRuleScoreDefault = 10;

    public static readonly string currentDirectoryPath = Path.GetDirectoryName(
                                                             Uri.UnescapeDataString(new UriBuilder(Assembly.GetExecutingAssembly().CodeBase).Path))
                                                         ?? AppDomain.CurrentDomain.BaseDirectory;

    public static readonly IEnumerable<string> ArchiveFileTypesDefault = new[]
    {
        "*.7z",
        "*.ar",
        "*.arj",
        "*.bz2",
        "*.bzip2",
        "*.cab",
        "*.chm",
        "*.cpio",
        "*.cramfs",
        "*.dmg",
        "*.ext",
        "*.fat",
        "*.gpt",
        "*.gz",
        "*.gzip",
        "*.hfs",
        "*.ihex",
        "*.iso",
        "*.lzh",
        "*.lzma",
        "*.mbr",
        "*.msi",
        "*.nsis",
        "*.ntfs",
        "*.qcow2",
        "*.rar",
        "*.rpm",
        "*.squashfs",
        "*.tar",
        "*.udf",
        "*.uefi",
        "*.vdi",
        "*.vhd",
        "*.vmdk",
        "*.wim",
        "*.xar",
        "*.xz",
        "*.z",
        "*.zip"
    };

    public static readonly IEnumerable<string> ExecutableExtensionsDefault = new[]
    {
        "*.exe",
        "*.bat",
        "*.ps1"
    };
}