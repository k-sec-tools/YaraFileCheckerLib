using System;
using System.Diagnostics;

namespace YaraFileCheckerLib;

public class Limits : IDisposable
{
    public Limits() => StopWatch = Stopwatch.StartNew();

    public Stopwatch StopWatch { get; set; }
    public int TotalBytes { get; set; }
    public int ArchiveDepth { get; set; }
    public int FilesCount { get; set; }
    public int TotalScore { get; set; }

    public void Dispose()
    {
        StopWatch.Stop();
    }
}