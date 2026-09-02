window.BENCHMARK_DATA = {
  "lastUpdate": 1788307708114,
  "repoUrl": "https://github.com/cplieger/ci",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "name": "cplieger",
            "username": "cplieger",
            "email": "917744+cplieger@users.noreply.github.com"
          },
          "committer": {
            "name": "Christopher Plieger",
            "username": "cplieger",
            "email": "917744+cplieger@users.noreply.github.com"
          },
          "id": "a66dd3d4479d96bf77d84ed08b78651e2477d1f4",
          "message": "fix: measure the weekly benchmarks instead of reporting an empty run green\n\nThe fanout discovered repos with a jq filter that emits one name per line, then tested enrolment with a space-delimited substring match. A newline is not a space, so every enrolled repo was rejected as not live, the matrix came out empty, the run job skipped on its non-empty guard, and the leg reported success having measured nothing. Confirmed by the absence of a benchmarks branch on all four enrolled repos despite three consecutive green runs.\n\nFlattens the discovery output, then makes the two silent paths fail closed: a hardcoded enrolment list resolving to zero live repos is a defect rather than a weekly state, and an empty matrix now fails instead of skipping the run job. Also guards the HEAD lookup, which had the same unguarded shape that took down the sibling mutation-testing fanout in August.",
          "timestamp": "2026-08-21T11:04:22Z",
          "url": "https://github.com/cplieger/ci/commit/a66dd3d4479d96bf77d84ed08b78651e2477d1f4"
        },
        "date": 1787311169526,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "BenchmarkIsPublicAddr_6to4Embed - B/op",
            "value": 0,
            "range": "± 0.0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_6to4Embed - allocs/op",
            "value": 0,
            "range": "± 0.0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_6to4Embed",
            "value": 120.25,
            "range": "± 2.9",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_CGNAT - B/op",
            "value": 0,
            "range": "± 0.0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_CGNAT - allocs/op",
            "value": 0,
            "range": "± 0.0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_CGNAT",
            "value": 23.245,
            "range": "± 0.64",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_IPv4Mapped - B/op",
            "value": 0,
            "range": "± 0.0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_IPv4Mapped - allocs/op",
            "value": 0,
            "range": "± 0.0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_IPv4Mapped",
            "value": 10.875,
            "range": "± 0.23",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_Loopback - B/op",
            "value": 0,
            "range": "± 0.0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_Loopback - allocs/op",
            "value": 0,
            "range": "± 0.0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_Loopback",
            "value": 7.3745,
            "range": "± 0.338",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PrivateIPv4 - B/op",
            "value": 0,
            "range": "± 0.0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PrivateIPv4 - allocs/op",
            "value": 0,
            "range": "± 0.0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PrivateIPv4",
            "value": 10.255,
            "range": "± 0.26",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv4 - B/op",
            "value": 0,
            "range": "± 0.0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv4 - allocs/op",
            "value": 0,
            "range": "± 0.0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv4",
            "value": 88.035,
            "range": "± 5.62",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv6 - B/op",
            "value": 0,
            "range": "± 0.0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv6 - allocs/op",
            "value": 0,
            "range": "± 0.0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv6",
            "value": 89.945,
            "range": "± 0.73",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_BareHostname - B/op",
            "value": 368,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateHost_BareHostname - allocs/op",
            "value": 8,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateHost_BareHostname",
            "value": 4489,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateHost_DottedHostname - B/op",
            "value": 240,
            "range": "± 0.0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_DottedHostname - allocs/op",
            "value": 3,
            "range": "± 0.0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_DottedHostname",
            "value": 462.05,
            "range": "± 21.4",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_Localhost - B/op",
            "value": 240,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateHost_Localhost - allocs/op",
            "value": 4,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateHost_Localhost",
            "value": 3855,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateHost_PrivateIP - B/op",
            "value": 304,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateHost_PrivateIP - allocs/op",
            "value": 6,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateHost_PrivateIP",
            "value": 4240,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateHost_PublicIP - B/op",
            "value": 144,
            "range": "± 0.0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_PublicIP - allocs/op",
            "value": 1,
            "range": "± 0.0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_PublicIP",
            "value": 419.95,
            "range": "± 3.5",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_BadScheme - B/op",
            "value": 288,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateURL_BadScheme - allocs/op",
            "value": 5,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateURL_BadScheme",
            "value": 3948,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateURL_IPv4MappedBlocked - B/op",
            "value": 344,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateURL_IPv4MappedBlocked - allocs/op",
            "value": 7,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateURL_IPv4MappedBlocked",
            "value": 5017,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateURL_LoopbackBlocked - B/op",
            "value": 304,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateURL_LoopbackBlocked - allocs/op",
            "value": 6,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateURL_LoopbackBlocked",
            "value": 4564,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateURL_PrivateBlocked - B/op",
            "value": 304,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateURL_PrivateBlocked - allocs/op",
            "value": 6,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateURL_PrivateBlocked",
            "value": 4340,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateURL_PublicHTTPS - B/op",
            "value": 144,
            "range": "± 0.0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_PublicHTTPS - allocs/op",
            "value": 1,
            "range": "± 0.0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_PublicHTTPS",
            "value": 509.75,
            "range": "± 53.9",
            "unit": "ns/op",
            "extra": "10 samples, median"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Christopher Plieger",
            "username": "cplieger",
            "email": "917744+cplieger@users.noreply.github.com"
          },
          "committer": {
            "name": "Christopher Plieger",
            "username": "cplieger",
            "email": "917744+cplieger@users.noreply.github.com"
          },
          "id": "9b784475c83b9540230831ae3621fc38e5d80686",
          "message": "fix: revert the benchmark attribution change that broke publishing\n\nThe attempted fix set GITHUB_REPOSITORY on the publish step to redirect the action commit lookup at the repo being benchmarked. That cannot work: GitHub reserves the default GITHUB_* variables and the runner value wins at process level, so the step env block printed the override while the lookup still targeted cplieger/ci. Passing the consumer SHA as ref then asked ci for an object it does not have, and all four repos failed with \"No commit found for SHA\".\n\nRestores the previous behaviour, which publishes correctly but attributes each data point to a cplieger/ci commit. That attribution defect is real and still open; it needs either an upstream owner/repo input for the commit lookup, a post-processing pass over the published data, or running the benchmark in the consumer own workflow context.",
          "timestamp": "2026-08-21T12:10:35Z",
          "url": "https://github.com/cplieger/ci/commit/9b784475c83b9540230831ae3621fc38e5d80686"
        },
        "date": 1787315426391,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "BenchmarkIsPublicAddr_6to4Embed - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_6to4Embed - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_6to4Embed",
            "value": 88.795,
            "range": "± 1.93",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_CGNAT - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_CGNAT - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_CGNAT",
            "value": 16.13,
            "range": "± 0.17",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_IPv4Mapped - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_IPv4Mapped - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_IPv4Mapped",
            "value": 7.7865,
            "range": "± 0.55",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_Loopback - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_Loopback - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_Loopback",
            "value": 5.452,
            "range": "± 0.579",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PrivateIPv4 - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PrivateIPv4 - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PrivateIPv4",
            "value": 7.585,
            "range": "± 0.569",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv4 - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv4 - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv4",
            "value": 64.045,
            "range": "± 1.06",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv6 - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv6 - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv6",
            "value": 64.445,
            "range": "± 2.79",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_BareHostname - B/op",
            "value": 368,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateHost_BareHostname - allocs/op",
            "value": 8,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateHost_BareHostname",
            "value": 3285,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateHost_DottedHostname - B/op",
            "value": 240,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_DottedHostname - allocs/op",
            "value": 3,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_DottedHostname",
            "value": 326,
            "range": "± 8.6",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_Localhost - B/op",
            "value": 240,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateHost_Localhost - allocs/op",
            "value": 4,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateHost_Localhost",
            "value": 3146,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateHost_PrivateIP - B/op",
            "value": 304,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateHost_PrivateIP - allocs/op",
            "value": 6,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateHost_PrivateIP",
            "value": 3302,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateHost_PublicIP - B/op",
            "value": 144,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_PublicIP - allocs/op",
            "value": 1,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_PublicIP",
            "value": 281.5,
            "range": "± 3.2",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_BadScheme - B/op",
            "value": 288,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateURL_BadScheme - allocs/op",
            "value": 5,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateURL_BadScheme",
            "value": 3058,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateURL_IPv4MappedBlocked - B/op",
            "value": 344,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateURL_IPv4MappedBlocked - allocs/op",
            "value": 7,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateURL_IPv4MappedBlocked",
            "value": 3816,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateURL_LoopbackBlocked - B/op",
            "value": 304,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateURL_LoopbackBlocked - allocs/op",
            "value": 6,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateURL_LoopbackBlocked",
            "value": 3233,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateURL_PrivateBlocked - B/op",
            "value": 304,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateURL_PrivateBlocked - allocs/op",
            "value": 6,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateURL_PrivateBlocked",
            "value": 3351,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateURL_PublicHTTPS - B/op",
            "value": 144,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_PublicHTTPS - allocs/op",
            "value": 1,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_PublicHTTPS",
            "value": 342.4,
            "range": "± 32.4",
            "unit": "ns/op",
            "extra": "10 samples, median"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Christopher Plieger",
            "username": "cplieger",
            "email": "917744+cplieger@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "8f573606381efbe38847c0dad38b415f565b718c",
          "message": "chore(sync): synced file(s) with cplieger/ci (#367)\n\nCo-authored-by: github-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>",
          "timestamp": "2026-08-21T12:16:12Z",
          "url": "https://github.com/cplieger/ssrf/commit/8f573606381efbe38847c0dad38b415f565b718c"
        },
        "date": 1787316747320,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "BenchmarkIsPublicAddr_6to4Embed - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_6to4Embed - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_6to4Embed",
            "value": 114.45,
            "range": "± 3.8",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_CGNAT - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_CGNAT - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_CGNAT",
            "value": 20.84,
            "range": "± 0.29",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_IPv4Mapped - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_IPv4Mapped - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_IPv4Mapped",
            "value": 10.06,
            "range": "± 0.671",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_Loopback - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_Loopback - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_Loopback",
            "value": 6.6905,
            "range": "± 0.437",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PrivateIPv4 - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PrivateIPv4 - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PrivateIPv4",
            "value": 9.6735,
            "range": "± 0.673",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv4 - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv4 - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv4",
            "value": 82.02,
            "range": "± 6.17",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv6 - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv6 - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv6",
            "value": 82.15,
            "range": "± 1.16",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_BareHostname - B/op",
            "value": 368,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateHost_BareHostname - allocs/op",
            "value": 8,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateHost_BareHostname",
            "value": 4211,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateHost_DottedHostname - B/op",
            "value": 240,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_DottedHostname - allocs/op",
            "value": 3,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_DottedHostname",
            "value": 429.15,
            "range": "± 37.2",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_Localhost - B/op",
            "value": 240,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateHost_Localhost - allocs/op",
            "value": 4,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateHost_Localhost",
            "value": 3767,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateHost_PrivateIP - B/op",
            "value": 304,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateHost_PrivateIP - allocs/op",
            "value": 6,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateHost_PrivateIP",
            "value": 4161,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateHost_PublicIP - B/op",
            "value": 144,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_PublicIP - allocs/op",
            "value": 1,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_PublicIP",
            "value": 360.8,
            "range": "± 2.4",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_BadScheme - B/op",
            "value": 288,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateURL_BadScheme - allocs/op",
            "value": 5,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateURL_BadScheme",
            "value": 3815,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateURL_IPv4MappedBlocked - B/op",
            "value": 344,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateURL_IPv4MappedBlocked - allocs/op",
            "value": 7,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateURL_IPv4MappedBlocked",
            "value": 4943,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateURL_LoopbackBlocked - B/op",
            "value": 304,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateURL_LoopbackBlocked - allocs/op",
            "value": 6,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateURL_LoopbackBlocked",
            "value": 4196,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateURL_PrivateBlocked - B/op",
            "value": 304,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateURL_PrivateBlocked - allocs/op",
            "value": 6,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateURL_PrivateBlocked",
            "value": 4568,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateURL_PublicHTTPS - B/op",
            "value": 144,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_PublicHTTPS - allocs/op",
            "value": 1,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_PublicHTTPS",
            "value": 457.85,
            "range": "± 26.5",
            "unit": "ns/op",
            "extra": "10 samples, median"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Christopher Plieger",
            "username": "cplieger",
            "email": "917744+cplieger@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "f8a17f98b829fcaa53b48491da5efc040724552d",
          "message": "chore(sync): synced file(s) with cplieger/ci (#368)\n\nCo-authored-by: github-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>",
          "timestamp": "2026-08-21T13:17:29Z",
          "url": "https://github.com/cplieger/ssrf/commit/f8a17f98b829fcaa53b48491da5efc040724552d"
        },
        "date": 1787320851000,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "BenchmarkIsPublicAddr_6to4Embed - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_6to4Embed - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_6to4Embed",
            "value": 141.55,
            "range": "± 11.6",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_CGNAT - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_CGNAT - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_CGNAT",
            "value": 21.855,
            "range": "± 1.38",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_IPv4Mapped - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_IPv4Mapped - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_IPv4Mapped",
            "value": 8.568,
            "range": "± 0.837",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_Loopback - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_Loopback - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_Loopback",
            "value": 5.4565,
            "range": "± 0.286",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PrivateIPv4 - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PrivateIPv4 - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PrivateIPv4",
            "value": 7.967,
            "range": "± 0.403",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv4 - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv4 - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv4",
            "value": 101.1,
            "range": "± 8.44",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv6 - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv6 - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv6",
            "value": 91.9,
            "range": "± 4.29",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_BareHostname - B/op",
            "value": 368,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateHost_BareHostname - allocs/op",
            "value": 8,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateHost_BareHostname",
            "value": 3173,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateHost_DottedHostname - B/op",
            "value": 240,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_DottedHostname - allocs/op",
            "value": 3,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_DottedHostname",
            "value": 395.4,
            "range": "± 22.4",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_Localhost - B/op",
            "value": 240,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateHost_Localhost - allocs/op",
            "value": 4,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateHost_Localhost",
            "value": 2908,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateHost_PrivateIP - B/op",
            "value": 304,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateHost_PrivateIP - allocs/op",
            "value": 6,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateHost_PrivateIP",
            "value": 3056,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateHost_PublicIP - B/op",
            "value": 144,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_PublicIP - allocs/op",
            "value": 1,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_PublicIP",
            "value": 372.65,
            "range": "± 16.5",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_BadScheme - B/op",
            "value": 288,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateURL_BadScheme - allocs/op",
            "value": 5,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateURL_BadScheme",
            "value": 2899,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateURL_IPv4MappedBlocked - B/op",
            "value": 344,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateURL_IPv4MappedBlocked - allocs/op",
            "value": 7,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateURL_IPv4MappedBlocked",
            "value": 3595,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateURL_LoopbackBlocked - B/op",
            "value": 304,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateURL_LoopbackBlocked - allocs/op",
            "value": 6,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateURL_LoopbackBlocked",
            "value": 3167,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateURL_PrivateBlocked - B/op",
            "value": 304,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateURL_PrivateBlocked - allocs/op",
            "value": 6,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateURL_PrivateBlocked",
            "value": 3242,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateURL_PublicHTTPS - B/op",
            "value": 144,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_PublicHTTPS - allocs/op",
            "value": 1,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_PublicHTTPS",
            "value": 426.5,
            "range": "± 33",
            "unit": "ns/op",
            "extra": "10 samples, median"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Christopher Plieger",
            "username": "cplieger",
            "email": "917744+cplieger@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "f8a17f98b829fcaa53b48491da5efc040724552d",
          "message": "chore(sync): synced file(s) with cplieger/ci (#368)\n\nCo-authored-by: github-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>",
          "timestamp": "2026-08-21T13:17:29Z",
          "url": "https://github.com/cplieger/ssrf/commit/f8a17f98b829fcaa53b48491da5efc040724552d"
        },
        "date": 1787321656744,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "BenchmarkIsPublicAddr_6to4Embed - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_6to4Embed - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_6to4Embed",
            "value": 120.15,
            "range": "± 1.9",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_CGNAT - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_CGNAT - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_CGNAT",
            "value": 23.205,
            "range": "± 0.35",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_IPv4Mapped - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_IPv4Mapped - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_IPv4Mapped",
            "value": 10.835,
            "range": "± 0.26",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_Loopback - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_Loopback - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_Loopback",
            "value": 7.4405,
            "range": "± 0.322",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PrivateIPv4 - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PrivateIPv4 - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PrivateIPv4",
            "value": 10.24,
            "range": "± 0.26",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv4 - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv4 - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv4",
            "value": 86.51,
            "range": "± 4.58",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv6 - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv6 - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv6",
            "value": 89.96,
            "range": "± 0.94",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_BareHostname - B/op",
            "value": 368,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateHost_BareHostname - allocs/op",
            "value": 8,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateHost_BareHostname",
            "value": 4300,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateHost_DottedHostname - B/op",
            "value": 240,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_DottedHostname - allocs/op",
            "value": 3,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_DottedHostname",
            "value": 464.55,
            "range": "± 43.7",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_Localhost - B/op",
            "value": 240,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateHost_Localhost - allocs/op",
            "value": 4,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateHost_Localhost",
            "value": 3790,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateHost_PrivateIP - B/op",
            "value": 304,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateHost_PrivateIP - allocs/op",
            "value": 6,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateHost_PrivateIP",
            "value": 4077,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateHost_PublicIP - B/op",
            "value": 144,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_PublicIP - allocs/op",
            "value": 1,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_PublicIP",
            "value": 414.3,
            "range": "± 9.5",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_BadScheme - B/op",
            "value": 288,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateURL_BadScheme - allocs/op",
            "value": 5,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateURL_BadScheme",
            "value": 4018,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateURL_IPv4MappedBlocked - B/op",
            "value": 344,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateURL_IPv4MappedBlocked - allocs/op",
            "value": 7,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateURL_IPv4MappedBlocked",
            "value": 4661,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateURL_LoopbackBlocked - B/op",
            "value": 304,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateURL_LoopbackBlocked - allocs/op",
            "value": 6,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateURL_LoopbackBlocked",
            "value": 4211,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateURL_PrivateBlocked - B/op",
            "value": 304,
            "unit": "B/op"
          },
          {
            "name": "BenchmarkValidateURL_PrivateBlocked - allocs/op",
            "value": 6,
            "unit": "allocs/op"
          },
          {
            "name": "BenchmarkValidateURL_PrivateBlocked",
            "value": 4250,
            "unit": "ns/op"
          },
          {
            "name": "BenchmarkValidateURL_PublicHTTPS - B/op",
            "value": 144,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_PublicHTTPS - allocs/op",
            "value": 1,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_PublicHTTPS",
            "value": 498.3,
            "range": "± 38.2",
            "unit": "ns/op",
            "extra": "10 samples, median"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Christopher Plieger",
            "username": "cplieger",
            "email": "917744+cplieger@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "65b861026e97593c4b59a8ce6ea68719457da9c2",
          "message": "chore(sync): synced file(s) with cplieger/ci (#378)\n\nCo-authored-by: github-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>",
          "timestamp": "2026-08-25T08:14:10Z",
          "url": "https://github.com/cplieger/ssrf/commit/65b861026e97593c4b59a8ce6ea68719457da9c2"
        },
        "date": 1787697996023,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "BenchmarkIsPublicAddr_6to4Embed - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_6to4Embed - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_6to4Embed",
            "value": 119.5,
            "range": "± 0.55",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_CGNAT - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_CGNAT - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_CGNAT",
            "value": 22.475,
            "range": "± 0.09",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_IPv4Mapped - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_IPv4Mapped - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_IPv4Mapped",
            "value": 10.295,
            "range": "± 0.035",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_Loopback - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_Loopback - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_Loopback",
            "value": 7.4885,
            "range": "± 0.0195",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PrivateIPv4 - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PrivateIPv4 - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PrivateIPv4",
            "value": 9.988,
            "range": "± 0.0105",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv4 - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv4 - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv4",
            "value": 83.995,
            "range": "± 0.72",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv6 - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv6 - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv6",
            "value": 89.075,
            "range": "± 0.38",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkRedirectPolicy_AcceptedHop - B/op",
            "value": 96,
            "range": "± 0.0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkRedirectPolicy_AcceptedHop - allocs/op",
            "value": 2,
            "range": "± 0.0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkRedirectPolicy_AcceptedHop",
            "value": 170.75,
            "range": "± 0.75",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkSafeControl_AcceptedIP - B/op",
            "value": 0,
            "range": "± 0.0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkSafeControl_AcceptedIP - allocs/op",
            "value": 0,
            "range": "± 0.0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkSafeControl_AcceptedIP",
            "value": 159.8,
            "range": "± 1.3",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_BareHostname - B/op",
            "value": 336,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_BareHostname - allocs/op",
            "value": 6,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_BareHostname",
            "value": 631.4,
            "range": "± 2.2",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_DottedHostname - B/op",
            "value": 240,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_DottedHostname - allocs/op",
            "value": 3,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_DottedHostname",
            "value": 421.65,
            "range": "± 2.05",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_Localhost - B/op",
            "value": 208,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_Localhost - allocs/op",
            "value": 2,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_Localhost",
            "value": 254.85,
            "range": "± 1.15",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_PrivateIP - B/op",
            "value": 272,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_PrivateIP - allocs/op",
            "value": 4,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_PrivateIP",
            "value": 561.75,
            "range": "± 7.4",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_PublicIP - B/op",
            "value": 144,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_PublicIP - allocs/op",
            "value": 1,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_PublicIP",
            "value": 373.85,
            "range": "± 3.6",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_BadScheme - B/op",
            "value": 272,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_BadScheme - allocs/op",
            "value": 4,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_BadScheme",
            "value": 408.45,
            "range": "± 1.75",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_IPv4MappedBlocked - B/op",
            "value": 312,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_IPv4MappedBlocked - allocs/op",
            "value": 5,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_IPv4MappedBlocked",
            "value": 952.6,
            "range": "± 4.45",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_LoopbackBlocked - B/op",
            "value": 272,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_LoopbackBlocked - allocs/op",
            "value": 4,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_LoopbackBlocked",
            "value": 538.55,
            "range": "± 4.75",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_PrivateBlocked - B/op",
            "value": 272,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_PrivateBlocked - allocs/op",
            "value": 4,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_PrivateBlocked",
            "value": 555.95,
            "range": "± 1.8",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_PublicHTTPS - B/op",
            "value": 144,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_PublicHTTPS - allocs/op",
            "value": 1,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_PublicHTTPS",
            "value": 408.3,
            "range": "± 1.6",
            "unit": "ns/op",
            "extra": "10 samples, median"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Christopher Plieger",
            "username": "cplieger",
            "email": "917744+cplieger@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "73fcb5e94e2f68f4366ffd27bd2af0247e0b054a",
          "message": "chore(deps): update cplieger/ci digest to 77bb665 (#557)",
          "timestamp": "2026-09-01T16:02:18Z",
          "url": "https://github.com/cplieger/ci/commit/73fcb5e94e2f68f4366ffd27bd2af0247e0b054a"
        },
        "date": 1788307707838,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "BenchmarkIsPublicAddr_6to4Embed - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_6to4Embed - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_6to4Embed",
            "value": 91.605,
            "range": "± 0.99",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_CGNAT - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_CGNAT - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_CGNAT",
            "value": 16.19,
            "range": "± 0.14",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_IPv4Mapped - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_IPv4Mapped - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_IPv4Mapped",
            "value": 7.618,
            "range": "± 0.1145",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_Loopback - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_Loopback - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_Loopback",
            "value": 5.1915,
            "range": "± 0.2345",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PrivateIPv4 - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PrivateIPv4 - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PrivateIPv4",
            "value": 7.3625,
            "range": "± 0.2335",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv4 - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv4 - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv4",
            "value": 64.065,
            "range": "± 0.63",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv6 - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv6 - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkIsPublicAddr_PublicIPv6",
            "value": 64.155,
            "range": "± 1.035",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkRedirectPolicy_AcceptedHop - B/op",
            "value": 96,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkRedirectPolicy_AcceptedHop - allocs/op",
            "value": 2,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkRedirectPolicy_AcceptedHop",
            "value": 126.5,
            "range": "± 0.4",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkSafeControl_AcceptedIP - B/op",
            "value": 0,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkSafeControl_AcceptedIP - allocs/op",
            "value": 0,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkSafeControl_AcceptedIP",
            "value": 110.35,
            "range": "± 0.6",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_BareHostname - B/op",
            "value": 336,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_BareHostname - allocs/op",
            "value": 6,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_BareHostname",
            "value": 421.6,
            "range": "± 2.6",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_DottedHostname - B/op",
            "value": 240,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_DottedHostname - allocs/op",
            "value": 3,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_DottedHostname",
            "value": 286.3,
            "range": "± 17.15",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_Localhost - B/op",
            "value": 208,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_Localhost - allocs/op",
            "value": 2,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_Localhost",
            "value": 166.6,
            "range": "± 3.55",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_PrivateIP - B/op",
            "value": 272,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_PrivateIP - allocs/op",
            "value": 4,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_PrivateIP",
            "value": 364.85,
            "range": "± 1.65",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_PublicIP - B/op",
            "value": 144,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_PublicIP - allocs/op",
            "value": 1,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateHost_PublicIP",
            "value": 245.9,
            "range": "± 0.9",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_BadScheme - B/op",
            "value": 272,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_BadScheme - allocs/op",
            "value": 4,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_BadScheme",
            "value": 276,
            "range": "± 2.7",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_IPv4MappedBlocked - B/op",
            "value": 312,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_IPv4MappedBlocked - allocs/op",
            "value": 5,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_IPv4MappedBlocked",
            "value": 652.6,
            "range": "± 9.65",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_LoopbackBlocked - B/op",
            "value": 272,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_LoopbackBlocked - allocs/op",
            "value": 4,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_LoopbackBlocked",
            "value": 356.35,
            "range": "± 1.9",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_PrivateBlocked - B/op",
            "value": 272,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_PrivateBlocked - allocs/op",
            "value": 4,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_PrivateBlocked",
            "value": 358.7,
            "range": "± 1.9",
            "unit": "ns/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_PublicHTTPS - B/op",
            "value": 144,
            "range": "± 0",
            "unit": "B/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_PublicHTTPS - allocs/op",
            "value": 1,
            "range": "± 0",
            "unit": "allocs/op",
            "extra": "10 samples, median"
          },
          {
            "name": "BenchmarkValidateURL_PublicHTTPS",
            "value": 264.9,
            "range": "± 1.45",
            "unit": "ns/op",
            "extra": "10 samples, median"
          }
        ]
      }
    ]
  }
}