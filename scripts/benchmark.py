#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Sebastian Paul Banszky <contact@originzero.art>

"""Concurrent HTTP benchmark harness evaluating zero-origin edge mitigation & overhead."""

import argparse
import concurrent.futures
import statistics
import time
import urllib.error
import urllib.request


def single_request(url: str, user_agent: str) -> tuple[int, float]:
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
            code = resp.status
    except urllib.error.HTTPError as err:
        code = err.code
    dt_ms = (time.perf_counter() - t0) * 1000.0
    return code, dt_ms


def run_benchmark(url: str, requests_count: int, concurrency: int):
    latencies = []
    statuses = {}
    t_start = time.perf_counter()

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [
            pool.submit(
                single_request,
                url,
                "GPTBot/1.0" if i % 4 == 0 else "Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36",
            )
            for i in range(requests_count)
        ]
        for fut in concurrent.futures.as_completed(futures):
            code, dt_ms = fut.result()
            latencies.append(dt_ms)
            statuses[code] = statuses.get(code, 0) + 1

    wall = time.perf_counter() - t_start
    latencies.sort()
    p50 = statistics.median(latencies)
    p99 = latencies[int(len(latencies) * 0.99)] if latencies else 0.0
    print(
        f"Completed {requests_count} requests (concurrency={concurrency}) in {wall:.2f}s | "
        f"p50={p50:.2f}ms | p99={p99:.2f}ms | statuses={statuses}"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Benchmark zero-origin L7 Edge Proxy")
    parser.add_argument("--target", default="http://127.0.0.1:8088/ai.txt")
    parser.add_argument("--requests", type=int, default=400)
    parser.add_argument("--concurrency", type=int, default=32)
    args = parser.parse_args()
    run_benchmark(args.target, args.requests, args.concurrency)
