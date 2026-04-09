"""
Visualize threading benchmark results to demonstrate the threading sweet spot.

Usage:
    python benchmark_visualizer.py [--file benchmark_results.json] [--output plot.png]

This script reads benchmark results and creates:
1. A throughput vs thread count graph (shows the plateau effect)
2. A parallel efficiency graph (shows where overhead dominates)
3. A comparison table with key insights
"""

import json
import argparse
from pathlib import Path

try:
    import matplotlib.pyplot as plt
    import matplotlib.ticker as ticker
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("⚠ matplotlib not installed. Install with: pip install matplotlib")


def load_results(filepath: str) -> dict:
    """Load benchmark results from JSON file."""
    with open(filepath, 'r') as f:
        return json.load(f)


def analyze_results(results: dict) -> dict:
    """Compute derived metrics from benchmark results."""
    workers = sorted([int(k) for k in results.keys()])
    baseline_tput = results["1"]["throughput"]
    
    analysis = {
        "workers": workers,
        "throughput": [results[str(w)]["throughput"] for w in workers],
        "speedup": [results[str(w)]["throughput"] / baseline_tput for w in workers],
        "efficiency": [(results[str(w)]["throughput"] / baseline_tput) / w * 100 for w in workers],
        "time": [results[str(w)]["time_sec"] for w in workers],
        "iterations": [results[str(w)]["iterations"] for w in workers],
    }
    
    # Find optimal thread count (best throughput)
    best_idx = analysis["throughput"].index(max(analysis["throughput"]))
    analysis["optimal_workers"] = workers[best_idx]
    
    # Find peak efficiency (best efficiency)
    best_eff_idx = analysis["efficiency"].index(max(analysis["efficiency"]))
    analysis["best_efficiency_workers"] = workers[best_eff_idx]
    
    return analysis


def print_analysis(analysis: dict) -> None:
    """Print text-based analysis."""
    print("\n" + "="*70)
    print("THREADING BENCHMARK ANALYSIS")
    print("="*70 + "\n")
    
    print(f"{'Workers':<10} {'Throughput':<15} {'Speedup':<12} {'Efficiency':<12} {'Time':<10}")
    print("-" * 70)
    
    for i, w in enumerate(analysis["workers"]):
        tput = analysis["throughput"][i]
        speedup = analysis["speedup"][i]
        eff = analysis["efficiency"][i]
        time_sec = analysis["time"][i]
        print(f"{w:<10} {tput:<15.1f} {speedup:<12.2f}x {eff:<12.1f}% {time_sec:<10.2f}s")
    
    print("\n" + "="*70)
    print("KEY INSIGHTS")
    print("="*70 + "\n")
    
    optimal = analysis["optimal_workers"]
    tput_optimal = analysis["throughput"][analysis["workers"].index(optimal)]
    tput_baseline = analysis["throughput"][0]
    eff_optimal = analysis["efficiency"][analysis["workers"].index(optimal)]
    
    print(f"✓ OPTIMAL THREAD COUNT: {optimal} threads")
    print(f"  Throughput:  {tput_optimal:.1f} iters/sec ({tput_optimal/tput_baseline:.2f}x vs 1 thread)")
    print(f"  Efficiency:  {eff_optimal:.1f}%\n")
    
    # Diminishing returns analysis
    if optimal > 1:
        # Check if adding more threads helps
        ideal_speedup = optimal
        actual_speedup = analysis["speedup"][analysis["workers"].index(optimal)]
        diminishing = ((ideal_speedup - actual_speedup) / ideal_speedup) * 100
        
        print(f"✓ DIMINISHING RETURNS: {diminishing:.1f}% overhead")
        print(f"  Theoretical speedup:  {ideal_speedup:.2f}x (100% efficient)")
        print(f"  Actual speedup:       {actual_speedup:.2f}x\n")
    
    # Check if scaling stops
    max_throughput_idx = analysis["throughput"].index(max(analysis["throughput"]))
    min_throughput_idx = len(analysis["throughput"]) - 1
    
    if min_throughput_idx > max_throughput_idx:
        tput_decrease = ((analysis["throughput"][max_throughput_idx] - 
                         analysis["throughput"][min_throughput_idx]) / 
                        analysis["throughput"][max_throughput_idx]) * 100
        best_workers = analysis["workers"][max_throughput_idx]
        best_tput = analysis["throughput"][max_throughput_idx]
        worst_workers = analysis["workers"][min_throughput_idx]
        worst_tput = analysis["throughput"][min_throughput_idx]
        print(f"⚠ SCALING PLATEAUED/DEGRADED:")
        print(f"  Best at {best_workers} threads: {best_tput:.1f} iters/sec")
        print(f"  At {worst_workers} threads: {worst_tput:.1f} iters/sec")
        print(f"  Loss: {tput_decrease:.1f}% (contention/overhead dominates)\n")
    else:
        max_w = analysis["workers"][-1]
        print(f"ℹ Still scaling at {max_w} threads (could test higher)\n")


def create_plots(analysis: dict, output_file: str = "benchmark_plot.png") -> None:
    """Create visualization plots."""
    if not HAS_MATPLOTLIB:
        print("⚠ Skipping plots: matplotlib not installed")
        return
    
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle("Thread Scaling Analysis: Finding the Sweet Spot", fontsize=16, fontweight='bold')
    
    workers = analysis["workers"]
    
    # Plot 1: Throughput vs Workers (main metric)
    ax = axes[0, 0]
    ax.plot(workers, analysis["throughput"], 'o-', linewidth=2, markersize=8, color='#2E86AB', label='Actual')
    optimal_idx = workers.index(analysis["optimal_workers"])
    ax.plot(workers[optimal_idx], analysis["throughput"][optimal_idx], 'g*', markersize=20, label='Optimal')
    ax.set_xlabel("Number of Workers", fontweight='bold')
    ax.set_ylabel("Throughput (iterations/sec)", fontweight='bold')
    ax.set_title("Throughput Scaling", fontweight='bold')
    ax.grid(True, alpha=0.3)
    ax.legend()
    ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    
    # Plot 2: Speedup vs Ideal (shows overhead)
    ax = axes[0, 1]
    ideal_speedup = [w for w in workers]  # Linear scaling (100% efficient)
    ax.plot(workers, analysis["speedup"], 'o-', linewidth=2, markersize=8, color='#A23B72', label='Actual Speedup')
    ax.plot(workers, ideal_speedup, '--', linewidth=2, color='gray', label='Ideal (Linear)')
    ax.set_xlabel("Number of Workers", fontweight='bold')
    ax.set_ylabel("Speedup (vs 1 worker)", fontweight='bold')
    ax.set_title("Speedup vs Ideal (Linear) Scaling", fontweight='bold')
    ax.grid(True, alpha=0.3)
    ax.legend()
    ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    
    # Plot 3: Parallel Efficiency
    ax = axes[1, 0]
    colors = ['green' if e >= 75 else 'orange' if e >= 50 else 'red' for e in analysis["efficiency"]]
    bars = ax.bar(workers, analysis["efficiency"], color=colors, alpha=0.7)
    ax.axhline(y=75, color='green', linestyle='--', alpha=0.5, label='Good (75%)')
    ax.axhline(y=50, color='orange', linestyle='--', alpha=0.5, label='Marginal (50%)')
    ax.set_xlabel("Number of Workers", fontweight='bold')
    ax.set_ylabel("Parallel Efficiency (%)", fontweight='bold')
    ax.set_title("Parallel Efficiency (speedup/workers * 100)", fontweight='bold')
    ax.set_ylim(0, 110)
    ax.grid(True, alpha=0.3, axis='y')
    ax.legend()
    ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    
    # Add value labels on bars
    for i, (w, eff) in enumerate(zip(workers, analysis["efficiency"])):
        ax.text(w, eff + 2, f'{eff:.0f}%', ha='center', fontweight='bold')
    
    # Plot 4: Time vs Workers (reciprocal of throughput)
    ax = axes[1, 1]
    ax.plot(workers, analysis["time"], 'o-', linewidth=2, markersize=8, color='#F18F01')
    optimal_idx = workers.index(analysis["optimal_workers"])
    ax.plot(workers[optimal_idx], analysis["time"][optimal_idx], 'g*', markersize=20, label='Optimal')
    ax.set_xlabel("Number of Workers", fontweight='bold')
    ax.set_ylabel("Wall-clock Time (seconds)", fontweight='bold')
    ax.set_title("Execution Time vs Worker Count", fontweight='bold')
    ax.grid(True, alpha=0.3)
    ax.legend()
    ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    print(f"\n✓ Plot saved to: {output_file}")
    print(f"  Open this file to visualize the threading sweet spot")


def main():
    parser = argparse.ArgumentParser(
        description="Visualize threading benchmark results",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  python benchmark_visualizer.py
  python benchmark_visualizer.py --file results.json --output scaling.png
        """
    )
    parser.add_argument("--file", default="benchmark_results.json",
                       help="Input JSON file with benchmark results")
    parser.add_argument("--output", default="benchmark_plot.png",
                       help="Output image file for plots")
    parser.add_argument("--no-plot", action="store_true",
                       help="Skip plotting (text analysis only)")
    
    args = parser.parse_args()
    
    # Load and analyze
    filepath = Path(args.file)
    if not filepath.exists():
        print(f"❌ Error: {filepath} not found")
        print(f"   Run benchmark first: python fuzzer.py --target ... --benchmark ...")
        return
    
    print(f"📊 Loading results from {filepath}")
    results = load_results(filepath)
    analysis = analyze_results(results)
    
    # Print text analysis
    print_analysis(analysis)
    
    # Create plots
    if not args.no_plot:
        create_plots(analysis, args.output)
    
    print("\n" + "="*70)
    print("INTERPRETATION")
    print("="*70 + "\n")
    optimal = analysis["optimal_workers"]
    print(f"""
The graphs above demonstrate the threading sweet spot:

1. THROUGHPUT GRAPH: Shows where performance peaks. If throughput
   plateaus or DECREASES, you've found the optimal thread count.
   Adding more threads beyond this point adds overhead without benefit.

2. SPEEDUP vs IDEAL: The gap between actual and ideal shows overhead.
   Wider gap = more contention/synchronization cost per thread.

3. PARALLEL EFFICIENCY: Shows how well threads are utilized.
   High efficiency (75%+) = good scaling.
   Low efficiency (<50%) = overhead dominates.

4. TIME GRAPH: When execution time stops decreasing or increases,
   that's your practical limit.

CONCLUSION:
Run your fuzzer with {optimal} workers for best performance.
This balances parallelism with synchronization overhead.
""")


if __name__ == "__main__":
    main()
