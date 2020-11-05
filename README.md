## Pre-Simulation readiness checking

- `Checkpointing/SyscallAnalysis/prerun_check.py` - Perform a prerun check based on the info in manifest DB.
- `Checkpointing/SyscallAnalysis/generate_manifest.py` - Analyze the System Call trace for an entire SPEC simulation (dumped by a special version of [spike](https://github.com/s117/riscv-isa-sim/tree/feature_syscall_trace)). Then produce the manifest for it. Finally save the manifest into DB.


## Misc.

- `SpecResultVerification/spike_trim.py` - Trim out the extra header/tail message produced by spike or pk during the simulation. Useful if you want to automatically verify the STDOUT output of a SPEC simulation.
- `Checkpointing/ChkptDescFileGen/smpt2ckptdesc.py` - Convert the Simpoint output file to the checkpoint job description file accepted by Spike.
- `Checkpointing/DumpHTIF/chkpt_htif_dump.py` - Show the HTIF syscalls recorded in a checkpoint file. When restoring a checkpoint, those syscalls will be executed in sequence to bring back the state of [HTIF FESVR](https://github.com/s117/riscv-fesvr).
- `TetherSim/SimTetheringController.py` - Controller for [721sims](https://github.ncsu.edu/jli95/721sim/tree/trace_support) working in tethering mode.


## To work with trace dump

- `CpuTraceAnalysis/trace2google.py` - Analyze the trace dumped by [spike](https://github.com/s117/riscv-isa-sim/tree/WIB_trace_support) or [721sim](https://github.ncsu.edu/jli95/721sim/tree/trace_support) and output the result in Google's Trace Event Format.
- To visualize the result, use [speedscope](https://github.com/jlfwong/speedscope) (recommend) or Chromium's *about://tracing* .
  - if `ignore_symbol.yaml` exists in CWD, it will be read to filter out the defined function calls. See `CpuTraceAnalysis/ignore_symbol.yaml` for an example.

- `CpuTraceAnalysis/trace2tracevis.py` - Analyze and visualize the trace dumped by [spike](https://github.com/s117/riscv-isa-sim/tree/WIB_trace_support) or [721sim](https://github.ncsu.edu/jli95/721sim/tree/trace_support) in a homebrew timeline frontend (using [timeline-js](https://github.com/visjs/vis-timeline)).
  - if `ignore_symbol.yaml` exists in CWD - Will be read to filter out the defined function calls. See `CpuTraceAnalysis/ignore_symbol.yaml` for an example.
  - **It's recommended to use `trace2google.py`.** Because the trace_vis frontend uses timeline-js, which is not intended for visualizing tracing result, it can be very slow and unresponsive when working with trace with a large amount of event.

![image-20201105011703029](https://raw.githubusercontent.com/s117/anycore-dbg-supplement/master/README.assets/image-20201105011703029.png)

<p align=center>Viewing the trace2google.py output with speedscope</p>

![image-20201105011839379](https://raw.githubusercontent.com/s117/anycore-dbg-supplement/master/README.assets/image-20201105011839379.png)

<p align=center>Viewing the trace2google.py output with Chrome's about:tracing</p>

![image-20200813043919822](https://raw.githubusercontent.com/s117/anycore-dbg-supplement/master/README.assets/image-20200813043919822.png)

<p align=center>Viewing the trace using homebrew TraceVis frontend (use timeline-js)</p>

**WIP**.