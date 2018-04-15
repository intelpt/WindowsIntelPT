Windows Intel PT Support 
========================
  
This driver implements the Intel Processor Trace functionality in Intel Skylake architecture for Microsoft Windows. 
  
Overview 
--------
  
Intel Processor Trace is a high performance hardware supported branch tracing mechanism in Intel Skylake architecure. 

Primary benefits include: 

* Avoids cache and TLB polution by writing directly to physical memory 
* Uses a compressed logging format that is suitable for long running traces 
* Able to trace all branches on a CPU core including userspace and kernel 

**Driver Features**

* Trace user processes using CR3 filtering
* Trace kernel mode drivers using linear range filtering
* Trace up to four arbitrary ranges of physical memory
* Log to single physical address range 
* Log to table of physical pages and map to virtual address range
* Multi-core tracing support 
* Full support for HyperV Root Partitions

**Build Instructions**

* Open the included Visual Studio Project file in Visual Studio 2013 or 2015.
* Ensure build options are set to x64 Release and build

**Driver Loading Instructions**

* Ensure your CPU is Skylake architecture and you are running on native hardware (not a hypervisor)
* Boot your Windows 8.1 or Windows 10 OS using boot options that allow loading test signed drivers 
* Install the WindowsPtDriver using `sc create intelpt BinPath=%cd%\WindowsPtDriver\x64\Release\WindowsPtDriver.sys`

**Current Limitations**
 
All threads in a usermode process will log to a single buffer, making it difficult to determine accurate 
execution per-thread. This something we are working to fix.
 
The IOCTLs for this driver must not be called from within the traced process. The driver maps the 
physical memory ranges holding the trace data into the process that initialized the trace, this is
unstable if mapped into the trace target. Use the included command line tool for executing traces 
against target processes. 

   
**Development Notes**

The driver currently executes a DbgBreak() on load if a kernel debugger is attached. 


**TODO List**

* Output sideband memory map information for post processing
* Per-thread logging
* Implement the support for Kernel KVA Shadowing


  
Last revision: 04/15/2018
