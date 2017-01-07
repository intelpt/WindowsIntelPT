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

**Build Instructions**

* Open the included Visual Studio Project file in Visual Studio 2013 or 2015.
* Open Project Properties, navigate to Driver Signing page, and enable set "Sign Mode" to "Test Signing" 
* Under the Test Certificate drop down, select "Create Test Certificate"
* Ensure build options are set to x64 Release and build

**Driver Loading Instructions**

* Ensure your CPU is Skylake architecture and you are running on native hardware (not a hypervisor)
* Boot your Windows 8.1 or Windows 10 OS using boot options that allow loading test signed drivers 
* Install the WindowsPtDriver using a tool such as InstDrv from the Windows RK (included in Build directory)

**Current Limitations**
 
This driver currently supports tracing on only one CPU core at a time, traced processes must be launched 
with processor affinity set in order to capture a full trace. This is a software limitation we will fix
eventually, but is not a priority for our use case. Please open a bug if this feature is important to you. 

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
* Implement multi-core tracing 


  
Last revision: 01/04/2017
