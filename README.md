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
 
The driver is currently hardcoded to trace only a single usermode process via CR3 filtering. Intel 
Processor Trace is capable of tracing all threads executing on a CPU core including kernel and all
user processes scheduled on that core. This can be configured by modifing the Intel PT configuration 
flags, but this is not currently exposed through an IOCTL. 

The IOCTLs for this driver must not be called from within the traced process. The driver maps the 
physical memory ranges holding the trace data into the process that initialized the trace, this is
unstable if mapped into the trace target. Use the included command line tool for executing traces 
against target processes. 

   
**Development Notes**

The driver currently executes a DbgBreak() on load if a kernel debugger is attached. 


**TODO List**

* Implement address range filtering - up to four virtual address ranges may be specified to target specific binaries in the process space
* Output sideband memory map information for post processing (this should be done by the usermode launcher process)
* Implement multi-core tracing 


  
Last revision: 01/04/2017
