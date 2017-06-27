<h2>Compiled Windows Intel PT Driver</h2>

<p>This folder contains the compiled version of the Windows Intel PT Driver and Control Application</p>
<p>Version: 0.6</p>
<p>News:
<ul>
   <li>Re-designed the entire driver code. Now it is much more modular and scalable</li>
   <li>Added and tested the support for Kernel-mode tracing</li>
   <li>Added the support for Kernel tracing from the user-mode application (requires Administratives privilege)</li>
   <li>Added the support for Microsoft HyperV (Root Partition only)</li>
   <li>Written some example code for doing Kernel-tracing of the loading/unloading code of a target driver</li>
</ul></p>
<p>Unfortunately the driver code is still too young to be compiled as signed. 
You need to enable the Test Signing mode in your Windows OS to be able to use the driver.
By the way our tests highlighted that the code was really very stable.
Write us a mail (<a href="mailto:info@andrea-allievi.com">info@andrea-allievi.com</a>) if you find some bugs or for any other queries.
If I find the time I will be happy to answer.
</p>
<p>Last Revision: 17th June 2017 - Recon Conference<br>
</p>
