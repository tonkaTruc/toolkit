PMD Streams
===========

This directory contains 4 PMD test streams in three different formats: XML, PCAP and WAV

Each PMD stream covers a different use-case or scenario:

pmd_51main - 5.1 Main with 1 presentation
pmd_51eng_and_spa - 5.1 M&E plus English and Spanish dialogue tracks with 2 presentations
pmd_514_eng_spa_vds - 5.1.4 M&E plus English and Spanish dialogue and VDS tracks with 4 presentations
pmd_514_4objects - 5.1.4 M&E plus 4 dialogue objects in different positions with 4 presentations

The exact details of the streams can easily be determined by viewing the XML.

The pcap files can be played back using tcreplay or a similar tool. The files use a multicast address of 239.1.110.250 and a port of 5004. These streams use SMPTE ST 2110-31 formatting to encapsulate the SMPTE ST 337 data into RTP packets.
A packet timing of 1ms or 48 samples is used in all files.
The resulting RTP packet stream can be monitored using the provided pmd_viewer tool:

For example on Mac OS:
tcpreplay --intf1=en0 pmd_51main.pcap &
pmd_viewer.py en0 239.150.197.2 5004

This will bring up a tree view that matches the XML description of the stream.