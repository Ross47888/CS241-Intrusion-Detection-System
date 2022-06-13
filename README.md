# CS241-Intrusion-Detection-System

For this coursework, you will implement a basic intrusion detection system. This will test your understanding of TCP/IP protocols (networks) and threading (OS) as well as your ability to develop a non-trivial program in C. The coursework contributes 20% to your total marks in the module.

You have been provided with an application skeleton that is able to intercept (sniff) packets at a specific interface and print them to the screen. The code uses the libpcap library to receive packets and strips the outer-most layer of the packet. The goal of this coursework is to extend the skeleton to detect potentially malicious traffic in high-throughput networks. The key deliverables of this coursework and their associated weightings are as follows.

Extend the skeleton to efficiently intercept internet packets and navigate through the packet headers. (~20%)
Detect specific malicious activities (e.g., SYN attacks, ARP cache Poisoning attack, Blacklisted URL deection) and show them on the terminal as specified later. (~25%)
(relative weights: SYN attack detection 50%, ARP poisoning attack detection 25%, Blacklisted URL detection 25%)
Implement a threading strategy to allow efficient detection of the attacks when there is high traffic. (~25%)
Write a report no more than 1000 words in length (excluding references) explaining the critical design decisions and testing of your solution. The report should be short, mainly containing a description of your threading strategy and implementation, a justification for your choice of the threading model, and how you have tested your solution. (~20%)
The final ~10% is awarded for code quality and adherence to relevant software engineering principles.
You must base your solution on the skeletonLink opens in a new window provided and it must be written entirely in the C programming language.

Your solution must compile and run without errors, warnings, memory leaks, and without crashing (e.g., seg faults) on the DCS system. If this is not the case, then marks will be lost.

You should only consider IPv4 - there are no additional marks available for IPv6 functionality.
