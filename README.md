# Cellular-Security-Papers

This repo collects academic papers / open source projects / conference talks / frameworks / tools related to the research of cellular security and privacy.

## Table of Content

- [Baseband Analysis](https://github.com/onehouwong/Cellular-Security-Papers#baseband-analysis)
- [Vulnerability Discovery / Analysis](https://github.com/onehouwong/Cellular-Security-Papers#vulnerability-discovery--analysis)
- [Defense](https://github.com/onehouwong/Cellular-Security-Papers#defense)
- [O-RAN Related](https://github.com/onehouwong/Cellular-Security-Papers#o-ran-related)
- [Core Network Security](https://github.com/onehouwong/Cellular-Security-Papers#core-network-security)
- [Network Slicing Security](https://github.com/onehouwong/Cellular-Security-Papers#network-slicing-security)
- [Survey](https://github.com/onehouwong/Cellular-Security-Papers#survey)
- [Open Source Projects / Frameworks / Tools](https://github.com/onehouwong/Cellular-Security-Papers#open-source-projects--frameworks--tools)
- [Testbeds](https://github.com/onehouwong/Cellular-Security-Papers#testbeds)
- [Open Dataset](https://github.com/onehouwong/Cellular-Security-Papers#open-dataset)


## Baseband Analysis 
### Baseband Reverse Engineering

[awesome-baseband-research](https://github.com/lololosys/awesome-baseband-research) Nice summary of research works in baseband firmware RE. 

[Shannon (SAMSUNG) baseband reverse engineering](https://github.com/grant-h/ShannonBaseband)

[MediaTec-baseband-LTE-RE](https://github.com/cyrozap/mediatek-lte-baseband-re)

[Huawei baseband exploit](https://i.blackhat.com/us-18/Thu-August-9/us-18-Grassi-Exploitation-of-a-Modern-Smartphone-Baseband-wp.pdf) (BH 18) 

[How to design a baseband debugger (Samsung Shannon)](https://www.sstic.org/media/SSTIC2020/SSTIC-actes/how_to_design_a_baseband_debugger/SSTIC2020-Article-how_to_design_a_baseband_debugger-berard_fargues.pdf) 

[Baseband Attacks: Remote Exploitation of Memory Corruptions in Cellular Protocol Stacks](https://www.usenix.org/system/files/conference/woot12/woot12-final24.pdf) (USENIX WOOT 12) 

[BASESPEC: Comparative Analysis of Baseband Software and Cellular Specifications for L3 Protocols](https://www.ndss-symposium.org/wp-content/uploads/2021-365-paper.pdf) (NDSS 21)

[BASECOMP: A Comparative Analysis for Integrity Protection in Cellular Baseband Software](https://www.usenix.org/system/files/usenixsecurity23-kim-eunsoo.pdf) (USENIX Security 23)

[Semantic-Enhanced Static Vulnerability Detection in Baseband Firmware](https://dl.acm.org/doi/pdf/10.1145/3597503.3639158) (ICSE'24)

[Logic Gone Astray: A Security Analysis Framework for the Control Plane Protocols of 5G Basebands](https://www.usenix.org/system/files/usenixsecurity24-tu.pdf) (USENIX Security 24)

[BaseMirror: Automatic Reverse Engineering of Baseband Commands from Android's Radio Interface Layer](https://arxiv.org/pdf/2409.00475) (CCS 24)

[Stateful Analysis and Fuzzing of Commercial Baseband Firmware](https://www.computer.org/csdl/proceedings-article/sp/2025/223600b082/26hiU6JdGYE) (IEEE S&P 25)

### Emulation and fuzzing 
[Emulating Samsung’s Baseband for Security Testing](https://i.blackhat.com/USA-20/Wednesday/us-20-Hernandez-Emulating-Samsungs-Baseband-For-Security-Testing.pdf)

[BaseSAFE: Baseband SAnitized Fuzzing through Emulation](https://dl.acm.org/doi/pdf/10.1145/3395351.3399360) (WiSec 20)

[ARIstoteles – Dissecting Apple’s Baseband Interface](https://link.springer.com/chapter/10.1007/978-3-030-88418-5_7) (ESORICS 21)

[FIRMWIRE: Transparent Dynamic Analysis for Cellular Baseband Firmware](https://www.ndss-symposium.org/wp-content/uploads/2022-136-paper.pdf) (NDSS 22)

[BaseBridge: Bridging the Gap between Emulation and Over-The-Air Testing for Cellular Baseband Firmware](https://www.computer.org/csdl/proceedings-article/sp/2025/223600b101/26EkFnSdkOY) (IEEE S&P 25)


## Vulnerability Discovery / Analysis

### Formal verification

[Formal Analysis of Access Control Mechanism of 5G Core Network](https://syed-rafiul-hussain.github.io/wp-content/uploads/2023/10/5GCVerif-ccs23.pdf) (CCS 23)

[Provable Non-Frameability for 5G Lawful Interception](https://www.ida.liu.se/labs/rtslab/publications/2023/Felipe_WiSec2023.pdf) (Wisec 23)

[LTEInspector: A Systematic Approach for Adversarial Testing of 4G LTE](https://www.ndss-symposium.org/wp-content/uploads/2018/02/ndss2018_02A-3_Hussain_paper.pdf) (NDSS 18)

[Component-Based Formal Analysis of 5G-AKA: Channel Assumptions and Session Confusion](https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_06B-1_Cremers_paper.pdf) (NDSS 19)

[5GReasoner: A Property-Directed Security and Privacy Analysis Framework for 5G Cellular Network Protocol](https://dl.acm.org/doi/pdf/10.1145/3319535.3354263) (CCS 19)

[A Formal Analysis of 5G Authentication](https://dl.acm.org/doi/pdf/10.1145/3243734.3243846) (CCS 18)

[A Systematic Analysis Method for 5G Non-Access Stratum Signalling Security](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=8817957) (IEEE Access 19)

[From Control to Chaos: A Comprehensive Formal Analysis of 5G's Access Control](https://www.computer.org/csdl/proceedings-article/sp/2025/223600b043/26hiU5s1BGE) (IEEE S&P 25)


### Fuzzing & Testing
[Touching the Untouchables: Dynamic Security Analysis of the LTE Control Plane](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=8835363) (IEEE S&P 19)

[ProChecker: An Automated Security and Privacy Analysis Framework for 4G LTE Protocol Implementations](https://ieeexplore.ieee.org/document/9546434) (ICDCS21)

[Noncompliance as Deviant Behavior: An Automated Black-box Noncompliance Checker for 4G LTE Cellular Devices](https://dl.acm.org/doi/pdf/10.1145/3460120.3485388) (CCS 21)

[DoLTEst: In-depth Downlink Negative Testing Framework for LTE Devices](https://www.usenix.org/system/files/sec22-park-cheoljun.pdf) (USENIX Sec 22)

[Putting LTE Security Functions to the Test: A Framework to Evaluate Implementation Correctness](https://www.usenix.org/system/files/conference/woot16/woot16-paper-rupprecht.pdf) (WOOT 16)

[UE Security Reloaded: Developing a 5G Standalone User-Side Security Testing Framework](https://dl.acm.org/doi/pdf/10.1145/3558482.3590194) (Wisec 23)

[SecChecker: Inspecting the security implementation of 5G Commercial Off-The-Shelf (COTS) mobile devices](https://www.sciencedirect.com/science/article/abs/pii/S0167404823002717)

[Towards Automated Fuzzing of 4G/5G Protocol Implementations Over the Air](https://asset-group.github.io/papers/AutoFuzz4G5G.pdf)

[An Experimental Testbed for 5G Network Security Assessment](https://inria.hal.science/hal-04364306/file/NOMS_2023.pdf)

[VET5G: A Virtual End-to-End Testbed for 5G Network Security Experimentation](https://dl.acm.org/doi/pdf/10.1145/3546096.3546111) (CSET 22)

[An Automated Vulnerability Detection Method for the 5G RRC Protocol Based on Fuzzing](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=9849690)

[5Greplay: a 5G Network Traffic Fuzzer - Application to Attack Injection](https://dl.acm.org/doi/pdf/10.1145/3465481.3470079)

[ASTRA-5G: Automated Over-the-Air Security Testing and Research Architecture for 5G SA Devices](https://dl.acm.org/doi/pdf/10.1145/3643833.3656141) (Wisec'24)

[RANsacked: A Domain-Informed Approach for Fuzzing LTE and 5G RAN-Core Interfaces](https://nathanielbennett.com/publications/ransacked.pdf) (CCS'24)

[Feedback-Guided API Fuzzing of 5G Network](https://www.ndss-symposium.org/wp-content/uploads/futureg25-71.pdf) (NDSS FutureG Workshop'25)

[MOBIDOJO: A Virtual Security Combat Platform for 5G Cellular Networks](https://www.ndss-symposium.org/wp-content/uploads/futureg25-35.pdf) (NDSS FutureG Workshop'25)

[GLaDoS: Location-aware Denial-of-Service of Cellular Networks](https://www.usenix.org/conference/usenixsecurity25/presentation/erni) (USENIX Sec 25)

### Specification analysis

[Bookworm Game: Automatic Discovery of LTE Vulnerabilities Through Documentation Analysis](https://ieeexplore.ieee.org/document/9519388) (IEEE S&P 21)

[Seeing the Forest for the Trees: Understanding Security Hazards in the 3GPP Ecosystem through Intelligent Analysis on Change Requests](https://www.usenix.org/system/files/sec22-chen-yi.pdf) (USENIX Security 22)

[Sherlock on Specs: Building LTE Conformance Tests through Automated Reasoning](https://www.usenix.org/system/files/sec23fall-prepub-518-chen-yi.pdf) (USENIX Security 23)

[Instructions Unclear: Undefined Behaviour in Cellular Network Specifications](https://www.usenix.org/system/files/usenixsecurity23-klischies.pdf) (USENIX Security 23)

[Hermes: Unlocking Security Analysis of Cellular Network Protocols by Synthesizing Finite State Machines from Natural Language Specifications](https://arxiv.org/pdf/2310.04381.pdf) (USENIX Security 24)

[CellularLint: A Systematic Approach to Identify Inconsistent Behavior in Cellular Network Specifications](https://www.usenix.org/system/files/sec24fall-prepub-400-rahman.pdf) (USENIX Security 24)


### Lower Layer attacks

[Breaking LTE on Layer Two](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=8835335) (IEEE S&P 19)

[IMP4GT: IMPersonation Attacks in 4G NeTworks](https://www.ndss-symposium.org/wp-content/uploads/2020/02/24283.pdf) (NDSS 20)

[LTE PHY Layer Vulnerability Analysis and Testing Using Open-Source SDR Tools](https://ieeexplore.ieee.org/document/8170787) (MilCom17)

[On the Criticality of Integrity Protection in 5G Fronthaul Networks](https://www.usenix.org/system/files/usenixsecurity24-xing-jiarong.pdf) (USENIX Security 24)


### Overshadowing attacks

[Hiding in Plain Signal: Physical Signal Overshadowing Attack on LTE](https://www.usenix.org/system/files/sec19-yang-hojoon.pdf) (USENIX Sec 19)

[AdaptOver: Adaptive Overshadowing Attacks in Cellular Networks](https://dl.acm.org/doi/pdf/10.1145/3495243.3560525) (MobiCom 21)

[LTRACK: Stealthy Tracking of Mobile Phones in LTE](https://www.usenix.org/system/files/sec22summer_kotuliak.pdf) (Usenix Sec 22)

[SigUnder: a stealthy 5G low power attack and defenses](https://dl.acm.org/doi/pdf/10.1145/3448300.3467817) (Wisec 21)

### Eavesdropping

[Call Me Maybe: Eavesdropping Encrypted LTE Calls With ReVoLTE](https://www.usenix.org/system/files/sec20-rupprecht.pdf) (USENIX Sec 20)

[From 5G Sniffing to Harvesting Leakages of Privacy-Preserving Messengers](https://www.khoury.northeastern.edu/home/noubir/publications-local/LRN2023.pdf) (IEEE S&P 23)

[LTESniffer: An Open-source LTE Downlink/Uplink Eavesdropper](https://syssec.kaist.ac.kr/pub/2023/wisec2023_tuan.pdf) (Wisec 23)

### SMS attacks

[New Security Threats Caused by IMS-based SMS Service in 4G LTE Networks](https://dl.acm.org/doi/pdf/10.1145/2976749.2978393) (CCS 16)

[IMS is Not That Secure on Your 5G/4G Phones](https://dl.acm.org/doi/pdf/10.1145/3636534.3649377) (MobiCom 24)

### Emergency Systems

[You have been warned: Abusing 5G’s Warning and Emergency Systems](https://dl.acm.org/doi/pdf/10.1145/3564625.3568000) (ACSAC 22)

[Uncovering Problematic Designs Hindering Ubiquitous Cellular Emergency Services Access](https://dl.acm.org/doi/pdf/10.1145/3636534.3690704) (MobiCom 24)

### Spoofing

[Ghost Telephonist Impersonates You: Vulnerability In 4G LTE CS Fallback](https://ieeexplore.ieee.org/document/8228629) (CNS17)

[Ghost Calls from Operational 4G Call Systems: IMS Vulnerability, Call DoS Attack, and Countermeasure](https://dl.acm.org/doi/pdf/10.1145/3372224.3380885?) (MobiCom 20)

[This is Your President Speaking: Spoofing Alerts in 4G LTE Networks](https://dl.acm.org/doi/pdf/10.1145/3307334.3326082) (MobiSys 19)

[LTE Security Disabled—Misconfiguration in Commercial Networks](https://dl.acm.org/doi/pdf/10.1145/3317549.3324927) (Wisec 19)

### Tracking

[5G SUCI-Catchers: Still catching them all?](https://dl.acm.org/doi/pdf/10.1145/3448300.3467826) (Wisec 21)

[GUTI Reallocation Demystified: Cellular Location Tracking with Changing Temporary Identifier](https://syssec.kaist.ac.kr/pub/2018/hong_ndss_2018.pdf) (NDSS 18)

[Practical Attacks Against Privacy and Availability in 4G/LTE Mobile Communication Systems](https://arxiv.org/pdf/1510.07563.pdf) (NDSS 16) 

[Enabling Physical Localization of Uncooperative Cellular Devices](https://arxiv.org/pdf/2403.14963) (MobiCom 24)

### Handover attacks

[Don’t hand it Over: Vulnerabilities in the Handover Procedure of Cellular Telecommunications](https://dl.acm.org/doi/pdf/10.1145/3485832.3485914) (ACSAC 21)

### Side-channel attacks

[Watching the Watchers: Practical Video Identification Attack in LTE Networks](https://www.usenix.org/system/files/sec22summer_bae.pdf) (USENIX Sec 22)

[Privacy Attacks to the 4G and 5G Cellular Paging Protocols Using Side Channel Information](https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_05B-5_Hussain_paper.pdf) (NDSS19)

### SIM Security

[SecureSIM: Rethinking Authentication and Access Control for SIM/eSIM](https://dl.acm.org/doi/pdf/10.1145/3447993.3483254) (MobiCom 21)

[SIMurai: Slicing Through the Complexity of SIM Card Security Research](https://www.usenix.org/system/files/usenixsecurity24-lisowski.pdf) (USENIX Security 24)

### Data-plane attack

[Data-Plane Signaling in Cellular IoT: Attacks and Defense](https://dl.acm.org/doi/pdf/10.1145/3447993.3483255) (MobiCom 21)

[Breaking Cellular IoT with Forged Data-plane Signaling: Attacks and Countermeasure](https://dl.acm.org/doi/pdf/10.1145/3534124) (MobiCom 21)

[Invade the Walled Garden: Evaluating GTP Security in Cellular Networks](https://www.computer.org/csdl/proceedings-article/sp/2025/223600a028/21B7QiopxHq) (IEEE S&P 25)

### Fingerprinting

[Preventing SIM Box Fraud Using Device Model Fingerprinting](https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_f416_paper.pdf) (NDSS 23)

[Targeted Privacy Attacks by Fingerprinting Mobile Apps in LTE Radio Layer](https://sefcom.asu.edu/publications/jaejong-dsn23.pdf) (DSN 23)

[Show Me Your Attach Request and I’ll Tell You Who You Are: Practical Fingerprinting Attacks in 4G and 5G Mobile Networks](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=9888899) (DSC 23)

[New vulnerabilities in 4G and 5G cellular access network protocols: exposing device capabilities](https://dl.acm.org/doi/pdf/10.1145/3317549.3319728) (WiSec19)

[AI-Assisted RF Fingerprinting for Identification of User Devices in 5G and FutureG](https://www.ndss-symposium.org/wp-content/uploads/futureg25-9.pdf) (NDSS FutureG Workshop'25)

### Downgrade

[Never Let Me Down Again: Bidding-Down Attacks and Mitigations in 5G and 4G](https://radix-security.com/files/2021_downgrade.pdf) (WiSec 23)

### Measurement

[Modeling and Generating Control-Plane Traffic for Cellular Networks](https://dl.acm.org/doi/pdf/10.1145/3618257.3624808) (IMC 23)

[Demystifying the Presence of Cellular Network Attacks and Misbehaviors](https://dl.acm.org/doi/pdf/10.1145/3517745.3563017) (IMC 23)

[BigMac 🍔 Performance Overhead of User Plane Integrity Protection in 5G Networks](https://radix-security.com/files/bigmac.pdf) (Wisec 23)

[European 5G Security in the Wild: Reality versus Expectations](https://arxiv.org/pdf/2305.08635.pdf) (Wisec 23)

[MOBILEATLAS: Geographically Decoupled Measurements in Cellular Networks for Security and Privacy Research](https://www.usenix.org/system/files/sec23fall-prepub-390-gegenhuber.pdf) (USENIX Security 23)

[Characterizing and Modeling Control-Plane Traffic for Mobile Core Network](https://arxiv.org/ftp/arxiv/papers/2212/2212.13248.pdf)

[Measuring the Deployment of 5G Security Enhancement](https://dl.acm.org/doi/pdf/10.1145/3507657.3528559) (Wisec 22)

[Uncovering Security Vulnerabilities in Real-world Implementation and Deployment of 5G Messaging Services](https://dl.acm.org/doi/pdf/10.1145/3643833.3656131) (Wisec'24)

[Demystifying Privacy in 5G Stand Alone Networks](https://arxiv.org/pdf/2409.17700) (MobiCom 24)

### Satellite Networks

[The Dark Side of Scale: Insecurity of Direct-to-Cell Satellite Mega-Constellations](https://ieeexplore.ieee.org/document/10646850) (IEEE S&P 24)

### Software Analysis

[Towards LLM-Assisted Vulnerability Detection and Repair for Open-Source 5G UE Implementations](https://www.ndss-symposium.org/wp-content/uploads/futureg25-21.pdf) (NDSS FutureG Workshop'25)

## Defense

### Protocol Modification
[Look Before You Leap: Secure Connection Bootstrapping for 5G Networks to Defend Against Fake Base-Stations](https://dl.acm.org/doi/pdf/10.1145/3433210.3453082) (ASIACCS 21)

[A Vulnerability in 5G Authentication Protocols and Its Countermeasure](https://www.jstage.jst.go.jp/article/transinf/E103.D/8/E103.D_2019FOL0001/_pdf)

[Privacy-Preserving and Standard-Compatible AKA Protocol for 5G](https://www.usenix.org/system/files/sec21-wang-yuchen.pdf) (USENIX Sec 21)

[Insecure Connection Bootstrapping in Cellular Networks: The Root of All Evil](https://dl.acm.org/doi/pdf/10.1145/3317549.3323402) (Wisec 19)

[BARON: Base-Station Authentication Through Core Network for Mobility Management in 5G Networks](https://dl.acm.org/doi/pdf/10.1145/3558482.3590187) (Wisec 23)

[Fixing Insecure Cellular System Information Broadcasts For Good](https://dl.acm.org/doi/pdf/10.1145/3678890.3678924) (RAID 24)

[AKMA+: Security and Privacy-Enhanced and Standard-Compatible AKMA for 5G Communication](https://www.usenix.org/conference/usenixsecurity25/presentation/yang-yang) (USENIX Sec 25)

### Defense in UE

[Thwarting Smartphone SMS Attacks at the Radio Interface Layer](https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_f432_paper.pdf) (NDSS 23)

[PHOENIX: Device-Centric Cellular Network Protocol Monitoring using Runtime Verification](https://www.ndss-symposium.org/wp-content/uploads/ndss2021_4A-3_24390_paper.pdf) (NDSS 21)

[CellDAM: User-Space, Rootless Detection and Mitigation for 5G Data Plane](https://www.usenix.org/system/files/nsdi23-tan.pdf) (NSDI 23)

[M2HO: Mitigating the Adverse Effects of 5G Handovers on TCP](https://www.cs.ucr.edu/~zhiyunq/pub/mobicom24_5g_handover.pdf) (MobiCom 24)

[Gotta Detect ’Em All: Fake Base Station and Multi-Step Attack Detection in Cellular Networks](https://www.usenix.org/conference/usenixsecurity25/presentation/mubasshir) (USENIX Sec 25)

### Fake Base Station Detection

[Murat: Multi-RAT False Base Station Detector](https://arxiv.org/pdf/2102.08780.pdf)

[FBS-Radar: Uncovering Fake Base Stations at Scale in the Wild](https://www.ccs.neu.edu/home/cbw/static/pdf/li-ndss17.pdf) (NDSS 17)

[Lies in the Air: Characterizing Fake-base-station Spam Ecosystem in China](https://dl.acm.org/doi/pdf/10.1145/3372297.3417257) (CCS 20)

[FBSleuth: Fake Base Station Forensics via Radio Frequency Fingerprinting](https://dl.acm.org/doi/pdf/10.1145/3196494.3196521) (AsiaCCS 18)

[SeaGlass: Enabling City-Wide IMSI-Catcher Detection](https://techpolicylab.uw.edu/wp-content/uploads/2018/07/SeaGlass-Enabling-City-Wide-IMSI-Catcher-Detection.pdf)

[IMSI-Catch Me If You Can: IMSI-Catcher-Catchers](https://dl.acm.org/doi/pdf/10.1145/2664243.2664272) (ACSAC 14)

[Catch You Cause I Can: Busting Rogue Base Stations using CellGuard and the Apple Cell Location Database](https://dl.acm.org/doi/pdf/10.1145/3678890.3678898) (RAID 24)

[Detecting IMSI-Catchers by Characterizing Identity Exposing Messages in Cellular Traffic](https://www.ndss-symposium.org/wp-content/uploads/2025-1115-paper.pdf) (NDSS 25)

[Gotta Detect 'Em All: Fake Base Station and Multi-Step Attack Detection in Cellular Networks](https://arxiv.org/pdf/2401.04958) (USENIX Security 25)

### Defense on O-RAN

[5G-Spector: An O-RAN Compliant Layer-3 Cellular Attack Detection Service](http://web.cse.ohio-state.edu/~wen.423/papers/5G-Spector-NDSS24.pdf) (NDSS 24)

[Developing xApps for Rogue Base Station Detection in SDR-Enabled O-RAN](https://ieeexplore.ieee.org/document/10225868) (INFOCOM WKSHPS 23)

[A Fine-Grained Telemetry Stream for Security Services in 5G Open Radio Access Networks](https://dl.acm.org/doi/pdf/10.1145/3565474.3569070) (EmergingWireless 22)

[Det-RAN: Data-Driven Cross-Layer Real-Time Attack Detection in 5G Open RANs](https://ece.northeastern.edu/wineslab/papers/scalingi2024infocom.pdf) (INFOCOM 24)

[6G-XSec: Explainable Edge Security for Emerging OpenRAN Architectures](https://dl.acm.org/doi/pdf/10.1145/3696348.3696881) (HotNets 24)

[SpotLight: Accurate, Explainable and Efficient Anomaly Detection for Open RAN](https://dl.acm.org/doi/pdf/10.1145/3636534.3649380) (MobiCom 24)

### Network Diagnosis

[SEEN: ML Assisted Cellular Service Diagnosis](https://dl.acm.org/doi/pdf/10.1145/3636534.3690678) (MobiCom 24)

## O-RAN related

[AI Testing Framework for Next-G O-RAN Networks: Requirements, Design, and Research Opportunities](https://arxiv.org/pdf/2211.03979.pdf)

[Taking 5G RAN Analytics and Control to a New Level](https://dl.acm.org/doi/pdf/10.1145/3570361.3592493) (MobiCom 23)

[dApps: Distributed Applications for Real-time Inference and Control in O-RAN](https://arxiv.org/pdf/2203.02370.pdf)

[DeepBeam: Deep Waveform Learning for Coordination-Free Beam Management in mmWave Networks](https://arxiv.org/pdf/2012.14350.pdf)

[Intelligence and Learning in O-RAN for Data-Driven NextG Cellular Networks](https://ece.northeastern.edu/wineslab/papers/bonati2021intelligence.pdf)

[ColO-RAN: Developing Machine Learning-based xApps for Open RAN Closed-loop Control on Programmable Experimental Platforms](https://arxiv.org/pdf/2112.09559.pdf)

[Understanding O-RAN: Architecture, Interfaces, Algorithms, Security, and Research Challenges](https://arxiv.org/pdf/2202.01032.pdf)

[Securing 5G OpenRAN with a Scalable Authorization Framework for xApps](https://arxiv.org/pdf/2212.11465.pdf)

[Programmable and Customized Intelligence for Traffic Steering in 5G Networks Using Open RAN Architectures](https://arxiv.org/pdf/2209.14171.pdf)

[FlexRAN: A Flexible and Programmable Platform for Software-Defined Radio Access Networks](https://dl.acm.org/doi/pdf/10.1145/2999572.2999599)

[FlexRIC: An SDK for Next-Generation SD-RANs](https://dl.acm.org/doi/pdf/10.1145/3485983.3494870)

[Security Testing The O-RAN Near-Real Time RIC & A1 Interface](https://dl.acm.org/doi/pdf/10.1145/3643833.3656118) (Wisec'24)

[System-level Analysis of Adversarial Attacks and Defenses on Intelligence in O-RAN based Cellular Networks](https://dl.acm.org/doi/pdf/10.1145/3643833.3656119) (Wisec'24)

[Implementing and Evaluating Security in O-RAN: Interfaces, Intelligence, and Platforms](https://arxiv.org/pdf/2304.11125) (IEEE Network Magazine)

[ABElity: Attribute Based Encryption for Securing RIC Communication in Open RAN](https://www.ndss-symposium.org/wp-content/uploads/futureg25-99.pdf) (NDSS FutureG Workshop'25)

## Core Network Security

[Evaluating the Security Posture of 5G Networks by Combining State Auditing and Event Monitoring](https://cisr.encs.concordia.ca/papers/ESORICS_2023_paper_377_5GSPE.pdf) (ESORICS'23)

[A Systematic Analysis of 5G Networks With a Focus on 5G Core Security](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=9709835)

[Device-centric detection and mitigation of diameter signaling attacks against mobile core](https://ieeexplore.ieee.org/document/9705031)

[On the Challenges of Automata Reconstruction in LTE Networks](https://dl.acm.org/doi/pdf/10.1145/3448300.3469133)

[5GAC-Analyzer: Identifying Over-Privilege Between 5G Core Network Functions](https://dl.acm.org/doi/pdf/10.1145/3643833.3656134) (Wisec'24)

[PROV5GC: Hardening 5G Core Network Security with Attack Detection and Attribution Based on Provenance Graphs](https://dl.acm.org/doi/pdf/10.1145/3643833.3656129) (Wisec'24)

[Performance Evaluation of Transport Layer Security in the 5G Core Control Plane](https://dl.acm.org/doi/pdf/10.1145/3643833.3656140) (Wisec'24)

[Towards Shielding 5G Control Plane Functions](https://dsn2024uq.github.io/Proceedings/pdfs/DSN2024-6rvE3SSpzFYmysif75Dkid/410500a302/410500a302.pdf) (DSN'24)

[Examining Cryptography and Randomness Failures in Open-Source Cellular Cores](https://www.enck.org/pubs/english-codaspy24.pdf) (CODASPY'24)

[Towards Establishing a Systematic Security Framework for Next Generation Cellular Networks](https://www.ndss-symposium.org/wp-content/uploads/futureg25-84.pdf) (NDSS FutureG Workshop'25)

[CoreCrisis: Threat-Guided and Context-Aware Iterative Learning and Fuzzing of 5G Core Networks](https://www.usenix.org/conference/usenixsecurity25/presentation/dong-yilu) (USENIX Sec 25)


## Network Slicing Security

[Slicure5G: Secure Slicing for 5G](https://www.cs.purdue.edu/homes/fahmy/posters/nsdi23poster5G.pdf)

[SliceSecure: Impact and Detection of DoS/DDoS Attacks on 5G Network Slices](https://uregina.ca/~nss373/papers/slice-secure.pdf)

[Secure5G: A Deep Learning Framework Towards a Secure Network Slicing in 5G and Beyond](https://ieeexplore.ieee.org/abstract/document/9031158)

[DeepSecure: Detection of distributed denial of service attacks on 5G network slicing—Deep learning approach](https://ieeexplore.ieee.org/abstract/document/9638941)

## Survey

[5G core network security issues and attack classification from network protocol perspective](https://isyou.info/jisis/vol10/no2/jisis-2020-vol10-no2-01.pdf)

[5G Security and Privacy – A Research Roadmap](https://arxiv.org/ftp/arxiv/papers/2003/2003.13604.pdf)

[Improving 4G/5G air interface security: A survey of existing attacks on different LTE layers](https://www.sciencedirect.com/science/article/pii/S1389128621004576)


## Open Source Projects / Frameworks / Tools

### RAN

[srsRAN](https://github.com/srsran)

[openairinterface5g](https://gitlab.eurecom.fr/oai/openairinterface5g)

[UERANSIM](https://github.com/aligungr/UERANSIM)

[YateBTS](https://yatebts.com/)

### Core

[Open5GS](https://github.com/open5gs/open5gs)

[Free5gc](https://github.com/free5gc/free5gc)

[OAI 5GC](https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-fed/)

### O-RAN RIC / xApps / rApps

[O-RAN SC](https://wiki.o-ran-sc.org/display/ORAN)

[SDRAN-in-a-Box (RiaB)](https://docs.sd-ran.org/master/sdran-in-a-box/README.html)

[FlexRIC](https://gitlab.eurecom.fr/mosaic5g/flexric)

[Open AI Cellular](https://www.openaicellular.org/)

### Misc

[Awesome-Cellular-Hacking](https://github.com/W00t3k/Awesome-Cellular-Hacking)

[awesome-5g](https://github.com/calee0219/awesome-5g)

[5Ghoul - 5G NR Attacks & 5G OTA Fuzzing⚡](https://github.com/asset-group/5ghoul-5g-nr-attacks)

## Testbeds

[Colosseum](https://www.northeastern.edu/colosseum/) 

[Colosseum: Large-Scale Wireless Experimentation Through Hardware-in-the-Loop Network Emulation](https://arxiv.org/pdf/2110.10617.pdf)

[Powder (the Platform for Open Wireless Data-driven Experimental Research)](https://powderwireless.net/)


## Open Dataset

[5G Traffic Datasets](https://ieee-dataport.org/documents/5g-traffic-datasets)

[Beyond Throughput, The Next Generation: a 5G Dataset with Channel and Context Metrics](https://github.com/uccmisl/5Gdataset)

[SPEC5G: A Dataset for 5G Cellular Network Protocol Analysis](https://arxiv.org/pdf/2301.09201.pdf)

[OpenRAN Gym](https://openrangym.com/datasets)

[5G-NIDD: A Comprehensive Network Intrusion Detection Dataset Generated over 5G Wireless Network](https://arxiv.org/pdf/2212.01298.pdf)

[OpenCellid](https://www.opencellid.org/#zoom=16&lat=37.77889&lon=-122.41942)

[MobileInsight](http://www.mobileinsight.net/data.html)

[5GAD-2022 5G attack detection dataset](https://github.com/IdahoLabResearch/5GAD)

[5G Traffic Generation for Practical Simulations Using Open Datasets](https://github.com/0913ktg/5G-Traffic-Generator)

[5GC PFCP Intrusion Detection Dataset](https://ieee-dataport.org/documents/5gc-pfcp-intrusion-detection-dataset-0)

[TSpec-LLM: An Open-source Dataset for LLM Understanding of 3GPP Specifications](https://huggingface.co/datasets/rasoul-nikbakht/TSpec-LLM)

[ORAN-Bench-13K: An Open Source Benchmark for Assessing LLMs in Open Radio Access Networks](https://arxiv.org/pdf/2407.06245)

[Gotta Detect ’Em All: Fake Base Station and Multi-Step Attack Detection in Cellular Networks](https://arxiv.org/pdf/2401.04958)

