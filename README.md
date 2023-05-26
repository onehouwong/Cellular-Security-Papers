# Cellular-Security-Papers

This repo collects academic papers / Git repos / conference talks / frameworks / tools related to the research of cellular security and privacy.

## Table of Content

- [Baseband Analysis](https://github.com/onehouwong/Cellular-Security-Papers#baseband-analysis)
- [Vulnerability Discovery](https://github.com/onehouwong/Cellular-Security-Papers#vulnerability-discovery)
- [Defense](https://github.com/onehouwong/Cellular-Security-Papers#defense)
- [O-RAN Related](https://github.com/onehouwong/Cellular-Security-Papers#o-ran-related)
- [Core Network Security](https://github.com/onehouwong/Cellular-Security-Papers#core-network-security)
- [Survey](https://github.com/onehouwong/Cellular-Security-Papers#survey)
- [Open Source Projects / Frameworks / Tools](https://github.com/onehouwong/Cellular-Security-Papers#open-source-projects--frameworks--tools)
- [Open Dataset](https://github.com/onehouwong/Cellular-Security-Papers#open-dataset)


## Baseband Analysis 
### Baseband Reverse Engineering

[awesome-baseband-research](https://github.com/lololosys/awesome-baseband-research) Nice summary of research works in baseband firmware RE. 

[Shannon (SAMSUNG) baseband reverse engineering](https://github.com/grant-h/ShannonBaseband)

[MediaTec-baseband-LTE-RE](https://github.com/cyrozap/mediatek-lte-baseband-re)

[BASESPEC: Comparative Analysis of Baseband Software and Cellular Specifications for L3 Protocols](https://www.ndss-symposium.org/wp-content/uploads/2021-365-paper.pdf) (NDSS 2021)

[Baseband Attacks: Remote Exploitation of Memory Corruptions in Cellular Protocol Stacks](https://www.usenix.org/system/files/conference/woot12/woot12-final24.pdf&lang=en) (USENIX WOOT 2012) 

[Huawei baseband exploit](https://i.blackhat.com/us-18/Thu-August-9/us-18-Grassi-Exploitation-of-a-Modern-Smartphone-Baseband-wp.pdf) (BH 18) 

[How to design a baseband debugger (Samsung Shannon)](https://www.sstic.org/media/SSTIC2020/SSTIC-actes/how_to_design_a_baseband_debugger/SSTIC2020-Article-how_to_design_a_baseband_debugger-berard_fargues.pdf) 

[Putting LTE Security Functions to the Test: A Framework to Evaluate Implementation Correctness](https://www.usenix.org/system/files/conference/woot16/woot16-paper-rupprecht.pdf) (WOOT 16)

### Emulation and fuzzing 
[Emulating Samsung’s Baseband for Security Testing](https://i.blackhat.com/USA-20/Wednesday/us-20-Hernandez-Emulating-Samsungs-Baseband-For-Security-Testing.pdf)

[BaseSAFE: Baseband SAnitized Fuzzing through Emulation](https://dl.acm.org/doi/pdf/10.1145/3395351.3399360?casa_token=3UggI7CmJX4AAAAA:Deh7qkL1M6xy5lm6BqsPcYdH5wbhUDzH4ckQPNkDGo_LXTrkPVledrrqsnkefgzJeuX5f2DPXp4) (WiSec 20)

[FIRMWIRE: Transparent Dynamic Analysis for Cellular Baseband Firmware](https://www.ndss-symposium.org/wp-content/uploads/2022-136-paper.pdf) (NDSS 22)


## Vulnerability Discovery

### Formal verification
[LTEInspector: A Systematic Approach for Adversarial Testing of 4G LTE](https://www.ndss-symposium.org/wp-content/uploads/2018/02/ndss2018_02A-3_Hussain_paper.pdf) (NDSS18)

[5GReasoner: A Property-Directed Security and Privacy Analysis Framework for 5G Cellular Network Protocol](https://scholar.google.com/scholar_url?url=https://dl.acm.org/doi/pdf/10.1145/3319535.3354263&hl=en&sa=T&oi=gsb-gga&ct=res&cd=0&d=8387770294509502037&ei=9xZwZKCVOpn5yATM9JTYDw&scisig=AGlGAw8UO9qubAAFKM0dMirIo53Y) (CCS19)

[A Formal Analysis of 5G Authentication](https://dl.acm.org/doi/pdf/10.1145/3243734.3243846?casa_token=Udg5jHRM7eIAAAAA:UFmvjlfg5cqOoO2sRiynZ61F3yiBOfvaKgByZE6_uI0Cgaf6HnlPmHsTNrKijHqCR6XflDstT7w) (CCS18)

### Fuzz testing
[Touching the Untouchables: Dynamic Security Analysis of the LTE Control Plane](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=8835363&casa_token=vyy_OHCpwYsAAAAA:HszCEmYSenLuMT33kFVwCiuvLhtdvYliLS1tBBfKoznBBeDpZtG_eXQx2TvK710ApqXF66c) (IEEE S&P 19)

[ProChecker: An Automated Security and Privacy Analysis Framework for 4G LTE Protocol Implementations](https://ieeexplore.ieee.org/document/9546434) (ICDCS21)

[Noncompliance as Deviant Behavior: An Automated Black-box Noncompliance Checker for 4G LTE Cellular Devices](https://dl.acm.org/doi/pdf/10.1145/3460120.3485388?casa_token=1trYQbO0eJ8AAAAA:movuNQPErx5n5KLo8iJxQMlFaKBYw5zA0Fm5ldAcXz6G1rNsYhIclTP2qCQaXmUGZWPN06Gjooo) (CCS 21)

[DoLTEst: In-depth Downlink Negative Testing Framework for LTE Devices](https://www.usenix.org/system/files/sec22-park-cheoljun.pdf) (USENIX Sec 22)

### Specification analysis
[Bookworm Game: Automatic Discovery of LTE Vulnerabilities Through Documentation Analysis](https://ieeexplore.ieee.org/document/9519388) (IEEE S&P 21)

[Seeing the Forest for the Trees: Understanding Security Hazards in the 3GPP Ecosystem through Intelligent Analysis on Change Requests](https://www.usenix.org/system/files/sec22-chen-yi.pdf) (USENIX Sec 22)

[Sherlock on Specs: Building LTE Conformance Tests through Automated Reasoning](https://www.usenix.org/system/files/sec23fall-prepub-518-chen-yi.pdf) (USENIX SEC 23)

### Layer 2/1 attacks

[Breaking LTE on Layer Two](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=8835335&casa_token=o8_6BFMHkgsAAAAA:4IXB1wl-Nz62dj2y5TmxJKbC96iDO-i_UDyQAwhMGBRb9RU_JSFs1Lmg1PQ3ZDd8ge7FHO0) (IEEE S&P 19)

[IMP4GT: IMPersonation Attacks in 4G NeTworks](https://www.ndss-symposium.org/wp-content/uploads/2020/02/24283.pdf) (NDSS 20)

[LTE PHY Layer Vulnerability Analysis and Testing Using Open-Source SDR Tools](https://ieeexplore.ieee.org/document/8170787) (MilCom17)

### Overshadowing attacks

[Hiding in Plain Signal: Physical Signal Overshadowing Attack on LTE](https://www.usenix.org/system/files/sec19-yang-hojoon.pdf) (USENIX Sec 19)

[AdaptOver: Adaptive Overshadowing Attacks in Cellular Networks](https://dl.acm.org/doi/pdf/10.1145/3495243.3560525) (MobiCom 21)

[LTRACK: Stealthy Tracking of Mobile Phones in LTE](https://www.usenix.org/system/files/sec22summer_kotuliak.pdf) (Usenix Sec 22)

[SigUnder: a stealthy 5G low power attack and defenses](https://dl.acm.org/doi/pdf/10.1145/3448300.3467817) (Wisec 21)

### Eavesdropping

[Call Me Maybe: Eavesdropping Encrypted LTE Calls With ReVoLTE](https://www.usenix.org/system/files/sec20-rupprecht.pdf) (USENIX Sec 20)

[From 5G Sniffing to Harvesting Leakages of Privacy-Preserving Messengers](https://www.computer.org/csdl/proceedings-article/sp/2023/933600b919/1Js0EtrckoM) (IEEE S&P 23)

### SMS attacks

[New Security Threats Caused by IMS-based SMS Service in 4G LTE Networks](https://dl.acm.org/doi/pdf/10.1145/2976749.2978393) (CCS 16)

### Spoofing

[Ghost Telephonist Impersonates You: Vulnerability In 4G LTE CS Fallback](https://ieeexplore.ieee.org/document/8228629) (CNS17)

[Ghost Calls from Operational 4G Call Systems: IMS Vulnerability, Call DoS Attack, and Countermeasure](https://dl.acm.org/doi/pdf/10.1145/3372224.3380885?) (MobiCom 20)

[This is Your President Speaking: Spoofing Alerts in 4G LTE Networks](https://dl.acm.org/doi/pdf/10.1145/3307334.3326082) (MobiSys 19)

[LTE Security Disabled—Misconfiguration in Commercial Networks](https://dl.acm.org/doi/pdf/10.1145/3317549.3324927) (Wisec 19)

[You have been warned: Abusing 5G’s Warning and Emergency Systems](https://dl.acm.org/doi/pdf/10.1145/3564625.3568000) (ACSAC 22)

### Tracking

[Practical Attacks Against Privacy and Availability in 4G/LTE Mobile Communication Systems](https://arxiv.org/pdf/1510.07563.pdf) (NDSS 16) 

[5G SUCI-Catchers: Still catching them all?](https://dl.acm.org/doi/pdf/10.1145/3448300.3467826) (Wisec 21)

### Handover attacks

[Don’t hand it Over: Vulnerabilities in the Handover Procedure of Cellular Telecommunications](https://dl.acm.org/doi/pdf/10.1145/3485832.3485914) (ACSAC 21)

### Side-channel attacks

[Watching the Watchers: Practical Video Identification Attack in LTE Networks](https://www.usenix.org/system/files/sec22summer_bae.pdf) (USENIX Sec 22)

[Privacy Attacks to the 4G and 5G Cellular Paging Protocols Using Side Channel Information](https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_05B-5_Hussain_paper.pdf) (NDSS19)

### SIM Security

[SecureSIM: Rethinking Authentication and Access Control for SIM/eSIM](https://dl.acm.org/doi/pdf/10.1145/3447993.3483254) (MobiCom 21)

### Data-plane attack

[Data-Plane Signaling in Cellular IoT: Attacks and Defense](https://dl.acm.org/doi/pdf/10.1145/3447993.3483255) (MobiCom 21)

[Breaking Cellular IoT with Forged Data-plane Signaling: Attacks and Countermeasure](https://dl.acm.org/doi/pdf/10.1145/3534124) (MobiCom 21)

### Fingerprinting

[Preventing SIM Box Fraud Using Device Model Fingerprinting](https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_f416_paper.pdf) (NDSS 23)

[Targeted Privacy Attacks by Fingerprinting Mobile Apps in LTE Radio Layer](https://sefcom.asu.edu/publications/jaejong-dsn23.pdf) (DSN 23)

[Show Me Your Attach Request and I’ll Tell You Who You Are: Practical Fingerprinting Attacks in 4G and 5G Mobile Networks](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=9888899) (DSC 23)

[New vulnerabilities in 4G and 5G cellular access network protocols: exposing device capabilities](https://dl.acm.org/doi/pdf/10.1145/3317549.3319728) (WiSec19)

## Defense
### Protocol Modification
[Look Before You Leap: Secure Connection Bootstrapping for 5G Networks to Defend Against Fake Base-Stations](https://dl.acm.org/doi/pdf/10.1145/3433210.3453082) (ASIACCS 21)

[A Vulnerability in 5G Authentication Protocols and Its Countermeasure](https://www.jstage.jst.go.jp/article/transinf/E103.D/8/E103.D_2019FOL0001/_pdf)

[Privacy-Preserving and Standard-Compatible AKA Protocol for 5G](https://www.usenix.org/system/files/sec21-wang-yuchen.pdf) (USENIX Sec 21)

[Insecure Connection Bootstrapping in Cellular Networks: The Root of All Evil](https://dl.acm.org/doi/pdf/10.1145/3317549.3323402) (Wisec 19)

### Defense in UE
[Thwarting Smartphone SMS Attacks at the Radio Interface Layer](https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_f432_paper.pdf) (NDSS 23)

[PHOENIX: Device-Centric Cellular Network Protocol Monitoring using Runtime Verification](https://www.ndss-symposium.org/wp-content/uploads/ndss2021_4A-3_24390_paper.pdf) (NDSS 21)

[CellDAM: User-Space, Rootless Detection and Mitigation for 5G Data Plane](https://www.usenix.org/system/files/nsdi23-tan.pdf) (NSDI 23)

### FBS Detection
[Murat: Multi-RAT False Base Station Detector](https://arxiv.org/pdf/2102.08780.pdf)

[FBS-Radar: Uncovering Fake Base Stations at Scale in the Wild](https://www.ccs.neu.edu/home/cbw/static/pdf/li-ndss17.pdf) (NDSS 17)

[Lies in the Air: Characterizing Fake-base-station Spam Ecosystem in China](https://dl.acm.org/doi/pdf/10.1145/3372297.3417257) (CCS 20)

[FBSleuth: Fake Base Station Forensics via Radio Frequency Fingerprinting](https://dl.acm.org/doi/pdf/10.1145/3196494.3196521) (AsiaCCS 18)

[SeaGlass: Enabling City-Wide IMSI-Catcher Detection](https://techpolicylab.uw.edu/wp-content/uploads/2018/07/SeaGlass-Enabling-City-Wide-IMSI-Catcher-Detection.pdf)

[IMSI-Catch Me If You Can: IMSI-Catcher-Catchers](https://dl.acm.org/doi/pdf/10.1145/2664243.2664272) (ACSAC 14)


## O-RAN related

[Understanding O-RAN: Architecture, Interfaces, Algorithms, Security, and Research Challenges](https://arxiv.org/pdf/2202.01032.pdf)

[Securing 5G OpenRAN with a Scalable Authorization Framework for xApps](https://arxiv.org/pdf/2212.11465.pdf)

[Programmable and Customized Intelligence for Traffic Steering in 5G Networks Using Open RAN Architectures](https://arxiv.org/pdf/2209.14171.pdf)

[FlexRAN: A Flexible and Programmable Platform for Software-Defined Radio Access Networks](https://dl.acm.org/doi/pdf/10.1145/2999572.2999599)

[FlexRIC: An SDK for Next-Generation SD-RANs](https://dl.acm.org/doi/pdf/10.1145/3485983.3494870)

[A Fine-Grained Telemetry Stream for Security Services in 5G Open Radio Access Networks](https://dl.acm.org/doi/pdf/10.1145/3565474.3569070)
       

## Core Network Security

[A Systematic Analysis of 5G Networks With a Focus on 5G Core Security](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=9709835)

[Device-centric detection and mitigation of diameter signaling attacks against mobile core](https://ieeexplore.ieee.org/document/9705031)

[On the Challenges of Automata Reconstruction in LTE Networks](https://dl.acm.org/doi/pdf/10.1145/3448300.3469133)

## Survey

[5G core network security issues and attack classification from network protocol perspective](https://isyou.info/jisis/vol10/no2/jisis-2020-vol10-no2-01.pdf)

[5G Security and Privacy – A Research Roadmap](https://arxiv.org/ftp/arxiv/papers/2003/2003.13604.pdf)

[Improving 4G/5G air interface security: A survey of existing attacks on different LTE layers](https://www.sciencedirect.com/science/article/pii/S1389128621004576?casa_token=XUZ6iZly_NcAAAAA:-TwnVCauW3481LCz1vcGxgRpIoVtA-hkvFLDJ-BeuvJowilDaLBrA-YkSTB5t_xImTP4GCFu)


## Open Source Projects / Frameworks / Tools

[srsRAN](https://github.com/srsran)

[openairinterface5g](https://gitlab.eurecom.fr/oai/openairinterface5g)

[Open5GS](https://github.com/open5gs/open5gs)

[Free5gc](https://github.com/free5gc/free5gc)

[UERANSIM](https://github.com/aligungr/UERANSIM)

[SDRAN-in-a-Box (RiaB)](https://docs.sd-ran.org/master/sdran-in-a-box/README.html)

[YateBTS](https://yatebts.com/)


## Open Dataset
[SPEC5G: A Dataset for 5G Cellular Network Protocol Analysis](https://arxiv.org/pdf/2301.09201.pdf)

[OpenRAN Gym](https://openrangym.com/datasets)

[5G-NIDD: A Comprehensive Network Intrusion Detection Dataset Generated over 5G Wireless Network](https://arxiv.org/pdf/2212.01298.pdf)

[OpenCellid](https://www.opencellid.org/#zoom=16&lat=37.77889&lon=-122.41942)

[MobileInsight](http://www.mobileinsight.net/data.html)
