# GOG Galaxy - Research Artifacts

## Repository Structure

This repository contains information related to Anvil's research project on CD Projekt Red's GOG Galaxy Desktop Application:

- `advisories/`: Advisories for both vulnerabilities.
- `demo/`: Video demonstration for each of the exploits.
- `poc/`: Proof-of-Concept PowerShell scripts used to weaponize the exploitation of both issues.

## Observations

Anvil performed an analysis of the GOG Galaxy Windows Desktop Application as part of a research project. Our goal was to review the security standpoint of the application, given the case that this is broadly used by gamers from all over the world, in search of potential security issues that could be abused by attackers, such as executing code as a privileged user on the victim's host. Our engineers reviewed previously disclosed vulnerabilities affecting the software, as well as corresponding security blog posts when available, and used that information as a starting point.

Our research focused on two specific aspects of the GOG Galaxy Desktop Application (Beta): local file manipulation and inter-process communication. It is not meant to be an exhaustive security review of the application as a whole.

The main objective was to assume the posture of an outside attacker with no access to internal or confidential information and discover security weaknesses that would impact confidentiality, integrity, or availability of the GOG Galaxy Client as an application and its underlying host machine when running.

We started our research with software version `v2.0.67.2 (Beta)` and confirmed that both findings were valid up to version `v2.0.71.2 (Beta)`, which as of that time, was the latest released version.

More specifically, we focused on both the target (`GalaxyClient.exe`) interaction with the underlying host and inter-process communication (IPC) with other services like `GalaxyClientService.exe`. We worked on understanding the program's architecture and identifying potential weaknesses that could be leveraged to break security boundaries (e.g. elevating privileges).

The Denial-of-Service (DoS) issue (CVE-2023-50915) is mostly tied to improper file handling, as the privileged `GalaxyClientService.exe` process is writing logs as `NT AUTHORITY/SYSTEM` into a folder on which plain users have read, write and execute access to.

For the Local Privilege Escalation (LPE) issue (CVE-2023-50914), we identified a design flaw in the way inter-process communication (IPC) is handled between the `GalaxyClient.exe` and the `GalaxyClientService.exe` processes. By leveraging this issue, we were able to forge and send an IPC packet which modified the discretionary access control list (DACL) of GOG Galaxy's main directory. This was further exploited to plant a malicious DLL named `profapi.dll` that was later loaded by the service's process (i.e. binary planting) and spawned a new CMD process as `NT AUTHORITY/SYSTEM`.

This LPE is related to CVEs CVE-2020-7352, CVE-2020-24574 and likely others. However, our exploitation path is new and target a function that was not found in previous public exploits.

It should be noted that the above mentioned findings can be exploited by a local attacker who has a low-privileged foothold on the victim's computer. By exploiting the vulnerabilities, the attacker can permanently damage the victim's computer or elevate from low to SYSTEM (the highest) privileges on the victim's computer. While it may be considered a high requirement for exploitation, local access is a common threat considered by most modern software, especially popular ones.

## Timeline

- **2023-09-07:** *Anvil contacted GOG via their support web page with a link containing the advisory with the findings and our 90-day disclosure policy.*
- **2023-09-28:** *After multiple follow-up emails, GOG confirms that they received Anvil's message and that they are forwarding it to their internal security team. Anvil asked if it was possible to be put in direct contact with their security team.*
- **2023-10-10:** *GOG replies that there is no actual ETA and that is not possible to establish a direct communication with their security team.*
- **2023-10-31:** *Anvil requested updates.*
- **2023-11-07:** *GOG replies that there is no update and asks for a new link pointing to the initial advisory as the previous one expired. Anvil provides a new link to the advisory.*
- **2023-12-06:** *Anvil requests an update and reminds GOG that the 90-day disclosure period has already expired. Anvil asks if GOG is requesting an extension.*
- **2023-12-14:** *Anvil requests CVE IDs to MITRE.*
- **2023-12-15:** *MITRE answers with the following assigned CVE IDs: CVE-2023-50914 and CVE-2023-50915.*
- **2024-01-04:** *GOG replies that they are still investigating the issues and that they have no actual ETA to provide. Anvil responds with the CVE IDs assigned by MITRE, and explains that we'll be publishing details about the issues in the upcoming months.*
- **2024-02-20:** *GOG sends an email explaining that the security team is still investigating the issues. Anvil replies that the publication of our blog post is coming soon.*
