# Detect, Investigate and Contain a Threat with CrowdStrike Falcon and TENEX.AI

**Duration:** approximately 60 minutes

## Scenario

You are a security analyst. Somewhere in your estate is a Windows machine that
is about to do something it should not.

In this lab you will play out a compressed version of a real security incident,
following the loop that every security operations team runs on:

**detect → triage → investigate → contain → remediate → close**

You will confirm your endpoint is being monitored, generate real detections at
three different severities, investigate the most serious one, cut the machine
off the network so an attacker cannot spread any further, prove the isolation
actually worked, and then release the machine and close the case.

---
## Your lab environment

Two virtual machines have been provisioned for you.

| | Analyst VM | Endpoint VM |
|---|---|---|
| **Hostname** | <inject key="AnalystHostname"></inject> | <inject key="EndpointHostname"></inject> |
| **Connect to (RDP)** | <inject key="analystRdpAddress"></inject> | <inject key="endpointRdpAddress"></inject> |
| **Public IP** | <inject key="analystPublicIp"></inject> | <inject key="endpointPublicIp"></inject> |
| **Private IP** | 10.0.1.20 | <inject key="endpointPrivateIp"></inject> |
| **Falcon sensor** | No | Yes |
| **Your role here** | This is your desk | This is the machine under attack |

**Sign in to both with:**

| | |
|---|---|
| Username | <inject key="adminUsername" enableCopy="false"/> |
| Password | <inject key="adminPassword" enableCopy="false"/> |

**Falcon and TENEX details** (also in your lab details panel):

| | |
|---|---|
| Falcon console | <inject key="falconConsoleUrl" enableCopy="false"/> |
| Falcon console username | <inject key="falconLoginEmail" enableCopy="false"/> |
| Falcon console password | <inject key="falconLoginPassword" enableCopy="false"/> |
| API client ID | <inject key="falconClientId" enableCopy="false"/> |
| API client secret | <inject key="falconSecret" enableCopy="false"/> |
| API base URL | <inject key="falconApiBaseUrl" enableCopy="false"/> |

### Why there are two machines

This matters, so it is worth understanding before you start rather than being
surprised in Exercise 5.

Network containment cuts the Endpoint VM off from **everything except the
CrowdStrike cloud**. If you were working on the endpoint when you contained it,
your own session to that machine would drop instantly and you would be locked
out mid-exercise.

So you work from the **Analyst VM** throughout. You will visit the Endpoint VM
exactly once, in Exercise 3, to run some commands. Everything else — the Falcon
console, TENEX, the connectivity tests — happens from the Analyst VM.

This also happens to be how real security teams operate. Nobody investigates a
compromised machine by logging into the compromised machine.

---

## Before you begin

1. Connect to the **Analyst VM** at <inject key="analystRdpAddress" enableCopy="false"/> using the
   credentials above.
2. On the desktop you will find **START-HERE.txt**, plus shortcuts to the
   Falcon console and the TENEX platform.
3. Leave this session open for the whole lab.

---

## Exercise 1: Confirm the endpoint is protected

**Time:** 10 minutes

You cannot respond to an incident on a machine you are not monitoring. Before
anything else, confirm the sensor on your endpoint is installed, online and
reporting to the Falcon cloud.

### Steps

1. On the **Analyst VM**, open the **Falcon Console** desktop shortcut (or
   browse to <inject key="falconConsoleUrl" enableCopy="false"/>).

2. Sign in with the Falcon console credentials from your lab details panel.
   You may be prompted to complete multi-factor authentication.

3. From the left-hand menu, open **Host setup and management → Host
   management**. (CrowdStrike occasionally reorganises these menus. If the path
   looks different, use the console's search and look for *Host management*.)

4. In the host list, find your endpoint: **<inject key="endpointHostname" enableCopy="false"/>**.
   Use the search or filter box — on a shared lab tenant there may be hosts
   belonging to other participants, so match the hostname exactly.

5. Click the hostname to open the host details panel, and note:
   - **Status** — should be *Online* or *Normal*
   - **Sensor version** — the version of the Falcon agent installed
   - **OS version** — Windows Server 2022
   - **Last seen** — should be within the last few minutes

### Expected result

Your endpoint appears in Host management as online, with a sensor version and a
recent "last seen" timestamp.

> **If the host is not listed**, give it two or three more minutes — the sensor
> registers shortly after the VM finishes provisioning, and the lab may have
> handed you the guide before that completed. Refresh the host list. If it is
> still missing after five minutes, raise it with your lab instructor.

### What just happened

The Falcon sensor is a lightweight agent running in the Windows kernel on the
endpoint. It watches every process start, command line, file write and network
connection, and streams that telemetry continuously to CrowdStrike's cloud. The
host record you are looking at is the cloud's view of that machine — proof the
channel is live in both directions, which is what makes the rest of this lab
possible.

---

## Exercise 2: Connect the TENEX integration

**Time:** 5 minutes

A real security team does not live in one console. Alerts from CrowdStrike flow
into whatever platform the team actually works in. TENEX connects to Falcon
through its REST API — no agent, no extra software on your machines.

### Steps

1. From your lab details panel, copy these three values:
   - **API client ID** — <inject key="falconClientId" enableCopy="false"/>
   - **API client secret** — <inject key="falconSecret" enableCopy="false"/>
   - **API base URL** — <inject key="falconApiBaseUrl" enableCopy="false"/>

2. On the **Analyst VM**, open the **TENEX Platform** desktop shortcut.

3. Add a new CrowdStrike connection using the three values above.

4. Confirm the connection reports as healthy and that TENEX can see your host.

### Expected result

TENEX shows an active CrowdStrike connection and begins pulling alerts from the
tenant.

> **Note:** depending on how your session is being run, this exercise may be
> demonstrated for you rather than performed by you. If so, read the "What just
> happened" note below and move on to Exercise 3 — nothing later in the lab
> depends on having completed this step yourself.

### What just happened

The client ID and secret are a machine identity. TENEX exchanges them for a
short-lived access token and then calls the Falcon API with it. The permissions
attached to that API client decide what TENEX is allowed to do:

- **Alerts: read** — lets it pull detections, which is the data feed it triages
- **Hosts: read and write** — lets it look up host details and, in Exercise 5,
  contain a machine without anyone opening the Falcon console

This is the integration pattern behind most security tooling: one platform
holds the sensors and the data, another consumes it through an API and acts on
it.

---

## Exercise 3: Generate detections

**Time:** 10 minutes

Now you need something to investigate. CrowdStrike provides built-in test
commands that produce genuine detections at chosen severities, without putting
any real malware on the machine.

This is the one exercise performed on the **Endpoint VM**.

### Steps

1. Connect to the **Endpoint VM** at <inject key="endpointRdpAddress" enableCopy="false"/> using the same
   credentials. (Keep your Analyst VM session open — you are coming straight
   back to it.)

2. Open **Command Prompt as Administrator**: right-click Start → *Terminal
   (Admin)* or *Command Prompt (Admin)*.

3. Run these three commands, one at a time:

   ```
   crowdstrike_test_critical
   ```
   ```
   crowdstrike_test_high
   ```
   ```
   crowdstrike_test_low
   ```

   Each one returns:

   ```
   'crowdstrike_test_critical' is not recognized as an internal or external
   command, operable program or batch file.
   ```

   **This is expected and is not a failure.** Keep going.

4. *(Optional)* For a visible on-screen reaction, open **PowerShell** and run:

   ```
   svchost.exe -testisatest
   ```

   This one behaves differently — Falcon actively blocks it, the PowerShell
   process is terminated, and a notification appears on screen.

5. Return to your **Analyst VM** session.

### Expected result

Nothing visible happened on the endpoint for the first three commands, but
three new detections now exist in the Falcon console — one Critical, one High,
one Low.

### What just happened

Those three commands are not programs, which is why Windows says it cannot find
them. Nothing executed. But the sensor saw the **command line**, recognised
these reserved strings as CrowdStrike's built-in test triggers, and raised a
detection at the matching severity in the cloud. The entire effect happened
server-side.

The optional PowerShell command is different in kind: that one demonstrates
*prevention* — Falcon terminating a process rather than merely recording it.

**Why three different severities?** Because that is the problem real security
teams actually have. A production Falcon console generates far more alerts than
anyone can read, most of them low priority. Deciding what deserves human
attention is the hard part, and it is exactly what TENEX is built to do. You
have just manufactured, in miniature, the pile of mixed-severity noise that an
analyst has to sort through every morning.

---

## Exercise 4: Investigate the critical detection

**Time:** 15 minutes

Three alerts have arrived. An analyst's first job is triage: which one matters,
and what actually happened?

### Steps

1. On the **Analyst VM**, in the Falcon console, open **Endpoint security →
   Monitor → Endpoint detections**. (Depending on console version this may be
   labelled *Alerts* or *Activity → Detections*.)

2. Confirm you can see your three new detections. Filter by hostname
   **<inject key="endpointHostname" enableCopy="false"/>** so you are looking only at your own machine.

3. Sort or filter by severity and open the **Critical** detection.

4. Work through the detection view and find each of the following:

   **The process tree.** A visual chain of what launched what. You should be
   able to read it top to bottom, something like:

   ```
   explorer.exe  →  cmd.exe  →  crowdstrike_test_critical
   ```

   Click through each process in the tree.

   **The command line.** For the flagged process, the exact command that was
   run. This is usually the single most valuable field in an investigation —
   the difference between "PowerShell ran" and "PowerShell ran *this*".

   **The host details.** Which machine, which logged-on user, which OS, and
   when. Confirm it is your endpoint and not someone else's.

   **The detection metadata.** Severity, tactic and technique, and what action
   the sensor took.

5. Now look at the **High** and **Low** detections, briefly. Notice how similar
   they look structurally despite the different severities.

### Expected result

You can describe, from the console alone, exactly what ran on the endpoint,
which process launched it, under which user account, and when.

### What just happened

This is the capability that distinguishes EDR — Endpoint Detection and Response
— from traditional antivirus. Antivirus answers one question: "was this file
bad, yes or no?" EDR records the full behavioural history so an analyst can
reconstruct an incident after the fact, including activity that is not
malicious in isolation.

No single step in a modern attack necessarily looks malicious. A document
opens. It spawns a script interpreter. The interpreter reaches out to a
website. The chain is the attack, and the process tree is how you see the
chain.

Step 5 is worth dwelling on: structurally these alerts look alike, but only one
of them deserved your time. Multiply that by a few thousand alerts a day and you
have the triage problem that TENEX exists to solve.

---

## Exercise 5: Respond — contain the host

**Time:** 15 minutes

You have decided the Critical detection is real. The priority now is to stop it
spreading, immediately, without waiting to finish the investigation.

**Network containment** blocks all network traffic to and from the endpoint
**except** traffic to the CrowdStrike cloud. The machine is cut off from file
shares, other machines, the internet and any attacker infrastructure — while
you keep full ability to investigate it and to release it later.

### Step 1: Establish your baseline

Before containing anything, prove the network path works.

On the **Analyst VM**, open a Command Prompt and run:

```
ping <inject key="endpointPrivateIp" enableCopy="false"/>
```

You should get replies. **Do not skip this** — without a working baseline, a
failed ping later proves nothing.

### Step 2: Contain the host

Either from the Falcon console:

1. Go to **Host management** and find <inject key="endpointHostname" enableCopy="false"/>.
2. Open the host's actions menu and choose **Network contain**.
3. Confirm the action.

Or, if you completed Exercise 2, trigger containment from **TENEX** instead.
The result is identical — TENEX is calling the same API the console uses.

### Step 3: Verify containment took effect

Two independent checks:

1. **In the console**, the host status for <inject key="endpointHostname" enableCopy="false"/> now reads
   **Contained**.

2. **From the Analyst VM**, run the ping again:

   ```
   ping <inject key="endpointPrivateIp" enableCopy="false"/>
   ```

   It should now **time out**.

   Your RDP session to the Endpoint VM will also have dropped, if you still had
   one open. That is containment working as designed, not a lab failure.

### Step 4: Lift containment

1. In the console, select <inject key="endpointHostname" enableCopy="false"/> again.
2. Choose **Lift containment** and confirm.
3. Wait up to a minute, then ping once more:

   ```
   ping <inject key="endpointPrivateIp" enableCopy="false"/>
   ```

   Replies should return. RDP to the endpoint works again too.

### Expected result

You contained a host, proved by two independent means that it was isolated,
then released it and proved connectivity recovered.

### What just happened

Containment is enforced by the sensor itself, in the kernel on the endpoint —
not by a network device, a firewall rule or a switch port. That is why it works
identically whether the machine is in your datacentre, in Azure, or on an
employee's home wifi.

The deliberate exception for CrowdStrike cloud traffic is the clever part. The
machine is isolated from everything that could do harm, but **not** from you.
You keep investigating it, you keep issuing commands to it, and you release it
when you are ready. A quarantine you cannot reverse remotely is not much use.

In an incident, this single action is what buys the team time: ransomware stops
spreading laterally, data stops leaving, and the attacker loses their channel —
in seconds, from a browser, without anybody walking to a desk.

---

## Exercise 6: Close the case and reset

**Time:** 5 minutes

An incident is not finished when the threat is stopped. It is finished when the
record is closed and the environment is back to a known state.

### Steps

1. In the Falcon console, open your three detections for
   **<inject key="endpointHostname" enableCopy="false"/>**.

2. For each one, set the status to **Closed** and add a brief comment, for
   example *"Lab test detection — verified benign, no action required."*

3. Confirm the host is no longer showing as Contained.

4. End your lab session.

### Expected result

No open detections remain for your host, and the host is in a normal,
uncontained state.

### What just happened

Closing alerts is not administrative tidiness. An alert left open is an alert
someone else will re-investigate, and a console full of stale alerts is how
genuine incidents get missed. Status and disposition are what let a team
measure itself: how many alerts were real, how fast they were handled, what the
false positive rate looks like.

When you relaunch this lab, you will get a brand new endpoint with a brand new
identity in the Falcon console, and none of today's detections. Every session
starts clean.

---

## Troubleshooting

| Symptom | What to check |
|---|---|
| Endpoint not listed in Host management | Wait 2–3 minutes after provisioning and refresh. The sensor registers shortly after first boot. |
| Test commands produce no detections | Confirm you opened Command Prompt **as Administrator**, and that you are on the Endpoint VM, not the Analyst VM. Allow a minute for the detection to reach the console. |
| Many hosts listed, cannot find mine | This is a shared tenant. Filter by the exact hostname <inject key="endpointHostname" enableCopy="false"/> from your lab details panel. |
| Ping fails before you contain anything | Confirm you are pinging <inject key="endpointPrivateIp" enableCopy="false"/> (the private IP) from the **Analyst VM**, not the public address. |
| Ping still succeeds after containment | Give it up to 60 seconds; the instruction has to reach the sensor. Then confirm the console shows the host as *Contained*. |
| "Network contain" option is not available | Your console account may not hold a role that permits containment. Raise it with your lab instructor. |
| RDP to the endpoint stopped working | Expected if the host is contained. Lift containment and it returns. |

---

## What you covered

| Concept | Where you saw it |
|---|---|
| Endpoint telemetry and sensor registration | Exercise 1 |
| API-based security integration | Exercise 2 |
| Detection severity and alert volume | Exercise 3 |
| Process trees and behavioural investigation | Exercise 4 |
| Network containment as a response action | Exercise 5 |
| Case closure and environment hygiene | Exercise 6 |

The loop you just completed — **detect, triage, investigate, contain,
remediate, close** — is the core rhythm of security operations. The hard part
in a real environment is not any single step; it is doing it across thousands
of alerts a day without missing the one that mattered. That is the problem
TENEX.AI is built to solve, and Exercise 3's three severities were your first
look at it.
