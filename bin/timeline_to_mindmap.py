#!/usr/bin/env python3
"""
Kill Chain Mind Map Generator
Connects to Splunk, pulls flagged events from the KVStore for a specific index,
and builds an XMind mind map as a chronological kill chain.

Output: .xmind file compatible with XMind 2020+
Dependencies: pip install splunk-sdk
"""

import argparse
import json
import sys
import uuid
import zipfile
from datetime import datetime
from xml.etree.ElementTree import Element, SubElement, tostring

import splunklib.client as client
import splunklib.results as results


# MITRE tactic colors (background fill)
TACTIC_COLORS = {
    "Reconnaissance":       "#4FC3F7",  # Light blue
    "Resource Development":  "#4DB6AC",  # Teal
    "Initial Access":       "#FF8A65",  # Orange
    "Execution":            "#E57373",  # Red
    "Persistence":          "#BA68C8",  # Purple
    "Privilege Escalation": "#F06292",  # Pink
    "Defense Evasion":      "#FFD54F",  # Yellow
    "Credential Access":    "#FF8A65",  # Deep orange
    "Discovery":            "#64B5F6",  # Blue
    "Lateral Movement":     "#81C784",  # Green
    "Collection":           "#A1887F",  # Brown
    "Command and Control":  "#90A4AE",  # Blue grey
    "Exfiltration":         "#7986CB",  # Indigo
    "Impact":               "#EF5350",  # Dark red
    "Uncategorized":        "#BDBDBD",  # Grey
}

# Pool of colors for hosts (cycled if more hosts than colors)
HOST_COLOR_POOL = [
    "#26A69A",  # Teal
    "#42A5F5",  # Blue
    "#AB47BC",  # Purple
    "#EC407A",  # Pink
    "#FFA726",  # Orange
    "#66BB6A",  # Green
    "#5C6BC0",  # Indigo
    "#EF5350",  # Red
    "#29B6F6",  # Light blue
    "#8D6E63",  # Brown
    "#FFCA28",  # Amber
    "#78909C",  # Blue grey
]


def uid():
    return str(uuid.uuid4())


def styled_topic(title, bg_color=None, children=None, notes=None):
    topic = {
        "id": uid(),
        "title": title,
    }
    props = {"fo:font-size": "14pt"}
    if bg_color:
        props["svg:fill"] = bg_color
    topic["style"] = {
        "id": uid(),
        "properties": props
    }
    if children:
        topic["children"] = {"attached": children}
    if notes:
        topic["notes"] = {"plain": {"content": notes}}
    return topic


def build_content_xml(root_title, sheet_title):
    xmap = Element("xmap-content", {
        "xmlns": "urn:xmind:xmap:xmlns:content:2.0",
        "xmlns:fo": "http://www.w3.org/1999/XSL/Format",
        "xmlns:svg": "http://www.w3.org/2000/svg",
        "xmlns:xhtml": "http://www.w3.org/1999/xhtml",
        "xmlns:xlink": "http://www.w3.org/1999/xlink",
        "version": "2.0",
    })
    sheet = SubElement(xmap, "sheet", {"id": uid()})
    title_el = SubElement(sheet, "title")
    title_el.text = sheet_title
    topic = SubElement(sheet, "topic", {"id": uid()})
    topic_title = SubElement(topic, "title")
    topic_title.text = root_title
    return '<?xml version="1.0" encoding="UTF-8" standalone="no"?>' + tostring(xmap, encoding="unicode")


def connect_splunk(host, port, username, password):
    service = client.connect(
        host=host, port=port, username=username, password=password, autologin=True,
    )
    print(f"[+] Connected to Splunk at {host}:{port}")
    return service


def pull_flagged_events(service, index_filter):
    query_kv = (
        '| inputlookup flagged_events where flag=1'
        f' | search idx="{index_filter}"'
        ' | table id, description, mitre_tactic, status, added_when'
    )
    print("[+] Pulling KVStore entries...")
    job = service.jobs.oneshot(query_kv, output_mode="json", count=0)
    reader = results.JSONResultsReader(job)

    kv_entries = {}
    uids = []
    for item in reader:
        if isinstance(item, dict):
            kv_entries[item.get("id", "")] = item
            uids.append(item.get("id", ""))

    if not uids:
        print(f"[+] No flagged events found for index '{index_filter}'")
        return []

    print(f"[+] Found {len(uids)} KVStore entries")

    uid_filter = " OR ".join([f'uid="{u}"' for u in uids])
    query_events = (
        f'search index="{index_filter}" ({uid_filter})'
        ' | stats latest(host) as host, latest(source) as source, latest(_time) as event_time by uid'
        ' | table uid, host, source, event_time'
    )
    print("[+] Enriching with host/source from original events...")
    job2 = service.jobs.oneshot(query_events, output_mode="json", count=0)
    reader2 = results.JSONResultsReader(job2)

    event_details = {}
    for item in reader2:
        if isinstance(item, dict):
            event_details[item.get("uid", "")] = item

    merged = []
    for uid_val, kv in kv_entries.items():
        ev = dict(kv)
        details = event_details.get(uid_val, {})
        ev["host"] = details.get("host", "N/A")
        ev["source"] = details.get("source", "N/A")
        ev["event_time"] = details.get("event_time", ev.get("added_when", "0"))
        merged.append(ev)

    print(f"[+] Merged {len(merged)} events")
    return merged


def get_event_time(ev):
    for field in ["event_time", "added_when"]:
        val = ev.get(field)
        if val:
            try:
                return float(val)
            except (ValueError, TypeError):
                pass
    return 0


def format_timestamp(epoch_val):
    try:
        ts = float(epoch_val)
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError, OSError):
        return str(epoch_val) if epoch_val else "Unknown"


def build_host_color_map(events):
    """Assign a unique color to each host."""
    hosts = sorted(set(ev.get("host", "N/A") for ev in events))
    color_map = {}
    for i, host in enumerate(hosts):
        color_map[host] = HOST_COLOR_POOL[i % len(HOST_COLOR_POOL)]
    return color_map


def build_event_topic(ev, host_colors):
    description = ev.get("description", "").strip()
    host = ev.get("host", "N/A")
    source = ev.get("source", "N/A")
    timestamp = format_timestamp(get_event_time(ev))

    title = timestamp

    host_color = host_colors.get(host)

    details = []
    if description:
        details.append(styled_topic(description))
    details.append(styled_topic(host, bg_color=host_color))
    details.append(styled_topic(source))

    # notes = (
    #     f"Time: {timestamp}\n"
    #     f"Host: {host}\n"
    #     f"Source: {source}\n"
    #     f"Description: {description}"
    # )

    topic = styled_topic(title, children=details)
    topic["structureClass"] = "org.xmind.ui.logic.right"
    return topic


def group_consecutive_tactics(events):
    groups = []
    current_tactic = None
    current_group = []

    for ev in events:
        tactic = ev.get("mitre_tactic", "").strip() or "Uncategorized"
        if tactic != current_tactic:
            if current_group:
                groups.append((current_tactic, current_group))
            current_tactic = tactic
            current_group = [ev]
        else:
            current_group.append(ev)

    if current_group:
        groups.append((current_tactic, current_group))

    return groups


def build_mindmap(events, index_filter, output_file):
    events.sort(key=get_event_time)
    groups = group_consecutive_tactics(events)
    host_colors = build_host_color_map(events)
    # Build phase topics with tactic colors
    phase_topics = []
    for i, (tactic, group_events) in enumerate(groups):
        event_topics = [build_event_topic(ev, host_colors) for ev in group_events]
        first_time = format_timestamp(get_event_time(group_events[0]))
        last_time = format_timestamp(get_event_time(group_events[-1]))
        if first_time == last_time:
            time_range = first_time
        else:
            time_range = f"{first_time} - {last_time}"
        title = f"{tactic} | {time_range}"
        tactic_color = TACTIC_COLORS.get(tactic, TACTIC_COLORS["Uncategorized"])
        phase = styled_topic(title, bg_color=tactic_color, children=event_topics)
        phase["structureClass"] = "org.xmind.ui.logic.right"
        phase_topics.append(phase)
    # Root
    first_time = format_timestamp(get_event_time(events[0]))
    last_time = format_timestamp(get_event_time(events[-1]))
    root_title = f"Kill Chain: {index_filter}"
    root = styled_topic(root_title, children=phase_topics)
    root["structureClass"] = "org.xmind.ui.tree.right"
    # Build legend as a separate branch
    legend_items = []
    # Tactic legend
    tactics_used = sorted(set(g[0] for g in groups))
    tactic_legend_children = []
    for t in tactics_used:
        c = TACTIC_COLORS.get(t, TACTIC_COLORS["Uncategorized"])
        tactic_legend_children.append(styled_topic(t, bg_color=c))
    legend_items.append(styled_topic("Tactics", children=tactic_legend_children))
    # Host legend
    host_legend_children = []
    for host in sorted(host_colors.keys()):
        host_legend_children.append(styled_topic(host, bg_color=host_colors[host]))
    legend_items.append(styled_topic("Hosts", children=host_legend_children))
    legend = styled_topic("Legend", children=legend_items)
    root["children"]["attached"].append(legend)
    sheet_title = f"Kill Chain - {index_filter}"
    sheet = {
        "id": uid(),
        "title": sheet_title,
        "rootTopic": root,
        "topicPositioning": "fixed",
    }
    content = [sheet]
    manifest = {"file-entries": {"content.json": {}, "metadata.json": {}}}
    content_xml = build_content_xml(root_title, sheet_title)
    with zipfile.ZipFile(output_file, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("content.json", json.dumps(content))
        zf.writestr("metadata.json", json.dumps({}))
        zf.writestr("manifest.json", json.dumps(manifest))
        zf.writestr("content.xml", content_xml)
    print(f"[+] Mind map saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate a chronological kill chain XMind mind map from Splunk flagged events"
    )
    parser.add_argument("--host", default="localhost", help="Splunk host (default: localhost)")
    parser.add_argument("--port", default=8089, type=int, help="Splunk management port (default: 8089)")
    parser.add_argument("--username", "-u", default="admin", help="Splunk username (default: admin)")
    parser.add_argument("--password", "-p", required=True, help="Splunk password")
    parser.add_argument("--index", "-i", required=True, help="Index to filter (idx field)")
    parser.add_argument("--output", "-o", default=None, help="Output .xmind filename")

    args = parser.parse_args()

    if not args.output:
        safe_name = args.index.replace("/", "_").replace("\\", "_")
        args.output = f"killchain_{safe_name}.xmind"

    service = connect_splunk(args.host, args.port, args.username, args.password)
    events = pull_flagged_events(service, args.index)

    if not events:
        print("[!] No flagged events found. Nothing to map.")
        sys.exit(0)

    build_mindmap(events, args.index, args.output)

    groups = group_consecutive_tactics(sorted(events, key=get_event_time))
    tactics_seq = [g[0] for g in groups]
    unique_tactics = set(tactics_seq)
    print("\n[+] Summary:")
    print(f"    Index:    {args.index}")
    print(f"    Events:   {len(events)}")
    print(f"    Phases:   {len(tactics_seq)} ({' -> '.join(tactics_seq)})")
    print(f"    Tactics:  {len(unique_tactics)} unique")
    print(f"    Output:   {args.output}")


if __name__ == "__main__":
    main()