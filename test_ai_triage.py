import asyncio
from opensource_production import OpenSourceTriageAgent

async def test_triage():
    agent = OpenSourceTriageAgent()
    sample_alerts = [
        {
            "id": "test-alert-001",
            "title": "Suspicious login detected",
            "rule_level": 10,
            "severity": "high",
            "user": "root",
            "category": "authentication",
            "host": "test-host",
            "agent_name": "test-agent"
        },
        {
            "id": "test-alert-002",
            "title": "Malware detected on endpoint",
            "rule_level": 12,
            "severity": "critical",
            "user": "user1",
            "category": "malware",
            "host": "endpoint-1",
            "agent_name": "agent-1"
        },
        {
            "id": "test-alert-003",
            "title": "Unusual outbound traffic",
            "rule_level": 7,
            "severity": "medium",
            "user": "user2",
            "category": "network",
            "host": "server-2",
            "agent_name": "agent-2"
        },
        {
            "id": "test-alert-004",
            "title": "Failed login attempts",
            "rule_level": 5,
            "severity": "low",
            "user": "user3",
            "category": "authentication",
            "host": "server-3",
            "agent_name": "agent-3"
        }
    ]
    for alert in sample_alerts:
        result = await agent.analyze_alert(alert)
        print(f"AI Triage Result for {alert['id']}: {result}")

if __name__ == "__main__":
    asyncio.run(test_triage()) 