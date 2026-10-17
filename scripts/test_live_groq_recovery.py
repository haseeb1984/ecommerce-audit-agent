"""Real Groq API smoke test for deprecated-model recovery; no DB or PageSpeed calls."""
import asyncio
import os
import sys

from ecommerce_agent import ContactInfo, StoreAuditMetrics, UniversalEcommerceAgent


async def main():
    if not os.getenv("GROQ_API_KEY"):
        raise RuntimeError("GROQ_API_KEY secret is missing; live recovery was not tested.")

    agent = UniversalEcommerceAgent()
    agent.model = "llama3-70b-8192"  # deliberately retired model
    audit = StoreAuditMetrics(
        domain="example.com",
        mobile_score=72,
        speed_index_sec=2.4,
        is_slow=False,
    )
    contact = ContactInfo(first_name="Store Owner", email="owner@example.com")

    pitch = await agent.generate_pitch(audit, contact)
    if not pitch.email_subject or not pitch.email_body or not pitch.revenue_leak_hypothesis:
        raise AssertionError("Recovered model returned an incomplete pitch.")
    if agent.model == "llama3-70b-8192":
        raise AssertionError("The deprecated model was not replaced.")
    print(f"PASS: deprecated model recovered to {agent.model}; structured pitch validated.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as exc:
        print(f"FAIL: live Groq recovery test: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise
