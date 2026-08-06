from sqlalchemy import Column, Integer, String, Float, Text, DateTime, func
from database import Base

class AuditLead(Base):
    __tablename__ = "audit_leads"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), index=True, nullable=False)
    mobile_score = Column(Integer, nullable=False)
    speed_index_sec = Column(Float, nullable=False)
    contact_email = Column(String(255), nullable=True)
    revenue_leak_hypothesis = Column(Text, nullable=True)
    email_subject = Column(String(255), nullable=True)
    email_body = Column(Text, nullable=True)
    source_channel = Column(String(50), default="wordpress_hub")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
